// SPDX-License-Identifier: LGPL-2.1-or-later
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

#[derive(Clone, Debug, Default)]
pub struct JsonObject {
    entries: Vec<(String, Value)>,
    indices: BTreeMap<String, usize>,
}

impl JsonObject {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.indices
            .get(key)
            .and_then(|index| self.entries.get(*index))
            .map(|(_, value)| value)
    }

    pub fn insert(&mut self, key: String, value: Value) -> Option<Value> {
        if let Some(index) = self.indices.get(&key).copied() {
            return Some(std::mem::replace(&mut self.entries[index].1, value));
        }
        self.indices.insert(key.clone(), self.entries.len());
        self.entries.push((key, value));
        None
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|(key, _)| key.as_str())
    }

    fn iter(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.entries
            .iter()
            .map(|(key, value)| (key.as_str(), value))
    }
}

impl PartialEq for JsonObject {
    fn eq(&self, other: &Self) -> bool {
        self.entries.len() == other.entries.len()
            && self
                .entries
                .iter()
                .all(|(key, value)| other.get(key) == Some(value))
    }
}

impl<K> FromIterator<(K, Value)> for JsonObject
where
    K: Into<String>,
{
    fn from_iter<T: IntoIterator<Item = (K, Value)>>(iter: T) -> Self {
        let mut object = Self::new();
        for (key, value) in iter {
            object.insert(key.into(), value);
        }
        object
    }
}

impl<K, const N: usize> From<[(K, Value); N]> for JsonObject
where
    K: Into<String>,
{
    fn from(entries: [(K, Value); N]) -> Self {
        entries.into_iter().collect()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(i128),
    String(String),
    Array(Vec<Value>),
    Object(JsonObject),
}

impl Value {
    pub fn object<K, I>(entries: I) -> Self
    where
        K: Into<String>,
        I: IntoIterator<Item = (K, Self)>,
    {
        Self::Object(entries.into_iter().collect())
    }

    pub fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Object(object) => object.get(key),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value.as_str()),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Number(value) => i64::try_from(*value).ok(),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Number(value) => u64::try_from(*value).ok(),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(values) => Some(values),
            _ => None,
        }
    }

    pub fn to_json(&self) -> String {
        let mut output = String::new();
        self.write_json(&mut output);
        output
    }

    pub fn to_json_pretty(&self) -> String {
        let mut output = String::new();
        self.write_json_pretty(&mut output, 0);
        output
    }

    fn write_json(&self, output: &mut String) {
        match self {
            Self::Null => output.push_str("null"),
            Self::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
            Self::Number(value) => output.push_str(&value.to_string()),
            Self::String(value) => write_string(value, output),
            Self::Array(values) => {
                output.push('[');
                for (index, value) in values.iter().enumerate() {
                    if index != 0 {
                        output.push(',');
                    }
                    value.write_json(output);
                }
                output.push(']');
            }
            Self::Object(object) => {
                output.push('{');
                for (index, (key, value)) in object.iter().enumerate() {
                    if index != 0 {
                        output.push(',');
                    }
                    write_string(key, output);
                    output.push(':');
                    value.write_json(output);
                }
                output.push('}');
            }
        }
    }

    fn write_json_pretty(&self, output: &mut String, depth: usize) {
        match self {
            Self::Array(values) if !values.is_empty() => {
                output.push_str("[\n");
                for (index, value) in values.iter().enumerate() {
                    output.push_str(&"\t".repeat(depth + 1));
                    value.write_json_pretty(output, depth + 1);
                    if index + 1 != values.len() {
                        output.push(',');
                    }
                    output.push('\n');
                }
                output.push_str(&"\t".repeat(depth));
                output.push(']');
            }
            Self::Object(object) if object.iter().next().is_some() => {
                output.push_str("{\n");
                let length = object.iter().count();
                for (index, (key, value)) in object.iter().enumerate() {
                    output.push_str(&"\t".repeat(depth + 1));
                    write_string(key, output);
                    output.push_str(" : ");
                    value.write_json_pretty(output, depth + 1);
                    if index + 1 != length {
                        output.push(',');
                    }
                    output.push('\n');
                }
                output.push_str(&"\t".repeat(depth));
                output.push('}');
            }
            _ => self.write_json(output),
        }
    }
}

fn write_string(value: &str, output: &mut String) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character < '\u{20}' => {
                use std::fmt::Write as _;
                let _ = write!(output, "\\u{:04x}", u32::from(character));
            }
            character => output.push(character),
        }
    }
    output.push('"');
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JsonError {
    pub offset: usize,
    pub message: String,
}

impl fmt::Display for JsonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "JSON byte {}: {}", self.offset, self.message)
    }
}

impl Error for JsonError {}

pub fn parse(input: &str) -> Result<Value, JsonError> {
    let mut parser = Parser { input, offset: 0 };
    let value = parser.parse_value()?;
    parser.skip_whitespace();
    if parser.offset == input.len() {
        Ok(value)
    } else {
        Err(parser.error("trailing data"))
    }
}

#[derive(Debug)]
struct Parser<'a> {
    input: &'a str,
    offset: usize,
}

impl<'a> Parser<'a> {
    fn error(&self, message: impl Into<String>) -> JsonError {
        JsonError {
            offset: self.offset,
            message: message.into(),
        }
    }

    fn remaining(&self) -> &'a str {
        &self.input[self.offset..]
    }

    fn byte(&self) -> Option<u8> {
        self.input.as_bytes().get(self.offset).copied()
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.byte(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.offset += 1;
        }
    }

    fn parse_value(&mut self) -> Result<Value, JsonError> {
        self.skip_whitespace();
        match self.byte() {
            Some(b'n') => {
                self.literal("null")?;
                Ok(Value::Null)
            }
            Some(b't') => {
                self.literal("true")?;
                Ok(Value::Bool(true))
            }
            Some(b'f') => {
                self.literal("false")?;
                Ok(Value::Bool(false))
            }
            Some(b'"') => self.parse_string().map(Value::String),
            Some(b'[') => self.parse_array(),
            Some(b'{') => self.parse_object(),
            Some(b'-' | b'0'..=b'9') => self.parse_number().map(Value::Number),
            Some(_) => Err(self.error("unexpected token")),
            None => Err(self.error("unexpected end of input")),
        }
    }

    fn literal(&mut self, literal: &str) -> Result<(), JsonError> {
        if self.remaining().starts_with(literal) {
            self.offset += literal.len();
            Ok(())
        } else {
            Err(self.error(format!("expected {literal}")))
        }
    }

    fn parse_string(&mut self) -> Result<String, JsonError> {
        if self.byte() != Some(b'"') {
            return Err(self.error("expected string"));
        }
        self.offset += 1;
        let mut output = String::new();
        loop {
            let byte = self
                .byte()
                .ok_or_else(|| self.error("unterminated string"))?;
            match byte {
                b'"' => {
                    self.offset += 1;
                    return Ok(output);
                }
                b'\\' => {
                    self.offset += 1;
                    self.parse_escape(&mut output)?;
                }
                0..=31 => return Err(self.error("control character in string")),
                0x20..=0x7f => {
                    output.push(char::from(byte));
                    self.offset += 1;
                }
                _ => {
                    let character = self
                        .remaining()
                        .chars()
                        .next()
                        .ok_or_else(|| self.error("invalid UTF-8"))?;
                    output.push(character);
                    self.offset += character.len_utf8();
                }
            }
        }
    }

    fn parse_escape(&mut self, output: &mut String) -> Result<(), JsonError> {
        let escape = self
            .byte()
            .ok_or_else(|| self.error("unterminated escape"))?;
        self.offset += 1;
        match escape {
            b'"' => output.push('"'),
            b'\\' => output.push('\\'),
            b'/' => output.push('/'),
            b'b' => output.push('\u{08}'),
            b'f' => output.push('\u{0c}'),
            b'n' => output.push('\n'),
            b'r' => output.push('\r'),
            b't' => output.push('\t'),
            b'u' => output.push(self.parse_unicode_escape()?),
            _ => return Err(self.error("invalid escape")),
        }
        Ok(())
    }

    fn parse_unicode_escape(&mut self) -> Result<char, JsonError> {
        let first = self.parse_hex_quad()?;
        let scalar = if (0xd800..=0xdbff).contains(&first) {
            if !self.remaining().starts_with("\\u") {
                return Err(self.error("high surrogate is not followed by a low surrogate"));
            }
            self.offset += 2;
            let second = self.parse_hex_quad()?;
            if !(0xdc00..=0xdfff).contains(&second) {
                return Err(self.error("invalid low surrogate"));
            }
            0x1_0000 + ((u32::from(first) - 0xd800) << 10) + (u32::from(second) - 0xdc00)
        } else if (0xdc00..=0xdfff).contains(&first) {
            return Err(self.error("unpaired low surrogate"));
        } else {
            u32::from(first)
        };
        char::from_u32(scalar).ok_or_else(|| self.error("invalid Unicode scalar value"))
    }

    fn parse_hex_quad(&mut self) -> Result<u16, JsonError> {
        let end = self
            .offset
            .checked_add(4)
            .ok_or_else(|| self.error("Unicode escape overflows input offset"))?;
        let bytes = self
            .input
            .as_bytes()
            .get(self.offset..end)
            .ok_or_else(|| self.error("short Unicode escape"))?;
        let mut value = 0u16;
        for byte in bytes {
            let digit = match *byte {
                b'0'..=b'9' => u16::from(*byte - b'0'),
                b'a'..=b'f' => u16::from(*byte - b'a') + 10,
                b'A'..=b'F' => u16::from(*byte - b'A') + 10,
                _ => return Err(self.error("invalid hexadecimal digit in Unicode escape")),
            };
            value = (value << 4) | digit;
        }
        self.offset = end;
        Ok(value)
    }

    fn parse_number(&mut self) -> Result<i128, JsonError> {
        let start = self.offset;
        if self.byte() == Some(b'-') {
            self.offset += 1;
        }
        match self.byte() {
            Some(b'0') => {
                self.offset += 1;
                if matches!(self.byte(), Some(b'0'..=b'9')) {
                    return Err(self.error("leading zero in number"));
                }
            }
            Some(b'1'..=b'9') => {
                while matches!(self.byte(), Some(b'0'..=b'9')) {
                    self.offset += 1;
                }
            }
            _ => return Err(self.error("number has no digits")),
        }
        if matches!(self.byte(), Some(b'.' | b'e' | b'E')) {
            return Err(self.error("non-integer numbers are not supported by this interface"));
        }
        self.input[start..self.offset]
            .parse()
            .map_err(|_| self.error("integer out of range"))
    }

    fn parse_array(&mut self) -> Result<Value, JsonError> {
        self.offset += 1;
        let mut values = Vec::new();
        self.skip_whitespace();
        if self.byte() == Some(b']') {
            self.offset += 1;
            return Ok(Value::Array(values));
        }
        loop {
            values.push(self.parse_value()?);
            self.skip_whitespace();
            match self.byte() {
                Some(b',') => self.offset += 1,
                Some(b']') => {
                    self.offset += 1;
                    return Ok(Value::Array(values));
                }
                _ => return Err(self.error("expected ',' or ']'")),
            }
        }
    }

    fn parse_object(&mut self) -> Result<Value, JsonError> {
        self.offset += 1;
        let mut values = JsonObject::new();
        self.skip_whitespace();
        if self.byte() == Some(b'}') {
            self.offset += 1;
            return Ok(Value::Object(values));
        }
        loop {
            self.skip_whitespace();
            let key = self.parse_string()?;
            self.skip_whitespace();
            if self.byte() != Some(b':') {
                return Err(self.error("expected ':'"));
            }
            self.offset += 1;
            let value = self.parse_value()?;
            if values.insert(key, value).is_some() {
                return Err(self.error("duplicate key"));
            }
            self.skip_whitespace();
            match self.byte() {
                Some(b',') => self.offset += 1,
                Some(b'}') => {
                    self.offset += 1;
                    return Ok(Value::Object(values));
                }
                _ => return Err(self.error("expected ',' or '}'")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_nested_value() {
        let value = Value::object([
            ("name", Value::String("resolver\nnode".to_owned())),
            ("enabled", Value::Bool(true)),
            (
                "numbers",
                Value::Array(vec![Value::Number(-1), Value::Number(42)]),
            ),
        ]);
        assert_eq!(parse(&value.to_json()), Ok(value));
    }

    #[test]
    fn preserves_object_field_order_on_the_wire() {
        let json = r#"{"third":3,"first":1,"second":2}"#;
        assert_eq!(parse(json).expect("ordered object").to_json(), json);
    }

    #[test]
    fn pretty_output_uses_systemd_style_tabs_and_colons() {
        let value = parse(r#"{"outer":{"items":[1,2]},"empty":[]}"#).expect("JSON value");
        assert_eq!(
            value.to_json_pretty(),
            "{\n\t\"outer\" : {\n\t\t\"items\" : [\n\t\t\t1,\n\t\t\t2\n\t\t]\n\t},\n\t\"empty\" : []\n}"
        );
    }

    #[test]
    fn object_equality_ignores_field_order() {
        assert_eq!(
            parse(r#"{"first":1,"second":2}"#),
            parse(r#"{"second":2,"first":1}"#)
        );
    }

    #[test]
    fn decodes_surrogate_pair() {
        assert_eq!(
            parse(r#""\ud83d\ude80""#),
            Ok(Value::String("🚀".to_owned()))
        );
    }

    #[test]
    fn rejects_duplicate_keys() {
        assert!(parse(r#"{"value":1,"value":2}"#).is_err());
    }

    #[test]
    fn rejects_leading_zero() {
        assert!(parse("01").is_err());
    }
}
