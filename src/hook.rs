// SPDX-License-Identifier: LGPL-2.1-or-later
use crate::json::{self, Value};
use crate::wire::{self, Header, WireError};
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_HOOK_DIRECTORY: &str = crate::native_paths::HOOK_DIR;
const FILTER_TIMEOUT: Duration = Duration::from_millis(100);
const MAX_FRAME_SIZE: usize = 1024 * 1024;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct HookFilter {
    domains: Option<Vec<String>>,
    labels_min: Option<u32>,
    labels_max: Option<u32>,
}

impl HookFilter {
    fn matches(&self, name: &str) -> bool {
        let name = canonical_name(name);
        let labels = if name.is_empty() {
            0
        } else {
            name.split('.').count() as u32
        };
        if self.labels_min.is_some_and(|minimum| labels < minimum)
            || self.labels_max.is_some_and(|maximum| labels > maximum)
        {
            return false;
        }
        self.domains.as_ref().map_or(true, |domains| {
            domains.iter().any(|domain| {
                domain.is_empty()
                    || name == *domain
                    || name
                        .strip_suffix(domain)
                        .is_some_and(|prefix| prefix.ends_with('.'))
            })
        })
    }
}

#[derive(Debug)]
struct HookReply {
    path: PathBuf,
    rcode: u16,
    answer: Vec<Vec<u8>>,
}

pub fn resolve(query: &[u8], unicast_query: &[u8], timeout: Duration) -> Option<Vec<u8>> {
    if !hooks_enabled() {
        return None;
    }
    let directory = std::env::var_os("RUSTD_RESOLVED_HOOK_PATH")
        .map_or_else(|| PathBuf::from(DEFAULT_HOOK_DIRECTORY), PathBuf::from);
    resolve_grouped_in_directory(query, &[unicast_query], &[query], timeout, &directory)
}

pub(crate) fn resolve_grouped(
    response_query: &[u8],
    idna_queries: &[&[u8]],
    utf8_queries: &[&[u8]],
    timeout: Duration,
) -> Option<Vec<u8>> {
    if !hooks_enabled() {
        return None;
    }
    let directory = std::env::var_os("RUSTD_RESOLVED_HOOK_PATH")
        .map_or_else(|| PathBuf::from(DEFAULT_HOOK_DIRECTORY), PathBuf::from);
    resolve_grouped_in_directory(
        response_query,
        idna_queries,
        utf8_queries,
        timeout,
        &directory,
    )
}

fn resolve_grouped_in_directory(
    response_query: &[u8],
    idna_queries: &[&[u8]],
    utf8_queries: &[&[u8]],
    timeout: Duration,
    directory: &Path,
) -> Option<Vec<u8>> {
    let questions = merge_questions(idna_queries, utf8_queries)?;
    let filter_names = questions
        .iter()
        .map(|question| question.name.text())
        .collect::<Vec<_>>();
    let mut replies = thread::scope(|scope| {
        let (sender, receiver) = mpsc::channel();
        let cancellation = crate::query_cancel::current();
        for path in discover(directory) {
            let sender = sender.clone();
            let questions = &questions;
            let filter_names = &filter_names;
            let cancellation = cancellation.clone();
            scope.spawn(move || {
                crate::query_cancel::with_optional(cancellation, || {
                    let filter = query_filter(&path).unwrap_or_default();
                    if !filter_names.iter().any(|name| filter.matches(name)) {
                        return;
                    }
                    let Some((rcode, answer)) = query_hook(&path, questions, timeout) else {
                        return;
                    };
                    let _ = sender.send(HookReply {
                        path,
                        rcode,
                        answer,
                    });
                });
            });
        }
        drop(sender);
        receiver.into_iter().collect::<Vec<_>>()
    });
    replies.sort_by(|left, right| left.path.cmp(&right.path));
    let selected = select_reply(replies)?;
    build_response(response_query, selected.rcode, &selected.answer).ok()
}

fn merge_questions(idna_queries: &[&[u8]], utf8_queries: &[&[u8]]) -> Option<Vec<wire::Question>> {
    let mut questions = Vec::new();
    for query in idna_queries.iter().chain(utf8_queries) {
        let question = wire::first_question(query).ok()?;
        let duplicate = questions.iter().any(|existing: &wire::Question| {
            existing.class == question.class
                && existing.rr_type == question.rr_type
                && existing.name.canonical_wire() == question.name.canonical_wire()
        });
        if !duplicate {
            questions.push(question);
        }
    }
    (!questions.is_empty()).then_some(questions)
}

fn hooks_enabled() -> bool {
    std::env::var("SYSTEMD_RESOLVED_HOOK")
        .map(|value| {
            !matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "0" | "no" | "false" | "off"
            )
        })
        .unwrap_or(true)
}

fn discover(directory: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut paths = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            entry
                .file_type()
                .ok()
                .filter(FileTypeExt::is_socket)
                .map(|_| entry.path())
        })
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

fn query_filter(path: &Path) -> Option<HookFilter> {
    let request = Value::object([
        (
            "method",
            Value::String("io.rustd.Resolve.Hook.QueryFilter".to_owned()),
        ),
        ("parameters", Value::object(Vec::<(String, Value)>::new())),
        ("more", Value::Bool(true)),
    ]);
    let reply = varlink_call(path, &request, FILTER_TIMEOUT).ok()?;
    if reply.get("error").is_some() || reply.get("continues").and_then(Value::as_bool) != Some(true)
    {
        return None;
    }
    parse_filter(reply.get("parameters")?)
}

fn parse_filter(parameters: &Value) -> Option<HookFilter> {
    let domains = match parameters.get("filterDomains") {
        None | Some(Value::Null) => None,
        Some(value) => Some(
            value
                .as_array()?
                .iter()
                .map(|domain| domain.as_str().map(canonical_name))
                .collect::<Option<Vec<_>>>()?,
        ),
    };
    let labels_min = optional_u32(parameters, "filterLabelsMin")?;
    let labels_max = optional_u32(parameters, "filterLabelsMax")?;
    Some(HookFilter {
        domains,
        labels_min,
        labels_max,
    })
}

fn optional_u32(parameters: &Value, key: &str) -> Option<Option<u32>> {
    match parameters.get(key) {
        None | Some(Value::Null) => Some(None),
        Some(value) => value
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .map(Some),
    }
}

fn canonical_name(name: &str) -> String {
    let name = name.trim_end_matches('.');
    if name.is_empty() {
        return String::new();
    }
    wire::make_query(name, wire::TYPE_A, 0)
        .ok()
        .and_then(|query| wire::first_question(&query).ok())
        .map_or_else(
            || name.to_ascii_lowercase(),
            |question| question.name.text().to_ascii_lowercase(),
        )
}

fn query_hook(
    path: &Path,
    questions: &[wire::Question],
    timeout: Duration,
) -> Option<(u16, Vec<Vec<u8>>)> {
    let questions = questions
        .iter()
        .map(|question| {
            Value::object([(
                "key",
                Value::object([
                    ("class", Value::Number(i128::from(question.class))),
                    ("type", Value::Number(i128::from(question.rr_type))),
                    ("name", Value::String(question.name.text().to_owned())),
                ]),
            )])
        })
        .collect();
    let request = Value::object([
        (
            "method",
            Value::String("io.rustd.Resolve.Hook.ResolveRecord".to_owned()),
        ),
        (
            "parameters",
            Value::object([("question", Value::Array(questions))]),
        ),
    ]);
    let reply = varlink_call(path, &request, timeout).ok()?;
    if reply.get("error").is_some() {
        return None;
    }
    let parameters = reply.get("parameters")?;
    let rcode = parameters
        .get("rcode")?
        .as_u64()
        .and_then(|value| u16::try_from(value).ok())?;
    if rcode > 15 {
        return None;
    }
    let answer = match parameters.get("answer") {
        None | Some(Value::Null) => Vec::new(),
        Some(value) => value
            .as_array()?
            .iter()
            .map(|entry| entry.get("raw")?.as_str().and_then(decode_base64))
            .collect::<Option<Vec<_>>>()?,
    };
    Some((rcode, answer))
}

fn select_reply(replies: Vec<HookReply>) -> Option<HookReply> {
    let mut selected: Option<HookReply> = None;
    for reply in replies {
        let replace = match &selected {
            None => true,
            Some(current) if reply.rcode == 0 => {
                current.rcode != 0
                    || current.answer.is_empty()
                    || (!reply.answer.is_empty() && reply.path < current.path)
            }
            Some(current) => reply.path < current.path,
        };
        if replace {
            selected = Some(reply);
        }
    }
    selected
}

fn varlink_call(path: &Path, request: &Value, timeout: Duration) -> io::Result<Value> {
    check_cancellation()?;
    let mut stream = UnixStream::connect(path)?;
    let io_timeout = timeout.min(Duration::from_millis(100));
    stream.set_read_timeout(Some(io_timeout))?;
    stream.set_write_timeout(Some(io_timeout))?;
    stream.write_all(request.to_json().as_bytes())?;
    stream.write_all(&[0])?;
    let started = Instant::now();
    let frame = read_frame_cancellable(&mut stream, timeout, started)?;
    let text = std::str::from_utf8(&frame)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    json::parse(text).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn read_frame_cancellable(
    stream: &mut UnixStream,
    timeout: Duration,
    started: Instant,
) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let length = match stream.read(&mut buffer) {
            Ok(length) => length,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                check_cancellation()?;
                if started.elapsed() >= timeout {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Varlink hook reply timed out",
                    ));
                }
                continue;
            }
            Err(error) => return Err(error),
        };
        if length == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Varlink connection closed before a reply",
            ));
        }
        if let Some(end) = buffer[..length].iter().position(|byte| *byte == 0) {
            output.extend_from_slice(&buffer[..end]);
            if output.len() > MAX_FRAME_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Varlink frame exceeds the size limit",
                ));
            }
            return Ok(output);
        }
        output.extend_from_slice(&buffer[..length]);
        if output.len() > MAX_FRAME_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Varlink frame exceeds the size limit",
            ));
        }
    }
}

fn check_cancellation() -> io::Result<()> {
    crate::query_cancel::check()
        .map_err(|_| io::Error::new(io::ErrorKind::Interrupted, "resolver client disconnected"))
}

fn read_frame(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let length = stream.read(&mut buffer)?;
        if length == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Varlink connection closed before a reply",
            ));
        }
        if let Some(end) = buffer[..length].iter().position(|byte| *byte == 0) {
            output.extend_from_slice(&buffer[..end]);
            if output.len() > MAX_FRAME_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Varlink frame exceeds the size limit",
                ));
            }
            return Ok(output);
        }
        output.extend_from_slice(&buffer[..length]);
        if output.len() > MAX_FRAME_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Varlink frame exceeds the size limit",
            ));
        }
    }
}

fn build_response(query: &[u8], rcode: u16, answer: &[Vec<u8>]) -> Result<Vec<u8>, WireError> {
    wire::validate(query, false)?;
    if rcode > 15 || answer.len() > usize::from(u16::MAX) {
        return Err(WireError::InvalidRecord);
    }
    let question_end = wire::question_end(query)?;
    let mut response = query[..question_end].to_vec();
    let query_flags = Header::parse(query)?.flags;
    let flags = (query_flags & 0x0110) | 0x8080 | rcode;
    response[2..4].copy_from_slice(&flags.to_be_bytes());
    let answer_count = u16::try_from(if rcode == 0 { answer.len() } else { 0 })
        .map_err(|_| WireError::ResponseTooLarge)?;
    response[6..8].copy_from_slice(&answer_count.to_be_bytes());
    response[8..12].fill(0);
    if rcode == 0 {
        for record in answer {
            response.extend_from_slice(record);
            if response.len() > usize::from(u16::MAX) {
                return Err(WireError::ResponseTooLarge);
            }
        }
    }
    wire::validate(&response, true)?;
    Ok(response)
}

fn decode_base64(input: &str) -> Option<Vec<u8>> {
    if input.len() % 4 != 0 {
        return None;
    }
    let mut output = Vec::with_capacity(input.len() / 4 * 3);
    for (index, chunk) in input.as_bytes().chunks_exact(4).enumerate() {
        let last = index + 1 == input.len() / 4;
        let first = base64_value(chunk[0])?;
        let second = base64_value(chunk[1])?;
        let third = if chunk[2] == b'=' {
            if chunk[3] != b'=' || !last || second & 0x0f != 0 {
                return None;
            }
            None
        } else {
            Some(base64_value(chunk[2])?)
        };
        let fourth = if chunk[3] == b'=' {
            if !last || third.is_some_and(|value| value & 0x03 != 0) {
                return None;
            }
            None
        } else {
            Some(base64_value(chunk[3])?)
        };
        if third.is_none() && fourth.is_some() {
            return None;
        }
        output.push((first << 2) | (second >> 4));
        if let Some(third) = third {
            output.push((second << 4) | (third >> 2));
            if let Some(fourth) = fourth {
                output.push((third << 6) | fourth);
            }
        }
    }
    Some(output)
}

const fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{
        extract_address_records, extract_answer_records, local_response, make_query,
    };
    use crate::wire::{LocalRecord, TYPE_A, TYPE_AAAA};
    use std::net::Ipv4Addr;
    use std::os::unix::net::UnixListener;
    use std::thread;
    use tempfile::tempdir;

    fn read_request(stream: &mut UnixStream) -> Value {
        let frame = read_frame(stream).expect("request frame");
        json::parse(std::str::from_utf8(&frame).expect("UTF-8 request")).expect("JSON request")
    }

    fn write_reply(stream: &mut UnixStream, reply: Value) {
        stream
            .write_all(reply.to_json().as_bytes())
            .expect("reply JSON");
        stream.write_all(&[0]).expect("reply terminator");
    }

    fn base64(input: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut output = String::new();
        for chunk in input.chunks(3) {
            let second = chunk.get(1).copied().unwrap_or(0);
            let third = chunk.get(2).copied().unwrap_or(0);
            output.push(char::from(ALPHABET[usize::from(chunk[0] >> 2)]));
            output.push(char::from(
                ALPHABET[usize::from(((chunk[0] & 3) << 4) | (second >> 4))],
            ));
            output.push(if chunk.len() > 1 {
                char::from(ALPHABET[usize::from(((second & 15) << 2) | (third >> 6))])
            } else {
                '='
            });
            output.push(if chunk.len() > 2 {
                char::from(ALPHABET[usize::from(third & 63)])
            } else {
                '='
            });
        }
        output
    }

    #[test]
    fn filter_matches_recursive_domains_and_label_bounds() {
        let filter = HookFilter {
            domains: Some(vec!["example.test".to_owned()]),
            labels_min: Some(3),
            labels_max: Some(4),
        };
        assert!(filter.matches("www.example.test"));
        assert!(filter.matches("deep.www.example.test."));
        assert!(!filter.matches("example.test"));
        assert!(!filter.matches("too.deep.www.example.test"));
        assert!(!filter.matches("notexample.test"));

        let internationalized = HookFilter {
            domains: Some(vec![canonical_name("bücher.example")]),
            labels_min: None,
            labels_max: None,
        };
        assert!(internationalized.matches(r"b\195\188cher.example"));
    }

    #[test]
    fn hook_answer_preempts_regular_resolution() {
        let temporary = tempdir().expect("temporary directory");
        let socket = temporary.path().join("10-test");
        let listener = UnixListener::bind(socket).expect("hook listener");
        let query = make_query("hook.example", TYPE_A, 0x7171).expect("query");
        let source = local_response(&query, &[LocalRecord::A(Ipv4Addr::new(192, 0, 2, 44))], 45)
            .expect("source response");
        let raw = extract_answer_records(&source).expect("source record")[0]
            .raw
            .clone();
        let server = thread::spawn(move || {
            let (mut filter, _) = listener.accept().expect("filter connection");
            let request = read_request(&mut filter);
            assert_eq!(
                request.get("method").and_then(Value::as_str),
                Some("io.rustd.Resolve.Hook.QueryFilter")
            );
            assert_eq!(request.get("more").and_then(Value::as_bool), Some(true));
            write_reply(
                &mut filter,
                Value::object([
                    (
                        "parameters",
                        Value::object([(
                            "filterDomains",
                            Value::Array(vec![Value::String("example".to_owned())]),
                        )]),
                    ),
                    ("continues", Value::Bool(true)),
                ]),
            );

            let (mut lookup, _) = listener.accept().expect("lookup connection");
            let request = read_request(&mut lookup);
            assert_eq!(
                request.get("method").and_then(Value::as_str),
                Some("io.rustd.Resolve.Hook.ResolveRecord")
            );
            write_reply(
                &mut lookup,
                Value::object([(
                    "parameters",
                    Value::object([
                        ("rcode", Value::Number(0)),
                        (
                            "answer",
                            Value::Array(vec![Value::object([(
                                "raw",
                                Value::String(base64(&raw)),
                            )])]),
                        ),
                    ]),
                )]),
            );
        });
        let response = resolve_grouped_in_directory(
            &query,
            &[&query],
            &[&query],
            Duration::from_secs(1),
            temporary.path(),
        )
        .expect("hook response");
        let records = extract_address_records(&response, Some(2)).expect("hook address");
        assert_eq!(
            records.addresses,
            [std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44))]
        );
        server.join().expect("hook server");
    }

    #[test]
    fn malformed_or_uninterested_hooks_fail_open() {
        let temporary = tempdir().expect("temporary directory");
        let socket = temporary.path().join("20-filtered");
        let listener = UnixListener::bind(socket).expect("hook listener");
        let server = thread::spawn(move || {
            let (mut filter, _) = listener.accept().expect("filter connection");
            let _ = read_request(&mut filter);
            write_reply(
                &mut filter,
                Value::object([
                    (
                        "parameters",
                        Value::object([(
                            "filterDomains",
                            Value::Array(vec![Value::String("elsewhere.test".to_owned())]),
                        )]),
                    ),
                    ("continues", Value::Bool(true)),
                ]),
            );
        });
        let query = make_query("hook.example", TYPE_A, 0x7272).expect("query");
        assert!(resolve_grouped_in_directory(
            &query,
            &[&query],
            &[&query],
            Duration::from_secs(1),
            temporary.path(),
        )
        .is_none());
        server.join().expect("hook server");
        assert!(decode_base64("Zh==").is_none());
        assert!(decode_base64("Zg==").is_some());
    }

    #[test]
    fn grouped_questions_are_idna_first_and_deduplicated() {
        let temporary = tempdir().expect("temporary directory");
        let socket = temporary.path().join("30-grouped");
        let listener = UnixListener::bind(socket).expect("hook listener");
        let server = thread::spawn(move || {
            let (mut filter, _) = listener.accept().expect("filter connection");
            let _ = read_request(&mut filter);
            write_reply(
                &mut filter,
                Value::object([
                    ("parameters", Value::object(Vec::<(String, Value)>::new())),
                    ("continues", Value::Bool(true)),
                ]),
            );

            let (mut lookup, _) = listener.accept().expect("lookup connection");
            let request = read_request(&mut lookup);
            let questions = request
                .get("parameters")
                .and_then(|parameters| parameters.get("question"))
                .and_then(Value::as_array)
                .expect("question array");
            let keys = questions
                .iter()
                .map(|question| {
                    let key = question.get("key").expect("question key");
                    (
                        key.get("name")
                            .and_then(Value::as_str)
                            .expect("question name"),
                        key.get("type")
                            .and_then(Value::as_u64)
                            .expect("question type"),
                    )
                })
                .collect::<Vec<_>>();
            assert_eq!(
                keys,
                [
                    ("xn--bcher-kva.example", u64::from(TYPE_A)),
                    ("xn--bcher-kva.example", u64::from(TYPE_AAAA)),
                    (r"b\195\188cher.example", u64::from(TYPE_A)),
                    (r"b\195\188cher.example", u64::from(TYPE_AAAA)),
                ]
            );
            write_reply(
                &mut lookup,
                Value::object([(
                    "parameters",
                    Value::object([
                        ("rcode", Value::Number(0)),
                        ("answer", Value::Array(Vec::new())),
                    ]),
                )]),
            );
        });

        let idna_a = make_query("xn--bcher-kva.example", TYPE_A, 0x7373).expect("IDNA A");
        let idna_aaaa = make_query("xn--bcher-kva.example", TYPE_AAAA, 0x7373).expect("IDNA AAAA");
        let utf8_a = make_query("bücher.example", TYPE_A, 0x7373).expect("UTF-8 A");
        let utf8_aaaa = make_query("bücher.example", TYPE_AAAA, 0x7373).expect("UTF-8 AAAA");
        assert!(resolve_grouped_in_directory(
            &utf8_a,
            &[&idna_a, &idna_aaaa, &idna_a],
            &[&utf8_a, &utf8_aaaa, &utf8_a],
            Duration::from_secs(1),
            temporary.path(),
        )
        .is_some());
        server.join().expect("hook server");
    }
}
