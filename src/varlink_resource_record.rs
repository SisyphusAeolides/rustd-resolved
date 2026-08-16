// SPDX-License-Identifier: LGPL-2.1-or-later

pub fn resource_record_json_from_raw(raw: &[u8]) -> Option<Value> {
    let parsed = crate::wire::parse_uncompressed_record(raw, 0).ok()?;
    if parsed.next_offset != raw.len() {
        return None;
    }
    resource_record_json(&crate::wire::AnswerRecord {
        name: parsed.name,
        rr_type: parsed.rr_type,
        class: parsed.class,
        ttl: parsed.ttl,
        rdata: parsed.rdata,
        raw: raw.to_vec(),
    })
}

pub fn resource_record_json(record: &crate::wire::AnswerRecord) -> Option<Value> {
    let parsed = crate::wire::parse_uncompressed_record(&record.raw, 0).ok()?;
    if parsed.next_offset != record.raw.len() {
        return None;
    }
    let mut fields = JsonObject::from([(
        "key".to_owned(),
        Value::object([
            ("class", Value::Number(i128::from(record.class))),
            ("type", Value::Number(i128::from(record.rr_type))),
            ("name", Value::String(record.name.text().to_owned())),
        ]),
    )]);
    let rdata = parsed.rdata.as_slice();
    match record.rr_type {
        1 if rdata.len() == 4 => rr_bytes(&mut fields, "address", rdata),
        28 if rdata.len() == 16 => rr_bytes(&mut fields, "address", rdata),
        2 | 5 | 12 | 39 => {
            let (name, end) = rr_name(&record.raw, parsed.rdata_offset)?;
            if end != parsed.next_offset {
                return None;
            }
            fields.insert("name".to_owned(), Value::String(name));
        }
        6 => {
            let (mname, offset) = rr_name(&record.raw, parsed.rdata_offset)?;
            let (rname, offset) = rr_name(&record.raw, offset)?;
            if offset.checked_add(20)? != parsed.next_offset {
                return None;
            }
            fields.insert("mname".to_owned(), Value::String(mname));
            fields.insert("rname".to_owned(), Value::String(rname));
            rr_number(&mut fields, "serial", rr_u32(&record.raw, offset)?);
            rr_number(&mut fields, "refresh", rr_u32(&record.raw, offset + 4)?);
            rr_number(&mut fields, "expire", rr_u32(&record.raw, offset + 8)?);
            rr_number(&mut fields, "minimum", rr_u32(&record.raw, offset + 16)?);
        }
        13 => {
            let (cpu, rest) = rr_character_string(rdata)?;
            let (os, rest) = rr_character_string(rest)?;
            if !rest.is_empty() {
                return None;
            }
            fields.insert("cpu".to_owned(), Value::String(rr_text(cpu)?));
            fields.insert("os".to_owned(), Value::String(rr_text(os)?));
        }
        15 => {
            rr_number(&mut fields, "priority", rr_u16(rdata, 0)?);
            let (exchange, end) = rr_name(&record.raw, parsed.rdata_offset + 2)?;
            if end != parsed.next_offset {
                return None;
            }
            fields.insert("exchange".to_owned(), Value::String(exchange));
        }
        16 | 99 => {
            fields.insert(
                "items".to_owned(),
                Value::Array(
                    rr_character_string_list(rdata)?
                        .into_iter()
                        .map(|item| Value::String(octescape(item)))
                        .collect(),
                ),
            );
        }
        29 if rdata.len() == 16 => {
            for (name, value) in [
                ("version", u32::from(rdata[0])),
                ("size", u32::from(rdata[1])),
                ("horiz_pre", u32::from(rdata[2])),
                ("vert_pre", u32::from(rdata[3])),
                ("latitude", rr_u32(rdata, 4)?),
                ("longitude", rr_u32(rdata, 8)?),
                ("altitude", rr_u32(rdata, 12)?),
            ] {
                rr_number(&mut fields, name, value);
            }
        }
        33 => {
            rr_number(&mut fields, "priority", rr_u16(rdata, 0)?);
            rr_number(&mut fields, "weight", rr_u16(rdata, 2)?);
            rr_number(&mut fields, "port", rr_u16(rdata, 4)?);
            let (name, end) = rr_name(&record.raw, parsed.rdata_offset + 6)?;
            if end != parsed.next_offset {
                return None;
            }
            fields.insert("name".to_owned(), Value::String(name));
        }
        35 => {
            rr_number(&mut fields, "order", rr_u16(rdata, 0)?);
            rr_number(&mut fields, "preference", rr_u16(rdata, 2)?);
            let (flags, rest) = rr_character_string(rdata.get(4..)?)?;
            let (services, rest) = rr_character_string(rest)?;
            let (regexp, rest) = rr_character_string(rest)?;
            let name_offset = parsed.next_offset.checked_sub(rest.len())?;
            let (replacement, end) = rr_name(&record.raw, name_offset)?;
            if end != parsed.next_offset {
                return None;
            }
            fields.insert("naptrFlags".to_owned(), Value::String(rr_text(flags)?));
            fields.insert("services".to_owned(), Value::String(rr_text(services)?));
            fields.insert("regexp".to_owned(), Value::String(rr_text(regexp)?));
            fields.insert("replacement".to_owned(), Value::String(replacement));
        }
        43 => {
            let value = crate::wire::parse_ds(&parsed).ok()?;
            rr_number(&mut fields, "keyTag", value.key_tag);
            rr_number(&mut fields, "algorithm", value.algorithm);
            rr_number(&mut fields, "digestType", value.digest_type);
            fields.insert("digest".to_owned(), Value::String(rr_hex(&value.digest)));
        }
        44 if rdata.len() >= 3 => {
            rr_number(&mut fields, "algorithm", rdata[0]);
            rr_number(&mut fields, "fptype", rdata[1]);
            fields.insert("fingerprint".to_owned(), Value::String(rr_hex(&rdata[2..])));
        }
        46 => {
            let value = crate::wire::parse_rrsig(&record.raw, &parsed).ok()?;
            fields.insert(
                "signer".to_owned(),
                Value::String(value.signer.text().to_owned()),
            );
            rr_number(&mut fields, "typeCovered", value.type_covered);
            rr_number(&mut fields, "algorithm", value.algorithm);
            rr_number(&mut fields, "labels", value.labels);
            rr_number(&mut fields, "originalTtl", value.original_ttl);
            rr_number(&mut fields, "expiration", value.expiration);
            rr_number(&mut fields, "inception", value.inception);
            rr_number(&mut fields, "keyTag", value.key_tag);
            fields.insert(
                "signature".to_owned(),
                Value::String(base64(&value.signature)),
            );
        }
        47 => {
            let value = crate::wire::parse_nsec(&record.raw, &parsed).ok()?;
            fields.insert(
                "nextDomain".to_owned(),
                Value::String(value.next_domain.text().to_owned()),
            );
            rr_numbers(&mut fields, "types", &value.types);
        }
        48 => {
            let value = crate::wire::parse_dnskey(&parsed).ok()?;
            rr_number(&mut fields, "flags", value.flags);
            rr_number(&mut fields, "protocol", value.protocol);
            rr_number(&mut fields, "algorithm", value.algorithm);
            fields.insert(
                "dnskey".to_owned(),
                Value::String(base64(&value.public_key)),
            );
        }
        50 => {
            let value = crate::wire::parse_nsec3(&parsed).ok()?;
            rr_number(&mut fields, "algorithm", value.hash_algorithm);
            rr_number(&mut fields, "flags", value.flags);
            rr_number(&mut fields, "iterations", value.iterations);
            fields.insert("salt".to_owned(), Value::String(rr_hex(&value.salt)));
            fields.insert(
                "hash".to_owned(),
                Value::String(rr_base32hex(&value.next_hashed_owner)),
            );
            rr_numbers(&mut fields, "types", &value.types);
        }
        52 if rdata.len() >= 3 => {
            rr_number(&mut fields, "certUsage", rdata[0]);
            rr_number(&mut fields, "selector", rdata[1]);
            rr_number(&mut fields, "matchingType", rdata[2]);
            fields.insert("data".to_owned(), Value::String(rr_hex(&rdata[3..])));
        }
        64 | 65 => {
            rr_number(&mut fields, "priority", rr_u16(rdata, 0)?);
            let (target, offset) = rr_name(&record.raw, parsed.rdata_offset + 2)?;
            fields.insert("target".to_owned(), Value::String(target));
            fields.insert(
                "svcparams".to_owned(),
                rr_svcparams(record.raw.get(offset..parsed.next_offset)?)?,
            );
        }
        257 if rdata.len() >= 2 => {
            let tag_length = usize::from(rdata[1]);
            let tag_end = 2usize.checked_add(tag_length)?;
            let tag = rdata.get(2..tag_end)?;
            rr_number(&mut fields, "flags", rdata[0]);
            fields.insert("tag".to_owned(), Value::String(rr_text(tag)?));
            fields.insert(
                "value".to_owned(),
                Value::String(caa_octescape(rdata.get(tag_end..)?)),
            );
        }
        _ => return None,
    }
    Some(Value::Object(fields))
}

fn caa_octescape(input: &[u8]) -> String {
    let mut output = String::new();
    for &byte in input {
        if (0x20..=0x7e).contains(&byte) && !matches!(byte, b'\\' | b'"') {
            output.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(output, "\\{byte:03o}");
        }
    }
    output
}

fn rr_number<T: Into<i128>>(fields: &mut JsonObject, name: &str, value: T) {
    fields.insert(name.to_owned(), Value::Number(value.into()));
}

fn rr_numbers(fields: &mut JsonObject, name: &str, values: &[u16]) {
    fields.insert(
        name.to_owned(),
        Value::Array(
            values
                .iter()
                .copied()
                .map(|value| Value::Number(i128::from(value)))
                .collect(),
        ),
    );
}

fn rr_bytes(fields: &mut JsonObject, name: &str, values: &[u8]) {
    fields.insert(
        name.to_owned(),
        Value::Array(
            values
                .iter()
                .copied()
                .map(|value| Value::Number(i128::from(value)))
                .collect(),
        ),
    );
}

fn rr_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn rr_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn rr_name(packet: &[u8], offset: usize) -> Option<(String, usize)> {
    let (name, end) = crate::wire::read_name(packet, offset).ok()?;
    Some((name.text().to_owned(), end))
}

fn rr_character_string(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let length = usize::from(*bytes.first()?);
    let end = 1usize.checked_add(length)?;
    Some((bytes.get(1..end)?, bytes.get(end..)?))
}

fn rr_character_string_list(mut bytes: &[u8]) -> Option<Vec<&[u8]>> {
    let mut items = Vec::new();
    while !bytes.is_empty() {
        let (item, rest) = rr_character_string(bytes)?;
        items.push(item);
        bytes = rest;
    }
    Some(items)
}

fn rr_text(bytes: &[u8]) -> Option<String> {
    String::from_utf8(bytes.to_vec()).ok()
}

fn rr_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn rr_base32hex(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";
    let mut output = String::with_capacity(bytes.len().saturating_mul(8).div_ceil(5));
    let mut accumulator = 0u32;
    let mut bits = 0u8;
    for byte in bytes {
        accumulator = (accumulator << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(char::from(
                ALPHABET[((accumulator >> bits) & 0x1f) as usize],
            ));
        }
    }
    if bits > 0 {
        output.push(char::from(
            ALPHABET[((accumulator << (5 - bits)) & 0x1f) as usize],
        ));
    }
    output
}

fn rr_svcparams(mut bytes: &[u8]) -> Option<Value> {
    let mut fields = JsonObject::new();
    let mut any = false;
    while !bytes.is_empty() {
        let key = rr_u16(bytes, 0)?;
        let length = usize::from(rr_u16(bytes, 2)?);
        let end = 4usize.checked_add(length)?;
        let value = bytes.get(4..end)?;
        let name = match key {
            0 => "mandatory".to_owned(),
            1 => "alpn".to_owned(),
            2 => "no-default-alpn".to_owned(),
            3 => "port".to_owned(),
            4 => "ipv4hint".to_owned(),
            5 => "ech".to_owned(),
            6 => "ipv6hint".to_owned(),
            7 => "dohpath".to_owned(),
            8 => "ohttp".to_owned(),
            _ => format!("key{key}"),
        };
        fields.insert(name, Value::String(base64(value)));
        any = true;
        bytes = bytes.get(end..)?;
    }
    if !any {
        Some(Value::Null)
    } else {
        Some(Value::Object(fields))
    }
}

#[cfg(test)]
mod resource_record_json_tests {
    use super::*;

    fn answer(rr_type: u16, rdata: &[u8]) -> crate::wire::AnswerRecord {
        let mut raw = crate::wire::encode_name("example.test").expect("owner name");
        raw.extend_from_slice(&rr_type.to_be_bytes());
        raw.extend_from_slice(&crate::wire::CLASS_IN.to_be_bytes());
        raw.extend_from_slice(&300u32.to_be_bytes());
        raw.extend_from_slice(
            &u16::try_from(rdata.len())
                .expect("record data length")
                .to_be_bytes(),
        );
        raw.extend_from_slice(rdata);
        let parsed = crate::wire::parse_record(&raw, 0).expect("resource record");
        crate::wire::AnswerRecord {
            name: parsed.name,
            rr_type,
            class: crate::wire::CLASS_IN,
            ttl: 300,
            rdata: rdata.to_vec(),
            raw,
        }
    }

    #[test]
    fn serializes_name_service_and_soa_records() {
        let target = crate::wire::encode_name("target.test").expect("target name");
        for (rr_type, prefix, field) in [
            (2, Vec::new(), "name"),
            (15, 10u16.to_be_bytes().to_vec(), "exchange"),
        ] {
            let mut rdata = prefix;
            rdata.extend_from_slice(&target);
            let value = resource_record_json(&answer(rr_type, &rdata)).expect("record JSON");
            assert_eq!(
                value.get(field).and_then(Value::as_str),
                Some("target.test")
            );
        }

        let mut srv = Vec::new();
        srv.extend_from_slice(&10u16.to_be_bytes());
        srv.extend_from_slice(&20u16.to_be_bytes());
        srv.extend_from_slice(&443u16.to_be_bytes());
        srv.extend_from_slice(&target);
        let value = resource_record_json(&answer(33, &srv)).expect("SRV JSON");
        assert_eq!(value.get("priority").and_then(Value::as_i64), Some(10));
        assert_eq!(value.get("weight").and_then(Value::as_i64), Some(20));
        assert_eq!(value.get("port").and_then(Value::as_i64), Some(443));

        let mut soa = target.clone();
        soa.extend_from_slice(&crate::wire::encode_name("hostmaster.test").expect("rname"));
        for value in [1u32, 2, 3, 4, 5] {
            soa.extend_from_slice(&value.to_be_bytes());
        }
        let value = resource_record_json(&answer(6, &soa)).expect("SOA JSON");
        assert_eq!(value.get("serial").and_then(Value::as_i64), Some(1));
        assert_eq!(value.get("refresh").and_then(Value::as_i64), Some(2));
        assert_eq!(value.get("expire").and_then(Value::as_i64), Some(3));
        assert_eq!(value.get("minimum").and_then(Value::as_i64), Some(5));
    }

    #[test]
    fn serializes_svcb_svcparams_with_dohpath_and_ohttp() {
        let target = crate::wire::encode_name("svc.target").expect("svc.target");
        let mut rdata = 1u16.to_be_bytes().to_vec();
        rdata.extend_from_slice(&target);
        rdata.extend_from_slice(&7u16.to_be_bytes());
        rdata.extend_from_slice(&4u16.to_be_bytes());
        rdata.extend_from_slice(b"foo/");
        rdata.extend_from_slice(&8u16.to_be_bytes());
        rdata.extend_from_slice(&1u16.to_be_bytes());
        rdata.extend_from_slice(&[0x42]);
        let value = resource_record_json(&answer(64, &rdata)).expect("SVCB JSON");
        let params = match value.get("svcparams") {
            Some(Value::Object(object)) => object,
            _ => panic!("svcparams"),
        };
        assert_eq!(
            params.get("dohpath").and_then(Value::as_str),
            Some("Zm9vLw==")
        );
        assert_eq!(params.get("ohttp").and_then(Value::as_str), Some("Qg=="));
    }

    #[test]
    fn serializes_dnssec_record_families() {
        let ds = answer(43, &[0x12, 0x34, 8, 99, 0xaa, 0xbb]);
        let value = resource_record_json(&ds).expect("DS JSON");
        assert_eq!(value.get("keyTag").and_then(Value::as_i64), Some(0x1234));
        assert_eq!(value.get("digest").and_then(Value::as_str), Some("aabb"));

        let dnskey = answer(48, &[1, 1, 3, 15, 1, 2, 3]);
        let value = resource_record_json(&dnskey).expect("DNSKEY JSON");
        assert_eq!(value.get("dnskey").and_then(Value::as_str), Some("AQID"));

        let signer = crate::wire::encode_name("signer.test").expect("signer name");
        let mut rrsig = Vec::new();
        rrsig.extend_from_slice(&1u16.to_be_bytes());
        rrsig.extend_from_slice(&[15, 2]);
        rrsig.extend_from_slice(&300u32.to_be_bytes());
        rrsig.extend_from_slice(&20u32.to_be_bytes());
        rrsig.extend_from_slice(&10u32.to_be_bytes());
        rrsig.extend_from_slice(&0x1234u16.to_be_bytes());
        rrsig.extend_from_slice(&signer);
        rrsig.extend_from_slice(&[1, 2, 3]);
        let value = resource_record_json(&answer(46, &rrsig)).expect("RRSIG JSON");
        assert_eq!(
            value.get("signer").and_then(Value::as_str),
            Some("signer.test")
        );
        assert_eq!(value.get("signature").and_then(Value::as_str), Some("AQID"));

        let mut nsec = crate::wire::encode_name("next.test").expect("next name");
        nsec.extend_from_slice(&[0, 1, 0x40]);
        let value = resource_record_json(&answer(47, &nsec)).expect("NSEC JSON");
        assert_eq!(
            value
                .get("types")
                .and_then(Value::as_array)
                .and_then(|types| types.first())
                .and_then(Value::as_i64),
            Some(1)
        );

        let value = resource_record_json(&answer(50, &[1, 0, 0, 0, 0, 1, 0xaa, 0, 1, 0x40]))
            .expect("NSEC3 JSON");
        assert_eq!(value.get("hash").and_then(Value::as_str), Some("L8"));
    }

    #[test]
    fn serializes_svcb_caa_and_naptr_records() {
        let target = crate::wire::encode_name("target.test").expect("target name");
        let mut svcb = 1u16.to_be_bytes().to_vec();
        svcb.extend_from_slice(&target);
        svcb.extend_from_slice(&3u16.to_be_bytes());
        svcb.extend_from_slice(&2u16.to_be_bytes());
        svcb.extend_from_slice(&443u16.to_be_bytes());
        let value = resource_record_json(&answer(64, &svcb)).expect("SVCB JSON");
        assert_eq!(
            value.get("target").and_then(Value::as_str),
            Some("target.test")
        );
        assert_eq!(
            value
                .get("svcparams")
                .and_then(|params| params.get("port"))
                .and_then(Value::as_str),
            Some("Abs=")
        );

        let value = resource_record_json(&answer(257, b"\0\x05issueca.example")).expect("CAA JSON");
        assert_eq!(value.get("tag").and_then(Value::as_str), Some("issue"));
        assert_eq!(
            value.get("value").and_then(Value::as_str),
            Some("ca.example")
        );

        let mut naptr = Vec::new();
        naptr.extend_from_slice(&10u16.to_be_bytes());
        naptr.extend_from_slice(&20u16.to_be_bytes());
        for value in [b"s".as_slice(), b"SIP+D2U".as_slice(), b"".as_slice()] {
            naptr.push(u8::try_from(value.len()).expect("character string length"));
            naptr.extend_from_slice(value);
        }
        naptr.extend_from_slice(&target);
        let value = resource_record_json(&answer(35, &naptr)).expect("NAPTR JSON");
        assert_eq!(value.get("order").and_then(Value::as_i64), Some(10));
        assert_eq!(value.get("naptrFlags").and_then(Value::as_str), Some("s"));
        assert_eq!(
            value.get("replacement").and_then(Value::as_str),
            Some("target.test")
        );
    }

    #[test]
    fn raw_record_projection_omits_unstructured_types() {
        let unsupported = answer(10, &[1, 2, 3]);
        assert!(resource_record_json(&unsupported).is_none());
        assert!(resource_record_json_from_raw(&unsupported.raw).is_none());
        assert_eq!(rr_base32hex(b"foo"), "CPNMU");
    }
}
