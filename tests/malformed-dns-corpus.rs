// SPDX-License-Identifier: LGPL-2.1-or-later
#![allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
use rustd_resolved::{edns, wire};
use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;

const CASES_PER_SEED: usize = 2_048;
const MAX_PACKET_SIZE: usize = 4_096;

#[test]
fn malformed_dns_corpus_never_panics() {
    let mut seeds = vec![
        Vec::new(),
        vec![0; wire::DNS_HEADER_LEN - 1],
        vec![0xff; wire::DNS_HEADER_LEN],
        wire::make_query("example.test", wire::TYPE_A, 0x1234).expect("A query"),
        wire::make_query(".", wire::TYPE_AAAA, 0x4321).expect("root query"),
    ];

    let mut pointer_loop =
        wire::make_query("example.test", wire::TYPE_A, 0x0102).expect("compression-loop seed");
    pointer_loop[wire::DNS_HEADER_LEN] = 0xc0;
    pointer_loop[wire::DNS_HEADER_LEN + 1] = wire::DNS_HEADER_LEN as u8;
    seeds.push(pointer_loop);

    let mut state = 0x7265_736f_6c76_6564_u64;
    for (seed_index, seed) in seeds.iter().enumerate() {
        for case_index in 0..CASES_PER_SEED {
            let packet = mutate(seed, &mut state);
            let name_offset = if packet.is_empty() {
                0
            } else {
                usize::try_from(next(&mut state)).unwrap_or(0) % packet.len()
            };
            let record_offset = if packet.is_empty() {
                0
            } else {
                usize::try_from(next(&mut state)).unwrap_or(0) % packet.len()
            };

            let result = catch_unwind(AssertUnwindSafe(|| {
                let _ = wire::Header::parse(&packet);
                let _ = wire::validate(&packet, false);
                let _ = wire::validate(&packet, true);
                let _ = wire::first_question(&packet);
                let _ = wire::read_name(&packet, name_offset);
                let _ = wire::parse_record(&packet, record_offset);
                let _ = wire::extract_answer_records(&packet);
                let _ = wire::extract_service_records(&packet);
                let _ = edns::inspect_opt(&packet);
                if let Ok(opt) = edns::inspect_opt(&packet) {
                    let _ = edns::full_rcode(&packet, opt.as_ref());
                    if let Some(opt) = opt {
                        let _ = edns::extended_error(&opt);
                    }
                }
            }));

            assert!(
                result.is_ok(),
                "decoder panicked for seed {seed_index}, case {case_index}, {} bytes: {}",
                packet.len(),
                encode_hex(&packet)
            );
        }
    }
}

#[test]
fn hostile_section_counts_remain_bounded() {
    let mut packet = vec![0; wire::DNS_HEADER_LEN];
    packet[4..12].fill(0xff);

    let result = catch_unwind(AssertUnwindSafe(|| {
        assert!(wire::validate(&packet, false).is_err());
        assert!(wire::validate(&packet, true).is_err());
        assert!(edns::inspect_opt(&packet).is_err());
    }));
    assert!(result.is_ok());
}

#[test]
fn fuzz_corpus_entries_do_not_panic() {
    let corpus_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz")
        .join("corpus")
        .join("dns_packet");
    let mut entries = match fs::read_dir(&corpus_path) {
        Ok(entries) => entries,
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => panic!("fuzz corpus directory: {e}"),
    };
    entries
        .by_ref()
        .try_for_each(|entry| {
            let path = entry.expect("corpus entry").path();
            if !path.is_file() {
                return Ok(());
            }
            let packet = fs::read(&path).expect("corpus packet");
            let result = catch_unwind(AssertUnwindSafe(|| {
                let _ = wire::Header::parse(&packet);
                let _ = wire::validate(&packet, false);
                let _ = wire::validate(&packet, true);
                let _ = wire::first_question(&packet);
                if !packet.is_empty() {
                    let max_offset = packet.len().saturating_sub(1);
                    let _ = wire::read_name(&packet, max_offset / 2);
                    let _ = wire::parse_record(&packet, max_offset / 3);
                }
                let _ = wire::extract_answer_records(&packet);
                let _ = wire::extract_service_records(&packet);
                let _ = edns::inspect_opt(&packet);
            }));
            assert!(
                result.is_ok(),
                "fuzz corpus seed panicked: {}",
                path.display()
            );
            Ok::<(), std::io::Error>(())
        })
        .expect("corpus entries checked");
}

fn mutate(seed: &[u8], state: &mut u64) -> Vec<u8> {
    let mut packet = seed.to_vec();
    let operations = 1 + usize::try_from(next(state) % 12).unwrap_or(1);

    for _ in 0..operations {
        match next(state) % 7 {
            0 => flip_byte(&mut packet, state),
            1 => insert_byte(&mut packet, state),
            2 => remove_byte(&mut packet, state),
            3 => truncate(&mut packet, state),
            4 => overwrite_u16(&mut packet, state),
            5 => append_run(&mut packet, state),
            _ => rotate(&mut packet, state),
        }
        packet.truncate(MAX_PACKET_SIZE);
    }
    packet
}

fn flip_byte(packet: &mut Vec<u8>, state: &mut u64) {
    if packet.is_empty() {
        packet.push(next(state) as u8);
        return;
    }
    let index = index(packet.len(), state);
    packet[index] ^= 1_u8 << (next(state) % 8);
}

fn insert_byte(packet: &mut Vec<u8>, state: &mut u64) {
    if packet.len() >= MAX_PACKET_SIZE {
        return;
    }
    let position = index(packet.len().saturating_add(1), state);
    packet.insert(position, next(state) as u8);
}

fn remove_byte(packet: &mut Vec<u8>, state: &mut u64) {
    if !packet.is_empty() {
        let position = index(packet.len(), state);
        packet.remove(position);
    }
}

fn truncate(packet: &mut Vec<u8>, state: &mut u64) {
    let length = index(packet.len().saturating_add(1), state);
    packet.truncate(length);
}

fn overwrite_u16(packet: &mut [u8], state: &mut u64) {
    if packet.len() < 2 {
        return;
    }
    let position = index(packet.len() - 1, state);
    let value = (next(state) as u16).to_be_bytes();
    packet[position..position + 2].copy_from_slice(&value);
}

fn append_run(packet: &mut Vec<u8>, state: &mut u64) {
    let available = MAX_PACKET_SIZE.saturating_sub(packet.len());
    let length = usize::try_from(next(state) % 33)
        .unwrap_or(0)
        .min(available);
    let value = next(state) as u8;
    packet.extend(std::iter::repeat(value).take(length));
}

fn rotate(packet: &mut [u8], state: &mut u64) {
    if packet.len() > 1 {
        let amount = index(packet.len(), state);
        packet.rotate_left(amount);
    }
}

fn index(length: usize, state: &mut u64) -> usize {
    if length == 0 {
        0
    } else {
        usize::try_from(next(state)).unwrap_or(0) % length
    }
}

fn next(state: &mut u64) -> u64 {
    let mut value = *state;
    value ^= value << 13;
    value ^= value >> 7;
    value ^= value << 17;
    *state = value;
    value
}

fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes.iter().take(256) {
        let _ = write!(output, "{byte:02x}");
    }
    if bytes.len() > 256 {
        output.push_str("...");
    }
    output
}
