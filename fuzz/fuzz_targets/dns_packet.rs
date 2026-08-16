#![no_main]

use libfuzzer_sys::fuzz_target;
use rustd_resolved::wire;

fuzz_target!(|packet: &[u8]| {
    let _ = wire::Header::parse(packet);
    let _ = wire::validate(packet, false);
    let _ = wire::validate(packet, true);
    let _ = wire::first_question(packet);
    let _ = wire::question_end(packet);
    let _ = wire::root_rrsig_missing(packet);
});
