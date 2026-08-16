#![no_main]

use libfuzzer_sys::fuzz_target;
use rustd_resolved::wire;

fuzz_target!(|packet: &[u8]| {
    let _ = wire::extract_answer_records(packet);
    let _ = wire::extract_service_records(packet);
    let _ = wire::extract_addresses(packet, Some(2));
    let _ = wire::extract_addresses(packet, Some(10));
    let _ = wire::extract_ptr_names(packet);
    let _ = wire::classify_redirect_answer(packet);
});
