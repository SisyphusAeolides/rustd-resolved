#![no_main]

use libfuzzer_sys::fuzz_target;
use rustd_resolved::config::Config;
use rustd_resolved::resolver::Resolver;
use rustd_resolved::varlink;

fuzz_target!(|input: &str| {
    let resolver = Resolver::new(Config::default());
    let _ = varlink::dispatch(input, &resolver);
});
