// SPDX-License-Identifier: LGPL-2.1-or-later
#[cfg(test)]
mod test_25_flush_caches_clears_multicast_state {
    use super::*;

    #[test]
    fn flush_cache_clears_multicast_caches() {
        crate::mdns::runtime::seed_cache_for_flush_test();
        crate::llmnr::runtime::seed_cache_for_flush_test();
        assert!(crate::mdns::runtime::cache_has_flush_test_record());
        assert!(crate::llmnr::runtime::cache_has_flush_test_record());

        Resolver::new(Config::default()).flush_cache();

        assert!(!crate::mdns::runtime::cache_has_flush_test_record());
        assert!(!crate::llmnr::runtime::cache_has_flush_test_record());
    }
}
