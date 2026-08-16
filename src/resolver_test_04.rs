#[cfg(test)]
mod test_04_candidate_expansion_skips_route_only_domains {
    use super::*;

    #[test]
    fn candidate_expansion_skips_route_only_domains() {
        let domains = vec![
            Domain {
                name: "route.test".to_owned(),
                route_only: true,
            },
            Domain {
                name: "example.test".to_owned(),
                route_only: false,
            },
            Domain {
                name: "lab.test".to_owned(),
                route_only: false,
            },
        ];
        assert_eq!(
            lookup_candidates("host", &domains, false),
            vec!["host.example.test".to_owned(), "host.lab.test".to_owned()]
        );
        assert_eq!(
            lookup_candidates("host", &domains, true),
            vec![
                "host.example.test".to_owned(),
                "host.lab.test".to_owned(),
                "host".to_owned(),
            ]
        );
        assert!(lookup_candidates("host", &[], false).is_empty());
        assert_eq!(
            lookup_candidates("host.example", &domains, false),
            vec!["host.example".to_owned()]
        );
        assert_eq!(
            lookup_candidates("host.", &domains, false),
            vec!["host.".to_owned()]
        );
    }

}
