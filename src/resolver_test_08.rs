#[cfg(test)]
mod test_08_per_link_search_domains_are_available_to_name_expansion {
    use super::*;

    #[test]
    fn per_link_search_domains_are_available_to_name_expansion() {
        let resolver = Resolver::new(Config::default());
        resolver
            .set_link_domains(
                9,
                vec![
                    Domain {
                        name: "search.example".to_owned(),
                        route_only: false,
                    },
                    Domain {
                        name: "route.example".to_owned(),
                        route_only: true,
                    },
                ],
            )
            .expect("set link domains");
        assert_eq!(
            resolver.search_domains(None).expect("search domains"),
            vec![Domain {
                name: "search.example".to_owned(),
                route_only: false,
            }]
        );
    }

}
