use super::*;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

#[test]
fn miri_dns_wire_round_trip() {
    let query = wire::make_query("example.test", wire::TYPE_A, 0).expect("query");
    wire::validate(&query).expect("valid query");
    let header = wire::Header::parse(&query).expect("header");
    assert_eq!(header.question_count(), 1);
    let question = wire::first_question(&query).expect("question");
    assert_eq!(question.rr_type, wire::TYPE_A);
    assert_eq!(question.name.text(), "example.test");
}

#[test]
fn miri_dns_reverse_name_round_trip() {
    let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53));
    let reverse = wire::reverse_name(address);
    assert_eq!(reverse, "53.2.0.192.in-addr.arpa");
    let query = wire::make_query(&reverse, wire::TYPE_PTR, 0).expect("PTR query");
    wire::validate(&query).expect("valid PTR query");
}

#[test]
fn miri_server_spec_parser_preserves_identity() {
    let parsed = config::parse_server_spec("192.0.2.53:853%7#resolver.example")
        .expect("server specification");
    assert_eq!(parsed.address.to_string(), "192.0.2.53:853");
    assert_eq!(parsed.interface.as_deref(), Some("7"));
    assert_eq!(parsed.server_name.as_deref(), Some("resolver.example"));
}

#[test]
fn miri_json_parser_round_trip() {
    let value = json::parse(
        r#"{"method":"io.rustd.Resolve.ResolveHostname","parameters":{"name":"example.test","family":2,"flags":0}}"#,
    )
    .expect("JSON request");
    let encoded = value.to_json();
    let reparsed = json::parse(&encoded).expect("reparsed JSON");
    assert_eq!(value, reparsed);
}

#[test]
fn miri_mdns_cache_flush_and_expiry() {
    use mdns::parity::{
        MdnsAddressFamily, MdnsCache, MdnsCacheKey, MdnsInterface, MdnsRecord,
        MdnsRecordSection,
    };

    let now = Instant::now();
    let interface = MdnsInterface::new(2, MdnsAddressFamily::Ipv4);
    let owner = mdns::parity::canonical_wire_name(b"\x04host\x05local\0")
        .expect("owner");
    let record = MdnsRecord {
        owner: owner.clone(),
        rr_type: wire::TYPE_A,
        class: 1,
        cache_flush: true,
        ttl: 120,
        rdata: vec![192, 0, 2, 10],
        section: MdnsRecordSection::Answer,
    };
    let mut cache = MdnsCache::default();
    cache.insert_response(interface, &[record], now);
    let key = MdnsCacheKey {
        owner,
        rr_type: wire::TYPE_A,
        class: 1,
        interface,
    };
    assert_eq!(cache.lookup(&key, now).len(), 1);
    assert_eq!(
        cache.lookup(&key, now + Duration::from_secs(121)).len(),
        0
    );
}

#[test]
fn miri_dnssd_record_generation_is_bounded() {
    use mdns::parity::{MdnsAddressFamily, MdnsInterface};
    use mdns::parity_dnssd::{
        DnsSdDomain, DnsSdHost, DnsSdInstance, DnsSdRegistration, DnsSdServiceType,
    };
    use std::collections::BTreeSet;

    let registration = DnsSdRegistration {
        instance: DnsSdInstance::new(b"Miri Service".to_vec()).expect("instance"),
        service_type: DnsSdServiceType::parse("_http._tcp").expect("service type"),
        domain: DnsSdDomain::local(),
        host: DnsSdHost::local("miri-host").expect("host"),
        port: 8080,
        priority: 0,
        weight: 0,
        txt: vec![b"path=/".to_vec()],
        subtypes: BTreeSet::from(["_demo".to_owned()]),
        addresses: BTreeSet::from([IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]),
        interface: MdnsInterface::new(2, MdnsAddressFamily::Ipv4),
        ttl: 120,
    };
    let records = registration.records(false).expect("records");
    assert!(records.iter().any(|record| record.rr_type == 12));
    assert!(records.iter().any(|record| record.rr_type == 33));
    assert!(records.iter().any(|record| record.rr_type == 16));
    assert!(records.iter().any(|record| record.rr_type == 1));
}
