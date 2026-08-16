from pathlib import Path


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise SystemExit(f"expected one match in {path}, found {text.count(old)}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


link = Path("src/dbus_link.rs")
old = '''fn decode_dns_servers(
    addresses: Vec<(i32, Vec<u8>)>,
    port: u16,
) -> Result<Vec<SocketAddr>, DbusError> {
    addresses
        .into_iter()
        .map(|(family, address)| {
            decode_address(family, &address).map(|address| SocketAddr::new(address, port))
        })
        .collect()
}
'''
new = '''fn validate_dns_server_address(address: IpAddr) -> Result<IpAddr, DbusError> {
    let invalid = match address {
        IpAddr::V4(address) => {
            address.is_unspecified()
                || matches!(address.octets(), [127, 0, 0, 53] | [127, 0, 0, 54])
        }
        IpAddr::V6(address) => address.is_unspecified(),
    };
    if invalid {
        Err(DbusError::InvalidArgs(
            "invalid DNS server address".to_owned(),
        ))
    } else {
        Ok(address)
    }
}

fn decode_dns_server_address(family: i32, address: &[u8]) -> Result<IpAddr, DbusError> {
    validate_dns_server_address(decode_address(family, address)?)
}

fn decode_dns_servers(
    addresses: Vec<(i32, Vec<u8>)>,
    port: u16,
) -> Result<Vec<SocketAddr>, DbusError> {
    addresses
        .into_iter()
        .map(|(family, address)| {
            decode_dns_server_address(family, &address)
                .map(|address| SocketAddr::new(address, port))
        })
        .collect()
}
'''
replace_once(link, old, new)

helpers = Path("src/dbus_helpers.rs")
replace_once(
    helpers,
    "decode_address(family, &address)?,\n                    dns_ex_input_port(port),",
    "decode_dns_server_address(family, &address)?,\n                    dns_ex_input_port(port),",
)

tests = Path("src/dbus_tests.rs")
marker = '''    #[test]
    fn modes_round_trip() {
'''
addition = '''    #[test]
    fn dns_server_address_validation_matches_upstream() {
        let invalid = [
            (AF_INET, vec![0, 0, 0, 0]),
            (AF_INET, vec![127, 0, 0, 53]),
            (AF_INET, vec![127, 0, 0, 54]),
            (AF_INET6, vec![0; 16]),
        ];
        for (family, address) in invalid {
            assert!(decode_dns_servers(vec![(family, address.clone())], DNS_PORT).is_err());
            assert!(
                decode_dns_server_specs(vec![(family, address, 0, String::new())]).is_err()
            );
        }

        assert_eq!(
            decode_dns_servers(vec![(AF_INET, vec![127, 0, 0, 1])], DNS_PORT)
                .expect("loopback DNS server"),
            vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                DNS_PORT,
            )],
        );
    }

'''
replace_once(tests, marker, addition + marker)
