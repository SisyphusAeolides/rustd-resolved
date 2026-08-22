// SPDX-License-Identifier: LGPL-2.1-or-later
use crate::config::parse_server_spec;
use crate::json::{JsonObject, Value};
use std::error::Error;
use std::fs;
use std::io;
use std::net::IpAddr;
use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::OwnedObjectPath;

const BUS_NAME: &str = "org.freedesktop.resolve1";
const MANAGER_PATH: &str = "/org/freedesktop/resolve1";
const MANAGER_INTERFACE: &str = "org.freedesktop.resolve1.Manager";
const NETWORK_BUS_NAME: &str = "org.freedesktop.network1";
const NETWORK_MANAGER_PATH: &str = "/org/freedesktop/network1";
const NETWORK_MANAGER_INTERFACE: &str = "org.freedesktop.network1.Manager";
const LINK_BUSY_ERROR: &str = "org.freedesktop.resolve1.LinkBusy";

pub fn is_command(command: &str) -> bool {
    matches!(
        command,
        "dns"
            | "domain"
            | "default-route"
            | "llmnr"
            | "mdns"
            | "dnsovertls"
            | "dnssec"
            | "nta"
            | "revert"
    )
}

pub fn execute(
    command: &str,
    arguments: &[String],
    json: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let connection = Connection::system()?;
    let proxy = Proxy::new(&connection, BUS_NAME, MANAGER_PATH, MANAGER_INTERFACE)?;

    if command != "revert" && arguments.len() <= 1 {
        return show(&connection, &proxy, command, arguments, json);
    }

    let network = Proxy::new(
        &connection,
        NETWORK_BUS_NAME,
        NETWORK_MANAGER_PATH,
        NETWORK_MANAGER_INTERFACE,
    )?;

    match command {
        "dns" => set_dns(&proxy, &network, arguments),
        "domain" => set_domains(&proxy, &network, arguments),
        "default-route" => set_default_route(&proxy, &network, arguments),
        "llmnr" => set_mode(&proxy, &network, "SetLinkLLMNR", arguments),
        "mdns" => set_mode(&proxy, &network, "SetLinkMulticastDNS", arguments),
        "dnsovertls" => set_mode(&proxy, &network, "SetLinkDNSOverTLS", arguments),
        "dnssec" => set_mode(&proxy, &network, "SetLinkDNSSEC", arguments),
        "nta" => set_negative_trust_anchors(&proxy, &network, arguments),
        "revert" => revert(&proxy, &network, arguments),
        _ => Err(format!("unsupported D-Bus command: {command}").into()),
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ResolvconfAction {
    Add,
    Delete,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ResolvconfLookupType {
    Regular,
    Private,
    Exclusive,
}

struct ResolvconfOptions {
    action: ResolvconfAction,
    lookup_type: ResolvconfLookupType,
    permissive: bool,
    interface: String,
}

pub fn resolvconf_requires_input(arguments: &[String]) -> Result<bool, Box<dyn Error>> {
    Ok(parse_resolvconf_arguments(arguments)?
        .is_some_and(|options| options.action == ResolvconfAction::Add))
}

fn parse_resolvconf_arguments(
    arguments: &[String],
) -> Result<Option<ResolvconfOptions>, Box<dyn Error>> {
    let mut action = None;
    let mut lookup_type = if std::env::var_os("IF_PRIVATE").is_some() {
        ResolvconfLookupType::Private
    } else if std::env::var_os("IF_EXCLUSIVE").is_some() {
        ResolvconfLookupType::Exclusive
    } else {
        ResolvconfLookupType::Regular
    };
    let mut permissive = false;
    let mut interface = None;
    let mut index = 0;

    while index < arguments.len() {
        match arguments[index].as_str() {
            "-a" => action = Some(ResolvconfAction::Add),
            "-d" => action = Some(ResolvconfAction::Delete),
            "-p" => lookup_type = ResolvconfLookupType::Private,
            "-x" => lookup_type = ResolvconfLookupType::Exclusive,
            "-f" => permissive = true,
            "-u" => return Ok(None),
            "-m" => {
                index += 1;
                if index >= arguments.len() {
                    return Err("resolvconf -m requires an argument".into());
                }
            }
            value if value.starts_with("-m") && value.len() > 2 => {}
            value if value.starts_with('-') => {
                return Err(format!("unsupported resolvconf option: {value}").into());
            }
            value => {
                if interface.replace(value.to_owned()).is_some() {
                    return Err("resolvconf requires exactly one interface".into());
                }
            }
        }
        index += 1;
    }

    let action = action.ok_or("resolvconf requires either -a or -d")?;
    let interface = interface.ok_or("resolvconf requires an interface")?;
    Ok(Some(ResolvconfOptions {
        action,
        lookup_type,
        permissive,
        interface,
    }))
}

pub fn execute_resolvconf(arguments: &[String], input: &str) -> Result<(), Box<dyn Error>> {
    let Some(options) = parse_resolvconf_arguments(arguments)? else {
        return Ok(());
    };
    let Some(interface) = resolvconf_interface(&options.interface) else {
        if options.permissive {
            return Ok(());
        }
        return Err(format!("interface not found: {}", options.interface).into());
    };

    if options.action == ResolvconfAction::Delete {
        return execute("revert", &[interface], None);
    }

    let (servers, mut domains) = parse_resolvconf_input(input);
    if servers.is_empty() {
        return Err("no DNS servers specified, refusing operation".into());
    }
    if options.lookup_type == ResolvconfLookupType::Exclusive {
        domains.push("~.".to_owned());
    }
    if options.lookup_type == ResolvconfLookupType::Private {
        execute("default-route", &[interface.clone(), "no".to_owned()], None)?;
    }
    let mut dns_arguments = Vec::with_capacity(servers.len() + 1);
    dns_arguments.push(interface.clone());
    dns_arguments.extend(servers);
    execute("dns", &dns_arguments, None)?;

    let mut domain_arguments = Vec::with_capacity(domains.len() + 1);
    domain_arguments.push(interface);
    if domains.is_empty() {
        domain_arguments.push(String::new());
    } else {
        domain_arguments.extend(domains);
    }
    execute("domain", &domain_arguments, None)
}

fn parse_resolvconf_input(input: &str) -> (Vec<String>, Vec<String>) {
    let mut servers = Vec::new();
    let mut domains = Vec::new();
    for line in input.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let mut words = line.split_whitespace();
        match words.next() {
            Some("nameserver") => servers.extend(words.map(str::to_owned)),
            Some("domain" | "search") => domains.extend(words.map(str::to_owned)),
            _ => {}
        }
    }
    (servers, domains)
}

fn resolvconf_interface(value: &str) -> Option<String> {
    let mut candidate = value;
    loop {
        if parse_ifindex(candidate).is_ok() {
            return Some(candidate.to_owned());
        }
        let (prefix, _) = candidate.rsplit_once('.')?;
        candidate = prefix;
    }
}

fn show(
    connection: &Connection,
    manager: &Proxy<'_>,
    command: &str,
    arguments: &[String],
    json: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let Some(interface) = arguments.first() else {
        return show_all(connection, manager, command, json);
    };
    let ifindex = parse_ifindex(interface)?;
    let (path,): (OwnedObjectPath,) = manager.call("GetLink", &(ifindex,))?;
    let proxy = Proxy::new(
        connection,
        BUS_NAME,
        path.as_str(),
        "org.freedesktop.resolve1.Link",
    )?;
    let ifname = interface_name(ifindex).unwrap_or_else(|| interface.clone());
    let value = link_value(&proxy, command)?;
    print_link_value(ifindex, &ifname, command, value, json)
}

fn show_all(
    connection: &Connection,
    manager: &Proxy<'_>,
    command: &str,
    json: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let global = global_value(manager, command)?;
    let mut values = vec![global.clone()];
    let mut links = Vec::new();
    for (ifindex, ifname) in non_loopback_interfaces() {
        let (path,): (OwnedObjectPath,) = manager.call("GetLink", &(ifindex,))?;
        let proxy = Proxy::new(
            connection,
            BUS_NAME,
            path.as_str(),
            "org.freedesktop.resolve1.Link",
        )?;
        let value = link_value(&proxy, command)?;
        values.push(with_link_identity(value.clone(), ifindex, &ifname)?);
        links.push((ifindex, ifname, value));
    }

    if !matches!(json, None | Some("off")) {
        let value = Value::Array(values);
        println!(
            "{}",
            if json == Some("pretty") {
                value.to_json_pretty()
            } else {
                value.to_json()
            }
        );
        return Ok(());
    }

    if command != "default-route" {
        print_value("Global", command, &global)?;
    }
    for (ifindex, ifname, value) in links {
        print_value(&format!("Link {ifindex} ({ifname})"), command, &value)?;
    }
    Ok(())
}

fn link_value(proxy: &Proxy<'_>, command: &str) -> Result<Value, Box<dyn Error>> {
    let value = match command {
        "dns" => {
            let entries: Vec<(i32, Vec<u8>, u16, String)> = proxy.get_property("DNSEx")?;
            let servers = entries
                .into_iter()
                .map(|(family, address, port, name)| dns_server_value(family, address, port, name))
                .collect::<Result<Vec<_>, _>>()?;
            Value::object([("servers", nullable_array(servers))])
        }
        "domain" => {
            let entries: Vec<(String, bool)> = proxy.get_property("Domains")?;
            let domains = entries
                .into_iter()
                .map(|(name, route_only)| {
                    Value::object([
                        ("name", Value::String(name)),
                        ("routeOnly", Value::Bool(route_only)),
                    ])
                })
                .collect();
            Value::object([("searchDomains", nullable_array(domains))])
        }
        "default-route" => Value::object([(
            "defaultRoute",
            Value::Bool(proxy.get_property("DefaultRoute")?),
        )]),
        "llmnr" => Value::object([("llmnr", Value::String(proxy.get_property("LLMNR")?))]),
        "mdns" => Value::object([("mDNS", Value::String(proxy.get_property("MulticastDNS")?))]),
        "dnsovertls" => Value::object([(
            "dnsOverTLS",
            Value::String(proxy.get_property("DNSOverTLS")?),
        )]),
        "dnssec" => Value::object([("dnssec", Value::String(proxy.get_property("DNSSEC")?))]),
        "nta" => {
            let names: Vec<String> = proxy.get_property("DNSSECNegativeTrustAnchors")?;
            Value::object([(
                "negativeTrustAnchors",
                nullable_array(names.into_iter().map(Value::String).collect()),
            )])
        }
        "revert" => return Err("revert requires a link and has no query form".into()),
        _ => return Err(format!("unsupported D-Bus command: {command}").into()),
    };
    Ok(value)
}

fn global_value(manager: &Proxy<'_>, command: &str) -> Result<Value, Box<dyn Error>> {
    let value = match command {
        "dns" => {
            let entries: Vec<(i32, i32, Vec<u8>, u16, String)> = manager.get_property("DNSEx")?;
            let servers = entries
                .into_iter()
                .filter(|(ifindex, _, _, _, _)| *ifindex == 0)
                .map(|(_, family, address, port, name)| {
                    dns_server_value(family, address, port, name)
                })
                .collect::<Result<Vec<_>, _>>()?;
            Value::object([("servers", nullable_array(servers))])
        }
        "domain" => {
            let entries: Vec<(i32, String, bool)> = manager.get_property("Domains")?;
            let domains = entries
                .into_iter()
                .filter(|(ifindex, _, _)| *ifindex == 0)
                .map(|(_, name, route_only)| {
                    Value::object([
                        ("name", Value::String(name)),
                        ("routeOnly", Value::Bool(route_only)),
                    ])
                })
                .collect();
            Value::object([("searchDomains", nullable_array(domains))])
        }
        "default-route" => Value::object([("defaultRoute", Value::Null)]),
        "llmnr" => Value::object([("llmnr", Value::String(manager.get_property("LLMNR")?))]),
        "mdns" => Value::object([("mDNS", Value::String(manager.get_property("MulticastDNS")?))]),
        "dnsovertls" => Value::object([(
            "dnsOverTLS",
            Value::String(manager.get_property("DNSOverTLS")?),
        )]),
        "dnssec" => Value::object([("dnssec", Value::String(manager.get_property("DNSSEC")?))]),
        "nta" => {
            let names: Vec<String> = manager.get_property("DNSSECNegativeTrustAnchors")?;
            Value::object([(
                "negativeTrustAnchors",
                nullable_array(names.into_iter().map(Value::String).collect()),
            )])
        }
        "revert" => return Err("revert requires a link and has no query form".into()),
        _ => return Err(format!("unsupported D-Bus command: {command}").into()),
    };
    Ok(value)
}

fn print_link_value(
    ifindex: i32,
    ifname: &str,
    command: &str,
    value: Value,
    json: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let value = with_link_identity(value, ifindex, ifname)?;
    if !matches!(json, None | Some("off")) {
        let value = Value::Array(vec![value]);
        println!(
            "{}",
            if json == Some("pretty") {
                value.to_json_pretty()
            } else {
                value.to_json()
            }
        );
        return Ok(());
    }

    let label = if ifindex == 0 {
        "Global".to_owned()
    } else {
        format!("Link {ifindex} ({ifname})")
    };
    print_value(&label, command, &value)
}

fn with_link_identity(value: Value, ifindex: i32, ifname: &str) -> Result<Value, Box<dyn Error>> {
    let Value::Object(fields) = value else {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid link value").into());
    };
    let mut output = JsonObject::new();
    output.insert("ifname".to_owned(), Value::String(ifname.to_owned()));
    output.insert("ifindex".to_owned(), Value::Number(i128::from(ifindex)));
    for key in fields.keys() {
        let value = fields
            .get(key)
            .expect("a JsonObject key must resolve to its value")
            .clone();
        output.insert(key.to_owned(), annotate_link_value(key, value, ifindex));
    }
    Ok(Value::Object(output))
}

fn annotate_link_value(field: &str, value: Value, ifindex: i32) -> Value {
    let Value::Array(entries) = value else {
        return value;
    };
    let entries = entries
        .into_iter()
        .map(|entry| match (field, entry) {
            ("servers", Value::Object(mut server)) => {
                server.insert("ifindex".to_owned(), Value::Number(i128::from(ifindex)));
                server.insert("accessible".to_owned(), Value::Bool(true));
                Value::Object(server)
            }
            ("searchDomains", Value::Object(mut domain)) => {
                domain.insert("ifindex".to_owned(), Value::Number(i128::from(ifindex)));
                Value::Object(domain)
            }
            (_, entry) => entry,
        })
        .collect();
    Value::Array(entries)
}

fn print_value(label: &str, command: &str, value: &Value) -> Result<(), Box<dyn Error>> {
    match command {
        "dns" => {
            let values = value
                .get("servers")
                .and_then(Value::as_array)
                .unwrap_or_default()
                .iter()
                .filter_map(|server| {
                    let address = server.get("addressString")?.as_str()?;
                    let name = server.get("name").and_then(Value::as_str);
                    Some(
                        name.map_or_else(|| address.to_owned(), |name| format!("{address}#{name}")),
                    )
                })
                .collect::<Vec<_>>();
            println!("{}", format_list_value(label, &values));
        }
        "domain" => {
            let values = value
                .get("searchDomains")
                .and_then(Value::as_array)
                .unwrap_or_default()
                .iter()
                .filter_map(|domain| {
                    let name = domain.get("name")?.as_str()?;
                    Some(
                        if domain.get("routeOnly").and_then(Value::as_bool) == Some(true) {
                            format!("~{name}")
                        } else {
                            name.to_owned()
                        },
                    )
                })
                .collect::<Vec<_>>();
            println!("{}", format_list_value(label, &values));
        }
        "default-route" => println!(
            "{label}: {}",
            if value.get("defaultRoute").and_then(Value::as_bool) == Some(true) {
                "yes"
            } else {
                "no"
            }
        ),
        "llmnr" => print_string_field(label, value, "llmnr"),
        "mdns" => print_string_field(label, value, "mDNS"),
        "dnsovertls" => print_string_field(label, value, "dnsOverTLS"),
        "dnssec" => print_string_field(label, value, "dnssec"),
        "nta" => {
            let values = value
                .get("negativeTrustAnchors")
                .and_then(Value::as_array)
                .unwrap_or_default()
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>();
            println!("{}", format_list_value(label, &values));
        }
        _ => return Err(format!("unsupported D-Bus command: {command}").into()),
    }
    Ok(())
}

fn format_list_value<T: AsRef<str>>(label: &str, values: &[T]) -> String {
    if values.is_empty() {
        format!("{label}:")
    } else {
        format!(
            "{label}: {}",
            values
                .iter()
                .map(AsRef::as_ref)
                .collect::<Vec<_>>()
                .join(" ")
        )
    }
}

fn nullable_array(values: Vec<Value>) -> Value {
    if values.is_empty() {
        Value::Null
    } else {
        Value::Array(values)
    }
}

fn non_loopback_interfaces() -> Vec<(i32, String)> {
    let mut interfaces = fs::read_dir("/sys/class/net")
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == "lo" {
                return None;
            }
            let index = fs::read_to_string(entry.path().join("ifindex"))
                .ok()?
                .trim()
                .parse::<i32>()
                .ok()?;
            Some((index, name))
        })
        .collect::<Vec<_>>();
    interfaces.sort_unstable_by_key(|(index, _)| *index);
    interfaces
}

fn print_string_field(label: &str, value: &Value, field: &str) {
    println!(
        "{label}: {}",
        value.get(field).and_then(Value::as_str).unwrap_or("")
    );
}

fn dns_server_value(
    family: i32,
    address: Vec<u8>,
    port: u16,
    name: String,
) -> Result<Value, Box<dyn Error>> {
    let text = decode_address(family, &address)?;
    let mut fields = JsonObject::new();
    fields.insert("addressString".to_owned(), Value::String(text));
    fields.insert(
        "address".to_owned(),
        Value::Array(
            address
                .into_iter()
                .map(|byte| Value::Number(i128::from(byte)))
                .collect(),
        ),
    );
    fields.insert("family".to_owned(), Value::Number(i128::from(family)));
    fields.insert(
        "port".to_owned(),
        Value::Number(i128::from(if port == 0 { 53 } else { port })),
    );
    if !name.is_empty() {
        fields.insert("name".to_owned(), Value::String(name));
    }
    Ok(Value::Object(fields))
}

fn decode_address(family: i32, bytes: &[u8]) -> Result<String, Box<dyn Error>> {
    match (family, bytes) {
        (2, [a, b, c, d]) => Ok(std::net::Ipv4Addr::new(*a, *b, *c, *d).to_string()),
        (10, bytes) if bytes.len() == 16 => {
            let octets: [u8; 16] = bytes.try_into()?;
            Ok(std::net::Ipv6Addr::from(octets).to_string())
        }
        _ => Err("invalid D-Bus DNS address".into()),
    }
}

fn interface_name(ifindex: i32) -> Option<String> {
    fs::read_dir("/sys/class/net")
        .ok()?
        .filter_map(Result::ok)
        .find_map(|entry| {
            let index = fs::read_to_string(entry.path().join("ifindex")).ok()?;
            (index.trim().parse::<i32>().ok()? == ifindex)
                .then(|| entry.file_name().to_string_lossy().into_owned())
        })
}

fn set_dns(
    proxy: &Proxy<'_>,
    network: &Proxy<'_>,
    arguments: &[String],
) -> Result<(), Box<dyn Error>> {
    let (link, values) = link_and_values("dns", arguments)?;
    let values = if values == [""] { &[] } else { values };
    let mut servers = Vec::with_capacity(values.len());
    for value in values {
        let spec = parse_server_spec(value)?;
        if let Some(interface) = &spec.interface {
            let specified = parse_ifindex(interface)?;
            if specified != link {
                return Err(format!(
                    "DNS server {value} is scoped to interface {specified}, not {link}"
                )
                .into());
            }
        }
        let (family, bytes) = encode_address(spec.address.ip());
        servers.push((
            family,
            bytes,
            spec.address.port(),
            spec.server_name.unwrap_or_default(),
        ));
    }
    call_with_networkd(proxy.call("SetLinkDNSEx", &(link, &servers)), || {
        network.call("SetLinkDNSEx", &(link, &servers))
    })?;
    Ok(())
}

fn set_domains(
    proxy: &Proxy<'_>,
    network: &Proxy<'_>,
    arguments: &[String],
) -> Result<(), Box<dyn Error>> {
    let (link, values) = link_and_values("domain", arguments)?;
    let values = if values == [""] { &[] } else { values };
    let mut domains = Vec::with_capacity(values.len());
    for value in values {
        let (route_only, name) = value
            .strip_prefix('~')
            .map_or((false, value.as_str()), |name| (true, name));
        let name = name.trim_end_matches('.');
        let name = if name.is_empty() && value.ends_with('.') {
            "."
        } else {
            name
        };
        if name.is_empty() {
            return Err(format!("invalid domain: {value}").into());
        }
        domains.push((name.to_owned(), route_only));
    }
    call_with_networkd(proxy.call("SetLinkDomains", &(link, &domains)), || {
        network.call("SetLinkDomains", &(link, &domains))
    })?;
    Ok(())
}

fn set_default_route(
    proxy: &Proxy<'_>,
    network: &Proxy<'_>,
    arguments: &[String],
) -> Result<(), Box<dyn Error>> {
    require_exact("default-route", arguments, 2)?;
    let link = parse_ifindex(&arguments[0])?;
    let enabled = parse_boolean(&arguments[1])?;
    call_with_networkd(proxy.call("SetLinkDefaultRoute", &(link, enabled)), || {
        network.call("SetLinkDefaultRoute", &(link, enabled))
    })?;
    Ok(())
}

fn set_mode(
    proxy: &Proxy<'_>,
    network: &Proxy<'_>,
    method: &str,
    arguments: &[String],
) -> Result<(), Box<dyn Error>> {
    require_exact(method, arguments, 2)?;
    let link = parse_ifindex(&arguments[0])?;
    let mode = arguments[1].as_str();
    call_with_networkd(proxy.call(method, &(link, mode)), || {
        network.call(method, &(link, mode))
    })?;
    Ok(())
}

fn set_negative_trust_anchors(
    proxy: &Proxy<'_>,
    network: &Proxy<'_>,
    arguments: &[String],
) -> Result<(), Box<dyn Error>> {
    let (link, values) = link_and_values("nta", arguments)?;
    let names = parse_negative_trust_anchors(values)?;
    call_with_networkd(
        proxy.call("SetLinkDNSSECNegativeTrustAnchors", &(link, &names)),
        || network.call("SetLinkDNSSECNegativeTrustAnchors", &(link, &names)),
    )?;
    Ok(())
}

fn parse_negative_trust_anchors(values: &[String]) -> Result<Vec<String>, Box<dyn Error>> {
    if values == [""] {
        return Ok(Vec::new());
    }
    let names = values
        .iter()
        .map(|name| name.trim_end_matches('.'))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if names.iter().any(String::is_empty) {
        return Err("negative trust anchors must not be empty".into());
    }
    Ok(names)
}

fn revert(
    proxy: &Proxy<'_>,
    network: &Proxy<'_>,
    arguments: &[String],
) -> Result<(), Box<dyn Error>> {
    require_exact("revert", arguments, 1)?;
    let link = parse_ifindex(&arguments[0])?;
    call_with_networkd(proxy.call("RevertLink", &(link,)), || {
        network.call("RevertLinkDNS", &(link,))
    })?;
    Ok(())
}

fn call_with_networkd(
    resolver_result: Result<(), zbus::Error>,
    network_call: impl FnOnce() -> Result<(), zbus::Error>,
) -> Result<(), zbus::Error> {
    match resolver_result {
        Ok(()) => Ok(()),
        Err(error) if is_link_busy(&error) => network_call(),
        Err(error) => Err(error),
    }
}

fn is_link_busy(error: &zbus::Error) -> bool {
    matches!(
        error,
        zbus::Error::MethodError(name, _, _) if is_link_busy_name(name.as_str())
    )
}

fn is_link_busy_name(name: &str) -> bool {
    name == LINK_BUSY_ERROR
}

fn link_and_values<'a>(
    command: &str,
    arguments: &'a [String],
) -> Result<(i32, &'a [String]), Box<dyn Error>> {
    let Some((link, values)) = arguments.split_first() else {
        return Err(format!("{command} requires a link").into());
    };
    Ok((parse_ifindex(link)?, values))
}

fn require_exact(
    command: &str,
    arguments: &[String],
    expected: usize,
) -> Result<(), Box<dyn Error>> {
    if arguments.len() != expected {
        return Err(format!(
            "{command} requires {expected} argument{}",
            if expected == 1 { "" } else { "s" }
        )
        .into());
    }
    Ok(())
}

fn parse_ifindex(value: &str) -> Result<i32, Box<dyn Error>> {
    crate::interface::resolve_ifindex(value).map_err(|error| {
        let message = error.to_string();
        let message = message
            .split(" (os error ")
            .next()
            .unwrap_or(message.as_str());
        format!("Failed to resolve interface {value:?}: {message}").into()
    })
}

fn parse_boolean(value: &str) -> Result<bool, Box<dyn Error>> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "yes" | "y" | "true" | "t" | "on" => Ok(true),
        "0" | "no" | "n" | "false" | "f" | "off" => Ok(false),
        _ => Err(format!("invalid boolean value: {value}").into()),
    }
}

fn encode_address(address: IpAddr) -> (i32, Vec<u8>) {
    match address {
        IpAddr::V4(address) => (2, address.octets().to_vec()),
        IpAddr::V6(address) => (10, address.octets().to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_only_link_management_commands() {
        assert!(is_command("dns"));
        assert!(is_command("revert"));
        assert!(!is_command("query"));
        assert!(!is_command("unknown"));
    }

    #[test]
    fn recognizes_only_the_resolved_managed_link_error_name() {
        assert!(is_link_busy_name("org.freedesktop.resolve1.LinkBusy"));
        assert!(!is_link_busy_name("org.freedesktop.resolve1.NoSuchLink"));
        assert!(!is_link_busy_name("org.freedesktop.network1.LinkBusy"));
    }

    #[test]
    fn empty_negative_trust_anchor_argument_clears_the_list() {
        assert!(parse_negative_trust_anchors(&[String::new()])
            .unwrap()
            .is_empty());
        assert_eq!(
            parse_negative_trust_anchors(&["private.test.".to_owned()]).unwrap(),
            ["private.test"]
        );
        assert!(parse_negative_trust_anchors(&[String::new(), "private.test".to_owned()]).is_err());
    }

    #[test]
    fn parses_boolean_spellings() {
        assert!(parse_boolean("yes").unwrap());
        assert!(parse_boolean("t").unwrap());
        assert!(!parse_boolean("OFF").unwrap());
        assert!(!parse_boolean("N").unwrap());
        assert!(parse_boolean("maybe").is_err());
    }

    #[test]
    fn accepts_only_existing_interface_indices() {
        let loopback = parse_ifindex("lo").expect("loopback ifindex");
        assert_eq!(parse_ifindex(&loopback.to_string()).unwrap(), loopback);
        assert!(parse_ifindex("0").is_err());
        assert!(parse_ifindex("-1").is_err());
        assert!(parse_ifindex("2147483647").is_err());
    }

    #[test]
    fn unknown_interface_errors_match_resolvectl() {
        assert_eq!(
            parse_ifindex("resolvectl-parity-does-not-exist")
                .expect_err("unknown link must fail")
                .to_string(),
            "Failed to resolve interface \"resolvectl-parity-does-not-exist\": No such device"
        );
    }

    #[test]
    fn parses_resolvconf_servers_and_domains() {
        let (servers, domains) = parse_resolvconf_input(
            "# generated\nnameserver 192.0.2.1 2001:db8::1\n\
             domain example.test corp.test\nsearch search.test\nunknown ignored\n",
        );
        assert_eq!(servers, ["192.0.2.1", "2001:db8::1"]);
        assert_eq!(domains, ["example.test", "corp.test", "search.test"]);
    }

    #[test]
    fn resolvconf_reads_input_only_for_the_final_add_mode() {
        assert!(resolvconf_requires_input(&["-a".to_owned(), "lo".to_owned()]).unwrap());
        assert!(
            !resolvconf_requires_input(&["-a".to_owned(), "-d".to_owned(), "lo".to_owned()])
                .unwrap()
        );
        assert!(
            resolvconf_requires_input(&["-d".to_owned(), "-a".to_owned(), "lo".to_owned()])
                .unwrap()
        );
        assert!(!resolvconf_requires_input(&["-u".to_owned()]).unwrap());
        assert!(
            resolvconf_requires_input(&["-m100".to_owned(), "-a".to_owned(), "lo".to_owned()])
                .unwrap()
        );
    }

    #[test]
    fn renders_dns_server_json_with_upstream_defaults() {
        let value = dns_server_value(2, vec![192, 0, 2, 53], 53, String::new()).unwrap();
        assert_eq!(
            value.get("addressString").and_then(Value::as_str),
            Some("192.0.2.53")
        );
        assert_eq!(value.get("port").and_then(Value::as_u64), Some(53));
        assert_eq!(value.get("name"), None);
    }

    #[test]
    fn rejects_invalid_dbus_address_lengths() {
        assert!(decode_address(2, &[127, 0, 0]).is_err());
        assert!(decode_address(10, &[0; 15]).is_err());
    }

    #[test]
    fn renders_empty_lists_without_trailing_whitespace() {
        assert_eq!(
            format_list_value("Link 1 (lo)", &[] as &[String]),
            "Link 1 (lo):"
        );
        assert_eq!(
            format_list_value(
                "Global",
                &["192.0.2.53".to_owned(), "2001:db8::53".to_owned()]
            ),
            "Global: 192.0.2.53 2001:db8::53"
        );
    }
}
