// SPDX-License-Identifier: LGPL-2.1-or-later
mod resolvectl_rr;

use rustd_resolved::json::{self, JsonObject, Value};
use std::env;
use std::error::Error;
use std::ffi::OsStr;
use std::fmt;
use std::io::IsTerminal as _;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};
use zbus::blocking::{Connection, Proxy};

const DEFAULT_SOCKET: &str = "/run/systemd/resolve/io.rustd.Resolve";
const DEFAULT_MONITOR_SOCKET: &str = "/run/systemd/resolve/io.rustd.Resolve.Monitor";
const MAX_REPLY_SIZE: usize = 1024 * 1024;

fn print_systemd_version() {
    println!("{}", rustd_resolved::UPSTREAM_VERSION_BANNER);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RawMode {
    None,
    Payload,
    Packet,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InvocationMode {
    Native,
    Resolvconf,
    SystemdResolve,
}

#[derive(Debug)]
struct Options {
    socket: PathBuf,
    socket_explicit: bool,
    family: i32,
    ifindex: i32,
    request_flags: u64,
    legend: bool,
    rr_type: Option<u16>,
    rr_class: u16,
    raw: RawMode,
    ask_password: bool,
    json: Option<String>,
    command: String,
    arguments: Vec<String>,
}

#[derive(Debug)]
struct CliError(String);

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for CliError {}

#[derive(Debug)]
struct QueryFailed;

impl fmt::Display for QueryFailed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("query operation(s) failed")
    }
}

impl Error for QueryFailed {}

#[derive(Clone, Copy, Debug)]
struct LookupOptions<'a> {
    family: i32,
    ifindex: i32,
    request_flags: u64,
    json: Option<&'a str>,
    legend: bool,
    rr_type: Option<u16>,
    rr_class: u16,
    raw: RawMode,
}

impl Options {
    fn lookup_options(&self) -> LookupOptions<'_> {
        LookupOptions {
            family: self.family,
            ifindex: self.ifindex,
            request_flags: self.request_flags,
            json: self.json.as_deref(),
            legend: self.legend,
            rr_type: self.rr_type,
            rr_class: self.rr_class,
            raw: self.raw,
        }
    }
}

fn main() -> ExitCode {
    let program = env::args()
        .next()
        .unwrap_or_else(|| "resolvectl".to_owned());
    match execute() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if error.is::<QueryFailed>() {
                ExitCode::FAILURE
            } else if let Some(error) = error.downcast_ref::<CliError>() {
                if !error.to_string().is_empty() {
                    eprintln!("{error}");
                }
                ExitCode::FAILURE
            } else {
                let message = error.to_string();
                if let Some(argument) = message.strip_prefix("unknown option: ") {
                    if argument.len() == 2
                        && argument.starts_with('-')
                        && !argument.starts_with("--")
                    {
                        eprintln!(
                            "{program}: invalid option -- '{}'",
                            argument.chars().nth(1).unwrap_or('-')
                        );
                    } else {
                        eprintln!("{program}: unrecognized option '{argument}'");
                    }
                } else if message == "Too few arguments."
                    || message == "Too many arguments."
                    || message == "Interface argument required."
                    || message.starts_with("Failed to parse RR record type")
                    || message.starts_with("Failed to parse RR record class")
                    || message.starts_with("Unknown argument to --json= switch:")
                    || message.starts_with("Unknown --raw specifier")
                    || message.starts_with("unknown --raw specifier")
                    || message.starts_with("Failed to parse boolean argument to")
                    || message.starts_with("Failed to resolve interface")
                    || message.starts_with("--class= may only be used in conjunction with --type=.")
                    || message.starts_with("Unknown protocol specifier:")
                    || message.starts_with("Unknown record type:")
                    || message.starts_with("Unknown record class:")
                    || message.starts_with("Use --json=pretty")
                    || message.starts_with("Failed to resolve interface")
                {
                    eprintln!("{message}");
                } else if let Some(option) = message.strip_suffix(" requires a value") {
                    if option.starts_with("--") {
                        eprintln!("resolvectl: option '{option}' requires an argument");
                    } else if option.starts_with('-') && option.chars().count() == 2 {
                        let option = option.chars().nth(1).unwrap_or('-');
                        eprintln!("{program}: option requires an argument -- '{option}'");
                    } else {
                        eprintln!("resolvectl: {error}");
                    }
                } else {
                    eprintln!("resolvectl: {error}");
                }
                ExitCode::FAILURE
            }
        }
    }
}

fn execute() -> Result<(), Box<dyn Error>> {
    let mut process_arguments = env::args_os();
    let program = process_arguments.next().unwrap_or_default();
    let invoked_as = env::var_os("SYSTEMD_INVOKED_AS");
    let raw_arguments = process_arguments
        .map(|argument| {
            argument
                .into_string()
                .map_err(|_| "argument is not valid UTF-8")
        })
        .collect::<Result<Vec<_>, _>>()?;

    match invocation_mode(&program, invoked_as.as_deref()) {
        InvocationMode::Resolvconf => {
            if raw_arguments
                .iter()
                .any(|argument| matches!(argument.as_str(), "-h" | "--help"))
            {
                print_resolvconf_help();
                return Ok(());
            }
            if raw_arguments.iter().any(|argument| argument == "--version") {
                print_systemd_version();
                return Ok(());
            }
            let mut input = String::new();
            if rustd_resolved::resolvectl_dbus::resolvconf_requires_input(&raw_arguments)? {
                io::stdin()
                    .take((MAX_REPLY_SIZE + 1) as u64)
                    .read_to_string(&mut input)?;
                if input.len() > MAX_REPLY_SIZE {
                    return Err("resolvconf input exceeds the configured limit".into());
                }
            }
            rustd_resolved::resolvectl_dbus::execute_resolvconf(&raw_arguments, &input)
        }
        InvocationMode::SystemdResolve => {
            if raw_arguments
                .iter()
                .any(|argument| matches!(argument.as_str(), "-h" | "--help"))
            {
                print_systemd_resolve_help();
                return Ok(());
            }
            if raw_arguments.iter().any(|argument| argument == "--version") {
                print_systemd_version();
                return Ok(());
            }
            for arguments in translate_systemd_resolve(raw_arguments)? {
                if let Some(options) = parse_options(arguments)? {
                    execute_options(&options)?;
                }
            }
            Ok(())
        }
        InvocationMode::Native => {
            let Some(options) = parse_options(raw_arguments)? else {
                return Ok(());
            };
            execute_options(&options)
        }
    }
}

fn execute_options(options: &Options) -> Result<(), Box<dyn Error>> {
    let monitor_socket = options.monitor_socket();
    let lookup = options.lookup_options();
    match options.command.as_str() {
        "query" => query_many(&options.socket, &options.arguments, lookup),
        "service" => service(&options.socket, &options.arguments, lookup),
        "openpgp" => resolvectl_rr::openpgp(&options.socket, &options.arguments, lookup)
            .map_err(|error| Box::new(CliError(error.to_string())) as Box<dyn Error>),
        "tlsa" => resolvectl_rr::tlsa(&options.socket, &options.arguments, lookup)
            .map_err(|error| Box::new(CliError(error.to_string())) as Box<dyn Error>),
        "status" => status(&options.socket, &options.arguments, options.json.as_deref()),
        "monitor" => monitor(
            &monitor_socket,
            &options.arguments,
            options.json.as_deref(),
            options.ask_password,
        ),
        "log-level" => log_level(&options.arguments),
        "statistics" => statistics(
            &monitor_socket,
            options.json.as_deref(),
            options.ask_password,
        ),
        "show-cache" => show_cache(
            &monitor_socket,
            options.json.as_deref(),
            options.ask_password,
        ),
        "show-server-state" => show_server_state(
            &monitor_socket,
            options.json.as_deref(),
            options.ask_password,
        ),
        "flush-caches" => control(
            &options.socket,
            "io.rustd.Resolve.FlushCaches",
            options.ask_password,
        ),
        "reset-statistics" => control(
            &monitor_socket,
            "io.rustd.Resolve.Monitor.ResetStatistics",
            options.ask_password,
        ),
        "reset-server-features" => control(
            &options.socket,
            "io.rustd.Resolve.ResetServerFeatures",
            options.ask_password,
        ),
        command
            if rustd_resolved::resolvectl_dbus::is_command(command)
                && options.arguments.is_empty() =>
        {
            show_configuration_field(&options.socket, command, options.json.as_deref())
        }
        command if rustd_resolved::resolvectl_dbus::is_command(command) => {
            rustd_resolved::resolvectl_dbus::execute(
                command,
                &options.arguments,
                options.json.as_deref(),
            )
        }
        command => Err(format!("unknown command: {command}").into()),
    }
}

fn invocation_mode(program: &OsStr, override_name: Option<&OsStr>) -> InvocationMode {
    let effective = override_name
        .filter(|name| !name.is_empty())
        .unwrap_or(program);
    let name = Path::new(effective)
        .file_name()
        .unwrap_or(effective)
        .to_string_lossy();
    if name.contains("resolvconf") {
        InvocationMode::Resolvconf
    } else if name.contains("systemd-resolve") {
        InvocationMode::SystemdResolve
    } else {
        InvocationMode::Native
    }
}

fn service(
    socket: &Path,
    arguments: &[String],
    options: LookupOptions<'_>,
) -> Result<(), Box<dyn Error>> {
    let (name, service_type, domain, owner) = match arguments {
        [domain] => (None, None, domain.as_str(), domain.clone()),
        [service_type, domain] => (
            None,
            Some(service_type.clone()),
            domain.as_str(),
            format!("{service_type}.{domain}"),
        ),
        [name, service_type, domain] => (
            Some(name.clone()),
            Some(service_type.clone()),
            domain.as_str(),
            format!("{name}.{service_type}.{domain}"),
        ),
        _ => return Err("service requires [[NAME] TYPE] DOMAIN".into()),
    };
    let mut parameters = JsonObject::from([
        ("domain", Value::String(domain.to_owned())),
        ("ifindex", Value::Number(i128::from(options.ifindex))),
        ("family", Value::Number(i128::from(options.family))),
        ("flags", Value::Number(i128::from(options.request_flags))),
    ]);
    if let Some(name) = name {
        parameters.insert("name".to_owned(), Value::String(name));
    }
    if let Some(service_type) = service_type {
        parameters.insert("type".to_owned(), Value::String(service_type));
    }
    let reply = call(
        socket,
        "io.rustd.Resolve.ResolveService",
        Value::Object(parameters),
    )
    .map_err(resolve_service_error)?;
    if reply_is_nxdomain(&reply) {
        if let Some(hostname) =
            resolve_service_target(socket, &owner, options.ifindex, options.request_flags)
        {
            return Err(format!("Name '{hostname}' not found").into());
        }
    }
    let parameters = reply_parameters_for_query(&reply, domain).map_err(resolve_service_error)?;
    if json_enabled(options.json) {
        println!("{}", json_output(parameters, options.json));
        return Ok(());
    }
    let services = parameters
        .get("services")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_data("service reply is missing its services"))?;
    if services.is_empty() {
        return Err("service reply contains no services".into());
    }
    for service in services {
        let hostname = service
            .get("hostname")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let port = service.get("port").and_then(Value::as_u64).unwrap_or(0);
        let priority = service.get("priority").and_then(Value::as_u64).unwrap_or(0);
        let weight = service.get("weight").and_then(Value::as_u64).unwrap_or(0);
        println!("{domain}: {hostname}:{port} [priority={priority}, weight={weight}]");
        if let Some(addresses) = service.get("addresses").and_then(Value::as_array) {
            for address in addresses {
                let address_family = address.get("family").and_then(Value::as_i64).unwrap_or(0);
                let bytes = byte_array(address.get("address"))?;
                println!("             {}", decode_address(address_family, &bytes)?);
            }
        }
    }
    if let Some(txt) = parameters.get("txt").and_then(Value::as_array) {
        for item in txt.iter().filter_map(Value::as_str) {
            println!("             {item}");
        }
    }
    if options.legend {
        print_query_legend(parameters, Duration::ZERO);
    }
    Ok(())
}

fn reply_is_nxdomain(reply: &Value) -> bool {
    reply.get("error").and_then(Value::as_str) == Some("io.rustd.Resolve.DNSError")
        && reply
            .get("parameters")
            .and_then(|parameters| parameters.get("rcode"))
            .and_then(Value::as_u64)
            == Some(3)
}

fn resolve_service_error(error: Box<dyn Error>) -> Box<dyn Error> {
    let message = format_query_error(error.as_ref());
    drop(error);
    Box::new(CliError(format!("Resolve call failed: {message}")))
}

fn resolve_record_error(input: &str, error: Box<dyn Error>) -> Box<dyn Error> {
    let message = format_query_error(error.as_ref());
    drop(error);
    Box::new(CliError(format!("{input}: resolve call failed: {message}")))
}

fn resolve_service_target(
    socket: &Path,
    owner: &str,
    ifindex: i32,
    request_flags: u64,
) -> Option<String> {
    let reply = call(
        socket,
        "io.rustd.Resolve.ResolveRecord",
        Value::object([
            ("ifindex", Value::Number(i128::from(ifindex))),
            ("name", Value::String(owner.to_owned())),
            ("class", Value::Number(1)),
            ("type", Value::Number(33)),
            ("flags", Value::Number(i128::from(request_flags))),
        ]),
    )
    .ok()?;
    let parameters = reply_parameters_for_query(&reply, owner).ok()?;
    service_target_from_parameters(parameters)
}

fn service_target_from_parameters(parameters: &Value) -> Option<String> {
    for value in parameters.get("rrs")?.as_array()? {
        let raw = value.get("raw")?.as_str()?;
        let decoded = resolvectl_rr::decode_base64(raw).ok()?;
        let record = resolvectl_rr::parse_canonical_record(&decoded).ok()?;
        if record.rr_type != 33 || record.rdata.len() < 7 {
            continue;
        }
        let (target, end) = decode_wire_name(&record.rdata, 6).ok()?;
        if end == record.rdata.len() && target != "." {
            return Some(target);
        }
    }
    None
}

fn log_level(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    if arguments.len() > 1 {
        return Err("log-level accepts at most one level".into());
    }
    let connection = Connection::system()?;
    let proxy = Proxy::new(
        &connection,
        "org.freedesktop.resolve1",
        "/org/freedesktop/LogControl1",
        "org.freedesktop.LogControl1",
    )?;
    if let Some(level) = arguments.first() {
        proxy.set_property("LogLevel", level)?;
    } else {
        let level: String = proxy.get_property("LogLevel")?;
        println!("{level}");
    }
    Ok(())
}

fn monitor(
    socket: &Path,
    arguments: &[String],
    json: Option<&str>,
    ask_password: bool,
) -> Result<(), Box<dyn Error>> {
    if !arguments.is_empty() {
        return Err("monitor accepts no arguments".into());
    }
    let request = Value::object([
        (
            "method",
            Value::String("io.rustd.Resolve.Monitor.SubscribeQueryResults".to_owned()),
        ),
        ("more", Value::Bool(true)),
        (
            "parameters",
            Value::object([("allowInteractiveAuthentication", Value::Bool(ask_password))]),
        ),
    ]);
    let mut stream = UnixStream::connect(socket)?;
    stream.write_all(request.to_json().as_bytes())?;
    stream.write_all(&[0])?;
    let mut pending = Vec::new();
    loop {
        let reply = read_varlink_reply(&mut stream, &mut pending)?;
        if let Some(error) = monitor_varlink_error(&reply) {
            return Err(Box::new(error));
        }
        let parameters = reply_parameters(&reply)?;
        if parameters.get("ready").and_then(Value::as_bool) == Some(true) {
            let _ = rustd_resolved::native::notify("READY=1");
            continue;
        }
        if json_enabled(json) {
            println!("{}", json_output(parameters, json));
        } else {
            print_monitor_event(parameters);
        }
    }
}

fn monitor_varlink_error(reply: &Value) -> Option<CliError> {
    reply
        .get("error")
        .and_then(Value::as_str)
        .map(|identifier| CliError(format!("Varlink error: {identifier}")))
}

fn read_varlink_reply(
    stream: &mut UnixStream,
    pending: &mut Vec<u8>,
) -> Result<Value, Box<dyn Error>> {
    loop {
        if let Some(position) = pending.iter().position(|byte| *byte == 0) {
            let message = pending.drain(..=position).collect::<Vec<_>>();
            let text = std::str::from_utf8(&message[..message.len() - 1])?;
            return Ok(json::parse(text)?);
        }
        let mut chunk = [0; 8192];
        let length = stream.read(&mut chunk)?;
        if length == 0 {
            return Err("Varlink connection closed before a complete reply".into());
        }
        pending.extend_from_slice(&chunk[..length]);
        if pending.len() > MAX_REPLY_SIZE {
            return Err("Varlink reply exceeds the configured limit".into());
        }
    }
}

fn print_monitor_event(parameters: &Value) {
    if let Some(questions) = parameters.get("question").and_then(Value::as_array) {
        for question in questions {
            let name = question.get("name").and_then(Value::as_str).unwrap_or("?");
            let class = question.get("class").and_then(Value::as_u64).unwrap_or(1);
            let rr_type = question.get("type").and_then(Value::as_u64).unwrap_or(0);
            println!(
                "→ Q: {name} {} {}",
                class_name(class),
                record_type_name(rr_type)
            );
        }
    }
    let state = parameters
        .get("state")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    print!("← S: {state}");
    if let Some(result) = parameters.get("result").and_then(Value::as_str) {
        print!(": {result}");
    }
    if let Some(rcode) = parameters.get("rcode").and_then(Value::as_i64) {
        print!(": rcode {rcode}");
    }
    println!();
    if let Some(answers) = parameters.get("answer").and_then(Value::as_array) {
        for answer in answers {
            let result = (|| {
                let raw = answer
                    .get("raw")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid_data("monitor answer has no raw record"))?;
                let decoded = resolvectl_rr::decode_base64(raw)?;
                let record = resolvectl_rr::parse_canonical_record(&decoded)?;
                format_record_text(&record, None)
            })();
            match result {
                Ok(record) => println!("← A: {record}"),
                Err(error) => eprintln!("resolvectl: ignoring invalid monitor answer: {error}"),
            }
        }
    }
    println!();
}

impl Options {
    fn monitor_socket(&self) -> PathBuf {
        if self.socket_explicit {
            monitor_socket_for(&self.socket)
        } else {
            PathBuf::from(DEFAULT_MONITOR_SOCKET)
        }
    }
}

fn monitor_socket_for(path: &Path) -> PathBuf {
    if path.file_name().and_then(|name| name.to_str()) == Some("io.rustd.Resolve") {
        return path.with_file_name("io.rustd.Resolve.Monitor");
    }
    let mut monitor = path.as_os_str().to_owned();
    monitor.push(".Monitor");
    PathBuf::from(monitor)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompatMode {
    Query,
    Service,
    OpenPgp,
    Tlsa,
    Statistics,
    ResetStatistics,
    Status,
    FlushCaches,
    ResetServerFeatures,
    SetLink,
    RevertLink,
}

#[allow(clippy::too_many_lines)]
fn translate_systemd_resolve(
    raw_arguments: Vec<String>,
) -> Result<Vec<Vec<String>>, Box<dyn Error>> {
    let mut mode = CompatMode::Query;
    let mut common = Vec::new();
    let mut operands = Vec::new();
    let mut interface = None;
    let mut interface_index = 0;
    let mut tlsa_family = None;
    let mut set_dns = Vec::new();
    let mut set_domain = Vec::new();
    let mut set_nta = Vec::new();
    let mut set_llmnr = None;
    let mut set_mdns = None;
    let mut set_dnsovertls = None;
    let mut set_dnssec = None;
    let mut saw_type = false;
    let mut saw_class = false;
    let mut arguments = raw_arguments.into_iter();

    while let Some(argument) = arguments.next() {
        if argument == "--" {
            operands.extend(arguments);
            break;
        }
        if matches!(argument.as_str(), "-h" | "--help" | "--version") {
            return Ok(vec![vec![argument]]);
        }

        let (name, attached) = compat_option(&argument);
        match name {
            "-4" | "-6" | "--no-pager" => common.push(name.to_owned()),
            "-i" | "--interface" => {
                let value = compat_option_value(attached, &mut arguments, name)?;
                let index = rustd_resolved::interface::resolve_ifindex(&value)?;
                merge_ifindex(&mut interface_index, index)?;
                interface = Some(value.clone());
                common.push(format!("--interface={value}"));
            }
            "-p" | "--protocol" => {
                let value = compat_option_value(attached, &mut arguments, name)?;
                if value == "help" {
                    return Ok(vec![vec![format!("--protocol={value}")]]);
                }
                protocol_flags(&value)?;
                common.push(format!("--protocol={value}"));
            }
            "-t" | "--type" => {
                let value = compat_option_value(attached, &mut arguments, name)?;
                if value == "help" {
                    return Ok(vec![vec![format!("--type={value}")]]);
                }
                parse_record_type(&value)?;
                common.push(format!("--type={value}"));
                saw_type = true;
            }
            "-c" | "--class" => {
                let value = compat_option_value(attached, &mut arguments, name)?;
                if value == "help" {
                    return Ok(vec![vec![format!("--class={value}")]]);
                }
                parse_record_class(&value)?;
                common.push(format!("--class={value}"));
                saw_class = true;
            }
            "--service-address" | "--service-txt" | "--cname" | "--search" | "--legend" => {
                let value = compat_option_value(attached, &mut arguments, name)?;
                parse_yes_no(&value)?;
                common.push(format!("{name}={value}"));
            }
            "--raw" => {
                if io::stdout().is_terminal() {
                    return Err("refusing to write binary data to a terminal".into());
                }
                if attached.is_some_and(|value| !matches!(value, "payload" | "packet")) {
                    return Err(format!(
                        "unknown --raw specifier: {}",
                        attached.unwrap_or_default()
                    )
                    .into());
                }
                common.push(
                    attached.map_or_else(|| "--raw".to_owned(), |value| format!("--raw={value}")),
                );
            }
            "--service" if attached.is_none() => mode = CompatMode::Service,
            "--openpgp" if attached.is_none() => mode = CompatMode::OpenPgp,
            "--tlsa" => {
                if let Some(value) = attached {
                    if !matches!(value, "tcp" | "udp" | "sctp") {
                        return Err(format!("unknown TLSA service family: {value}").into());
                    }
                    tlsa_family = Some(value.to_owned());
                }
                mode = CompatMode::Tlsa;
            }
            "--statistics" if attached.is_none() => mode = CompatMode::Statistics,
            "--reset-statistics" if attached.is_none() => mode = CompatMode::ResetStatistics,
            "--status" if attached.is_none() => mode = CompatMode::Status,
            "--flush-caches" if attached.is_none() => mode = CompatMode::FlushCaches,
            "--reset-server-features" if attached.is_none() => {
                mode = CompatMode::ResetServerFeatures;
            }
            "--set-dns" => {
                set_dns.push(compat_option_value(attached, &mut arguments, name)?);
                mode = CompatMode::SetLink;
            }
            "--set-domain" => {
                set_domain.push(compat_option_value(attached, &mut arguments, name)?);
                mode = CompatMode::SetLink;
            }
            "--set-nta" => {
                set_nta.push(compat_option_value(attached, &mut arguments, name)?);
                mode = CompatMode::SetLink;
            }
            "--set-llmnr" => {
                set_llmnr = Some(compat_option_value(attached, &mut arguments, name)?);
                mode = CompatMode::SetLink;
            }
            "--set-mdns" => {
                set_mdns = Some(compat_option_value(attached, &mut arguments, name)?);
                mode = CompatMode::SetLink;
            }
            "--set-dnsovertls" => {
                set_dnsovertls = Some(compat_option_value(attached, &mut arguments, name)?);
                mode = CompatMode::SetLink;
            }
            "--set-dnssec" => {
                set_dnssec = Some(compat_option_value(attached, &mut arguments, name)?);
                mode = CompatMode::SetLink;
            }
            "--revert" if attached.is_none() => mode = CompatMode::RevertLink,
            value if value.starts_with('-') => {
                return Err(format!("unknown systemd-resolve option: {argument}").into());
            }
            _ => operands.push(argument),
        }
    }

    if mode == CompatMode::Service && saw_type {
        return Err("--service and --type may not be combined".into());
    }
    if saw_class && !saw_type {
        return Err("--class may only be used together with --type".into());
    }

    let simple = |command: &str, arguments: Vec<String>| {
        let mut translated = common.clone();
        translated.push(command.to_owned());
        translated.extend(arguments);
        vec![translated]
    };
    Ok(match mode {
        CompatMode::Query => simple("query", operands),
        CompatMode::Service => simple("service", operands),
        CompatMode::OpenPgp => simple("openpgp", operands),
        CompatMode::Tlsa => {
            let mut arguments = Vec::new();
            arguments.extend(tlsa_family);
            arguments.extend(operands);
            simple("tlsa", arguments)
        }
        CompatMode::Statistics => simple("statistics", Vec::new()),
        CompatMode::ResetStatistics => simple("reset-statistics", Vec::new()),
        CompatMode::Status => {
            if operands.is_empty() {
                operands.extend(interface.clone());
            }
            simple("status", operands)
        }
        CompatMode::FlushCaches => simple("flush-caches", Vec::new()),
        CompatMode::ResetServerFeatures => simple("reset-server-features", Vec::new()),
        CompatMode::RevertLink => {
            let interface = interface.ok_or("--revert requires --interface")?;
            vec![vec!["revert".to_owned(), interface]]
        }
        CompatMode::SetLink => {
            let interface = interface.ok_or("link setters require --interface")?;
            let mut plans = Vec::new();
            push_link_plan(&mut plans, "dns", &interface, set_dns);
            push_link_plan(&mut plans, "domain", &interface, set_domain);
            push_link_plan(&mut plans, "nta", &interface, set_nta);
            push_optional_link_plan(&mut plans, "llmnr", &interface, set_llmnr);
            push_optional_link_plan(&mut plans, "mdns", &interface, set_mdns);
            push_optional_link_plan(&mut plans, "dnsovertls", &interface, set_dnsovertls);
            push_optional_link_plan(&mut plans, "dnssec", &interface, set_dnssec);
            plans
        }
    })
}

fn compat_option(argument: &str) -> (&str, Option<&str>) {
    if let Some((name, value)) = argument.split_once('=') {
        return (name, Some(value));
    }
    for name in ["-i", "-p", "-t", "-c"] {
        if let Some(value) = argument
            .strip_prefix(name)
            .filter(|value| !value.is_empty())
        {
            return (name, Some(value));
        }
    }
    (argument, None)
}

fn compat_option_value(
    attached: Option<&str>,
    arguments: &mut impl Iterator<Item = String>,
    option: &str,
) -> Result<String, Box<dyn Error>> {
    let value = attached.map(str::to_owned).or_else(|| arguments.next());
    match value {
        Some(value) if !value.is_empty() => Ok(value),
        _ => Err(format!("{option} requires a value").into()),
    }
}

fn push_link_plan(
    plans: &mut Vec<Vec<String>>,
    command: &str,
    interface: &str,
    values: Vec<String>,
) {
    if !values.is_empty() {
        let mut plan = vec![command.to_owned(), interface.to_owned()];
        plan.extend(values);
        plans.push(plan);
    }
}

fn push_optional_link_plan(
    plans: &mut Vec<Vec<String>>,
    command: &str,
    interface: &str,
    value: Option<String>,
) {
    if let Some(value) = value {
        plans.push(vec![command.to_owned(), interface.to_owned(), value]);
    }
}

fn merge_ifindex(current: &mut i32, new: i32) -> Result<(), Box<dyn Error>> {
    if *current > 0 && *current != new {
        return Err("multiple different interfaces were specified".into());
    }
    *current = new;
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn parse_options(raw_arguments: Vec<String>) -> Result<Option<Options>, Box<dyn Error>> {
    let mut socket = PathBuf::from(DEFAULT_SOCKET);
    let mut socket_explicit = false;
    let mut family = 0;
    let mut ifindex = 0;
    let mut request_flags = 0;
    let mut legend = true;
    let mut rr_type = None;
    let mut rr_class = None;
    let mut raw = RawMode::None;
    let mut ask_password = true;
    let mut json = None;
    let mut command = None;
    let mut command_arguments = Vec::new();
    let mut arguments = raw_arguments.into_iter();

    while let Some(argument) = arguments.next() {
        if argument == "--" {
            if command.is_none() {
                command = arguments.next();
            }
            command_arguments.extend(arguments);
            break;
        }
        if argument.starts_with("-j") && argument != "-j" {
            let Some(rest) = argument.strip_prefix("-j") else {
                unreachable!("pattern already checked")
            };
            if rest.starts_with('=') {
                return Err("invalid option -- '='".into());
            }
            if let Some(value) = rest.strip_prefix('p') {
                if value.is_empty() {
                    return Err("option requires an argument -- 'p'".into());
                }
                if value == "help" {
                    if legend {
                        println!("Known protocol types:");
                    }
                    println!("dns\nllmnr\nllmnr-ipv4\nllmnr-ipv6\nmdns\nmdns-ipv4\nmdns-ipv6");
                    return Ok(None);
                }
                protocol_flags(value)?;
                return Ok(None);
            }
            let invalid = rest.chars().next().unwrap_or('-');
            return Err(format!("invalid option -- '{invalid}'").into());
        }
        if argument.starts_with("-h") && !argument.starts_with("--") {
            print_help();
            return Ok(None);
        }
        let (name, inline_value) = split_option(&argument);
        match name {
            "--json" => {
                json = Some(option_value_json(inline_value, &mut arguments, name)?);
            }
            "-j" => {
                json = Some(if io::stdout().is_terminal() {
                    "pretty".to_owned()
                } else {
                    "short".to_owned()
                });
            }
            "-i" | "--interface" => {
                let value = option_value(inline_value, &mut arguments, name)?;
                let index =
                    rustd_resolved::interface::resolve_ifindex(&value).map_err(|error| {
                        let error = error.to_string();
                        let error = error.split(" (os error ").next().unwrap_or(error.as_str());
                        format!("Failed to resolve interface {value:?}: {error}")
                    })?;
                merge_ifindex(&mut ifindex, index)?;
            }
            "-p" | "--protocol" => {
                let value = if let Some("") = inline_value {
                    String::new()
                } else {
                    option_value(inline_value, &mut arguments, name)?
                };
                if value == "help" {
                    if legend {
                        println!("Known protocol types:");
                    }
                    println!("dns\nllmnr\nllmnr-ipv4\nllmnr-ipv6\nmdns\nmdns-ipv4\nmdns-ipv6");
                    return Ok(None);
                }
                request_flags |= protocol_flags(&value)?;
            }
            "-t" | "--type" => {
                let value = option_value_with_empty_allowed(inline_value, &mut arguments, name)?;
                if value == "help" {
                    if legend {
                        println!("Known DNS RR types:");
                    }
                    for value in 1..=32_769 {
                        if let Some(name) = rustd_resolved::config::dns_record_type_name(value) {
                            println!("{name}");
                        }
                    }
                    return Ok(None);
                }
                rr_type = Some(parse_record_type(&value)?);
            }
            "-c" | "--class" => {
                let value = option_value_with_empty_allowed(inline_value, &mut arguments, name)?;
                if value == "help" {
                    if legend {
                        println!("Known DNS RR classes:");
                    }
                    println!("IN\nANY");
                    return Ok(None);
                }
                rr_class = Some(parse_record_class(&value)?);
            }
            "--service-address" => set_disabled_flag(
                &mut request_flags,
                rustd_resolved::dbus_resolve1_abi::flags::SD_RESOLVED_NO_ADDRESS,
                name,
                &option_value(inline_value, &mut arguments, name)?,
            )?,
            "--service-txt" => set_disabled_flag(
                &mut request_flags,
                rustd_resolved::dbus_resolve1_abi::flags::SD_RESOLVED_NO_TXT,
                name,
                &option_value(inline_value, &mut arguments, name)?,
            )?,
            "--cname" => set_disabled_flag(
                &mut request_flags,
                rustd_resolved::dbus_resolve1_abi::flags::SD_RESOLVED_NO_CNAME,
                name,
                &option_value(inline_value, &mut arguments, name)?,
            )?,
            "--validate" => set_disabled_flag(
                &mut request_flags,
                rustd_resolved::dbus_resolve1_abi::flags::SD_RESOLVED_NO_VALIDATE,
                name,
                &option_value(inline_value, &mut arguments, name)?,
            )?,
            "--synthesize" => set_disabled_flag(
                &mut request_flags,
                rustd_resolved::dbus_resolve1_abi::flags::SD_RESOLVED_NO_SYNTHESIZE,
                name,
                &option_value(inline_value, &mut arguments, name)?,
            )?,
            "--cache" => set_disabled_flag(
                &mut request_flags,
                rustd_resolved::dbus_resolve1_abi::flags::SD_RESOLVED_NO_CACHE,
                name,
                &option_value(inline_value, &mut arguments, name)?,
            )?,
            "--stale-data" => set_disabled_flag(
                &mut request_flags,
                rustd_resolved::dbus_resolve1_abi::flags::SD_RESOLVED_NO_STALE,
                name,
                &option_value(inline_value, &mut arguments, name)?,
            )?,
            "--zone" => set_disabled_flag(
                &mut request_flags,
                rustd_resolved::dbus_resolve1_abi::flags::SD_RESOLVED_NO_ZONE,
                name,
                &option_value(inline_value, &mut arguments, name)?,
            )?,
            "--trust-anchor" => set_disabled_flag(
                &mut request_flags,
                rustd_resolved::dbus_resolve1_abi::flags::SD_RESOLVED_NO_TRUST_ANCHOR,
                name,
                &option_value(inline_value, &mut arguments, name)?,
            )?,
            "--network" => set_disabled_flag(
                &mut request_flags,
                rustd_resolved::dbus_resolve1_abi::flags::SD_RESOLVED_NO_NETWORK,
                name,
                &option_value(inline_value, &mut arguments, name)?,
            )?,
            "--search" => set_disabled_flag(
                &mut request_flags,
                rustd_resolved::dbus_resolve1_abi::flags::SD_RESOLVED_NO_SEARCH,
                name,
                &option_value(inline_value, &mut arguments, name)?,
            )?,
            "--relax-single-label" => set_enabled_flag(
                &mut request_flags,
                rustd_resolved::dbus_resolve1_abi::flags::SD_RESOLVED_RELAX_SINGLE_LABEL,
                name,
                &option_value(inline_value, &mut arguments, name)?,
            )?,
            "--legend" => {
                legend =
                    parse_named_yes_no(name, &option_value(inline_value, &mut arguments, name)?)?;
            }
            "--raw" => {
                let parsed = match inline_value {
                    None | Some("payload") => RawMode::Payload,
                    Some("packet") => RawMode::Packet,
                    Some(value) => {
                        return Err(format!("Unknown --raw specifier \"{value}\".").into());
                    }
                };
                if io::stdout().is_terminal() {
                    return Err("refusing to write binary data to a terminal".into());
                }
                raw = parsed;
                legend = false;
            }
            "--no-pager" => {}
            "--no-ask-password" => ask_password = false,
            "--socket" => {
                socket = option_value(inline_value, &mut arguments, name)?.into();
                socket_explicit = true;
            }
            "-4" => family = 2,
            "-6" => family = 10,
            "--version" => {
                if inline_value.is_some() {
                    return Err("option '--version' doesn't allow an argument".into());
                }
                print_systemd_version();
                return Ok(None);
            }
            "--help" | "-h" => {
                if name == "--help" && inline_value.is_some() {
                    return Err("option '--help' doesn't allow an argument".into());
                }
                print_help();
                return Ok(None);
            }
            "help" if command.is_none() => {
                print_help();
                return Ok(None);
            }
            _ if command.is_some() && !argument.starts_with('-') => {
                command_arguments.push(argument);
            }
            _ if argument.starts_with("--") => {
                return Err(format!("unrecognized option '{argument}'").into());
            }
            _ if argument.starts_with('-') => {
                let mut chars = argument.chars();
                let _ = chars.next();
                let option = chars.next().unwrap_or('-');
                return Err(format!("invalid option -- '{option}'").into());
            }
            _ => command = Some(argument),
        }
    }

    let command = command.unwrap_or_else(|| "status".to_owned());
    if json
        .as_deref()
        .is_some_and(|mode| !matches!(mode, "off" | "pretty" | "short"))
    {
        return Err("--json mode must be one of: off, pretty, short".into());
    }
    if rr_class.is_some() && rr_type.is_none() {
        return Err("--class= may only be used in conjunction with --type=.".into());
    }
    validate_command_arity(&command, command_arguments.len())?;
    Ok(Some(Options {
        socket,
        socket_explicit,
        family,
        ifindex,
        request_flags,
        legend,
        rr_type,
        rr_class: rr_class.unwrap_or(1),
        raw,
        ask_password,
        json,
        command,
        arguments: command_arguments,
    }))
}

fn validate_command_arity(command: &str, arguments: usize) -> Result<(), Box<dyn Error>> {
    let (minimum, maximum) = match command {
        "query" | "openpgp" | "tlsa" => (1, None),
        "service" => (1, Some(3)),
        "status" | "dns" | "domain" | "nta" => (0, None),
        "statistics"
        | "reset-statistics"
        | "flush-caches"
        | "reset-server-features"
        | "monitor"
        | "show-cache"
        | "show-server-state" => (0, Some(0)),
        "default-route" | "llmnr" | "mdns" | "dnsovertls" | "dnssec" => (0, Some(2)),
        "revert" => (1, Some(1)),
        "log-level" => (0, Some(1)),
        _ => return Ok(()),
    };
    if arguments < minimum {
        if minimum > 0 {
            if command == "revert" {
                return Err("Interface argument required.".into());
            }
            return Err("Too few arguments.".into());
        }
        return Ok(());
    }
    if maximum.is_some_and(|maximum| arguments > maximum) {
        return Err("Too many arguments.".into());
    }
    Ok(())
}

fn option_value(
    inline: Option<&str>,
    arguments: &mut impl Iterator<Item = String>,
    option: &str,
) -> Result<String, Box<dyn Error>> {
    if let Some(value) = inline {
        if value.is_empty() {
            return Err(format!("{option} requires a value").into());
        }
        return Ok(value.to_owned());
    }
    arguments
        .next()
        .ok_or_else(|| format!("{option} requires a value").into())
}

#[derive(Debug)]
struct QueryArguments<'a> {
    inputs: Vec<&'a str>,
    rr_type: Option<u16>,
    rr_class: u16,
    legend: bool,
}

fn query_many(
    socket: &Path,
    arguments: &[String],
    options: LookupOptions<'_>,
) -> Result<(), Box<dyn Error>> {
    let query_arguments =
        parse_query_arguments(arguments, options.legend, options.rr_type, options.rr_class)?;
    let options = LookupOptions {
        legend: query_arguments.legend,
        rr_type: query_arguments.rr_type,
        rr_class: query_arguments.rr_class,
        ..options
    };
    let mut failed = Vec::new();
    for input in query_arguments.inputs {
        let result = options.rr_type.map_or_else(
            || query(socket, input, options),
            |rr_type| query_record(socket, input, rr_type, options),
        );
        if let Err(error) = result {
            if error.is::<CliError>() {
                eprintln!("{}", format_query_error(error.as_ref()));
            } else {
                eprintln!("{input}: {}", format_query_error(error.as_ref()));
            }
            failed.push(input);
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(Box::new(QueryFailed))
    }
}

fn format_query_error(error: &dyn Error) -> String {
    error.to_string()
}

fn parse_query_arguments(
    arguments: &[String],
    default_legend: bool,
    default_rr_type: Option<u16>,
    default_rr_class: u16,
) -> Result<QueryArguments<'_>, Box<dyn Error>> {
    let mut inputs = Vec::new();
    let mut rr_type = default_rr_type;
    let mut rr_class = default_rr_class;
    let mut class_set = false;
    let mut legend = default_legend;
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        let (name, inline) = split_option(argument);
        match name {
            "-t" | "--type" => {
                let value = if let Some(value) = inline {
                    value
                } else {
                    index += 1;
                    arguments
                        .get(index)
                        .ok_or_else(|| format!("{name} requires a record type"))?
                };
                rr_type = Some(parse_record_type(value)?);
            }
            "-c" | "--class" => {
                let value = if let Some(value) = inline {
                    value
                } else {
                    index += 1;
                    arguments
                        .get(index)
                        .ok_or_else(|| format!("{name} requires a record class"))?
                };
                rr_class = parse_record_class(value)?;
                class_set = true;
            }
            "--legend" => {
                let value = inline.ok_or("--legend requires a value")?;
                legend = parse_named_yes_no(name, value)?;
            }
            value if value.starts_with('-') => {
                return Err(format!("unsupported query option: {argument}").into());
            }
            _ => inputs.push(argument),
        }
        index += 1;
    }
    if class_set && rr_type.is_none() {
        return Err("--class= may only be used in conjunction with --type=.".into());
    }
    if inputs.is_empty() {
        return Err("Too few arguments.".into());
    }
    Ok(QueryArguments {
        inputs,
        rr_type,
        rr_class,
        legend,
    })
}

fn parse_yes_no(value: &str) -> Result<bool, Box<dyn Error>> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "yes" | "y" | "true" | "t" | "on" => Ok(true),
        "0" | "no" | "n" | "false" | "f" | "off" => Ok(false),
        _ => Err(format!("invalid boolean value: {value}").into()),
    }
}

fn parse_named_yes_no(option: &str, value: &str) -> Result<bool, Box<dyn Error>> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "yes" | "y" | "true" | "t" | "on" => Ok(true),
        "0" | "no" | "n" | "false" | "f" | "off" => Ok(false),
        _ => Err(format!("Failed to parse boolean argument to {option}=: {value}.").into()),
    }
}

fn parse_record_type(value: &str) -> Result<u16, Box<dyn Error>> {
    if value == "help" {
        return Err("known record types include A, AAAA, CNAME, MX, PTR, SRV, TXT, and ANY".into());
    }
    rustd_resolved::config::dns_record_type_from_string(&value.to_ascii_uppercase())
        .ok_or_else(|| format!("Failed to parse RR record type {value}: Invalid argument").into())
}

fn parse_record_class(value: &str) -> Result<u16, Box<dyn Error>> {
    if value == "help" {
        return Err("known record classes: IN, ANY".into());
    }
    let uppercase = value.to_ascii_uppercase();
    match uppercase.as_str() {
        "IN" => Ok(1),
        "ANY" => Ok(255),
        class => class
            .strip_prefix("CLASS")
            .unwrap_or(class)
            .parse::<u16>()
            .map_err(|_| {
                format!("Failed to parse RR record class {value}: Invalid argument").into()
            }),
    }
}

fn split_option(argument: &str) -> (&str, Option<&str>) {
    if argument.starts_with("--") {
        argument
            .split_once('=')
            .map_or((argument, None), |(name, value)| (name, Some(value)))
    } else if argument.starts_with('-') && argument.len() > 1 {
        attached_short_option(argument)
            .map_or((argument, None), |(name, value)| (name, Some(value)))
    } else {
        (argument, None)
    }
}

fn option_value_with_empty_allowed(
    inline: Option<&str>,
    arguments: &mut impl Iterator<Item = String>,
    option: &str,
) -> Result<String, Box<dyn Error>> {
    if let Some(value) = inline {
        Ok(value.to_owned())
    } else {
        arguments
            .next()
            .ok_or_else(|| format!("{option} requires a value").into())
    }
}

fn protocol_flags(value: &str) -> Result<u64, Box<dyn Error>> {
    use rustd_resolved::dbus_resolve1_abi::flags::{
        SD_RESOLVED_DNS, SD_RESOLVED_LLMNR_IPV4, SD_RESOLVED_LLMNR_IPV6, SD_RESOLVED_MDNS_IPV4,
        SD_RESOLVED_MDNS_IPV6,
    };

    if value == "help" {
        return Err(
            "known protocols: dns, llmnr, llmnr-ipv4, llmnr-ipv6, mdns, mdns-ipv4, mdns-ipv6"
                .into(),
        );
    }

    match value.to_ascii_lowercase().as_str() {
        "dns" => Ok(SD_RESOLVED_DNS),
        "llmnr" => Ok(SD_RESOLVED_LLMNR_IPV4 | SD_RESOLVED_LLMNR_IPV6),
        "llmnr-ipv4" => Ok(SD_RESOLVED_LLMNR_IPV4),
        "llmnr-ipv6" => Ok(SD_RESOLVED_LLMNR_IPV6),
        "mdns" => Ok(SD_RESOLVED_MDNS_IPV4 | SD_RESOLVED_MDNS_IPV6),
        "mdns-ipv4" => Ok(SD_RESOLVED_MDNS_IPV4),
        "mdns-ipv6" => Ok(SD_RESOLVED_MDNS_IPV6),
        _ => Err(format!("Unknown protocol specifier: {value}").into()),
    }
}

fn set_disabled_flag(
    flags: &mut u64,
    flag: u64,
    option: &str,
    value: &str,
) -> Result<(), Box<dyn Error>> {
    if parse_named_yes_no(option, value)? {
        *flags &= !flag;
    } else {
        *flags |= flag;
    }
    Ok(())
}

fn set_enabled_flag(
    flags: &mut u64,
    flag: u64,
    option: &str,
    value: &str,
) -> Result<(), Box<dyn Error>> {
    if parse_named_yes_no(option, value)? {
        *flags |= flag;
    } else {
        *flags &= !flag;
    }
    Ok(())
}

fn option_value_json(
    inline: Option<&str>,
    arguments: &mut impl Iterator<Item = String>,
    option: &str,
) -> Result<String, Box<dyn Error>> {
    let value = if let Some(value) = inline {
        value.to_owned()
    } else {
        arguments
            .next()
            .ok_or_else(|| -> Box<dyn Error> { format!("{option} requires an argument").into() })?
    };
    parse_json(value.as_str())
}

fn parse_json(value: &str) -> Result<String, Box<dyn Error>> {
    match value {
        "off" | "pretty" | "short" => Ok(value.to_string()),
        _ => Err(format!("Unknown argument to --json= switch: {value}").into()),
    }
}

fn attached_short_option(argument: &str) -> Option<(&str, &str)> {
    if argument.len() <= 2 || argument.starts_with("--") {
        return None;
    }
    for name in ["-h", "-i", "-p", "-t", "-c"] {
        if let Some(value) = argument.strip_prefix(name) {
            return Some((name, value));
        }
    }
    None
}

#[allow(clippy::too_many_lines)]
fn query(socket: &Path, input: &str, options: LookupOptions<'_>) -> Result<(), Box<dyn Error>> {
    if input.starts_with("dns:") {
        let (name, rr_class, rr_type) = parse_dns_uri(input, options.rr_class, 1)?;
        return query_record(
            socket,
            &name,
            rr_type,
            LookupOptions {
                rr_class,
                rr_type: Some(rr_type),
                ..options
            },
        );
    }

    if json_enabled(options.json) && options.rr_type.is_none() {
        if parse_address_with_scope(input, options.ifindex)?.is_some() {
            return Err(Box::new(CliError(
                "Use --json=pretty with --type= to acquire resource record information in JSON format."
                    .to_owned(),
            )));
        }

        return Err(Box::new(CliError(
            "Use --json=pretty with --type=A or --type=AAAA to acquire address record information in JSON format."
                .to_owned(),
        )));
    }

    let (method, parameters) =
        if let Some((address, ifindex)) = parse_address_with_scope(input, options.ifindex)? {
            let (address_family, bytes): (i32, Vec<u8>) = match address {
                IpAddr::V4(address) => (2, address.octets().to_vec()),
                IpAddr::V6(address) => (10, address.octets().to_vec()),
            };
            (
                "io.rustd.Resolve.ResolveAddress",
                Value::object([
                    ("ifindex", Value::Number(i128::from(ifindex))),
                    ("family", Value::Number(i128::from(address_family))),
                    (
                        "address",
                        Value::Array(
                            bytes
                                .into_iter()
                                .map(|byte| Value::Number(i128::from(byte)))
                                .collect(),
                        ),
                    ),
                    ("flags", Value::Number(i128::from(options.request_flags))),
                ]),
            )
        } else {
            (
                "io.rustd.Resolve.ResolveHostname",
                Value::object([
                    ("ifindex", Value::Number(i128::from(options.ifindex))),
                    ("name", Value::String(input.to_owned())),
                    ("family", Value::Number(i128::from(options.family))),
                    ("flags", Value::Number(i128::from(options.request_flags))),
                ]),
            )
        };

    let start = Instant::now();
    let reply = call(socket, method, parameters)?;
    let elapsed = start.elapsed();
    let parameters = reply_parameters_for_query(&reply, input)?;
    if json_enabled(options.json) {
        println!("{}", json_output(parameters, options.json));
        return Ok(());
    }
    let mut printed = false;

    if let Some(addresses) = parameters.get("addresses").and_then(Value::as_array) {
        for address in addresses {
            let family = address.get("family").and_then(Value::as_i64).unwrap_or(0);
            let bytes = byte_array(address.get("address"))?;
            let address_str = decode_address(family, &bytes)?;
            let address_text = address_str.to_string();
            print_query_text_value(
                input,
                &address_text,
                address.get("ifindex").and_then(Value::as_i64),
                !printed,
            );
            printed = true;
        }
    }
    if let Some(names) = parameters.get("names").and_then(Value::as_array) {
        for name_obj in names {
            if let Some(name) = name_obj.get("name").and_then(Value::as_str) {
                print_query_text_value(
                    input,
                    name,
                    name_obj.get("ifindex").and_then(Value::as_i64),
                    !printed,
                );
                printed = true;
            }
        }
    }
    if !printed {
        return Err("reply contained no addresses or names".into());
    }
    if options.legend {
        print_query_legend(parameters, elapsed);
    }
    Ok(())
}

fn print_query_text_value(input: &str, value: &str, ifindex: Option<i64>, first: bool) {
    let link = ifindex.filter(|index| *index > 0).map(|index| {
        i32::try_from(index)
            .ok()
            .and_then(|index| rustd_resolved::interface::resolve_ifname(index).ok())
            .unwrap_or_else(|| index.to_string())
    });
    println!("{}", query_text_line(input, value, link.as_deref(), first));
}

fn query_text_line(input: &str, value: &str, link: Option<&str>, first: bool) -> String {
    let prefix = if first {
        format!("{input}:")
    } else {
        " ".repeat(input.chars().count() + 1)
    };
    let rendered = format!("{prefix} {value}");
    link.map_or(rendered.clone(), |link| {
        format!("{rendered:<59} -- link: {link}")
    })
}

fn parse_dns_uri(
    input: &str,
    default_class: u16,
    default_type: u16,
) -> Result<(String, u16, u16), Box<dyn Error>> {
    let mut body = input
        .strip_prefix("dns:")
        .ok_or("DNS URI must start with dns:")?;
    if body.starts_with('/') {
        let authority_and_path = body
            .strip_prefix("//")
            .ok_or_else(|| format!("invalid DNS URI: {input}"))?;
        let (_, path) = authority_and_path
            .split_once('/')
            .ok_or_else(|| format!("invalid DNS URI: {input}"))?;
        body = path;
    }

    let (name, query) = body
        .split_once('?')
        .map_or((body, None), |(name, query)| (name, Some(query)));
    if name.is_empty() {
        return Err(format!("invalid DNS URI: {input}").into());
    }

    let mut rr_class = None;
    let mut rr_type = None;
    if let Some(query) = query {
        if query.is_empty() {
            return Err(format!("invalid DNS URI: {input}").into());
        }
        for field in query.split(';') {
            let (key, value) = field
                .split_once('=')
                .ok_or_else(|| format!("invalid DNS URI: {input}"))?;
            if key.eq_ignore_ascii_case("class") {
                if rr_class.is_some() {
                    return Err("DNS class specified twice".into());
                }
                rr_class = Some(parse_record_class(value)?);
            } else if key.eq_ignore_ascii_case("type") {
                if rr_type.is_some() {
                    return Err("DNS type specified twice".into());
                }
                rr_type = Some(parse_record_type(value)?);
            } else {
                return Err(format!("invalid DNS URI: {input}").into());
            }
        }
    }

    Ok((
        name.to_owned(),
        rr_class.unwrap_or(default_class),
        rr_type.unwrap_or(default_type),
    ))
}

fn parse_address_with_scope(
    input: &str,
    default_ifindex: i32,
) -> Result<Option<(IpAddr, i32)>, Box<dyn Error>> {
    if let Ok(address) = input.parse::<IpAddr>() {
        return Ok(Some((address, default_ifindex)));
    }

    let Some((address_text, interface)) = input.rsplit_once('%') else {
        return Ok(None);
    };
    let Ok(address) = address_text.parse::<Ipv6Addr>() else {
        return Err(
            "Invalid IPv6 scope specification: address must be IPv6 and include a valid scope"
                .into(),
        );
    };

    let ifindex = if interface
        .chars()
        .all(|character| character.is_ascii_digit())
    {
        let parsed = interface
            .parse::<i32>()
            .map_err(|_| "Invalid IPv6 scope interface index")?;
        if parsed <= 0 {
            return Err("Invalid IPv6 scope interface index".into());
        }
        parsed
    } else {
        if interface.is_empty() {
            return Err("Invalid IPv6 scope interface name".into());
        }
        if interface.contains('%') {
            return Err("Invalid IPv6 scope interface name".into());
        }
        rustd_resolved::interface::resolve_ifindex(interface)?
    };

    Ok(Some((IpAddr::V6(address), ifindex)))
}

fn query_record(
    socket: &Path,
    input: &str,
    rr_type: u16,
    options: LookupOptions<'_>,
) -> Result<(), Box<dyn Error>> {
    if matches!(rr_type, 0 | 41 | 46 | 249 | 250) {
        return Err(format!(
            "Specified resource record type {rr_type} may not be used in a query."
        )
        .into());
    }
    let start = Instant::now();
    let reply = call(
        socket,
        "io.rustd.Resolve.ResolveRecord",
        Value::object([
            ("ifindex", Value::Number(i128::from(options.ifindex))),
            ("name", Value::String(input.to_owned())),
            ("class", Value::Number(i128::from(options.rr_class))),
            ("type", Value::Number(i128::from(rr_type))),
            ("flags", Value::Number(i128::from(options.request_flags))),
        ]),
    )
    .map_err(|error| resolve_record_error(input, error))?;
    let elapsed = start.elapsed();
    let parameters = reply_parameters_for_query(&reply, input)
        .map_err(|error| resolve_record_error(input, error))?;
    let records = parameters
        .get("rrs")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_data("ResolveRecord reply has no record array"))?;
    if records.is_empty() {
        return Err("ResolveRecord reply contained no records".into());
    }
    for value in records {
        let raw = value
            .get("raw")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_data("ResolveRecord reply has no raw record"))?;
        let raw = resolvectl_rr::decode_base64(raw)?;
        let record = resolvectl_rr::parse_canonical_record(&raw)?;
        if options.raw == RawMode::Packet {
            io::stdout().write_all(&(raw.len() as u64).to_le_bytes())?;
            io::stdout().write_all(&raw)?;
        } else if options.raw == RawMode::Payload {
            io::stdout().write_all(record_payload(&record)?)?;
        } else if json_enabled(options.json) {
            let ifindex = value
                .get("ifindex")
                .and_then(Value::as_i64)
                .and_then(|value| i32::try_from(value).ok());
            print_record_json(&record, &raw, ifindex, options.json)?;
        } else {
            let ifindex = value
                .get("ifindex")
                .and_then(Value::as_i64)
                .and_then(|value| i32::try_from(value).ok());
            print_record_text(&record, ifindex)?;
        }
    }
    if options.raw == RawMode::None && !json_enabled(options.json) && options.legend {
        print_query_legend(parameters, elapsed);
    }
    Ok(())
}

fn print_query_legend(parameters: &Value, elapsed: Duration) {
    let flags = parameters.get("flags").and_then(Value::as_u64).unwrap_or(0);
    print_query_legend_flags(flags, elapsed);
}

fn print_query_legend_flags(flags: u64, elapsed: Duration) {
    if flags == 0 {
        return;
    }

    println!();

    let mut protocols = Vec::new();
    if flags & rustd_resolved::dbus_resolve1_abi::flags::SD_RESOLVED_DNS != 0 {
        protocols.push("DNS");
    }
    if flags & rustd_resolved::dbus_resolve1_abi::flags::SD_RESOLVED_LLMNR_IPV4 != 0 {
        protocols.push("LLMNR/IPv4");
    }
    if flags & rustd_resolved::dbus_resolve1_abi::flags::SD_RESOLVED_LLMNR_IPV6 != 0 {
        protocols.push("LLMNR/IPv6");
    }
    if flags & rustd_resolved::dbus_resolve1_abi::flags::SD_RESOLVED_MDNS_IPV4 != 0 {
        protocols.push("mDNS/IPv4");
    }
    if flags & rustd_resolved::dbus_resolve1_abi::flags::SD_RESOLVED_MDNS_IPV6 != 0 {
        protocols.push("mDNS/IPv6");
    }

    let authenticated =
        flags & rustd_resolved::dbus_resolve1_abi::flags::SD_RESOLVED_AUTHENTICATED != 0;
    let confidential =
        flags & rustd_resolved::dbus_resolve1_abi::flags::SD_RESOLVED_CONFIDENTIAL != 0;
    println!(
        "-- Information acquired via protocol {} in {}.",
        protocols.join(" "),
        format_query_duration(elapsed)
    );
    println!(
        "-- Data is authenticated: {}; Data was acquired via local or encrypted transport: {}",
        if authenticated { "yes" } else { "no" },
        if confidential { "yes" } else { "no" }
    );
    let mut sources = Vec::new();
    if flags & rustd_resolved::dbus_resolve1_abi::flags::SD_RESOLVED_SYNTHETIC != 0 {
        sources.push("synthetic");
    }
    if flags & rustd_resolved::dbus_resolve1_abi::flags::SD_RESOLVED_FROM_CACHE != 0 {
        sources.push("cache");
    }
    if flags & rustd_resolved::dbus_resolve1_abi::flags::SD_RESOLVED_FROM_ZONE != 0 {
        sources.push("zone");
    }
    if flags & rustd_resolved::dbus_resolve1_abi::flags::SD_RESOLVED_FROM_TRUST_ANCHOR != 0 {
        sources.push("trust-anchor");
    }
    if flags & rustd_resolved::dbus_resolve1_abi::flags::SD_RESOLVED_FROM_NETWORK != 0 {
        sources.push("network");
    }
    if flags & rustd_resolved::dbus_resolve1_abi::flags::SD_RESOLVED_FROM_HOOK != 0 {
        sources.push("hook");
    }
    if !sources.is_empty() {
        println!("-- Data from: {}", sources.join(" "));
    }
}

fn format_query_duration(duration: Duration) -> String {
    let micros = duration.as_micros();
    if micros < 1000 {
        format!("{micros}us")
    } else {
        format!("{:.1}ms", duration.as_secs_f64() * 1_000.0)
    }
}

/// Return the binary payload exposed by upstream `dns_resource_record_payload()`.
///
/// This deliberately does not mean "the RDATA": structured DNS records are not
/// universally safe or meaningful as raw output, and TLSA exposes only its
/// certificate association data.
fn record_payload(record: &resolvectl_rr::CanonicalRecord) -> Result<&[u8], Box<dyn Error>> {
    match record.rr_type {
        6 | 2 | 5 | 12 | 39 | 13 | 16 | 99 | 15 | 29 | 43 | 48 | 46 | 47 | 50 => {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Dumping of binary payload not available for RRs of this type: {}",
                    record_type_name(u64::from(record.rr_type))
                ),
            )
            .into())
        }
        52 => record
            .rdata
            .get(3..)
            .ok_or_else(|| invalid_data("TLSA record is shorter than three octets").into()),
        _ => Ok(&record.rdata),
    }
}

fn print_record_json(
    record: &resolvectl_rr::CanonicalRecord,
    raw: &[u8],
    ifindex: Option<i32>,
    json: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let value = record_json_value(record, raw, ifindex)?;
    println!("{}", json_output(&value, json));
    Ok(())
}

fn unsupported_json_record(record: &resolvectl_rr::CanonicalRecord) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "JSON formatting for records of type {} ({}) not available.",
            record_type_name(u64::from(record.rr_type)),
            record.rr_type
        ),
    )
}

fn record_json_value(
    record: &resolvectl_rr::CanonicalRecord,
    raw: &[u8],
    _ifindex: Option<i32>,
) -> Result<Value, Box<dyn Error>> {
    let Some(value) = rustd_resolved::varlink::resource_record_json_from_raw(raw) else {
        return Err(unsupported_json_record(record).into());
    };
    Ok(value)
}

fn print_record_text(
    record: &resolvectl_rr::CanonicalRecord,
    ifindex: Option<i32>,
) -> Result<(), Box<dyn Error>> {
    let text = format_record_text(record, ifindex)?;
    println!("{text}");
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn format_record_text(
    record: &resolvectl_rr::CanonicalRecord,
    ifindex: Option<i32>,
) -> Result<String, Box<dyn Error>> {
    let value = match record.rr_type {
        1 => decode_address(2, &record.rdata)?.to_string(),
        2 | 5 | 12 | 39 => decode_wire_name(&record.rdata, 0)?.0,
        6 => {
            let (zone_name, mut offset) = decode_wire_name(&record.rdata, 0)?;
            let (owner_name, rname_offset) = decode_wire_name(&record.rdata, offset)?;
            offset = rname_offset;
            let serial = read_record_u32(&record.rdata, offset)?;
            let refresh = read_record_u32(&record.rdata, offset + 4)?;
            let retry = read_record_u32(&record.rdata, offset + 8)?;
            let expire = read_record_u32(&record.rdata, offset + 12)?;
            let minimum = read_record_u32(&record.rdata, offset + 16)?;
            format!("{zone_name} {owner_name} {serial} {refresh} {retry} {expire} {minimum}")
        }
        15 => {
            let priority = read_record_u16(&record.rdata, 0)?;
            let exchange = decode_wire_name(&record.rdata, 2)?.0;
            format!("{priority} {exchange}")
        }
        16 | 99 => format_txt_rdata(&record.rdata)?,
        28 => decode_address(10, &record.rdata)?.to_string(),
        33 => {
            let priority = read_record_u16(&record.rdata, 0)?;
            let weight = read_record_u16(&record.rdata, 2)?;
            let port = read_record_u16(&record.rdata, 4)?;
            let target = decode_wire_name(&record.rdata, 6)?.0;
            format!("{priority} {weight} {port} {target}")
        }
        43 => {
            let key_tag = read_record_u16(&record.rdata, 0)?;
            let algorithm = *record
                .rdata
                .get(2)
                .ok_or_else(|| invalid_data("truncated DS"))?;
            let digest_type = *record
                .rdata
                .get(3)
                .ok_or_else(|| invalid_data("truncated DS"))?;
            let digest = hex_encode(
                record
                    .rdata
                    .get(4..)
                    .ok_or_else(|| invalid_data("truncated DS"))?,
            );
            format!("{key_tag} {algorithm} {digest_type} {digest}")
        }
        48 => {
            let flags = read_record_u16(&record.rdata, 0)?;
            let protocol = *record
                .rdata
                .get(2)
                .ok_or_else(|| invalid_data("truncated DNSKEY"))?;
            let algorithm = *record
                .rdata
                .get(3)
                .ok_or_else(|| invalid_data("truncated DNSKEY"))?;
            let public_key = record
                .rdata
                .get(4..)
                .ok_or_else(|| invalid_data("truncated DNSKEY"))?;

            let algorithm_name = dnssec_algorithm_name(algorithm);
            let record_value = format!(
                "{} {} {} {}",
                flags,
                protocol,
                algorithm_name,
                format_dnskey_key(public_key)
            );
            let key_tag = dnskey_key_tag(&record.rdata)?;
            let suffix = format!(
                "\n        -- Flags:{}{}{}\n        -- Key tag: {key_tag}",
                if flags & DNSKEY_FLAG_SEP == 0 {
                    ""
                } else {
                    " SEP"
                },
                if flags & DNSKEY_FLAG_REVOKE == 0 {
                    ""
                } else {
                    " REVOKE"
                },
                if flags & DNSKEY_FLAG_ZONE_KEY == 0 {
                    ""
                } else {
                    " ZONE_KEY"
                },
            );
            format!("{record_value}{suffix}")
        }
        52 => {
            let [cert_usage, selector, matching_type, data @ ..] = record.rdata.as_slice() else {
                return Err(invalid_data("TLSA record is shorter than three octets").into());
            };
            format!(
                "{cert_usage} {selector} {matching_type} {}\n        -- Cert. usage: {}\n        -- Selector: {}\n        -- Matching type: {}",
                hex_encode(data),
                tlsa_cert_usage(*cert_usage),
                tlsa_selector(*selector),
                tlsa_matching_type(*matching_type),
            )
        }
        61 => resolvectl_rr::encode_base64(&record.rdata),
        64 | 65 => format_svcb_rdata(&record.rdata)?,
        257 => {
            let flags = *record
                .rdata
                .first()
                .ok_or_else(|| invalid_data("truncated CAA"))?;
            let tag_len = *record
                .rdata
                .get(1)
                .ok_or_else(|| invalid_data("truncated CAA"))? as usize;
            let tag = std::str::from_utf8(
                record
                    .rdata
                    .get(2..2 + tag_len)
                    .ok_or_else(|| invalid_data("truncated CAA"))?,
            )
            .map_err(|_| invalid_data("invalid CAA tag"))?;
            let value = record
                .rdata
                .get(2 + tag_len..)
                .ok_or_else(|| invalid_data("truncated CAA"))?;
            let flags_suffix = if flags == 0 {
                String::new()
            } else {
                format!(
                    "\n        -- Flags:{}{}",
                    if flags & 0x80 == 0 { "" } else { " critical" },
                    if flags & !0x80 == 0 {
                        String::new()
                    } else {
                        format!(" {}", flags & !0x80)
                    },
                )
            };
            format!("{flags} {tag} \"{}\"{flags_suffix}", octescape(value))
        }
        _ => format!("\\# {} {}", record.rdata.len(), hex_encode(&record.rdata)),
    };
    let line = format!(
        "{} {} {} {}",
        record.owner,
        class_name(u64::from(record.class)),
        record_type_name(u64::from(record.rr_type)),
        value
    );
    if let Some(ifindex) = ifindex.and_then(|value| (value > 0).then_some(value)) {
        let comment = if let Ok(ifname) = rustd_resolved::interface::resolve_ifname(ifindex) {
            format!(" -- link: {ifname}")
        } else {
            format!(" -- link: {ifindex}")
        };
        let printed_so_far = line.len();
        let mut aligned = line;
        if printed_so_far < 59 {
            aligned.push_str(&" ".repeat(59 - printed_so_far));
        }
        Ok(format!("{aligned}{comment}"))
    } else {
        Ok(line)
    }
}

fn format_dnskey_key(public_key: &[u8]) -> String {
    let encoded = resolvectl_rr::encode_base64(public_key);
    base64_with_indent(&encoded, 8, 80)
}

fn base64_with_indent(input: &str, indent: usize, columns: usize) -> String {
    if columns <= indent {
        return input.to_owned();
    }

    let first_capacity = columns - indent;
    if input.len() <= first_capacity {
        return input.to_owned();
    }

    let mut out = String::new();
    let padding = " ".repeat(indent);
    out.push_str(&input[..first_capacity]);
    let mut index = first_capacity;
    while index < input.len() {
        let end = std::cmp::min(index + first_capacity, input.len());
        out.push('\n');
        out.push_str(&padding);
        out.push_str(&input[index..end]);
        index = end;
    }
    out
}

fn dnskey_key_tag(rdata: &[u8]) -> Result<u16, Box<dyn Error>> {
    let flags = read_record_u16(rdata, 0)? & !DNSKEY_FLAG_REVOKE;
    let protocol = *rdata
        .get(2)
        .ok_or_else(|| invalid_data("truncated DNSKEY"))?;
    let algorithm = *rdata
        .get(3)
        .ok_or_else(|| invalid_data("truncated DNSKEY"))?;
    let key = rdata
        .get(4..)
        .ok_or_else(|| invalid_data("truncated DNSKEY"))?;

    if algorithm == 1 {
        if rdata.len() < 3 {
            return Err(invalid_data("truncated DNSKEY").into());
        }
        return Ok(u16::from_be_bytes([
            rdata[rdata.len() - 3],
            rdata[rdata.len() - 2],
        ]));
    }

    let mut sum = u32::from(flags) + (u32::from(protocol) << 8) + u32::from(algorithm);
    for (index, value) in key.iter().copied().enumerate() {
        sum += if index % 2 == 0 {
            u32::from(value) << 8
        } else {
            u32::from(value)
        };
    }
    Ok((((sum >> 16) + (sum & 0xffff)) & 0xffff)
        .try_into()
        .expect("masked value fits u16"))
}

fn dnssec_algorithm_name(algorithm: u8) -> String {
    match algorithm {
        1 => "RSAMD5".to_string(),
        2 => "DH".to_string(),
        3 => "DSA".to_string(),
        4 => "ECC".to_string(),
        5 => "RSASHA1".to_string(),
        6 => "DSA-NSEC3-SHA1".to_string(),
        7 => "RSASHA1-NSEC3-SHA1".to_string(),
        8 => "RSASHA256".to_string(),
        10 => "RSASHA512".to_string(),
        12 => "ECC-GOST".to_string(),
        13 => "ECDSAP256SHA256".to_string(),
        14 => "ECDSAP384SHA384".to_string(),
        15 => "ED25519".to_string(),
        16 => "ED448".to_string(),
        252 => "INDIRECT".to_string(),
        253 => "PRIVATEDNS".to_string(),
        254 => "PRIVATEOID".to_string(),
        _ => format!("{algorithm}"),
    }
}

const DNSKEY_FLAG_SEP: u16 = 1 << 0;
const DNSKEY_FLAG_REVOKE: u16 = 1 << 7;
const DNSKEY_FLAG_ZONE_KEY: u16 = 1 << 8;

fn read_record_u16(input: &[u8], offset: usize) -> Result<u16, Box<dyn Error>> {
    let bytes: [u8; 2] = input
        .get(offset..offset + 2)
        .ok_or_else(|| invalid_data("resource record is truncated"))?
        .try_into()?;
    Ok(u16::from_be_bytes(bytes))
}

fn read_record_u32(input: &[u8], offset: usize) -> Result<u32, Box<dyn Error>> {
    let bytes: [u8; 4] = input
        .get(offset..offset + 4)
        .ok_or_else(|| invalid_data("resource record is truncated"))?
        .try_into()?;
    Ok(u32::from_be_bytes(bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{b:02x}").unwrap();
    }
    s
}

fn decode_wire_name(input: &[u8], mut offset: usize) -> Result<(String, usize), Box<dyn Error>> {
    let mut labels = Vec::new();
    loop {
        let length = usize::from(
            *input
                .get(offset)
                .ok_or_else(|| invalid_data("DNS name is truncated"))?,
        );
        offset += 1;
        if length == 0 {
            break;
        }
        if length > 63 || length & 0xc0 != 0 {
            return Err(invalid_data("DNS name is not canonical").into());
        }
        let end = offset
            .checked_add(length)
            .filter(|end| *end <= input.len())
            .ok_or_else(|| invalid_data("DNS name label is truncated"))?;
        labels.push(std::str::from_utf8(&input[offset..end])?.to_owned());
        offset = end;
    }
    Ok((
        if labels.is_empty() {
            ".".to_owned()
        } else {
            labels.join(".")
        },
        offset,
    ))
}

fn format_txt_rdata(input: &[u8]) -> Result<String, Box<dyn Error>> {
    Ok(decode_txt_items(input)?
        .into_iter()
        .map(|item| format!("\"{item}\""))
        .collect::<Vec<_>>()
        .join(" "))
}

fn decode_txt_items(input: &[u8]) -> Result<Vec<String>, Box<dyn Error>> {
    let mut offset = 0;
    let mut items = Vec::new();
    while offset < input.len() {
        let (item, end) = decode_dns_character_bytes(input, offset)?;
        items.push(txt_escape(item));
        offset = end;
    }
    Ok(items)
}

fn decode_dns_character_bytes(
    input: &[u8],
    offset: usize,
) -> Result<(&[u8], usize), Box<dyn Error>> {
    let length = usize::from(
        *input
            .get(offset)
            .ok_or_else(|| invalid_data("DNS character string is truncated"))?,
    );
    let start = offset + 1;
    let end = start
        .checked_add(length)
        .filter(|end| *end <= input.len())
        .ok_or_else(|| invalid_data("DNS character string is truncated"))?;
    Ok((&input[start..end], end))
}

fn txt_escape(input: &[u8]) -> String {
    let mut output = String::with_capacity(input.len());
    for byte in input {
        if *byte < b' ' || *byte == b'"' || *byte >= 127 {
            use std::fmt::Write as _;
            write!(output, "\\{byte:03o}").expect("writing to String cannot fail");
        } else {
            output.push(char::from(*byte));
        }
    }
    output
}

fn octescape(input: &[u8]) -> String {
    let mut output = String::with_capacity(input.len());
    for byte in input {
        if *byte < b' ' || *byte >= 127 || matches!(*byte, b'\\' | b'"') {
            use std::fmt::Write as _;
            write!(output, "\\{byte:03o}").expect("writing to String cannot fail");
        } else {
            output.push(char::from(*byte));
        }
    }
    output
}

fn tlsa_cert_usage(value: u8) -> &'static str {
    match value {
        0 => "CA constraint",
        1 => "Service certificate constraint",
        2 => "Trust anchor assertion",
        3 => "Domain-issued certificate",
        4..=254 => "Unassigned",
        255 => "Private use",
    }
}

fn tlsa_selector(value: u8) -> &'static str {
    match value {
        0 => "Full Certificate",
        1 => "SubjectPublicKeyInfo",
        2..=254 => "Unassigned",
        255 => "Private use",
    }
}

fn tlsa_matching_type(value: u8) -> &'static str {
    match value {
        0 => "No hash used",
        1 => "SHA-256",
        2 => "SHA-512",
        3..=254 => "Unassigned",
        255 => "Private use",
    }
}

fn format_svcb_rdata(input: &[u8]) -> Result<String, Box<dyn Error>> {
    let priority = read_record_u16(input, 0)?;
    let (target, mut offset) = decode_wire_name(input, 2)?;
    let mut parameters = Vec::new();
    while offset < input.len() {
        let key = read_record_u16(input, offset)?;
        let length = usize::from(read_record_u16(input, offset + 2)?);
        offset += 4;
        let end = offset
            .checked_add(length)
            .filter(|end| *end <= input.len())
            .ok_or_else(|| invalid_data("SVCB parameter is truncated"))?;
        let value = &input[offset..end];
        parameters.push(match key {
            1 => format!("alpn=\"{}\"", format_alpn(value)?),
            2 => "no-default-alpn".to_string(),
            3 => {
                let port = format_svcb_port(value)?;
                format!("port={port}")
            }
            4 => format!("ipv4hint={}", format_ipv4_hints(value)?),
            6 => format!("ipv6hint={}", format_ipv6_hints(value)?),
            _ => {
                let key_name = format_svcb_param_name(key);
                if value.is_empty() {
                    key_name
                } else {
                    format!("{key_name}={}", svcb_unknown(value))
                }
            }
        });
        offset = end;
    }
    Ok(format!(
        "{priority} {target}{}{}",
        if parameters.is_empty() { "" } else { " " },
        parameters.join(" ")
    ))
}

fn format_alpn(input: &[u8]) -> Result<String, Box<dyn Error>> {
    let mut offset = 0;
    let mut values = Vec::new();
    while offset < input.len() {
        let length = usize::from(input[offset]);
        offset += 1;
        let end = offset
            .checked_add(length)
            .filter(|end| *end <= input.len())
            .ok_or_else(|| invalid_data("ALPN value is truncated"))?;
        values.push(std::str::from_utf8(&input[offset..end])?.to_owned());
        offset = end;
    }
    Ok(values.join(","))
}

fn format_svcb_port(input: &[u8]) -> Result<u16, Box<dyn Error>> {
    if input.len() != 2 {
        return Err(invalid_data("invalid PORT value").into());
    }
    Ok(u16::from_be_bytes(
        input
            .try_into()
            .map_err(|_| invalid_data("invalid PORT value"))?,
    ))
}

fn format_ipv6_hints(input: &[u8]) -> Result<String, Box<dyn Error>> {
    if input.len() % 16 != 0 {
        return Err(invalid_data("IPv6 hint length is invalid").into());
    }
    Ok(input
        .chunks_exact(16)
        .map(|chunk| {
            let address = Ipv6Addr::from(<[u8; 16]>::try_from(chunk).expect("16-byte chunk"));
            address.to_string()
        })
        .collect::<Vec<_>>()
        .join(","))
}

fn format_svcb_param_name(key: u16) -> String {
    match key {
        0 => "mandatory".to_string(),
        1 => "alpn".to_string(),
        2 => "no-default-alpn".to_string(),
        3 => "port".to_string(),
        4 => "ipv4hint".to_string(),
        5 => "ech".to_string(),
        6 => "ipv6hint".to_string(),
        7 => "dohpath".to_string(),
        8 => "ohttp".to_string(),
        _ => format!("key{key}"),
    }
}

fn svcb_unknown(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len() + 2);
    out.push('"');
    for byte in input {
        let byte = *byte;
        if !(b' '..127).contains(&byte)
            || byte == b'\\'
            || byte == b'"'
            || byte == b' '
            || byte == b','
        {
            use std::fmt::Write as _;
            let _ = if byte == b'\\' {
                write!(out, "\\134")
            } else if byte == b'"' {
                write!(out, "\\042")
            } else {
                write!(out, "\\{byte:03o}")
            };
        } else {
            out.push(char::from(byte));
        }
    }
    out.push('"');
    out
}

fn format_ipv4_hints(input: &[u8]) -> Result<String, Box<dyn Error>> {
    if input.len() % 4 != 0 {
        return Err(invalid_data("IPv4 hint length is invalid").into());
    }
    Ok(input
        .chunks_exact(4)
        .map(|chunk| Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]).to_string())
        .collect::<Vec<_>>()
        .join(","))
}

fn byte_array(value: Option<&Value>) -> Result<Vec<u8>, Box<dyn Error>> {
    let bytes = value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_data("reply is missing an address byte array"))?
        .iter()
        .map(|value| {
            value
                .as_u64()
                .and_then(|number| u8::try_from(number).ok())
                .ok_or_else(|| invalid_data("reply contains an invalid address byte"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(bytes)
}

fn decode_address(family: i64, bytes: &[u8]) -> Result<IpAddr, Box<dyn Error>> {
    match (family, bytes) {
        (2, [a, b, c, d]) => Ok(IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d))),
        (10, bytes) if bytes.len() == 16 => {
            let mut address = [0; 16];
            address.copy_from_slice(bytes);
            Ok(IpAddr::V6(Ipv6Addr::from(address)))
        }
        _ => Err("reply contains an invalid address family or size".into()),
    }
}

fn status(socket: &Path, arguments: &[String], json: Option<&str>) -> Result<(), Box<dyn Error>> {
    validate_status_arguments(arguments)?;
    let reply = call(
        socket,
        "io.rustd.Resolve.DumpDNSConfiguration",
        Value::Object(JsonObject::new()),
    )?;
    let monitor_socket = monitor_socket_for(socket);
    let server_state_reply = call(
        &monitor_socket,
        "io.rustd.Resolve.Monitor.DumpServerState",
        interactive_parameters(false),
    )
    .ok();

    let parameters = reply_parameters(&reply)?;
    let server_state =
        server_state_reply.and_then(|r| reply_parameters(&r).ok().map(ToOwned::to_owned));

    let configurations = select_status_configurations(parameters, arguments)?;
    if json_enabled(json) {
        println!("{}", json_output(&Value::Array(configurations), json));
        return Ok(());
    }
    for (index, configuration) in configurations.iter().enumerate() {
        if index != 0 {
            println!();
        }
        print_status_configuration(configuration, server_state.as_ref());
    }
    Ok(())
}

fn validate_status_arguments(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    for argument in arguments {
        if let Err(error) = rustd_resolved::interface::resolve_ifindex(argument) {
            let error = error.to_string();
            let error = error.split(" (os error ").next().unwrap_or(error.as_str());
            return Err(Box::new(CliError(format!(
                "Failed to resolve interface {argument:?}: {error}\n\
                 Failed to filter configuration JSON links: {error}"
            ))));
        }
    }
    Ok(())
}

fn show_configuration_field(
    socket: &Path,
    command: &str,
    json: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let field = match command {
        "dns" => "servers",
        "domain" => "searchDomains",
        "default-route" => "defaultRoute",
        "llmnr" => "llmnr",
        "mdns" => "mDNS",
        "dnsovertls" => "dnsOverTLS",
        "dnssec" => "dnssec",
        "nta" => "negativeTrustAnchors",
        _ => return Err(format!("unsupported configuration command: {command}").into()),
    };
    let reply = call(
        socket,
        "io.rustd.Resolve.DumpDNSConfiguration",
        Value::Object(JsonObject::new()),
    )?;
    let output = configuration_field_output(reply_parameters(&reply)?, field)?;
    if json_enabled(json) {
        println!("{}", json_output(&Value::Array(output), json));
    } else {
        print!(
            "{}",
            format_configuration_field_output(command, field, &output)?
        );
    }
    Ok(())
}

fn configuration_field_output(
    parameters: &Value,
    field: &str,
) -> Result<Vec<Value>, Box<dyn Error>> {
    Ok(select_status_configurations(parameters, &[])?
        .into_iter()
        .map(|configuration| configuration_field(&configuration, field))
        .collect())
}

fn configuration_field(configuration: &Value, field: &str) -> Value {
    let mut output = JsonObject::new();
    for identifier in ["ifname", "ifindex", "delegate"] {
        if let Some(value) = configuration.get(identifier) {
            output.insert(identifier.to_owned(), value.clone());
        }
    }
    output.insert(
        field.to_owned(),
        configuration.get(field).cloned().unwrap_or(Value::Null),
    );
    Value::Object(output)
}

fn format_configuration_field_output(
    command: &str,
    field: &str,
    configurations: &[Value],
) -> Result<String, Box<dyn Error>> {
    let mut output = String::new();
    for configuration in configurations {
        if let Some(line) = format_configuration_field(command, field, configuration)? {
            output.push_str(&line);
        }
    }
    Ok(output)
}

fn format_configuration_field(
    command: &str,
    field: &str,
    configuration: &Value,
) -> Result<Option<String>, Box<dyn Error>> {
    let label = configuration_label(configuration);
    let global = label == "Global";
    let delegated = configuration.get("delegate").is_some();
    let output = match command {
        "dns" => format_configuration_list(&label, configuration, field, false, |value| {
            let address = value.get("addressString")?.as_str()?;
            Some(
                value
                    .get("name")
                    .and_then(Value::as_str)
                    .map_or_else(|| address.to_owned(), |name| format!("{address}#{name}")),
            )
        }),
        "domain" => format_configuration_list(&label, configuration, field, false, |value| {
            let name = value.get("name")?.as_str()?;
            Some(
                if value.get("routeOnly").and_then(Value::as_bool) == Some(true) {
                    format!("~{name}")
                } else {
                    name.to_owned()
                },
            )
        }),
        "nta" if !delegated => {
            format_configuration_list(&label, configuration, field, true, |value| {
                value.as_str().map(str::to_owned)
            })
        }
        "default-route" if !global => format_configuration_string(
            &label,
            if configuration.get(field).and_then(Value::as_bool) == Some(true) {
                "yes"
            } else {
                "no"
            },
        ),
        "llmnr" | "mdns" | "dnsovertls" | "dnssec" if !delegated => format_configuration_string(
            &label,
            configuration
                .get(field)
                .and_then(Value::as_str)
                .unwrap_or(""),
        ),
        "default-route" | "nta" | "llmnr" | "mdns" | "dnsovertls" | "dnssec" => {
            return Ok(None);
        }
        _ => return Err(format!("unsupported configuration command: {command}").into()),
    };
    Ok(Some(output))
}

fn configuration_label(configuration: &Value) -> String {
    if let (Some(ifname), Some(ifindex)) = (
        configuration.get("ifname").and_then(Value::as_str),
        configuration.get("ifindex").and_then(Value::as_i64),
    ) {
        format!("Link {ifindex} ({ifname})")
    } else if let Some(delegate) = configuration.get("delegate").and_then(Value::as_str) {
        format!("Delegate {delegate}")
    } else {
        "Global".to_owned()
    }
}

fn format_configuration_string(label: &str, value: &str) -> String {
    format!("{label}: {value}\n")
}

fn format_configuration_list(
    label: &str,
    configuration: &Value,
    field: &str,
    sort: bool,
    format: impl Fn(&Value) -> Option<String>,
) -> String {
    let mut values = configuration
        .get(field)
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .filter_map(format)
        .collect::<Vec<_>>();
    if sort {
        values.sort_unstable();
    }
    format_wrapped_list(label, &values)
}

fn format_wrapped_list(label: &str, values: &[String]) -> String {
    let indent = "Global: ".len();
    let columns = env::var("COLUMNS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > indent)
        .unwrap_or(80);
    let mut output = format!("{label}:");
    let mut position = label.len() + 2;
    for value in values {
        if position <= indent || position + value.len() + 1 < columns {
            output.push(' ');
            output.push_str(value);
            position += value.len() + 1;
        } else {
            use std::fmt::Write as _;
            let _ = write!(output, "\n{:indent$}{value}", "");
            position = indent + value.len();
        }
    }
    output.push('\n');
    output
}

fn select_status_configurations(
    parameters: &Value,
    arguments: &[String],
) -> Result<Vec<Value>, Box<dyn Error>> {
    let configurations = parameters
        .get("configuration")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_data("DNS configuration reply is missing its configuration"))?;
    let selected = configurations
        .iter()
        .filter(|configuration| {
            if arguments.is_empty() {
                return configuration.get("ifindex").and_then(Value::as_i64) != Some(1);
            }
            arguments
                .iter()
                .any(|argument| status_configuration_matches(configuration, argument))
        })
        .cloned()
        .collect::<Vec<_>>();
    if !arguments.is_empty() && selected.is_empty() {
        return Err(Box::new(CliError(
            "Failed to filter configuration JSON links: No such device".to_owned(),
        )));
    }
    Ok(selected)
}

fn status_configuration_matches(configuration: &Value, argument: &str) -> bool {
    configuration.get("ifname").and_then(Value::as_str) == Some(argument)
        || configuration
            .get("ifindex")
            .and_then(Value::as_i64)
            .is_some_and(|ifindex| ifindex.to_string() == argument)
        || configuration.get("delegate").and_then(Value::as_str) == Some(argument)
}

fn print_status_configuration(configuration: &Value, server_state: Option<&Value>) {
    if let Some(ifindex) = configuration.get("ifindex").and_then(Value::as_i64) {
        let ifname = configuration
            .get("ifname")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        println!("Link {ifindex} ({ifname})");
    } else if let Some(delegate) = configuration.get("delegate").and_then(Value::as_str) {
        println!("Delegate {delegate}");
    } else {
        println!("Global");
    }

    print_status_scopes(configuration, server_state);
    print_status_protocols(configuration, server_state);

    print_status_string(configuration, "resolvConfMode", "resolv.conf mode");
    print_status_server(configuration, "currentServer", "Current DNS Server");
    print_status_servers(configuration, "servers", "DNS Servers");
    print_status_servers(configuration, "fallbackServers", "Fallback DNS Servers");
    print_status_domains(configuration);
    print_status_default_route(configuration);
}

fn status_label_width(configuration: &Value) -> usize {
    if configuration.get("ifindex").is_some() {
        18
    } else {
        20
    }
}

fn print_status_scopes(configuration: &Value, _server_state: Option<&Value>) {
    if configuration.get("ifindex").is_none() {
        return;
    }

    let scopes = configuration
        .get("scopes")
        .and_then(Value::as_array)
        .unwrap_or(&[]);
    let width = status_label_width(configuration);
    if scopes.is_empty() {
        println!("{label:>width$}: none", label = "Current Scopes");
        return;
    }

    let mut scope_strings = Vec::new();
    for scope in scopes {
        let protocol = scope
            .get("Protocol")
            .or_else(|| scope.get("protocol"))
            .and_then(Value::as_str);
        if let Some(protocol) = protocol {
            let mut rendered = protocol.to_ascii_uppercase();
            if rendered == "MDNS" {
                rendered = "mDNS".to_string();
            }
            let family = scope
                .get("Family")
                .or_else(|| scope.get("family"))
                .and_then(Value::as_i64);
            if let Some(family) = family {
                if family == 2 {
                    rendered.push_str("/IPv4");
                } else if family == 10 {
                    rendered.push_str("/IPv6");
                }
            }
            scope_strings.push((scope_order(protocol, family), rendered));
        }
    }
    scope_strings.sort_unstable_by_key(|(order, _)| *order);
    if scope_strings.is_empty() {
        println!("{label:>width$}: none", label = "Current Scopes");
    } else {
        let scopes = scope_strings
            .into_iter()
            .map(|(_, rendered)| rendered)
            .collect::<Vec<_>>();
        println!(
            "{label:>width$}: {}",
            scopes.join(" "),
            label = "Current Scopes"
        );
    }
}

fn scope_order(protocol: &str, family: Option<i64>) -> (u8, u8) {
    let protocol = match protocol.to_ascii_lowercase().as_str() {
        "dns" => 0,
        "llmnr" => 1,
        "mdns" => 2,
        _ => 3,
    };
    let family = match family {
        Some(2) => 0,
        Some(10) => 1,
        _ => 2,
    };
    (protocol, family)
}

fn print_status_protocols(configuration: &Value, server_state: Option<&Value>) {
    let mut protocols = Vec::new();

    if configuration.get("ifindex").is_some() {
        if let Some(default_route) = configuration.get("defaultRoute").and_then(Value::as_bool) {
            protocols.push(format!(
                "{}DefaultRoute",
                if default_route { "+" } else { "-" }
            ));
        }
    }

    let llmnr = configuration
        .get("llmnr")
        .and_then(Value::as_str)
        .unwrap_or("no");
    protocols.push(format!("{}LLMNR", if llmnr == "no" { "-" } else { "+" }));

    let mdns = configuration
        .get("mDNS")
        .and_then(Value::as_str)
        .unwrap_or("no");
    protocols.push(format!("{}mDNS", if mdns == "no" { "-" } else { "+" }));

    let dot = configuration
        .get("dnsOverTLS")
        .and_then(Value::as_str)
        .unwrap_or("no");
    protocols.push(format!("{}DNSOverTLS", if dot == "no" { "-" } else { "+" }));

    let dnssec = configuration
        .get("dnssec")
        .and_then(Value::as_str)
        .unwrap_or("no");
    let mut dnssec_str = format!("DNSSEC={dnssec}");

    let mut dnssec_supported = false;
    if let Some(state) = server_state {
        if let Some(servers) = state.get("dump").and_then(Value::as_array) {
            let ifindex = configuration
                .get("ifindex")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            for server in servers {
                let srv_ifindex = server
                    .get("InterfaceIndex")
                    .and_then(Value::as_i64)
                    .unwrap_or(0);
                if srv_ifindex == ifindex {
                    if let Some(supported) = server.get("DNSSECSupported").and_then(Value::as_bool)
                    {
                        dnssec_supported = supported;
                    }
                    break;
                }
            }
        }
    }
    dnssec_str.push_str(if dnssec_supported {
        "/supported"
    } else {
        "/unsupported"
    });

    protocols.push(dnssec_str);

    let width = status_label_width(configuration);
    println!(
        "{label:>width$}: {}",
        protocols.join(" "),
        label = "Protocols"
    );
}

fn print_status_string(configuration: &Value, field: &str, label: &str) {
    if let Some(value) = configuration.get(field).and_then(Value::as_str) {
        let width = status_label_width(configuration);
        println!("{label:>width$}: {value}");
    }
}

fn print_status_default_route(configuration: &Value) {
    if let Some(value) = configuration.get("defaultRoute").and_then(Value::as_bool) {
        let value = if value { "yes" } else { "no" };
        let width = status_label_width(configuration);
        println!("{label:>width$}: {value}", label = "Default Route");
    }
}

fn print_status_server(configuration: &Value, field: &str, label: &str) {
    if let Some(server) = configuration.get(field) {
        if let Some(server) = status_server_value(server) {
            let width = status_label_width(configuration);
            println!("{label:>width$}: {server}");
        }
    }
}

fn print_status_servers(configuration: &Value, field: &str, label: &str) {
    let Some(servers) = configuration.get(field).and_then(Value::as_array) else {
        return;
    };
    let servers = servers
        .iter()
        .filter_map(status_server_value)
        .collect::<Vec<_>>();
    if !servers.is_empty() {
        print_status_values(label, status_label_width(configuration), &servers);
    }
}

fn status_server_value(server: &Value) -> Option<String> {
    let address = server.get("addressString")?.as_str()?;
    Some(
        server
            .get("name")
            .and_then(Value::as_str)
            .map_or_else(|| address.to_owned(), |name| format!("{address}#{name}")),
    )
}

fn print_status_values(label: &str, width: usize, values: &[String]) {
    let columns = env::var("COLUMNS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > width + 2)
        .unwrap_or(80);
    print!("{label:>width$}:");
    let mut position = width + 1;
    for value in values {
        if position <= width + 1 || position + value.len() < columns {
            print!(" {value}");
            position += value.len() + 1;
        } else {
            let continuation = width + 2;
            print!("\n{:continuation$}{value}", "");
            position = continuation + value.len();
        }
    }
    println!();
}

fn print_status_domains(configuration: &Value) {
    let Some(domains) = configuration.get("searchDomains").and_then(Value::as_array) else {
        return;
    };
    let domains = domains
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
    if !domains.is_empty() {
        print_status_values("DNS Domain", status_label_width(configuration), &domains);
    }
}

fn statistics(socket: &Path, json: Option<&str>, ask_password: bool) -> Result<(), Box<dyn Error>> {
    let reply = monitor_dump_call(
        socket,
        "io.rustd.Resolve.Monitor.DumpStatistics",
        ask_password,
    )?;
    let parameters = reply_parameters(&reply)?;
    if json_enabled(json) {
        println!("{}", json_output(parameters, json));
        return Ok(());
    }
    print_statistic_section(
        parameters,
        "transactions",
        "Transactions",
        &[
            ("Current Transactions", "currentTransactions"),
            ("Total Transactions", "totalTransactions"),
        ],
        true,
    );
    print_statistic_section(
        parameters,
        "cache",
        "Cache",
        &[
            ("Current Cache Size", "size"),
            ("Cache Hits", "hits"),
            ("Cache Misses", "misses"),
        ],
        true,
    );
    print_statistic_section(
        parameters,
        "transactions",
        "Failure Transactions",
        &[
            ("Total Timeouts", "totalTimeouts"),
            (
                "Total Timeouts (Stale Data Served)",
                "totalTimeoutsServedStale",
            ),
            ("Total Failure Responses", "totalFailedResponses"),
            (
                "Total Failure Responses (Stale Data Served)",
                "totalFailedResponsesServedStale",
            ),
        ],
        true,
    );
    print_statistic_section(
        parameters,
        "dnssec",
        "DNSSEC Verdicts",
        &[
            ("Secure", "secure"),
            ("Insecure", "insecure"),
            ("Bogus", "bogus"),
            ("Indeterminate", "indeterminate"),
        ],
        false,
    );
    Ok(())
}

fn print_statistic_section(
    parameters: &Value,
    field: &str,
    title: &str,
    entries: &[(&str, &str)],
    separator: bool,
) {
    let Some(text) = statistic_section_text(parameters, field, title, entries) else {
        return;
    };
    println!("{text}");
    if separator {
        println!("{:45}", "");
    }
}

fn statistic_section_text(
    parameters: &Value,
    field: &str,
    title: &str,
    entries: &[(&str, &str)],
) -> Option<String> {
    let section = parameters.get(field)?;
    let mut lines = vec![format!("{title:<45}")];
    for (label, key) in entries {
        if let Some(value) = section.get(key).and_then(Value::as_u64) {
            lines.push(format!("{label:>43}: {value:>5}"));
        }
    }
    Some(lines.join("\n"))
}

fn show_cache(socket: &Path, json: Option<&str>, ask_password: bool) -> Result<(), Box<dyn Error>> {
    let reply = monitor_dump_call(socket, "io.rustd.Resolve.Monitor.DumpCache", ask_password)?;
    let scopes = reply_parameters(&reply)?
        .get("dump")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_data("cache dump is missing its scope array"))?;

    if json_enabled(json) {
        println!("{}", cache_json(scopes, json));
        return Ok(());
    }

    for scope in scopes {
        print_cache_scope(scope)?;
    }
    Ok(())
}

fn cache_json(scopes: &[Value], json: Option<&str>) -> String {
    json_output(&Value::Array(scopes.to_vec()), json)
}

fn print_cache_scope(scope: &Value) -> Result<(), Box<dyn Error>> {
    println!("{}", cache_scope_header(scope));

    let cache = scope
        .get("cache")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_data("cache scope is missing its entries"))?;
    let mut records = 0;
    for entry in cache {
        let key = entry
            .get("key")
            .ok_or_else(|| invalid_data("cache entry is missing its resource key"))?;
        let name = key.get("name").and_then(Value::as_str).unwrap_or("?");
        let class = key.get("class").and_then(Value::as_u64).unwrap_or(1);
        let rr_type = key.get("type").and_then(Value::as_u64).unwrap_or(0);
        let key_text = format!("{name} {} {}", class_name(class), record_type_name(rr_type));
        if let Some(kind) = entry.get("type").and_then(Value::as_str) {
            println!("{key_text} {kind}");
            continue;
        }
        for resource_record in entry
            .get("rrs")
            .and_then(Value::as_array)
            .unwrap_or_default()
        {
            let raw = resource_record
                .get("raw")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid_data("cache resource record is missing raw data"))?;
            let raw = resolvectl_rr::decode_base64(raw)?;
            let record = resolvectl_rr::parse_canonical_record(&raw)?;
            println!("{}", format_record_text(&record, None)?);
            records += 1;
        }
    }
    if records == 0 {
        println!("No entries.");
    }
    println!();
    Ok(())
}

fn cache_scope_header(scope: &Value) -> String {
    let protocol = scope
        .get("protocol")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let mut header = format!("Scope protocol={protocol}");
    if let Some(family) = scope.get("family").and_then(Value::as_i64) {
        header.push_str(" family=");
        header.push_str(address_family_name(family));
    }
    if let Some(index) = scope.get("ifindex").and_then(Value::as_i64) {
        if index > 0 {
            header.push_str(" ifindex=");
            header.push_str(&index.to_string());
        }
    }
    if let Some(name) = scope.get("ifname").and_then(Value::as_str) {
        header.push_str(" ifname=");
        header.push_str(name);
    }
    if protocol == "dns" {
        if let Some(mode) = scope.get("dnssec").and_then(Value::as_str) {
            header.push_str(" DNSSEC=");
            header.push_str(mode);
        }
        if let Some(mode) = scope.get("dnsOverTLS").and_then(Value::as_str) {
            header.push_str(" DNSOverTLS=");
            header.push_str(mode);
        }
    }
    header
}

fn address_family_name(family: i64) -> &'static str {
    match family {
        2 => "AF_INET",
        10 => "AF_INET6",
        _ => "AF_UNSPEC",
    }
}

fn class_name(class: u64) -> String {
    match class {
        1 => "IN".to_owned(),
        255 => "ANY".to_owned(),
        other => format!("CLASS{other}"),
    }
}

fn record_type_name(rr_type: u64) -> String {
    u16::try_from(rr_type)
        .ok()
        .and_then(rustd_resolved::config::dns_record_type_name)
        .map_or_else(|| format!("TYPE{rr_type}"), str::to_owned)
}

fn show_server_state(
    socket: &Path,
    json: Option<&str>,
    ask_password: bool,
) -> Result<(), Box<dyn Error>> {
    let reply = monitor_dump_call(
        socket,
        "io.rustd.Resolve.Monitor.DumpServerState",
        ask_password,
    )?;
    let servers = reply_parameters(&reply)?
        .get("dump")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_data("server-state dump is missing its array"))?;
    if json_enabled(json) {
        println!("{}", json_output(&Value::Array(servers.to_vec()), json));
        return Ok(());
    }
    if servers.is_empty() {
        println!("No DNS servers are configured.");
        return Ok(());
    }

    for (index, server) in servers.iter().enumerate() {
        if index != 0 {
            println!();
        }
        print_server_state(server)?;
    }
    Ok(())
}

fn json_enabled(mode: Option<&str>) -> bool {
    !matches!(mode, None | Some("off"))
}

fn json_output(value: &Value, mode: Option<&str>) -> String {
    if mode == Some("pretty") {
        value.to_json_pretty()
    } else {
        value.to_json()
    }
}

fn print_server_state(server: &Value) -> Result<(), io::Error> {
    for line in server_state_lines(server)? {
        println!("{line}");
    }
    Ok(())
}

fn server_state_lines(server: &Value) -> Result<Vec<String>, io::Error> {
    let name = required_server_state_string(server, "Server")?;
    let kind = required_server_state_string(server, "Type")?;
    let mut lines = vec![format!("Server: {name}"), format!("  Type: {kind}")];
    if let Some(value) = optional_server_state_string(server, "Interface")? {
        lines.push(format!("  Interface: {value}"));
    }
    if let Some(value) = optional_server_state_ifindex(server)? {
        lines.push(format!("  Interface Index: {value}"));
    }
    for (label, field) in [
        ("Verified feature level", "VerifiedFeatureLevel"),
        ("Possible feature level", "PossibleFeatureLevel"),
    ] {
        if let Some(value) = optional_server_state_string(server, field)? {
            lines.push(format!("  {label}: {value}"));
        }
    }
    lines.extend([
        format!(
            "  DNSSEC Mode: {}",
            required_server_state_string(server, "DNSSECMode")?
        ),
        format!(
            "  DNSSEC Supported: {}",
            yes_no(required_server_state_bool(server, "DNSSECSupported")?)
        ),
        format!(
            "  Maximum UDP fragment size received: {}",
            required_server_state_u64(server, "ReceivedUDPFragmentMax")?
        ),
        format!(
            "  Failed UDP attempts: {}",
            required_server_state_u64(server, "FailedUDPAttempts")?
        ),
        format!(
            "  Failed TCP attempts: {}",
            required_server_state_u64(server, "FailedTCPAttempts")?
        ),
        format!(
            "  Seen truncated packet: {}",
            yes_no(required_server_state_bool(server, "PacketTruncated")?)
        ),
        format!(
            "  Seen OPT RR getting lost: {}",
            yes_no(required_server_state_bool(server, "PacketBadOpt")?)
        ),
        format!(
            "  Seen RRSIG RR missing: {}",
            yes_no(required_server_state_bool(server, "PacketRRSIGMissing")?)
        ),
        format!(
            "  Seen invalid packet: {}",
            yes_no(required_server_state_bool(server, "PacketInvalid")?)
        ),
        format!(
            "  Server dropped DO flag: {}",
            yes_no(required_server_state_bool(server, "PacketDoOff")?)
        ),
    ]);
    Ok(lines)
}

fn required_server_state_string<'a>(
    server: &'a Value,
    field: &'static str,
) -> Result<&'a str, io::Error> {
    server
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_server_state_field(field, "a string"))
}

fn optional_server_state_string<'a>(
    server: &'a Value,
    field: &'static str,
) -> Result<Option<&'a str>, io::Error> {
    match server.get(field) {
        None => Ok(None),
        Some(value) => value
            .as_str()
            .map(Some)
            .ok_or_else(|| invalid_server_state_field(field, "a string")),
    }
}

fn optional_server_state_ifindex(server: &Value) -> Result<Option<i64>, io::Error> {
    match server.get("InterfaceIndex") {
        None => Ok(None),
        Some(value) => value
            .as_i64()
            .filter(|index| *index >= 0)
            .map(Some)
            .ok_or_else(|| invalid_server_state_field("InterfaceIndex", "a non-negative integer")),
    }
}

fn required_server_state_bool(server: &Value, field: &'static str) -> Result<bool, io::Error> {
    server
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| invalid_server_state_field(field, "a boolean"))
}

fn required_server_state_u64(server: &Value, field: &'static str) -> Result<u64, io::Error> {
    server
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid_server_state_field(field, "a non-negative integer"))
}

fn invalid_server_state_field(field: &str, expected: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("server-state entry field '{field}' is missing or is not {expected}"),
    )
}

const fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn control(socket: &Path, method: &str, ask_password: bool) -> Result<(), Box<dyn Error>> {
    let reply = call(socket, method, interactive_parameters(ask_password))?;
    let _ = reply_parameters(&reply)?;
    Ok(())
}

fn interactive_parameters(ask_password: bool) -> Value {
    Value::object([("allowInteractiveAuthentication", Value::Bool(ask_password))])
}

fn monitor_dump_call(
    socket: &Path,
    method: &str,
    ask_password: bool,
) -> Result<Value, Box<dyn Error>> {
    let reply = call(socket, method, interactive_parameters(ask_password))?;
    if let Some(error) = monitor_dump_error(method, &reply) {
        return Err(Box::new(error));
    }
    Ok(reply)
}

fn monitor_dump_error(method: &str, reply: &Value) -> Option<CliError> {
    (reply.get("error").and_then(Value::as_str) == Some("org.varlink.service.PermissionDenied"))
        .then(|| {
            CliError(format!(
                "Failed to issue {method}() varlink call: Permission denied"
            ))
        })
}

fn call(socket: &Path, method: &str, parameters: Value) -> Result<Value, Box<dyn Error>> {
    let request = Value::object([
        ("method", Value::String(method.to_owned())),
        ("parameters", parameters),
    ]);
    let mut stream = UnixStream::connect(socket)?;
    stream.write_all(request.to_json().as_bytes())?;
    stream.write_all(&[0])?;

    let mut reply = Vec::new();
    let mut chunk = [0; 8192];
    loop {
        let length = stream.read(&mut chunk)?;
        if length == 0 {
            return Err("Varlink connection closed before a complete reply".into());
        }
        if let Some(position) = chunk[..length].iter().position(|byte| *byte == 0) {
            reply.extend_from_slice(&chunk[..position]);
            break;
        }
        reply.extend_from_slice(&chunk[..length]);
        if reply.len() > MAX_REPLY_SIZE {
            return Err("Varlink reply exceeds the configured limit".into());
        }
    }
    let text = std::str::from_utf8(&reply)?;
    Ok(json::parse(text)?)
}

fn reply_parameters(reply: &Value) -> Result<&Value, Box<dyn Error>> {
    reply_parameters_inner(reply, None)
}

fn reply_parameters_for_query<'a>(
    reply: &'a Value,
    query: &str,
) -> Result<&'a Value, Box<dyn Error>> {
    reply_parameters_inner(reply, Some(query))
}

fn reply_parameters_inner<'a>(
    reply: &'a Value,
    query: Option<&str>,
) -> Result<&'a Value, Box<dyn Error>> {
    if let Some(identifier) = reply.get("error").and_then(Value::as_str) {
        if identifier == "io.rustd.Resolve.QueryRefused" {
            return Err("DNS query type refused.".into());
        }
        if identifier == "io.rustd.Resolve.NoNameServers" {
            return Err("No appropriate name servers or networks for name found".into());
        }
        if identifier == "io.rustd.Resolve.MaxAttemptsReached" {
            return Err("All attempts to contact name servers or networks failed".into());
        }
        if identifier == "io.rustd.Resolve.DNSError" {
            if let Some(message) = dns_error_message(reply.get("parameters"), query) {
                return Err(message.into());
            }
        }
        if identifier == "io.rustd.Resolve.NoSuchResourceRecord" {
            return Err(query
                .map_or_else(
                    || "Name does not have any RR of the requested type".to_owned(),
                    |query| format!("Name '{query}' does not have any RR of the requested type"),
                )
                .into());
        }
        if identifier == "io.rustd.Resolve.DNSSECValidationFailed" {
            if let Some(message) = dnssec_error_message(reply.get("parameters")) {
                return Err(message.into());
            }
        }
        let detail = reply
            .get("parameters")
            .map(Value::to_json)
            .unwrap_or_default();
        if detail == "{}" || detail.is_empty() {
            return Err(identifier.to_owned().into());
        }
        return Err(format!("{identifier}: {detail}").into());
    }
    reply
        .get("parameters")
        .ok_or_else(|| "Varlink reply has no parameters".into())
}

fn dns_error_message(parameters: Option<&Value>, query: Option<&str>) -> Option<String> {
    let parameters = parameters?;
    let rcode = parameters.get("rcode").and_then(Value::as_u64)?;
    let query = query.or_else(|| parameters.get("queryString").and_then(Value::as_str));
    if rcode == 3 {
        if let Some(query) = query {
            return Some(format!("Name '{query}' not found"));
        }
    }
    let rcode_name = match rcode {
        0 => "SUCCESS",
        1 => "FORMERR",
        2 => "SERVFAIL",
        4 => "NOTIMP",
        5 => "REFUSED",
        6 => "YXDOMAIN",
        7 => "YXRRSET",
        8 => "NXRRSET",
        9 => "NOTAUTH",
        10 => "NOTZONE",
        16 => "BADVERS",
        _ => {
            return Some(query.map_or_else(
                || format!("DNS query failed: DNS error {rcode}"),
                |query| format!("Could not resolve '{query}', DNS error {rcode}"),
            ));
        }
    };
    let suffix = extended_dns_error(parameters)
        .map(|error| format!(" ({error})"))
        .unwrap_or_default();
    if rcode == 5 && suffix.is_empty() {
        return Some("DNS query type refused.".to_owned());
    }
    Some(query.map_or_else(
        || format!("DNS query failed: {rcode_name}{suffix}"),
        |query| {
            format!(
                "Could not resolve '{query}', server or network returned error: {rcode_name}{suffix}"
            )
        },
    ))
}

fn dnssec_error_message(parameters: Option<&Value>) -> Option<String> {
    let parameters = parameters?;
    let result = parameters.get("result").and_then(Value::as_str)?;
    let suffix = extended_dns_error(parameters)
        .map(|error| format!(" ({error})"))
        .unwrap_or_default();
    Some(format!("DNSSEC validation failed: {result}{suffix}"))
}

fn extended_dns_error(parameters: &Value) -> Option<String> {
    let code = parameters
        .get("extendedDNSErrorCode")
        .and_then(Value::as_u64)
        .and_then(|value| u16::try_from(value).ok())?;
    let message = parameters
        .get("extendedDNSErrorMessage")
        .and_then(Value::as_str);
    Some(rustd_resolved::edns::format_extended_error(code, message))
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn print_help() {
    print!(
        "{}",
        r"> resolvectl [OPTIONS…] COMMAND …

Send control commands to the network name resolution manager, or
resolve domain names, IPv4 and IPv6 addresses, DNS records, and services.

Commands:
  query                        Resolve domain names, IPv4 and IPv6 addresses
    HOSTNAME|ADDRESS…\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
  service [[NAME] TYPE]        Resolve service (SRV)
    DOMAIN\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
  openpgp EMAIL@DOMAIN…        Query OpenPGP public key
  tlsa DOMAIN[:PORT]…          Query TLS public key
  [status [LINK…]]             Show link and server status
  statistics                   Show resolver statistics
  reset-statistics             Reset resolver statistics
  flush-caches                 Flush all local DNS caches
  reset-server-features        Forget learnt DNS server feature levels
  monitor                      Monitor DNS queries
  show-cache                   Show cache contents
  show-server-state            Show servers state
  dns [LINK [SERVER…]]         Get/set per-interface DNS server address
  domain [LINK                 Get/set per-interface search domain
    [DOMAIN…]]\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
  default-route [LINK          Get/set per-interface default route flag
    [BOOL]]\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
  llmnr [LINK [MODE]]          Get/set per-interface LLMNR mode
  mdns [LINK [MODE]]           Get/set per-interface MulticastDNS mode
  dnsovertls [LINK             Get/set per-interface DNS-over-TLS mode
    [MODE]]\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
  dnssec [LINK [MODE]]         Get/set per-interface DNSSEC mode
  nta [LINK [DOMAIN…]]         Get/set per-interface DNSSEC NTA
  revert LINK                  Revert per-interface configuration
  log-level [LEVEL]            Get/set logging threshold for systemd-resolved

Options:
  -h --help                    Show this help
     --version                 Show package version
  -4                           Resolve IPv4 addresses
  -6                           Resolve IPv6 addresses
  -i --interface=INTERFACE     Look on interface
  -p --protocol=PROTO|help     Look via protocol
  -t --type=TYPE|help          Query RR with DNS type
  -c --class=CLASS|help        Query RR with DNS class
     --service-address=BOOL    Resolve address for services (default: yes)
     --service-txt=BOOL        Resolve TXT records for services (default: yes)
     --cname=BOOL              Follow CNAME redirects (default: yes)
     --validate=BOOL           Allow DNSSEC validation (default: yes)
     --synthesize=BOOL         Allow synthetic response (default: yes)
     --cache=BOOL              Allow response from cache (default: yes)
     --stale-data=BOOL         Allow response from cache with stale data
                               (default: yes)
     --relax-single-label=BOOL Allow single label lookups to go upstream
                               (default: no)
     --zone=BOOL               Allow response from locally registered mDNS/LLMNR
                               records (default: yes)
     --trust-anchor=BOOL       Allow response from local trust anchor (default:
                               yes)
     --network=BOOL            Allow response from network (default: yes)
     --search=BOOL             Use search domains for single-label names
                               (default: yes)
     --raw[=payload|packet]    Dump the answer as binary data
     --no-pager                Do not start a pager
     --no-ask-password         Do not prompt for password
     --legend=BOOL             Print headers and additional info (default: yes)
     --json=FORMAT             Generate JSON output (pretty, short, or off)
  -j                           Equivalent to --json=pretty (on TTY) or
                               --json=short (otherwise)

See the resolvectl(1) man page for details.
"
        .replace(r"\x20", " ")
    );
}

fn print_resolvconf_help() {
    println!(
        "resolvconf -a INTERFACE <FILE\n\
         resolvconf -d INTERFACE\n\
         \n\
         Register DNS server and domain configuration with systemd-resolved.\n\
         \n\
         Options:\n\
           -h --help     Show this help\n\
              --version  Show package version\n\
           -a            Register per-interface DNS configuration\n\
           -d            Unregister per-interface DNS configuration\n\
           -p            Do not use this interface as default route\n\
           -f            Ignore a missing interface\n\
           -x            Prefer DNS traffic over this interface\n\
           -m ARG        Ignore an openresolv metric\n\
           -u            Exit successfully without an update"
    );
}

fn print_systemd_resolve_help() {
    println!(
        "systemd-resolve [OPTIONS...] HOSTNAME|ADDRESS...\n\
         systemd-resolve [OPTIONS...] --service [[NAME] TYPE] DOMAIN\n\
         systemd-resolve [OPTIONS...] --openpgp EMAIL@DOMAIN...\n\
         systemd-resolve [OPTIONS...] --statistics\n\
         systemd-resolve [OPTIONS...] --reset-statistics\n\
         \n\
         Resolve domain names, IPv4 and IPv6 addresses, DNS records, and services.\n\
         \n\
         Options:\n\
           -h --help                  Show this help\n\
              --version               Show package version\n\
           -4                         Resolve IPv4 addresses\n\
           -6                         Resolve IPv6 addresses\n\
           -i --interface=INTERFACE   Look on interface\n\
           -p --protocol=PROTO|help   Look via protocol\n\
           -t --type=TYPE|help        Query RR with DNS type\n\
           -c --class=CLASS|help      Query RR with DNS class\n\
              --service               Resolve service records\n\
              --service-address=BOOL  Resolve addresses for services\n\
              --service-txt=BOOL      Resolve TXT records for services\n\
              --openpgp               Query OpenPGP public keys\n\
              --tlsa[=FAMILY]         Query TLS public keys\n\
              --cname=BOOL            Follow CNAME redirects\n\
              --search=BOOL           Use search domains\n\
              --statistics            Show resolver statistics\n\
              --reset-statistics      Reset resolver statistics\n\
              --status                Show link and server status\n\
              --flush-caches          Flush all local DNS caches\n\
              --reset-server-features Forget learnt DNS server features\n\
              --set-dns=SERVER        Set a per-interface DNS server\n\
              --set-domain=DOMAIN     Set a per-interface search domain\n\
              --set-llmnr=MODE        Set per-interface LLMNR mode\n\
              --set-mdns=MODE         Set per-interface MulticastDNS mode\n\
              --set-dnsovertls=MODE   Set per-interface DNS-over-TLS mode\n\
              --set-dnssec=MODE       Set per-interface DNSSEC mode\n\
              --set-nta=DOMAIN        Set a per-interface DNSSEC NTA\n\
              --revert                Revert per-interface configuration\n\
              --raw[=payload|packet]  Dump the answer as binary data\n\
              --no-pager              Do not pipe output into a pager\n\
              --legend=BOOL           Print additional information"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invocation_detection_matches_pinned_multicall_contract() {
        assert_eq!(
            invocation_mode(OsStr::new("/usr/bin/resolvectl"), None),
            InvocationMode::Native
        );
        assert_eq!(
            invocation_mode(OsStr::new("/usr/sbin/resolvconf"), None),
            InvocationMode::Resolvconf
        );
        assert_eq!(
            invocation_mode(OsStr::new("/usr/bin/systemd-resolve"), None),
            InvocationMode::SystemdResolve
        );
        assert_eq!(
            invocation_mode(
                OsStr::new("/usr/bin/resolvectl"),
                Some(OsStr::new("systemd-resolve"))
            ),
            InvocationMode::SystemdResolve
        );
    }

    #[test]
    fn systemd_resolve_queries_translate_to_the_native_verb() {
        let plans = translate_systemd_resolve(vec![
            "-4".to_owned(),
            "-ilo".to_owned(),
            "--type=A".to_owned(),
            "example.test".to_owned(),
        ])
        .unwrap();
        assert_eq!(
            plans,
            [vec![
                "-4",
                "--interface=lo",
                "--type=A",
                "query",
                "example.test"
            ]]
        );

        let mut interface = 0;
        merge_ifindex(&mut interface, 7).unwrap();
        merge_ifindex(&mut interface, 7).unwrap();
        assert!(merge_ifindex(&mut interface, 8).is_err());
    }

    #[test]
    fn systemd_resolve_modes_and_link_setters_translate_exactly() {
        assert_eq!(
            translate_systemd_resolve(vec!["--tlsa=udp".to_owned(), "example.test:853".to_owned()])
                .unwrap(),
            [vec!["tlsa", "udp", "example.test:853"]]
        );
        assert_eq!(
            translate_systemd_resolve(vec![
                "--interface=lo".to_owned(),
                "--set-mdns=yes".to_owned(),
                "--set-dns=192.0.2.53".to_owned(),
                "--set-domain=example.test".to_owned(),
                "--set-dns=192.0.2.54".to_owned(),
            ])
            .unwrap(),
            [
                vec!["dns", "lo", "192.0.2.53", "192.0.2.54"],
                vec!["domain", "lo", "example.test"],
                vec!["mdns", "lo", "yes"],
            ]
        );
        assert!(translate_systemd_resolve(vec!["--revert".to_owned()]).is_err());
        assert!(translate_systemd_resolve(vec![
            "--service".to_owned(),
            "--type=SRV".to_owned(),
            "example.test".to_owned(),
        ])
        .is_err());
        assert!(
            translate_systemd_resolve(vec!["--class=IN".to_owned(), "--status".to_owned()])
                .is_err()
        );
        assert!(translate_systemd_resolve(vec![
            "--service-txt=maybe".to_owned(),
            "--interface=lo".to_owned(),
            "--set-mdns=yes".to_owned(),
        ])
        .is_err());
        assert_eq!(
            translate_systemd_resolve(vec!["--protocol=help".to_owned()]).unwrap(),
            [vec!["--protocol=help"]]
        );
    }

    #[test]
    fn verb_arity_matches_pinned_v261_table() {
        for command in [
            "statistics",
            "reset-statistics",
            "flush-caches",
            "reset-server-features",
            "monitor",
            "show-cache",
            "show-server-state",
        ] {
            assert!(validate_command_arity(command, 0).is_ok());
            assert!(validate_command_arity(command, 1).is_err());
        }
        assert!(validate_command_arity("service", 0).is_err());
        assert!(validate_command_arity("service", 1).is_ok());
        assert!(validate_command_arity("service", 3).is_ok());
        assert!(validate_command_arity("service", 4).is_err());
        assert!(validate_command_arity("revert", 0).is_err());
        assert!(validate_command_arity("revert", 1).is_ok());
        assert!(validate_command_arity("revert", 2).is_err());
        assert!(validate_command_arity("dnssec", 2).is_ok());
        assert!(validate_command_arity("dnssec", 3).is_err());
        assert!(validate_command_arity("log-level", 1).is_ok());
        assert!(validate_command_arity("log-level", 2).is_err());
        assert!(validate_command_arity("status", 20).is_ok());
    }

    #[test]
    fn status_json_selects_named_and_numeric_links() {
        let parameters = Value::object([(
            "configuration",
            Value::Array(vec![
                Value::object([("servers", Value::Array(Vec::new()))]),
                Value::object([
                    ("ifname", Value::String("dns0".to_owned())),
                    ("ifindex", Value::Number(6)),
                ]),
                Value::object([
                    ("ifname", Value::String("lo".to_owned())),
                    ("ifindex", Value::Number(1)),
                ]),
                Value::object([("delegate", Value::String("vpn".to_owned()))]),
            ]),
        )]);

        let all = select_status_configurations(&parameters, &[]).unwrap();
        assert_eq!(all.len(), 3);
        assert!(all
            .iter()
            .all(|configuration| configuration.get("ifindex").and_then(Value::as_i64) != Some(1)));

        let named = select_status_configurations(&parameters, &["dns0".to_owned()]).unwrap();
        assert_eq!(named.len(), 1);
        assert_eq!(named[0].get("ifindex").and_then(Value::as_i64), Some(6));

        let numeric = select_status_configurations(&parameters, &["6".to_owned()]).unwrap();
        assert_eq!(numeric, named);
        assert!(select_status_configurations(&parameters, &["missing".to_owned()]).is_err());
    }

    #[test]
    fn configuration_field_retains_only_identity_and_requested_value() {
        let configuration = Value::object([
            ("ifname", Value::String("dns0".to_owned())),
            ("ifindex", Value::Number(6)),
            ("servers", Value::Array(Vec::new())),
            ("dnssec", Value::String("no".to_owned())),
        ]);
        assert_eq!(
            configuration_field(&configuration, "servers").to_json(),
            r#"{"ifname":"dns0","ifindex":6,"servers":[]}"#
        );
        assert_eq!(
            configuration_field(&Value::Object(JsonObject::new()), "servers").to_json(),
            r#"{"servers":null}"#
        );
    }

    #[derive(Clone, Copy)]
    struct ConfigurationFixture {
        ifname: Option<(&'static str, i128)>,
        delegate: Option<&'static str>,
        address: &'static str,
        domain: &'static str,
        route_only: bool,
        default_route: Option<bool>,
        llmnr: &'static str,
        mdns: &'static str,
        dns_over_tls: &'static str,
        dnssec: &'static str,
        nta: &'static str,
    }

    fn configuration_fixture_value(fixture: ConfigurationFixture) -> Value {
        let mut fields = JsonObject::new();
        if let Some((ifname, ifindex)) = fixture.ifname {
            fields.insert("ifname".to_owned(), Value::String(ifname.to_owned()));
            fields.insert("ifindex".to_owned(), Value::Number(ifindex));
        }
        if let Some(delegate) = fixture.delegate {
            fields.insert("delegate".to_owned(), Value::String(delegate.to_owned()));
        }
        fields.insert(
            "servers".to_owned(),
            Value::Array(vec![Value::object([(
                "addressString",
                Value::String(fixture.address.to_owned()),
            )])]),
        );
        fields.insert(
            "searchDomains".to_owned(),
            Value::Array(vec![Value::object([
                ("name", Value::String(fixture.domain.to_owned())),
                ("routeOnly", Value::Bool(fixture.route_only)),
            ])]),
        );
        if let Some(default_route) = fixture.default_route {
            fields.insert("defaultRoute".to_owned(), Value::Bool(default_route));
        }
        fields.insert("llmnr".to_owned(), Value::String(fixture.llmnr.to_owned()));
        fields.insert("mDNS".to_owned(), Value::String(fixture.mdns.to_owned()));
        fields.insert(
            "dnsOverTLS".to_owned(),
            Value::String(fixture.dns_over_tls.to_owned()),
        );
        fields.insert(
            "dnssec".to_owned(),
            Value::String(fixture.dnssec.to_owned()),
        );
        fields.insert(
            "negativeTrustAnchors".to_owned(),
            Value::Array(vec![Value::String(fixture.nta.to_owned())]),
        );
        Value::Object(fields)
    }

    fn zero_argument_configuration_fixture() -> Value {
        let fixtures = [
            ConfigurationFixture {
                ifname: None,
                delegate: None,
                address: "192.0.2.53",
                domain: "global.test",
                route_only: false,
                default_route: None,
                llmnr: "yes",
                mdns: "yes",
                dns_over_tls: "opportunistic",
                dnssec: "allow-downgrade",
                nta: "global.test",
            },
            ConfigurationFixture {
                ifname: Some(("lo", 1)),
                delegate: None,
                address: "127.0.0.1",
                domain: "loopback.test",
                route_only: false,
                default_route: Some(true),
                llmnr: "no",
                mdns: "no",
                dns_over_tls: "no",
                dnssec: "no",
                nta: "loopback.test",
            },
            ConfigurationFixture {
                ifname: Some(("ethernet", 2)),
                delegate: None,
                address: "192.0.2.54",
                domain: "ethernet.test",
                route_only: true,
                default_route: Some(false),
                llmnr: "resolve",
                mdns: "no",
                dns_over_tls: "yes",
                dnssec: "yes",
                nta: "ethernet.test",
            },
            ConfigurationFixture {
                ifname: Some(("wifi", 3)),
                delegate: None,
                address: "192.0.2.55",
                domain: "wifi.test",
                route_only: false,
                default_route: Some(true),
                llmnr: "no",
                mdns: "resolve",
                dns_over_tls: "no",
                dnssec: "no",
                nta: "wifi.test",
            },
            ConfigurationFixture {
                ifname: None,
                delegate: Some("tunnel"),
                address: "192.0.2.56",
                domain: "tunnel.test",
                route_only: false,
                default_route: None,
                llmnr: "yes",
                mdns: "yes",
                dns_over_tls: "yes",
                dnssec: "yes",
                nta: "tunnel.test",
            },
        ];
        Value::object([(
            "configuration",
            Value::Array(
                fixtures
                    .into_iter()
                    .map(configuration_fixture_value)
                    .collect(),
            ),
        )])
    }

    #[test]
    fn zero_argument_configuration_queries_include_global_and_non_loopback_links() {
        let parameters = zero_argument_configuration_fixture();
        for field in [
            "servers",
            "searchDomains",
            "defaultRoute",
            "llmnr",
            "mDNS",
            "dnsOverTLS",
            "dnssec",
            "negativeTrustAnchors",
        ] {
            let output = configuration_field_output(&parameters, field).unwrap();
            assert_eq!(output.len(), 4);
            assert_eq!(output[1].get("ifindex").and_then(Value::as_i64), Some(2));
            assert_eq!(output[2].get("ifindex").and_then(Value::as_i64), Some(3));
            assert_eq!(
                output[3].get("delegate").and_then(Value::as_str),
                Some("tunnel")
            );
            assert!(output
                .iter()
                .all(|entry| entry.get("ifindex").and_then(Value::as_i64) != Some(1)));
            assert!(output.iter().all(|entry| entry.get(field).is_some()));
        }
    }

    #[test]
    fn zero_argument_configuration_text_matches_v261_fixture() {
        let parameters = zero_argument_configuration_fixture();
        let expected = [
            ("dns", "servers", "Global: 192.0.2.53\nLink 2 (ethernet): 192.0.2.54\nLink 3 (wifi): 192.0.2.55\nDelegate tunnel: 192.0.2.56\n"),
            ("domain", "searchDomains", "Global: global.test\nLink 2 (ethernet): ~ethernet.test\nLink 3 (wifi): wifi.test\nDelegate tunnel: tunnel.test\n"),
            ("default-route", "defaultRoute", "Link 2 (ethernet): no\nLink 3 (wifi): yes\nDelegate tunnel: no\n"),
            ("llmnr", "llmnr", "Global: yes\nLink 2 (ethernet): resolve\nLink 3 (wifi): no\n"),
            ("mdns", "mDNS", "Global: yes\nLink 2 (ethernet): no\nLink 3 (wifi): resolve\n"),
            ("dnsovertls", "dnsOverTLS", "Global: opportunistic\nLink 2 (ethernet): yes\nLink 3 (wifi): no\n"),
            ("dnssec", "dnssec", "Global: allow-downgrade\nLink 2 (ethernet): yes\nLink 3 (wifi): no\n"),
            ("nta", "negativeTrustAnchors", "Global: global.test\nLink 2 (ethernet): ethernet.test\nLink 3 (wifi): wifi.test\n"),
        ];
        for (command, field, text) in expected {
            let output = configuration_field_output(&parameters, field).unwrap();
            assert_eq!(
                format_configuration_field_output(command, field, &output).unwrap(),
                text
            );
        }
    }

    #[test]
    fn formats_query_text_lines_like_stock_resolvectl() {
        assert_eq!(
            query_text_line("localhost", "127.0.0.1", Some("lo"), true),
            "localhost: 127.0.0.1                                        -- link: lo"
        );
        assert_eq!(
            query_text_line("localhost", "::1", Some("lo"), false),
            "           ::1                                              -- link: lo"
        );
        assert_eq!(
            query_text_line("::1", "ip6-localhost", None, false),
            "     ip6-localhost"
        );
    }

    #[test]
    fn monitor_permission_errors_match_stock_resolvectl() {
        let denied = Value::object([(
            "error",
            Value::String("org.varlink.service.PermissionDenied".to_owned()),
        )]);
        for method in [
            "io.rustd.Resolve.Monitor.DumpCache",
            "io.rustd.Resolve.Monitor.DumpStatistics",
            "io.rustd.Resolve.Monitor.DumpServerState",
        ] {
            assert_eq!(
                monitor_dump_error(method, &denied)
                    .expect("a denied monitor dump must be formatted")
                    .to_string(),
                format!("Failed to issue {method}() varlink call: Permission denied")
            );
        }
        assert_eq!(
            monitor_varlink_error(&denied)
                .expect("a monitor error must be formatted")
                .to_string(),
            "Varlink error: org.varlink.service.PermissionDenied"
        );
        assert!(monitor_dump_error(
            "io.rustd.Resolve.Monitor.DumpCache",
            &Value::Object(JsonObject::new()),
        )
        .is_none());
    }

    #[test]
    fn formats_server_state_like_stock_resolvectl() {
        let state = Value::object([
            ("Server", Value::String("192.0.2.53".to_owned())),
            ("Type", Value::String("link".to_owned())),
            ("Interface", Value::String("dns0".to_owned())),
            ("InterfaceIndex", Value::Number(6)),
            (
                "VerifiedFeatureLevel",
                Value::String("UDP+EDNS0".to_owned()),
            ),
            ("DNSSECMode", Value::String("allow-downgrade".to_owned())),
            ("DNSSECSupported", Value::Bool(true)),
            ("ReceivedUDPFragmentMax", Value::Number(1232)),
            ("FailedUDPAttempts", Value::Number(2)),
            ("FailedTCPAttempts", Value::Number(1)),
            ("PacketTruncated", Value::Bool(true)),
            ("PacketBadOpt", Value::Bool(false)),
            ("PacketRRSIGMissing", Value::Bool(false)),
            ("PacketInvalid", Value::Bool(false)),
            ("PacketDoOff", Value::Bool(false)),
        ]);
        assert_eq!(
            server_state_lines(&state).unwrap(),
            vec![
                "Server: 192.0.2.53",
                "  Type: link",
                "  Interface: dns0",
                "  Interface Index: 6",
                "  Verified feature level: UDP+EDNS0",
                "  DNSSEC Mode: allow-downgrade",
                "  DNSSEC Supported: yes",
                "  Maximum UDP fragment size received: 1232",
                "  Failed UDP attempts: 2",
                "  Failed TCP attempts: 1",
                "  Seen truncated packet: yes",
                "  Seen OPT RR getting lost: no",
                "  Seen RRSIG RR missing: no",
                "  Seen invalid packet: no",
                "  Server dropped DO flag: no",
            ]
        );
    }

    #[test]
    fn server_state_rejects_missing_or_ill_typed_mandatory_fields() {
        let missing_dnssec_support = Value::object([
            ("Server", Value::String("192.0.2.53".to_owned())),
            ("Type", Value::String("link".to_owned())),
            ("DNSSECMode", Value::String("allow-downgrade".to_owned())),
        ]);
        assert_eq!(
            server_state_lines(&missing_dnssec_support)
                .expect_err("v261 rejects incomplete server-state replies")
                .to_string(),
            "server-state entry field 'DNSSECSupported' is missing or is not a boolean"
        );

        let ill_typed_dnssec_support = Value::object([
            ("Server", Value::String("192.0.2.53".to_owned())),
            ("Type", Value::String("link".to_owned())),
            ("DNSSECMode", Value::String("allow-downgrade".to_owned())),
            ("DNSSECSupported", Value::String("yes".to_owned())),
        ]);
        assert_eq!(
            server_state_lines(&ill_typed_dnssec_support)
                .expect_err("v261 rejects ill-typed server-state replies")
                .to_string(),
            "server-state entry field 'DNSSECSupported' is missing or is not a boolean"
        );
    }

    #[test]
    fn formats_nxdomain_like_stock_resolvectl() {
        let reply = Value::object([
            (
                "error",
                Value::String("io.rustd.Resolve.DNSError".to_owned()),
            ),
            (
                "parameters",
                Value::object([
                    ("rcode", Value::Number(3)),
                    (
                        "queryString",
                        Value::String("invalidservice.signed.test".to_owned()),
                    ),
                ]),
            ),
        ]);
        assert_eq!(
            reply_parameters(&reply)
                .expect_err("NXDOMAIN must fail")
                .to_string(),
            "Name 'invalidservice.signed.test' not found"
        );
    }

    #[test]
    fn service_nxdomain_recovers_the_failed_srv_target() {
        let reply = Value::object([
            (
                "error",
                Value::String("io.rustd.Resolve.DNSError".to_owned()),
            ),
            ("parameters", Value::object([("rcode", Value::Number(3))])),
        ]);
        assert!(reply_is_nxdomain(&reply));

        let owner = "_invalidsvc._udp.signed.test";
        let target = "invalidservice.signed.test";
        let mut rdata = vec![0, 0, 0, 0, 0, 53];
        rdata.extend_from_slice(&rustd_resolved::wire::encode_name(target).unwrap());
        let mut raw = rustd_resolved::wire::encode_name(owner).unwrap();
        raw.extend_from_slice(&33_u16.to_be_bytes());
        raw.extend_from_slice(&1_u16.to_be_bytes());
        raw.extend_from_slice(&60_u32.to_be_bytes());
        raw.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
        raw.extend_from_slice(&rdata);
        let parameters = Value::object([(
            "rrs",
            Value::Array(vec![Value::object([(
                "raw",
                Value::String(resolvectl_rr::encode_base64(&raw)),
            )])]),
        )]);
        assert_eq!(
            service_target_from_parameters(&parameters).as_deref(),
            Some(target)
        );
    }

    #[test]
    fn json_record_output_rejects_unsupported_types() {
        let record = resolvectl_rr::CanonicalRecord {
            owner: "example.test".to_owned(),
            rr_type: 65_534,
            class: 1,
            ttl: 300,
            rdata: vec![1, 2, 3],
        };
        let error =
            record_json_value(&record, &record_raw(&record), None).expect_err("unsupported JSON");
        let io_error = error.downcast_ref::<io::Error>().expect("io error");
        assert_eq!(io_error.kind(), io::ErrorKind::Unsupported);
        assert_eq!(
            io_error.to_string(),
            "JSON formatting for records of type TYPE65534 (65534) not available."
        );
    }

    fn record_raw(record: &resolvectl_rr::CanonicalRecord) -> Vec<u8> {
        let mut raw =
            rustd_resolved::wire::encode_name(&record.owner).expect("record owner encodes");
        raw.extend_from_slice(&record.rr_type.to_be_bytes());
        raw.extend_from_slice(&record.class.to_be_bytes());
        raw.extend_from_slice(&record.ttl.to_be_bytes());
        raw.extend_from_slice(&u16::try_from(record.rdata.len()).unwrap().to_be_bytes());
        raw.extend_from_slice(&record.rdata);
        raw
    }

    #[test]
    fn renders_tlsa_and_caa_like_upstream_resolvectl() {
        let tlsa = resolvectl_rr::CanonicalRecord {
            owner: "_443._tcp.example.test".to_owned(),
            rr_type: 52,
            class: 1,
            ttl: 300,
            rdata: vec![3, 1, 1, 0xaa, 0xbb],
        };
        assert_eq!(
            format_record_text(&tlsa, None).unwrap(),
            "_443._tcp.example.test IN TLSA 3 1 1 aabb\n        -- Cert. usage: Domain-issued certificate\n        -- Selector: SubjectPublicKeyInfo\n        -- Matching type: SHA-256"
        );
        assert_eq!(
            record_json_value(&tlsa, &record_raw(&tlsa), None)
                .unwrap()
                .to_json(),
            r#"{"key":{"class":1,"type":52,"name":"_443._tcp.example.test"},"certUsage":3,"selector":1,"matchingType":1,"data":"aabb"}"#
        );

        let caa = resolvectl_rr::CanonicalRecord {
            owner: "example.test".to_owned(),
            rr_type: 257,
            class: 1,
            ttl: 300,
            rdata: vec![129, 5, b'i', b's', b's', b'u', b'e', b'a', b'\\', b'"', 1],
        };
        assert_eq!(
            format_record_text(&caa, None).unwrap(),
            "example.test IN CAA 129 issue \"a\\134\\042\\001\"\n        -- Flags: critical 1"
        );
        assert_eq!(
            record_json_value(&caa, &record_raw(&caa), None)
                .unwrap()
                .to_json(),
            r#"{"key":{"class":1,"type":257,"name":"example.test"},"flags":129,"tag":"issue","value":"a\\134\\042\\001"}"#
        );
    }

    #[test]
    fn record_json_value_drops_interface_metadata() {
        let tlsa = resolvectl_rr::CanonicalRecord {
            owner: "_443._tcp.example.test".to_owned(),
            rr_type: 52,
            class: 1,
            ttl: 300,
            rdata: vec![3, 1, 1, 0xaa, 0xbb],
        };
        let json = record_json_value(&tlsa, &record_raw(&tlsa), Some(3)).unwrap();
        assert_eq!(json.get("ifindex"), None);
        assert_eq!(json.get("ifname"), None);
    }

    #[test]
    fn dnskey_algorithm_name_falls_back_to_number() {
        assert_eq!(dnssec_algorithm_name(15), "ED25519");
        assert_eq!(dnssec_algorithm_name(42), "42");
    }

    #[test]
    fn dnskey_key_tag_masks_revoke_flag() {
        let record = resolvectl_rr::CanonicalRecord {
            owner: "example.test".to_owned(),
            rr_type: 48,
            class: 1,
            ttl: 300,
            rdata: vec![0x00, 0x81, 5, 8, 0x11, 0x22],
        };
        assert_eq!(dnskey_key_tag(&record.rdata).unwrap(), 0x162b);
    }

    #[test]
    fn raw_payload_matches_upstream_rr_type_rules() {
        let tlsa = resolvectl_rr::CanonicalRecord {
            owner: "example.test".to_owned(),
            rr_type: 52,
            class: 1,
            ttl: 0,
            rdata: vec![3, 1, 1, 0xaa, 0xbb],
        };
        assert_eq!(record_payload(&tlsa).unwrap(), [0xaa, 0xbb]);

        let txt = resolvectl_rr::CanonicalRecord {
            owner: "example.test".to_owned(),
            rr_type: 16,
            class: 1,
            ttl: 0,
            rdata: vec![2, b'o', b'k'],
        };
        assert_eq!(
            record_payload(&txt)
                .expect_err("TXT payload is unavailable")
                .to_string(),
            "Dumping of binary payload not available for RRs of this type: TXT"
        );
    }

    #[test]
    fn renders_svcb_known_and_unknown_param_names_like_upstream_resolvectl() {
        let mut target = rustd_resolved::wire::encode_name("svc.target").expect("target");
        let mut svcb = vec![0, 1];
        svcb.append(&mut target);
        svcb.extend_from_slice(&6u16.to_be_bytes());
        svcb.extend_from_slice(&16u16.to_be_bytes());
        svcb.extend_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());

        let known = resolvectl_rr::CanonicalRecord {
            owner: "query.example.test".to_owned(),
            rr_type: 64,
            class: 1,
            ttl: 300,
            rdata: svcb,
        };
        assert_eq!(
            format_record_text(&known, None).unwrap(),
            "query.example.test IN SVCB 1 svc.target ipv6hint=2001:db8::1"
        );

        let mut target = rustd_resolved::wire::encode_name("svc.target").expect("target");
        let mut svcb = vec![0, 1];
        svcb.append(&mut target);
        svcb.extend_from_slice(&7u16.to_be_bytes());
        svcb.extend_from_slice(&4u16.to_be_bytes());
        svcb.extend_from_slice(b"foo/");

        let unknown = resolvectl_rr::CanonicalRecord {
            owner: "query.example.test".to_owned(),
            rr_type: 64,
            class: 1,
            ttl: 300,
            rdata: svcb,
        };
        assert_eq!(
            format_record_text(&unknown, None).unwrap(),
            "query.example.test IN SVCB 1 svc.target dohpath=\"foo/\""
        );
    }

    #[test]
    fn formats_other_dns_errors_like_stock_resolvectl() {
        let reply = Value::object([
            (
                "error",
                Value::String("io.rustd.Resolve.DNSError".to_owned()),
            ),
            (
                "parameters",
                Value::object([
                    ("rcode", Value::Number(5)),
                    ("queryString", Value::String("example.test".to_owned())),
                ]),
            ),
        ]);
        assert_eq!(
            reply_parameters(&reply)
                .expect_err("REFUSED must fail")
                .to_string(),
            "DNS query type refused."
        );

        let explicit = Value::object([
            (
                "error",
                Value::String("io.rustd.Resolve.QueryRefused".to_owned()),
            ),
            ("parameters", Value::Object(JsonObject::new())),
        ]);
        assert_eq!(
            reply_parameters(&explicit)
                .expect_err("QueryRefused must fail")
                .to_string(),
            "DNS query type refused."
        );
    }

    #[test]
    fn formats_missing_record_with_query_context() {
        let reply = Value::object([
            (
                "error",
                Value::String("io.rustd.Resolve.NoSuchResourceRecord".to_owned()),
            ),
            ("parameters", Value::Object(JsonObject::new())),
        ]);
        assert_eq!(
            reply_parameters_for_query(&reply, "localhost5")
                .expect_err("missing record must fail")
                .to_string(),
            "Name 'localhost5' does not have any RR of the requested type"
        );

        let error =
            reply_parameters_for_query(&reply, "localhost5").expect_err("missing record must fail");
        assert_eq!(
            resolve_record_error("localhost5", error).to_string(),
            "localhost5: resolve call failed: Name 'localhost5' does not have any RR of the requested type"
        );
    }

    #[test]
    fn formats_extended_dns_errors_like_stock_resolvectl() {
        let reply = Value::object([
            (
                "error",
                Value::String("io.rustd.Resolve.DNSError".to_owned()),
            ),
            (
                "parameters",
                Value::object([
                    ("rcode", Value::Number(2)),
                    ("extendedDNSErrorCode", Value::Number(16)),
                    (
                        "extendedDNSErrorMessage",
                        Value::String("Nothing to see here!".to_owned()),
                    ),
                ]),
            ),
        ]);
        assert_eq!(
            reply_parameters(&reply)
                .expect_err("SERVFAIL with EDE must fail")
                .to_string(),
            "DNS query failed: SERVFAIL (Censored: Nothing to see here!)"
        );
    }

    #[test]
    fn formats_dnssec_extended_errors_like_stock_resolvectl() {
        let reply = Value::object([
            (
                "error",
                Value::String("io.rustd.Resolve.DNSSECValidationFailed".to_owned()),
            ),
            (
                "parameters",
                Value::object([
                    ("result", Value::String("upstream-failure".to_owned())),
                    ("extendedDNSErrorCode", Value::Number(6)),
                ]),
            ),
        ]);
        assert_eq!(
            reply_parameters(&reply)
                .expect_err("DNSSEC EDE must fail")
                .to_string(),
            "DNSSEC validation failed: upstream-failure (DNSSEC Bogus)"
        );
    }

    #[test]
    fn cache_json_is_the_raw_scope_array() {
        let scopes = vec![Value::object([
            ("protocol", Value::String("dns".to_owned())),
            ("ifindex", Value::Number(7)),
            ("ifname", Value::String("dns2".to_owned())),
            ("cache", Value::Array(Vec::new())),
            ("dnssec", Value::String("allow-downgrade".to_owned())),
        ])];
        assert_eq!(
            cache_json(&scopes, Some("short")),
            r#"[{"protocol":"dns","ifindex":7,"ifname":"dns2","cache":[],"dnssec":"allow-downgrade"}]"#
        );
    }

    #[test]
    fn cache_scope_header_matches_stock_resolvectl() {
        let scope = Value::object([
            ("protocol", Value::String("dns".to_owned())),
            ("family", Value::Number(2)),
            ("ifindex", Value::Number(6)),
            ("ifname", Value::String("dns0".to_owned())),
            ("dnssec", Value::String("allow-downgrade".to_owned())),
            ("dnsOverTLS", Value::String("opportunistic".to_owned())),
        ]);
        assert_eq!(
            cache_scope_header(&scope),
            "Scope protocol=dns family=AF_INET ifindex=6 ifname=dns0 DNSSEC=allow-downgrade DNSOverTLS=opportunistic"
        );
    }

    #[test]
    fn cache_scope_header_reports_default_dns_policy() {
        let scope = Value::object([
            ("protocol", Value::String("dns".to_owned())),
            ("dnssec", Value::String("allow-downgrade".to_owned())),
            ("dnsOverTLS", Value::String("no".to_owned())),
        ]);
        assert_eq!(
            cache_scope_header(&scope),
            "Scope protocol=dns DNSSEC=allow-downgrade DNSOverTLS=no"
        );
    }

    #[test]
    fn pretty_json_matches_systemd_layout() {
        let value = Value::object([
            ("name", Value::String("resolver".to_owned())),
            (
                "addresses",
                Value::Array(vec![Value::Number(127), Value::Number(1)]),
            ),
        ]);
        assert_eq!(
            json_output(&value, Some("pretty")),
            "{\n\t\"name\" : \"resolver\",\n\t\"addresses\" : [\n\t\t127,\n\t\t1\n\t]\n}"
        );
    }

    #[test]
    fn monitor_socket_tracks_default_and_custom_resolve_paths() {
        assert_eq!(
            monitor_socket_for(Path::new(DEFAULT_SOCKET)),
            PathBuf::from(DEFAULT_MONITOR_SOCKET)
        );
        assert_eq!(
            monitor_socket_for(Path::new("/tmp/resolved-test.sock")),
            PathBuf::from("/tmp/resolved-test.sock.Monitor")
        );
    }

    #[test]
    fn query_options_accept_upstream_type_and_legend_forms() {
        let arguments = [
            "--legend=no".to_owned(),
            "-t".to_owned(),
            "MX".to_owned(),
            "example.test".to_owned(),
        ];
        let parsed = parse_query_arguments(&arguments, true, None, 1).unwrap();
        assert_eq!(parsed.inputs, ["example.test"]);
        assert_eq!(parsed.rr_type, Some(15));
        assert!(!parsed.legend);

        let arguments = ["localhost".to_owned(), "--type=AAAA".to_owned()];
        let parsed = parse_query_arguments(&arguments, true, None, 1).unwrap();
        assert_eq!(parsed.inputs, ["localhost"]);
        assert_eq!(parsed.rr_type, Some(28));

        let arguments = ["--class=ANY".to_owned(), "example.test".to_owned()];
        let parsed = parse_query_arguments(&arguments, false, Some(16), 1).unwrap();
        assert_eq!(parsed.rr_type, Some(16));
        assert_eq!(parsed.rr_class, 255);
        assert!(!parsed.legend);
    }

    #[test]
    fn native_options_support_attached_short_aliases_like_upstream() {
        let options = parse_options(vec![
            "-tAAAA".to_owned(),
            "query".to_owned(),
            "localhost".to_owned(),
        ])
        .unwrap()
        .expect("query command should execute");

        assert_eq!(options.command, "query");
        assert_eq!(options.lookup_options().rr_type, Some(28));
        assert_eq!(options.arguments, vec!["localhost".to_owned()]);
    }

    #[test]
    fn query_arguments_accept_attached_type_and_class_forms() {
        let arguments = ["-tAAAA".to_owned(), "localhost".to_owned()];
        let parsed = parse_query_arguments(&arguments, true, None, 1).unwrap();
        assert_eq!(parsed.rr_type, Some(28));
        assert_eq!(parsed.inputs, ["localhost"]);

        let arguments = ["-cANY".to_owned(), "example.test".to_owned()];
        let parsed = parse_query_arguments(&arguments, false, Some(16), 1).unwrap();
        assert_eq!(parsed.rr_type, Some(16));
        assert_eq!(parsed.rr_class, 255);
        assert_eq!(parsed.inputs, ["example.test"]);
    }

    #[test]
    fn protocol_short_help_is_supported() {
        assert!(parse_options(vec!["query".to_owned(), "-phelp".to_owned()])
            .unwrap()
            .is_none());
    }

    #[test]
    fn query_json_requires_record_type_for_hostname_query() {
        let options = LookupOptions {
            family: 0,
            ifindex: 0,
            request_flags: 0,
            json: Some("pretty"),
            legend: true,
            rr_type: None,
            rr_class: 1,
            raw: RawMode::None,
        };
        assert_eq!(
            query(Path::new("/dev/null"), "localhost", options)
                .unwrap_err()
                .to_string(),
            "Use --json=pretty with --type=A or --type=AAAA to acquire address record information in JSON format."
        );
    }

    #[test]
    fn query_json_requires_record_type_for_address_query() {
        let options = LookupOptions {
            family: 0,
            ifindex: 0,
            request_flags: 0,
            json: Some("short"),
            legend: true,
            rr_type: None,
            rr_class: 1,
            raw: RawMode::None,
        };
        assert_eq!(
            query(Path::new("/dev/null"), "127.0.0.1", options)
                .unwrap_err()
                .to_string(),
            "Use --json=pretty with --type= to acquire resource record information in JSON format."
        );
    }

    #[test]
    fn parse_errors_match_upstream_for_json_and_boolean_arguments() {
        let query_json = parse_options(vec![
            "query".to_owned(),
            "--json=bad".to_owned(),
            "localhost".to_owned(),
        ])
        .expect_err("invalid --json argument must fail");
        assert_eq!(
            query_json.to_string(),
            "Unknown argument to --json= switch: bad"
        );

        let service_txt = parse_options(vec!["--service-address=maybe".to_owned()])
            .expect_err("invalid bool must fail");
        assert_eq!(
            service_txt.to_string(),
            "Failed to parse boolean argument to --service-address=: maybe."
        );
    }

    #[test]
    fn query_class_requires_type() {
        let parse_class =
            parse_query_arguments(&["-cANY".to_owned(), "localhost".to_owned()], true, None, 1)
                .expect_err("--class without --type must fail");
        assert_eq!(
            parse_class.to_string(),
            "--class= may only be used in conjunction with --type=."
        );

        let parse_class = parse_query_arguments(&["-cANY".to_owned()], true, None, 1)
            .expect_err("--class without --type must fail before input checks");
        assert_eq!(
            parse_class.to_string(),
            "--class= may only be used in conjunction with --type=."
        );
    }

    #[test]
    fn parse_options_reports_query_class_without_type_first() {
        let parse_class = parse_options(vec!["query".to_owned(), "-cANY".to_owned()])
            .expect_err("query --class without --type should fail");
        assert_eq!(
            parse_class.to_string(),
            "--class= may only be used in conjunction with --type=."
        );
    }

    #[test]
    fn parse_options_parse_help_and_error_tokens_for_type_and_class() {
        let parse_class = parse_options(vec![
            "query".to_owned(),
            "--class=HELP".to_owned(),
            "localhost".to_owned(),
        ])
        .expect_err("upper-case HELP must be treated as invalid class");
        assert_eq!(
            parse_class.to_string(),
            "Failed to parse RR record class HELP: Invalid argument"
        );

        let parse_type = parse_options(vec![
            "query".to_owned(),
            "--type=HELP".to_owned(),
            "localhost".to_owned(),
        ])
        .expect_err("upper-case HELP must be treated as invalid type");
        assert_eq!(
            parse_type.to_string(),
            "Failed to parse RR record type HELP: Invalid argument"
        );

        let parse_raw = parse_options(vec![
            "query".to_owned(),
            "--raw=bad".to_owned(),
            "localhost".to_owned(),
        ])
        .expect_err("invalid raw specifier should fail");
        assert_eq!(parse_raw.to_string(), "Unknown --raw specifier \"bad\".");

        let parse_protocol = parse_options(vec![
            "query".to_owned(),
            "--protocol=HELP".to_owned(),
            "localhost".to_owned(),
        ])
        .expect_err("upper-case HELP should be treated as invalid protocol");
        assert_eq!(
            parse_protocol.to_string(),
            "Unknown protocol specifier: HELP"
        );

        let parse_protocol_short = parse_options(vec![
            "-pHELP".to_owned(),
            "query".to_owned(),
            "localhost".to_owned(),
        ])
        .expect_err("short upper-case HELP should be treated as invalid protocol");
        assert_eq!(
            parse_protocol_short.to_string(),
            "Unknown protocol specifier: HELP"
        );

        let parse_help =
            parse_options(vec!["--help=1".to_owned()]).expect_err("help should reject =value");
        assert_eq!(
            parse_help.to_string(),
            "option '--help' doesn't allow an argument"
        );

        assert!(
            parse_options(vec!["-h=1".to_owned()]).is_ok(),
            "short help should print usage"
        );

        assert!(
            parse_options(vec!["-hfoo".to_owned()]).is_ok(),
            "help should print usage with attached short alias"
        );

        let parse_version = parse_options(vec!["--version=1".to_owned()])
            .expect_err("version should reject =value");
        assert_eq!(
            parse_version.to_string(),
            "option '--version' doesn't allow an argument"
        );
        assert!(
            parse_options(vec!["-c=help".to_owned()]).is_err_and(|error| error.to_string()
                == "Failed to parse RR record class =help: Invalid argument"),
            "class short attached lower-case should preserve case in error"
        );
        assert!(
            parse_options(vec!["-chelper".to_owned()]).is_err_and(|error| error.to_string()
                == "Failed to parse RR record class helper: Invalid argument"),
            "class short attached token should preserve case in error"
        );
        assert!(
            parse_options(vec!["--json=".to_owned()])
                .is_err_and(|error| error.to_string() == "Unknown argument to --json= switch: "),
            "empty json specifier should map to unknown argument"
        );
        assert!(
            parse_options(vec!["-jpretty".to_owned()])
                .is_err_and(|error| error.to_string() == "Unknown protocol specifier: retty"),
            "short flag cluster with json should be treated as protocol lookup"
        );
        assert!(
            parse_options(vec!["-jabc".to_owned()])
                .is_err_and(|error| error.to_string() == "invalid option -- 'a'"),
            "short unknown cluster char should be reported"
        );
        assert!(
            parse_options(vec!["-j=pretty".to_owned()])
                .is_err_and(|error| error.to_string() == "invalid option -- '='"),
            "short equals after json should be reported as invalid short option char"
        );
    }

    #[test]
    fn query_arguments_reject_invalid_legend_value() {
        let parse_legend = parse_query_arguments(
            &["--legend=maybe".to_owned(), "localhost".to_owned()],
            true,
            None,
            1,
        )
        .expect_err("invalid legend token should fail");
        assert_eq!(
            parse_legend.to_string(),
            "Failed to parse boolean argument to --legend=: maybe."
        );
    }

    #[test]
    fn parse_options_reports_interface_lookup_error_without_os_code() {
        let parse_interface = parse_options(vec![
            "-i=lo".to_owned(),
            "query".to_owned(),
            "localhost".to_owned(),
        ])
        .expect_err("unknown interface from attached short option should fail");
        assert_eq!(
            parse_interface.to_string(),
            "Failed to resolve interface \"=lo\": No such device"
        );
    }

    #[test]
    fn status_reports_invalid_links_before_filtering_configuration() {
        let error = validate_status_arguments(&["=lo".to_owned()])
            .expect_err("an invalid status link should be rejected");
        assert_eq!(
            error.to_string(),
            "Failed to resolve interface \"=lo\": No such device\n\
             Failed to filter configuration JSON links: No such device"
        );
    }

    #[test]
    fn no_name_servers_error_is_mapped() {
        let reply = Value::object([(
            "error",
            Value::String("io.rustd.Resolve.NoNameServers".to_owned()),
        )]);
        assert_eq!(
            reply_parameters_inner(&reply, None)
                .expect_err("no-name-servers should fail")
                .to_string(),
            "No appropriate name servers or networks for name found"
        );
    }

    #[test]
    fn query_policy_options_map_to_upstream_flags() {
        use rustd_resolved::dbus_resolve1_abi::flags::{
            SD_RESOLVED_DNS, SD_RESOLVED_LLMNR_IPV4, SD_RESOLVED_LLMNR_IPV6, SD_RESOLVED_MDNS_IPV4,
            SD_RESOLVED_MDNS_IPV6, SD_RESOLVED_NO_NETWORK, SD_RESOLVED_RELAX_SINGLE_LABEL,
        };

        assert_eq!(protocol_flags("dns").unwrap(), SD_RESOLVED_DNS);
        assert_eq!(
            protocol_flags("llmnr").unwrap(),
            SD_RESOLVED_LLMNR_IPV4 | SD_RESOLVED_LLMNR_IPV6
        );
        assert_eq!(
            protocol_flags("mdns").unwrap(),
            SD_RESOLVED_MDNS_IPV4 | SD_RESOLVED_MDNS_IPV6
        );

        let mut flags = 0;
        set_disabled_flag(&mut flags, SD_RESOLVED_NO_NETWORK, "--network", "no").unwrap();
        set_enabled_flag(
            &mut flags,
            SD_RESOLVED_RELAX_SINGLE_LABEL,
            "--relax-single-label",
            "yes",
        )
        .unwrap();
        assert_eq!(
            flags,
            SD_RESOLVED_NO_NETWORK | SD_RESOLVED_RELAX_SINGLE_LABEL
        );
        set_disabled_flag(&mut flags, SD_RESOLVED_NO_NETWORK, "--network", "yes").unwrap();
        set_enabled_flag(
            &mut flags,
            SD_RESOLVED_RELAX_SINGLE_LABEL,
            "--relax-single-label",
            "no",
        )
        .unwrap();
        assert_eq!(flags, 0);
    }

    #[test]
    fn scoped_ipv6_address_carries_its_interface() {
        let loopback = rustd_resolved::interface::resolve_ifindex("lo").expect("loopback ifindex");
        let scoped = format!("fe80::1%{loopback}");
        let (address, ifindex) = parse_address_with_scope(&scoped, 0)
            .unwrap()
            .expect("scoped address");
        assert_eq!(address, "fe80::1".parse::<IpAddr>().unwrap());
        assert_eq!(ifindex, loopback);

        let (_, ifindex) = parse_address_with_scope("127.0.0.1", 9)
            .unwrap()
            .expect("IPv4 address");
        assert_eq!(ifindex, 9);
        assert!(parse_address_with_scope("example.test", 0)
            .unwrap()
            .is_none());
    }

    #[test]
    fn parse_address_with_scope_rejects_invalid_forms() {
        assert!(parse_address_with_scope("127.0.0.1%lo", 0).is_err());
        assert!(parse_address_with_scope("fe80::1%", 0).is_err());
        assert!(parse_address_with_scope("fe80::1%0", 0).is_err());
        assert!(parse_address_with_scope("fe80::1%bad_interface", 0).is_err());
        assert!(parse_address_with_scope("example%lo", 0).is_err());
        assert!(parse_address_with_scope("fe80::1%lo%2", 0).is_err());
    }

    #[test]
    fn rfc4501_dns_uri_selects_record_class_and_type() {
        assert_eq!(
            parse_dns_uri("dns:example.test?class=IN;type=AAAA", 255, 16).unwrap(),
            ("example.test".to_owned(), 1, 28)
        );
        assert_eq!(
            parse_dns_uri("dns://ignored/example.test?TYPE=MX", 1, 1).unwrap(),
            ("example.test".to_owned(), 1, 15)
        );
        assert!(parse_dns_uri("dns:example.test?type=A;type=AAAA", 1, 1).is_err());
        assert!(parse_dns_uri("dns:/example.test", 1, 1).is_err());
    }

    #[test]
    fn svcb_text_formats_alpn_and_ipv4_hints() {
        let rdata = [
            0, 1, 0, // priority and root target
            0, 1, 0, 4, 3, b'd', b'o', b't', // ALPN
            0, 4, 0, 4, 10, 0, 0, 1, // IPv4 hint
        ];
        assert_eq!(
            format_svcb_rdata(&rdata).unwrap(),
            "1 . alpn=\"dot\" ipv4hint=10.0.0.1"
        );
    }

    #[test]
    fn svcb_unknown_values_are_deescaped_and_quoted() {
        assert_eq!(
            svcb_unknown(&[b'a', b' ', b',', b'\\', b'"', 0x01, 0x80]),
            "\"a\\040\\054\\134\\042\\001\\200\""
        );
    }

    #[test]
    fn monitor_record_text_includes_the_complete_resource_record() {
        let aaaa = resolvectl_rr::CanonicalRecord {
            owner: "ns1.unsigned.test".to_owned(),
            rr_type: 28,
            class: 1,
            ttl: 0,
            rdata: "fd00:dead:beef:cafe::1"
                .parse::<Ipv6Addr>()
                .unwrap()
                .octets()
                .to_vec(),
        };
        assert_eq!(
            format_record_text(&aaaa, None).unwrap(),
            "ns1.unsigned.test IN AAAA fd00:dead:beef:cafe::1"
        );
    }

    #[test]
    fn record_link_comments_use_the_stock_column() {
        let record = resolvectl_rr::CanonicalRecord {
            owner: "localhost".to_owned(),
            rr_type: 1,
            class: 1,
            ttl: 0,
            rdata: vec![127, 0, 0, 1],
        };
        assert_eq!(
            format_record_text(&record, Some(1)).unwrap(),
            "localhost IN A 127.0.0.1                                    -- link: lo"
        );
    }

    #[test]
    fn max_attempts_service_errors_use_the_stock_phrase() {
        let error: Box<dyn Error> = Box::new(CliError(
            "All attempts to contact name servers or networks failed".to_owned(),
        ));
        assert_eq!(
            resolve_service_error(error).to_string(),
            "Resolve call failed: All attempts to contact name servers or networks failed"
        );
    }

    #[test]
    fn statistics_sections_use_the_stock_table_layout() {
        let parameters = Value::object([(
            "transactions",
            Value::object([
                ("currentTransactions", Value::Number(0)),
                ("totalTransactions", Value::Number(31_410)),
            ]),
        )]);
        assert_eq!(
            statistic_section_text(
                &parameters,
                "transactions",
                "Transactions",
                &[
                    ("Current Transactions", "currentTransactions"),
                    ("Total Transactions", "totalTransactions"),
                ],
            ),
            Some(
                concat!(
                    "Transactions                                 ",
                    "\n                       Current Transactions:     0",
                    "\n                         Total Transactions: 31410"
                )
                .to_owned()
            )
        );
    }
}
