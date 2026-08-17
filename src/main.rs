// SPDX-License-Identifier: LGPL-2.1-or-later
use rustd_resolved::config::{parse_server, Config, DnsStubListenerMode};
use rustd_resolved::daemon::{install_signal_handlers, request_stop, run_stub_with_config, ReloadOverrides};
use rustd_resolved::dbus::DbusServer;
use rustd_resolved::resolver::Resolver;
use rustd_resolved::varlink::VarlinkServer;
use std::env;
use std::error::Error;
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::thread;

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug)]
struct Options {
    config: PathBuf,
    listeners: Vec<String>,
    proxy_listeners: Vec<String>,
    upstreams: Vec<String>,
    varlink: Option<PathBuf>,
    runtime_directory: Option<PathBuf>,
    workers: Option<usize>,
    port: Option<u16>,
    check_config: bool,
    no_stub: bool,
    no_varlink: bool,
    no_dbus: bool,
}

#[derive(Debug)]
struct CliError(String);

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for CliError {}

impl Default for Options {
    fn default() -> Self {
        Self {
            config: PathBuf::from("/etc/rustd/resolved.conf"),
            listeners: Vec::new(),
            proxy_listeners: Vec::new(),
            upstreams: Vec::new(),
            varlink: None,
            runtime_directory: None,
            workers: None,
            port: None,
            check_config: false,
            no_stub: false,
            no_varlink: false,
            no_dbus: true,
        }
    }
}

fn main() -> ExitCode {
    match execute() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if error.downcast_ref::<CliError>().is_some() {
                eprintln!("{error}");
            } else {
                eprintln!("rustd-resolved: {error}");
            }
            ExitCode::FAILURE
        }
    }
}

fn execute() -> Result<(), Box<dyn Error>> {
    let Some(options) = parse_options()? else {
        return Ok(());
    };
    let (config, reload_overrides) = configured_resolver(&options)?;

    if options.check_config {
        print_configuration(&config, options.no_varlink);
        return Ok(());
    }
    run_resolver(&config, &options, &reload_overrides)
}

fn configured_resolver(options: &Options) -> Result<(Config, ReloadOverrides), Box<dyn Error>> {
    let mut config = Config::load(&options.config)?;
    apply_environment(&mut config)?;

    if !options.listeners.is_empty() {
        config.listeners = parse_servers(&options.listeners)?;
    }
    if !options.proxy_listeners.is_empty() {
        config.proxy_listeners = parse_servers(&options.proxy_listeners)?;
    }
    if !options.upstreams.is_empty() {
        config.upstreams = parse_servers(&options.upstreams)?;
        config.fallback_upstreams.clear();
    }
    if let Some(path) = &options.varlink {
        config.varlink_path.clone_from(path);
    }
    if let Some(path) = &options.runtime_directory {
        config.runtime_directory.clone_from(path);
    }
    if let Some(workers) = options.workers {
        config.workers = workers;
    }
    if let Some(port) = options.port {
        rewrite_ports(&mut config.listeners, port);
        rewrite_ports(&mut config.proxy_listeners, port);
    }
    if options.no_stub {
        config.dns_stub_listener = DnsStubListenerMode::No;
        config.dns_stub_listener_extra.clear();
    }
    config.validate()?;
    let reload_overrides = reload_overrides(options, &config);
    Ok((config, reload_overrides))
}

fn reload_overrides(options: &Options, config: &Config) -> ReloadOverrides {
    let stub_environment = env::var("RUSTD_RESOLVED_STUB_ADDR")
        .ok()
        .map_or(false, |value| !value.trim().is_empty());
    let proxy_environment = env::var("RUSTD_RESOLVED_STUB_ADDR_ALT").is_ok();
    let runtime_environment = env::var("RUSTD_RESOLVED_RUN_DIR")
        .ok()
        .map_or(false, |value| !value.trim().is_empty());
    let varlink_environment = env::var("RUSTD_RESOLVED_VARLINK")
        .ok()
        .map_or(false, |value| !value.trim().is_empty());
    let workers_environment = env::var("RUSTD_RESOLVED_WORKERS")
        .ok()
        .map_or(false, |value| !value.trim().is_empty());
    let upstream_override = !options.upstreams.is_empty();
    let listeners_override =
        stub_environment || !options.listeners.is_empty() || options.port.is_some();
    let proxy_override =
        proxy_environment || !options.proxy_listeners.is_empty() || options.port.is_some();
    let runtime_override = runtime_environment || options.runtime_directory.is_some();
    let varlink_override = varlink_environment
        || (runtime_environment && env::var_os("RUSTD_RESOLVED_VARLINK").is_none())
        || options.varlink.is_some();
    let workers_override = workers_environment || options.workers.is_some();

    ReloadOverrides {
        upstreams: upstream_override.then(|| config.upstreams.clone()),
        upstream_specs: upstream_override.then(|| config.upstream_specs.clone()),
        fallback_upstreams: upstream_override.then(|| config.fallback_upstreams.clone()),
        fallback_upstream_specs: upstream_override
            .then(|| config.fallback_upstream_specs.clone()),
        listeners: listeners_override.then(|| config.listeners.clone()),
        proxy_listeners: proxy_override.then(|| config.proxy_listeners.clone()),
        dns_stub_listener: options.no_stub.then_some(config.dns_stub_listener),
        dns_stub_listener_extra: options
            .no_stub
            .then(|| config.dns_stub_listener_extra.clone()),
        varlink_path: varlink_override.then(|| config.varlink_path.clone()),
        runtime_directory: runtime_override.then(|| config.runtime_directory.clone()),
        workers: workers_override.then_some(config.workers),
    }
}

fn apply_environment(config: &mut Config) -> Result<(), Box<dyn Error>> {
    if let Ok(value) = env::var("RUSTD_RESOLVED_STUB_ADDR") {
        if !value.trim().is_empty() {
            config.listeners = vec![parse_server(&value)?];
        }
    }

    if let Ok(value) = env::var("RUSTD_RESOLVED_STUB_ADDR_ALT") {
        if value.trim().is_empty() || value.eq_ignore_ascii_case("none") {
            config.proxy_listeners.clear();
        } else {
            config.proxy_listeners = vec![parse_server(&value)?];
        }
    }

    if let Ok(value) = env::var("RUSTD_RESOLVED_RUN_DIR") {
        if !value.trim().is_empty() {
            let path = PathBuf::from(value);
            config.runtime_directory.clone_from(&path);
            if env::var_os("RUSTD_RESOLVED_VARLINK").is_none() {
                config.varlink_path = path.join("io.rustd.Resolve");
            }
        }
    }

    if let Ok(value) = env::var("RUSTD_RESOLVED_VARLINK") {
        if !value.trim().is_empty() {
            config.varlink_path = PathBuf::from(value);
        }
    }

    if let Ok(value) = env::var("RUSTD_RESOLVED_WORKERS") {
        if !value.trim().is_empty() {
            config.workers = value.parse::<usize>()?;
        }
    }

    Ok(())
}

fn run_resolver(
    config: &Config,
    options: &Options,
    reload_overrides: &ReloadOverrides,
) -> Result<(), Box<dyn Error>> {
    let primary_stub_enabled = config.dns_stub_listener != DnsStubListenerMode::No
        && (!config.listeners.is_empty() || !config.proxy_listeners.is_empty());
    let stub_enabled = primary_stub_enabled || !config.dns_stub_listener_extra.is_empty();
    if options.no_varlink && options.no_dbus && !stub_enabled {
        return Err("all resolver interfaces are disabled".into());
    }

    std::fs::create_dir_all(&config.runtime_directory)?;
    rustd_resolved::log_control::initialize();
    rustd_resolved::native::drop_privileges("rustd-resolve", &config.runtime_directory)?;
    install_signal_handlers()?;
    config.write_runtime_resolv_confs()?;

    let resolver = Arc::new(Resolver::new(config.clone()));
    let netlink_thread = rustd_resolved::netlink::spawn(Arc::clone(&resolver))?;
    let networkd_thread = rustd_resolved::networkd::spawn(Arc::clone(&resolver))?;
    if config.effective_upstreams().is_empty() {
        eprintln!("rustd-resolved: warning: no upstream DNS servers are configured");
    }

    let dbus_thread = spawn_dbus(&resolver, options.no_dbus)?;
    let varlink_thread = spawn_varlink(&resolver, config, options.no_varlink)?;
    log_stub_listeners(config, primary_stub_enabled);

    let result = run_stub_with_config(
        &resolver,
        Some(&options.config),
        Some(reload_overrides),
    );
    request_stop();
    if let Some(thread) = varlink_thread {
        let _ = thread.join();
    }
    if let Some(thread) = dbus_thread {
        let _ = thread.join();
    }
    let _ = networkd_thread.join();
    let _ = netlink_thread.join();
    result?;
    Ok(())
}

fn spawn_dbus(
    resolver: &Arc<Resolver>,
    disabled: bool,
) -> Result<Option<thread::JoinHandle<()>>, Box<dyn Error>> {
    if disabled {
        return Ok(None);
    }
    let server = DbusServer::new(Arc::clone(resolver));
    Ok(Some(
        thread::Builder::new()
            .name("rustd-resolved-dbus".to_owned())
            .spawn(move || {
                if let Err(error) = server.run() {
                    eprintln!("rustd-resolved: D-Bus server failed: {error}");
                    request_stop();
                }
            })?,
    ))
}

fn spawn_varlink(
    resolver: &Arc<Resolver>,
    config: &Config,
    disabled: bool,
) -> Result<Option<thread::JoinHandle<()>>, Box<dyn Error>> {
    if disabled {
        return Ok(None);
    }
    let server = VarlinkServer::new(config.varlink_path.clone(), Arc::clone(resolver))?;
    Ok(Some(
        thread::Builder::new()
            .name("rustd-resolved-varlink".to_owned())
            .spawn(move || {
                if let Err(error) = server.run() {
                    eprintln!("rustd-resolved: Varlink server failed: {error}");
                    request_stop();
                }
            })?,
    ))
}

fn log_stub_listeners(config: &Config, primary_enabled: bool) {
    if primary_enabled {
        for address in &config.listeners {
            eprintln!(
                "rustd-resolved: full stub listening on {address} ({})",
                config.dns_stub_listener.as_str()
            );
        }
        for address in &config.proxy_listeners {
            eprintln!(
                "rustd-resolved: proxy stub listening on {address} ({})",
                config.dns_stub_listener.as_str()
            );
        }
    }
    for listener in &config.dns_stub_listener_extra {
        eprintln!(
            "rustd-resolved: extra stub listening on {} ({})",
            listener.address(),
            listener.mode().as_str()
        );
    }
}

fn parse_servers(values: &[String]) -> Result<Vec<SocketAddr>, Box<dyn Error>> {
    values
        .iter()
        .map(|value| parse_server(value).map_err(|error| -> Box<dyn Error> { Box::new(error) }))
        .collect()
}

fn rewrite_ports(addresses: &mut [SocketAddr], port: u16) {
    for address in addresses {
        address.set_port(port);
    }
}

fn print_configuration(config: &Config, no_varlink: bool) {
    println!("configuration is valid");
    println!("upstreams: {}", config.effective_upstreams().len());
    println!("full listeners: {}", config.listeners.len());
    println!("proxy listeners: {}", config.proxy_listeners.len());
    println!("extra listeners: {}", config.dns_stub_listener_extra.len());
    println!("stub listener mode: {}", config.dns_stub_listener.as_str());
    if no_varlink {
        println!("varlink: disabled");
    } else {
        println!("varlink: {}", config.varlink_path.display());
    }
}

fn parse_options() -> Result<Option<Options>, Box<dyn Error>> {
    let mut arguments = env::args();
    let program = arguments
        .next()
        .unwrap_or_else(|| "rustd-resolved".to_owned());
    parse_options_from(&program, arguments)
}

fn parse_options_from(
    program: &str,
    mut arguments: impl Iterator<Item = String>,
) -> Result<Option<Options>, Box<dyn Error>> {
    let mut options = Options::default();

    while let Some(argument) = arguments.next() {
        if argument == "--" {
            if arguments.next().is_some() {
                return Err(Box::new(CliError(
                    "This program takes no arguments.".to_owned(),
                )));
            }
            break;
        }
        if !argument.starts_with('-') {
            return Err(Box::new(CliError(
                "This program takes no arguments.".to_owned(),
            )));
        }
        let (name, inline_value) = argument
            .split_once('=')
            .map_or((argument.as_str(), None), |(name, value)| {
                (name, Some(value))
            });
        match name {
            "--config" => {
                options.config = option_value(inline_value, &mut arguments, name)?.into();
            }
            "--listen" => {
                options
                    .listeners
                    .push(option_value(inline_value, &mut arguments, name)?);
            }
            "--proxy-listen" => {
                options
                    .proxy_listeners
                    .push(option_value(inline_value, &mut arguments, name)?);
            }
            "--upstream" => {
                options
                    .upstreams
                    .push(option_value(inline_value, &mut arguments, name)?);
            }
            "--varlink" => {
                options.varlink = Some(option_value(inline_value, &mut arguments, name)?.into());
            }
            "--runtime-directory" => {
                options.runtime_directory =
                    Some(option_value(inline_value, &mut arguments, name)?.into());
            }
            "--workers" => {
                options.workers =
                    Some(option_value(inline_value, &mut arguments, name)?.parse::<usize>()?);
            }
            "--port" => {
                options.port =
                    Some(option_value(inline_value, &mut arguments, name)?.parse::<u16>()?);
            }
            "--check-config" => options.check_config = true,
            "--no-stub" => options.no_stub = true,
            "--no-varlink" => options.no_varlink = true,
            "--no-dbus" => options.no_dbus = true,
            "--dbus" => options.no_dbus = false,
            "--bus-introspect" => {
                let pattern = option_value(inline_value, &mut arguments, "--bus-introspect")?;
                print!(
                    "{}",
                    rustd_resolved::service_introspection::render(&pattern)?
                );
                return Ok(None);
            }
            "--version" => {
                reject_inline_value(program, name, inline_value)?;
                println!("rustd-resolved {}", env!("CARGO_PKG_VERSION"));
                return Ok(None);
            }
            "--help" | "-h" => {
                if name == "--help" {
                    reject_inline_value(program, name, inline_value)?;
                }
                print_help(program);
                return Ok(None);
            }
            _ if argument.starts_with("--") => {
                return Err(Box::new(CliError(format!(
                    "{program}: unrecognized option '{name}'"
                ))));
            }
            _ => {
                let option = argument.chars().nth(1).unwrap_or('-');
                return Err(Box::new(CliError(format!(
                    "{program}: invalid option -- '{option}'"
                ))));
            }
        }
    }
    Ok(Some(options))
}

fn reject_inline_value(
    program: &str,
    option: &str,
    inline: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    if inline.is_some() {
        return Err(Box::new(CliError(format!(
            "{program}: option '{option}' doesn't allow an argument"
        ))));
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

fn print_help(program: &str) {
    print!("{}", help_text(program));
}

fn help_text(program: &str) -> String {
    let program = std::path::Path::new(program)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(program);
    format!(
        concat!(
            "> {} [OPTIONS...]\n\n",
            "RustD name resolver with DNS, mDNS, LLMNR, caching, and per-link routing.\n\n",
            "Options:\n",
            "  -h --help                Show this help\n",
            "     --version             Show package version\n",
            "     --config=PATH         Resolver configuration file\n",
            "     --listen=ADDRESS      Full DNS stub listener\n",
            "     --proxy-listen=ADDR   Proxy DNS stub listener\n",
            "     --upstream=ADDRESS    Upstream DNS server\n",
            "     --runtime-directory=P Runtime state directory\n",
            "     --varlink=PATH        RustD Varlink socket\n",
            "     --workers=N           Resolver worker count\n",
            "     --port=N              Override local listener port\n",
            "     --check-config        Validate configuration and exit\n",
            "     --no-stub             Disable DNS stub listeners\n",
            "     --no-varlink          Disable Varlink service\n",
            "     --no-dbus             Disable D-Bus compatibility service\n",
            "     --dbus                Enable org.freedesktop.resolve1 compatibility\n",
            "     --bus-introspect=PATH Write D-Bus XML introspection data\n"
        ),
        program
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cli_error(arguments: &[&str]) -> String {
        parse_options_from(
            "/usr/lib/rustd/rustd-resolved",
            arguments.iter().map(|argument| (*argument).to_owned()),
        )
        .expect_err("command line must fail")
        .to_string()
    }

    #[test]
    fn options_reject_invalid_arguments() {
        assert_eq!(
            cli_error(&["--help=value"]),
            "/usr/lib/rustd/rustd-resolved: option '--help' doesn't allow an argument"
        );
        assert_eq!(
            cli_error(&["--version=value"]),
            "/usr/lib/rustd/rustd-resolved: option '--version' doesn't allow an argument"
        );
        assert_eq!(
            cli_error(&["--bus-introspect"]),
            "--bus-introspect requires a value"
        );
    }

    #[test]
    fn positional_and_unknown_options_are_rejected() {
        assert_eq!(cli_error(&["argument"]), "This program takes no arguments.");
        assert_eq!(
            cli_error(&["--unknown"]),
            "/usr/lib/rustd/rustd-resolved: unrecognized option '--unknown'"
        );
        assert_eq!(
            cli_error(&["-x"]),
            "/usr/lib/rustd/rustd-resolved: invalid option -- 'x'"
        );
    }

    #[test]
    fn help_uses_native_rustd_identity() {
        let help = help_text("target/release/rustd-resolved");
        assert!(help.starts_with("> rustd-resolved [OPTIONS...]"));
        assert!(help.contains("RustD name resolver"));
        assert!(!help.contains("systemd-resolved"));
    }
}
