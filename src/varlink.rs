// SPDX-License-Identifier: LGPL-2.1-or-later
use crate::bounded_executor::varlink_executor;
use crate::daemon::stop_requested;
use crate::json::{self, JsonObject, Value};
use crate::log_control::LogControlState;
use crate::native;
#[cfg(test)]
use crate::resolve_flags::flags::RUSTD_RESOLVE_DNS;
use crate::resolve_flags::flags::{
    RUSTD_RESOLVE_NO_ADDRESS, RUSTD_RESOLVE_NO_SEARCH, RUSTD_RESOLVE_NO_TXT,
};
use crate::resolver::{ResolveError, Resolver};
use crate::varlink_polkit::{AuthorizationDecision, VarlinkAuthorization};
use crate::wire::{
    self, extract_answer_records, extract_matching_answer_records,
    extract_service_records_for_name, make_query, CLASS_IN, TYPE_A, TYPE_AAAA, TYPE_PTR, TYPE_SRV,
    TYPE_TXT,
};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(test)]
use std::os::fd::IntoRawFd;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

const MAX_MESSAGE_SIZE: usize = 1024 * 1024;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VarlinkEndpoint {
    Resolve,
    Monitor,
    Any,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SubscriptionMethod {
    BrowseServices,
    QueryResults,
    DnsConfiguration,
}

#[derive(Debug)]
enum ActivatedVarlinkSocket {
    Listener(UnixListener),
    Connection(UnixStream),
}

impl VarlinkEndpoint {
    fn allows(self, method: &str) -> bool {
        match self {
            Self::Resolve => {
                method.starts_with("org.varlink.service.")
                    || (method.starts_with("io.rustd.Resolve.")
                        && !method.starts_with("io.rustd.Resolve.Monitor."))
                    || method.starts_with("io.rustd.service.")
            }
            Self::Monitor => {
                method.starts_with("org.varlink.service.")
                    || method.starts_with("io.rustd.Resolve.Monitor.")
            }
            Self::Any => true,
        }
    }

    fn interfaces(self) -> Vec<Value> {
        let mut interfaces = Vec::new();
        if matches!(self, Self::Resolve | Self::Any) {
            interfaces.push(Value::String("io.rustd.Resolve".to_owned()));
            interfaces.push(Value::String("io.rustd.service".to_owned()));
        }
        if matches!(self, Self::Monitor | Self::Any) {
            interfaces.push(Value::String("io.rustd.Resolve.Monitor".to_owned()));
        }
        interfaces.insert(0, Value::String("io.rustd".to_owned()));
        interfaces.push(Value::String("org.varlink.service".to_owned()));
        interfaces
    }

    fn description(self, interface: &str) -> Option<&'static str> {
        match (self, interface) {
            (Self::Resolve | Self::Monitor | Self::Any, "io.rustd") => {
                Some(RUSTD_INTERFACE_DESCRIPTION)
            }
            (Self::Resolve | Self::Any, "io.rustd.Resolve") => Some(INTERFACE_DESCRIPTION),
            (Self::Monitor | Self::Any, "io.rustd.Resolve.Monitor") => {
                Some(MONITOR_INTERFACE_DESCRIPTION)
            }
            (Self::Resolve | Self::Any, "io.rustd.service") => Some(SERVICE_INTERFACE_DESCRIPTION),
            (Self::Resolve | Self::Monitor | Self::Any, "org.varlink.service") => {
                Some(ORG_VARLINK_SERVICE_DESCRIPTION)
            }
            _ => None,
        }
    }
}
const INTERFACE_DESCRIPTION: &str = include_str!("../interfaces/io.rustd.Resolve.varlink");
const RUSTD_INTERFACE_DESCRIPTION: &str = include_str!("../interfaces/io.rustd.varlink");
const SERVICE_INTERFACE_DESCRIPTION: &str = include_str!("../interfaces/io.rustd.service.varlink");
const ORG_VARLINK_SERVICE_DESCRIPTION: &str =
    include_str!("../interfaces/org.varlink.service.varlink");

#[derive(Debug)]
pub struct VarlinkServer {
    path: PathBuf,
    monitor_path: PathBuf,
    using_socket_activation: bool,
    resolver: Arc<Resolver>,
    activated_sockets: Vec<ActivatedVarlinkSocket>,
    activated_monitor_sockets: Vec<ActivatedVarlinkSocket>,
}

impl VarlinkServer {
    pub fn new(path: impl Into<PathBuf>, resolver: Arc<Resolver>) -> io::Result<Self> {
        let (activated_sockets, activated_monitor_sockets) = take_activated_sockets()?;
        let using_socket_activation =
            !activated_sockets.is_empty() || !activated_monitor_sockets.is_empty();
        let path = path.into();
        let monitor_path = monitor_path_for(&path);
        Ok(Self {
            path,
            monitor_path,
            using_socket_activation,
            resolver,
            activated_sockets,
            activated_monitor_sockets,
        })
    }

    pub fn run(&self) -> io::Result<()> {
        let mut listeners = activated_listeners(&self.activated_sockets)?;
        let remove_path = !self.using_socket_activation && self.activated_sockets.is_empty();
        if remove_path {
            listeners.push(bind_varlink_listener(&self.path)?);
        }
        for listener in &listeners {
            listener.set_nonblocking(true)?;
        }

        let mut monitor_listeners = activated_listeners(&self.activated_monitor_sockets)?;
        let remove_monitor_path = !self.using_socket_activation
            && self.activated_monitor_sockets.is_empty()
            && self.monitor_path != self.path;
        if remove_monitor_path {
            monitor_listeners.push(bind_varlink_listener(&self.monitor_path)?);
        }
        for listener in &monitor_listeners {
            listener.set_nonblocking(true)?;
        }

        serve_activated_connections(
            &self.activated_sockets,
            &self.resolver,
            "resolved-varlink-client",
            "Resolve",
            VarlinkEndpoint::Resolve,
        )?;
        serve_activated_connections(
            &self.activated_monitor_sockets,
            &self.resolver,
            "resolved-varlink-monitor-client",
            "Resolve.Monitor",
            VarlinkEndpoint::Monitor,
        )?;

        while !stop_requested() {
            let mut accepted = false;
            for listener in &listeners {
                accepted |= accept_varlink_connection(
                    listener,
                    &self.resolver,
                    "resolved-varlink-client",
                    "Resolve",
                    VarlinkEndpoint::Resolve,
                )?;
            }
            for listener in &monitor_listeners {
                accepted |= accept_varlink_connection(
                    listener,
                    &self.resolver,
                    "resolved-varlink-monitor-client",
                    "Resolve.Monitor",
                    VarlinkEndpoint::Monitor,
                )?;
            }
            if !accepted {
                thread::sleep(Duration::from_millis(50));
            }
        }
        if remove_path {
            let _ = fs::remove_file(&self.path);
        }
        if remove_monitor_path {
            let _ = fs::remove_file(&self.monitor_path);
        }
        Ok(())
    }
}

fn activated_listeners(sockets: &[ActivatedVarlinkSocket]) -> io::Result<Vec<UnixListener>> {
    sockets
        .iter()
        .filter_map(|socket| match socket {
            ActivatedVarlinkSocket::Listener(listener) => Some(listener.try_clone()),
            ActivatedVarlinkSocket::Connection(_) => None,
        })
        .collect()
}

fn serve_activated_connections(
    sockets: &[ActivatedVarlinkSocket],
    resolver: &Arc<Resolver>,
    thread_name: &str,
    interface_name: &'static str,
    endpoint: VarlinkEndpoint,
) -> io::Result<()> {
    for socket in sockets {
        if let ActivatedVarlinkSocket::Connection(stream) = socket {
            spawn_varlink_connection(
                stream.try_clone()?,
                resolver,
                thread_name,
                interface_name,
                endpoint,
            )?;
        }
    }
    Ok(())
}

fn monitor_path_for(path: &Path) -> PathBuf {
    if path.file_name().and_then(|name| name.to_str()) == Some("io.rustd.Resolve") {
        return path.with_file_name("io.rustd.Resolve.Monitor");
    }
    let mut monitor = path.as_os_str().to_owned();
    monitor.push(".Monitor");
    PathBuf::from(monitor)
}

fn bind_varlink_listener(path: &Path) -> io::Result<UnixListener> {
    prepare_socket_path(path)?;
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o666))?;
    Ok(listener)
}

fn accept_varlink_connection(
    listener: &UnixListener,
    resolver: &Arc<Resolver>,
    thread_name: &str,
    interface_name: &'static str,
    endpoint: VarlinkEndpoint,
) -> io::Result<bool> {
    match listener.accept() {
        Ok((stream, _)) => {
            spawn_varlink_connection(stream, resolver, thread_name, interface_name, endpoint)?;
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
        Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(false),
        Err(error) => Err(error),
    }
}

fn spawn_varlink_connection(
    stream: UnixStream,
    resolver: &Arc<Resolver>,
    thread_name: &str,
    interface_name: &'static str,
    endpoint: VarlinkEndpoint,
) -> io::Result<()> {
    let resolver = Arc::clone(resolver);
    let peer_key = varlink_peer_key(&stream);
    if !varlink_executor().try_submit(peer_key, move || {
        if let Err(error) = serve_connection(stream, resolver, endpoint) {
            eprintln!("rustd-resolved: {interface_name} Varlink connection failed: {error}");
        }
    }) {
        eprintln!("rustd-resolved: rejected {thread_name} Varlink connection: executor overloaded");
    }
    Ok(())
}

fn varlink_peer_key(stream: &UnixStream) -> u64 {
    varlink_peer_key_from_fd(stream.as_raw_fd())
}

fn varlink_peer_key_from_fd(client_fd: RawFd) -> u64 {
    use std::hash::{Hash, Hasher};
    if let Ok(credentials) = crate::native::peer_credentials(client_fd) {
        return u64::from(credentials.uid) << 32 | u64::from(credentials.pid);
    }
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    client_fd.hash(&mut hasher);
    hasher.finish()
}

fn take_activated_sockets() -> io::Result<(Vec<ActivatedVarlinkSocket>, Vec<ActivatedVarlinkSocket>)>
{
    let names = env::var("LISTEN_FDNAMES").ok();
    let count = native::listen_fds()?;
    let (main_fds, monitor_fds) = activated_varlink_fds(count, names.as_deref())?;
    Ok((
        main_fds
            .into_iter()
            .map(activated_socket_from_fd)
            .collect::<io::Result<_>>()?,
        monitor_fds
            .into_iter()
            .map(activated_socket_from_fd)
            .collect::<io::Result<_>>()?,
    ))
}

fn activated_socket_from_fd(fd: RawFd) -> io::Result<ActivatedVarlinkSocket> {
    if native::socket_accepting(fd)? {
        // SAFETY: activated_varlink_fds returns each activation-owned descriptor at most once.
        let listener = unsafe { UnixListener::from_raw_fd(fd) };
        let _ = listener.local_addr()?;
        Ok(ActivatedVarlinkSocket::Listener(listener))
    } else {
        // SAFETY: activated_varlink_fds returns each activation-owned descriptor at most once.
        let stream = unsafe { UnixStream::from_raw_fd(fd) };
        let _ = stream.peer_addr()?;
        Ok(ActivatedVarlinkSocket::Connection(stream))
    }
}

fn activated_varlink_fds(
    count: usize,
    names: Option<&str>,
) -> io::Result<(Vec<RawFd>, Vec<RawFd>)> {
    if count == 0 {
        return Ok((Vec::new(), Vec::new()));
    }

    let parsed_names = names.map(|names| names.split(':').collect::<Vec<_>>());
    if let Some(names) = parsed_names.as_ref() {
        if names.len() != count {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "activated Varlink descriptor names do not match descriptor count",
            ));
        }
    }

    let Some(names) = parsed_names else {
        return Ok((Vec::new(), Vec::new()));
    };
    let mut main_fds = Vec::new();
    let mut monitor_fds = Vec::new();
    for index in 0..count {
        let fd = 3 + i32::try_from(index).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid activation descriptor index",
            )
        })?;
        match names[index] {
            "varlink" => main_fds.push(fd),
            "varlink-monitor" => monitor_fds.push(fd),
            _ => {}
        }
    }
    Ok((main_fds, monitor_fds))
}

#[cfg(test)]
fn fallback_listener_plan(
    using_socket_activation: bool,
    path: &Path,
    monitor_path: &Path,
    main_count: usize,
    monitor_count: usize,
) -> (bool, bool) {
    (
        !using_socket_activation && main_count == 0,
        !using_socket_activation && monitor_count == 0 && monitor_path != path,
    )
}

fn prepare_socket_path(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => fs::remove_file(path),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "refusing to replace a non-socket Varlink path",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn serve_connection(
    mut stream: UnixStream,
    resolver: Arc<Resolver>,
    endpoint: VarlinkEndpoint,
) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let authorization = VarlinkAuthorization::new(native::peer_credentials(stream.as_raw_fd())?);
    let mut pending = Vec::new();
    let mut chunk = [0; 8192];
    loop {
        if let Some(end) = pending.iter().position(|byte| *byte == 0) {
            let message: Vec<_> = pending.drain(..=end).collect();
            let text = match std::str::from_utf8(&message[..message.len() - 1]) {
                Ok(text) => text,
                Err(_) => {
                    write_varlink_reply(&mut stream, &invalid_parameter("message"))?;
                    continue;
                }
            };
            if let Some(subscription) = subscription_method(text) {
                if !endpoint.allows(subscription.name()) {
                    write_varlink_reply(&mut stream, &error("org.varlink.service.MethodNotFound"))?;
                    continue;
                }
                let request = json::parse(text).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid Varlink request")
                })?;
                if request.get("more").and_then(Value::as_bool) != Some(true) {
                    write_varlink_reply(&mut stream, &error("org.varlink.service.ExpectedMore"))?;
                    continue;
                }
                if let Err(reply) = validate_method_parameters(&request, subscription.name()) {
                    write_varlink_reply(&mut stream, &reply)?;
                    continue;
                }
                if let Some(action) = subscription.action() {
                    let decision = authorization.authorize(action, allow_interactive(&request));
                    if decision != AuthorizationDecision::Authorized {
                        write_varlink_reply(&mut stream, &authorization_error(decision))?;
                        continue;
                    }
                }
                return serve_subscription(&mut stream, &resolver, subscription, &request);
            }
            let request = json::parse(text).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid Varlink request")
            })?;
            if let Some(method) = request.get("method").and_then(Value::as_str) {
                if !endpoint.allows(method) {
                    write_varlink_reply(&mut stream, &error("org.varlink.service.MethodNotFound"))?;
                    continue;
                }
            }
            if let Some(method) = request.get("method").and_then(Value::as_str) {
                if let Err(reply) = validate_method_parameters(&request, method) {
                    write_varlink_reply(&mut stream, &reply)?;
                    continue;
                }
            }
            let service_control = if let Some(method) = request
                .get("method")
                .and_then(Value::as_str)
                .filter(|method| service_method(method))
            {
                if method == "io.rustd.service.Ping" {
                    false
                } else if !authorization.service_owner() {
                    write_varlink_reply(
                        &mut stream,
                        &error("org.varlink.service.PermissionDenied"),
                    )?;
                    continue;
                } else {
                    true
                }
            } else {
                false
            };
            let can_control = if let Some(action) = request
                .get("method")
                .and_then(Value::as_str)
                .and_then(control_action)
            {
                let decision = authorization.authorize(action, allow_interactive(&request));
                if decision != AuthorizationDecision::Authorized {
                    write_varlink_reply(&mut stream, &authorization_error(decision))?;
                    continue;
                }
                true
            } else {
                false
            };
            let Some(reply) = dispatch_cancellable(
                text,
                &resolver,
                can_control,
                service_control,
                endpoint,
                stream.as_raw_fd(),
            )?
            else {
                return Ok(());
            };
            write_varlink_reply(&mut stream, &reply)?;
            continue;
        }

        let length = stream.read(&mut chunk)?;
        if length == 0 {
            return Ok(());
        }
        pending.extend_from_slice(&chunk[..length]);
        if pending.len() > MAX_MESSAGE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Varlink message is too large",
            ));
        }
    }
}

fn dispatch_cancellable(
    input: &str,
    resolver: &Arc<Resolver>,
    can_control: bool,
    service_control: bool,
    endpoint: VarlinkEndpoint,
    client_fd: RawFd,
) -> io::Result<Option<Value>> {
    let cancellation = crate::query_cancel::QueryCancellation::default();
    let worker_cancellation = cancellation.clone();
    let resolver = Arc::clone(resolver);
    let input = input.to_owned();
    let (sender, receiver) = mpsc::channel();
    let peer_key = varlink_peer_key_from_fd(client_fd);
    if !varlink_executor().try_submit(peer_key, move || {
        let reply = crate::query_cancel::with(worker_cancellation, || {
            dispatch_for_endpoint_with_access(
                &input,
                &resolver,
                can_control,
                service_control,
                endpoint,
            )
        });
        let _ = sender.send(reply);
    }) {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Varlink request rejected: executor overloaded",
        ));
    }

    loop {
        match receiver.recv_timeout(Duration::from_millis(20)) {
            Ok(reply) => return Ok(Some(reply)),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if native::socket_disconnected(client_fd)? {
                    cancellation.cancel();
                    return Ok(None);
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Varlink request worker stopped without a reply",
                ));
            }
        }
    }
}

impl SubscriptionMethod {
    const fn name(self) -> &'static str {
        match self {
            Self::BrowseServices => "io.rustd.Resolve.BrowseServices",
            Self::QueryResults => "io.rustd.Resolve.Monitor.SubscribeQueryResults",
            Self::DnsConfiguration => "io.rustd.Resolve.Monitor.SubscribeDNSConfiguration",
        }
    }

    const fn action(self) -> Option<&'static str> {
        match self {
            Self::BrowseServices => None,
            Self::QueryResults => Some("io.rustd.resolve.subscribe-query-results"),
            Self::DnsConfiguration => Some("io.rustd.resolve.subscribe-dns-configuration"),
        }
    }
}

fn control_action(method: &str) -> Option<&'static str> {
    match method {
        "io.rustd.Resolve.Monitor.DumpCache" => Some("io.rustd.resolve.dump-cache"),
        "io.rustd.Resolve.Monitor.DumpServerState" => Some("io.rustd.resolve.dump-server-state"),
        "io.rustd.Resolve.Monitor.DumpStatistics" => Some("io.rustd.resolve.dump-statistics"),
        "io.rustd.Resolve.Monitor.ResetStatistics" | "io.rustd.Resolve.ResetStatistics" => {
            Some("io.rustd.resolve.reset-statistics")
        }
        "io.rustd.Resolve.FlushCaches" => Some("io.rustd.resolve.flush-caches"),
        "io.rustd.Resolve.ResetServerFeatures" => Some("io.rustd.resolve.reset-server-features"),
        _ => None,
    }
}

fn service_method(method: &str) -> bool {
    matches!(
        method,
        "io.rustd.service.Ping"
            | "io.rustd.service.Reload"
            | "io.rustd.service.SetLogLevel"
            | "io.rustd.service.GetEnvironment"
    )
}

fn allow_interactive(request: &Value) -> bool {
    request
        .get("parameters")
        .and_then(|parameters| parameters.get("allowInteractiveAuthentication"))
        .and_then(Value::as_bool)
        == Some(true)
}

fn authorization_error(decision: AuthorizationDecision) -> Value {
    match decision {
        AuthorizationDecision::Authorized => success(Value::Object(JsonObject::new())),
        AuthorizationDecision::PermissionDenied => error("org.varlink.service.PermissionDenied"),
        AuthorizationDecision::InteractiveAuthenticationRequired => {
            error("org.varlink.service.InteractiveAuthenticationRequired")
        }
    }
}

fn subscription_method(input: &str) -> Option<SubscriptionMethod> {
    let request = json::parse(input).ok()?;
    match request.get("method").and_then(Value::as_str)? {
        "io.rustd.Resolve.BrowseServices" => Some(SubscriptionMethod::BrowseServices),
        "io.rustd.Resolve.Monitor.SubscribeQueryResults" => Some(SubscriptionMethod::QueryResults),
        "io.rustd.Resolve.Monitor.SubscribeDNSConfiguration" => {
            Some(SubscriptionMethod::DnsConfiguration)
        }
        _ => None,
    }
}

fn serve_subscription(
    stream: &mut UnixStream,
    resolver: &Resolver,
    subscription: SubscriptionMethod,
    request: &Value,
) -> io::Result<()> {
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    match subscription {
        SubscriptionMethod::BrowseServices => serve_browse_services(stream, request),
        SubscriptionMethod::QueryResults => serve_query_results(stream, resolver),
        SubscriptionMethod::DnsConfiguration => serve_dns_configuration(stream, resolver),
    }
}

fn serve_browse_services(stream: &mut UnixStream, request: &Value) -> io::Result<()> {
    let parameters = request
        .get("parameters")
        .cloned()
        .unwrap_or_else(|| Value::Object(JsonObject::new()));
    let domain = match optional_string(&parameters, "domain") {
        Ok(Some(value)) if valid_dns_domain(&value) => value,
        Ok(Some(_)) | Err(_) => {
            return write_varlink_reply(stream, &invalid_parameter("domain"));
        }
        Ok(None) => "local".to_owned(),
    };
    let service_type = match optional_string(&parameters, "type") {
        Ok(Some(value)) if service_type_is_valid(&value) => Some(value),
        Ok(Some(_)) | Err(_) => {
            return write_varlink_reply(stream, &invalid_parameter("type"));
        }
        Ok(None) => None,
    };
    let ifindex = match optional_ifindex(&parameters, "ifindex") {
        Ok(value) if value >= 0 => value,
        Ok(_) | Err(_) => {
            return write_varlink_reply(stream, &invalid_parameter("ifindex"));
        }
    };
    let flags = match optional_u64(&parameters, "flags", 0) {
        Ok(value) if browse_flags_are_valid(value) => value,
        Ok(_) | Err(_) => {
            return write_varlink_reply(stream, &invalid_parameter("flags"));
        }
    };
    if std::env::var_os("RUSTD_RESOLVED_QUERY_DIAGNOSTICS").is_some() {
        eprintln!(
            "rustd-resolved: BrowseServices request={} decoded-domain={domain:?} decoded-type={service_type:?} ifindex={ifindex} flags={flags}",
            request.to_json()
        );
    }
    let mut browser = match crate::mdns::runtime::MdnsBrowser::new(
        &domain,
        service_type.as_deref(),
        (ifindex > 0).then_some(ifindex),
        flags,
    ) {
        Ok(browser) => browser,
        Err(error) => {
            return write_varlink_reply(
                stream,
                &Value::object([
                    (
                        "error",
                        Value::String("io.rustd.Resolve.NoSuchResourceRecord".to_owned()),
                    ),
                    (
                        "parameters",
                        Value::object([("message", Value::String(error.to_string()))]),
                    ),
                ]),
            );
        }
    };
    loop {
        if stop_requested() || native::socket_disconnected(stream.as_raw_fd())? {
            return Ok(());
        }
        let updates = browser.poll(Duration::from_millis(250)).map_err(|error| {
            io::Error::new(io::ErrorKind::Other, format!("mDNS browse failed: {error}"))
        })?;
        if updates.is_empty() {
            continue;
        }
        write_varlink_reply(
            stream,
            &continued(Value::object([(
                "browserServiceData",
                Value::Array(updates.into_iter().map(browse_service_data).collect()),
            )])),
        )?;
    }
}

fn validate_method_parameters(request: &Value, method: &str) -> Result<(), Value> {
    let parameters = request
        .get("parameters")
        .cloned()
        .unwrap_or_else(|| Value::Object(JsonObject::new()));
    validate_parameter_names(&parameters, method_parameter_names(method))?;
    validate_parameter_types(&parameters, method)
}

fn validate_parameter_types(parameters: &Value, method: &str) -> Result<(), Value> {
    let Value::Object(parameters) = parameters else {
        return Ok(());
    };
    match method {
        "org.varlink.service.GetInterfaceDescription" => {
            if !matches!(parameters.get("interface"), Some(Value::String(_))) {
                return Err(invalid_parameter("interface"));
            }
        }
        "io.rustd.service.Reload" => {
            if let Some(value) = parameters.get("allowInteractiveAuthentication") {
                if !matches!(value, Value::Null | Value::Bool(_)) {
                    return Err(invalid_parameter("allowInteractiveAuthentication"));
                }
            }
        }
        "io.rustd.service.SetLogLevel" => {
            if !matches!(
                parameters.get("level"),
                Some(Value::Null | Value::Number(_))
            ) {
                return Err(invalid_parameter("level"));
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_parameter_names(parameters: &Value, allowed: Option<&[&str]>) -> Result<(), Value> {
    let (Value::Object(parameters), Some(allowed)) = (parameters, allowed) else {
        return Ok(());
    };
    if let Some(parameter) = parameters
        .keys()
        .find(|parameter| !allowed.contains(parameter))
    {
        return Err(invalid_parameter(parameter));
    }
    Ok(())
}

fn method_parameter_names(method: &str) -> Option<&'static [&'static str]> {
    match method {
        "org.varlink.service.GetInfo" => Some(&[]),
        "org.varlink.service.GetInterfaceDescription" => Some(&["interface"]),
        "io.rustd.service.Ping" | "io.rustd.service.GetEnvironment" => Some(&[]),
        "io.rustd.service.Reload" => Some(&["allowInteractiveAuthentication"]),
        "io.rustd.service.SetLogLevel" => Some(&["level"]),
        "io.rustd.Resolve.ResolveHostname" => Some(&["ifindex", "name", "family", "flags"]),
        "io.rustd.Resolve.ResolveAddress" => Some(&["ifindex", "family", "address", "flags"]),
        "io.rustd.Resolve.ResolveService" => {
            Some(&["name", "type", "domain", "ifindex", "family", "flags"])
        }
        "io.rustd.Resolve.ResolveRecord" => Some(&["ifindex", "name", "class", "type", "flags"]),
        "io.rustd.Resolve.BrowseServices" => Some(&["domain", "type", "ifindex", "flags"]),
        "io.rustd.Resolve.DumpDNSConfiguration" | "io.rustd.Resolve.GetStatistics" => Some(&[]),
        "io.rustd.Resolve.Monitor.SubscribeQueryResults"
        | "io.rustd.Resolve.Monitor.SubscribeDNSConfiguration"
        | "io.rustd.Resolve.Monitor.DumpCache"
        | "io.rustd.Resolve.Monitor.DumpServerState"
        | "io.rustd.Resolve.Monitor.DumpStatistics"
        | "io.rustd.Resolve.Monitor.ResetStatistics"
        | "io.rustd.Resolve.FlushCaches"
        | "io.rustd.Resolve.ResetServerFeatures"
        | "io.rustd.Resolve.ResetStatistics" => Some(&["allowInteractiveAuthentication"]),
        _ => None,
    }
}

fn browse_service_data(update: crate::mdns::runtime::MdnsBrowseUpdate) -> Value {
    Value::object([
        (
            "updateFlag",
            Value::String(if update.added { "added" } else { "removed" }.to_owned()),
        ),
        ("family", Value::Number(i128::from(update.family))),
        ("name", Value::String(update.name)),
        ("type", Value::String(update.service_type)),
        ("domain", Value::String(update.domain)),
        ("ifindex", Value::Number(i128::from(update.ifindex))),
    ])
}

fn valid_dns_domain(domain: &str) -> bool {
    make_query(domain, TYPE_PTR, 0).is_ok()
}

const fn browse_flags_are_valid(flags: u64) -> bool {
    const PROTOCOLS: u64 = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4);
    const MDNS: u64 = (1 << 3) | (1 << 4);
    const ALLOWED: u64 = (1 << 0)
        | (1 << 1)
        | (1 << 2)
        | (1 << 3)
        | (1 << 4)
        | (1 << 5)
        | (1 << 9)
        | (1 << 10)
        | (1 << 11)
        | (1 << 12)
        | (1 << 13)
        | (1 << 14)
        | (1 << 15)
        | (1 << 18)
        | (1 << 19)
        | (1 << 24)
        | (1 << 25);
    let protocols = flags & PROTOCOLS;
    flags & !ALLOWED == 0 && (protocols == 0 || protocols & MDNS != 0)
}

fn serve_query_results(stream: &mut UnixStream, resolver: &Resolver) -> io::Result<()> {
    let mut cursor = resolver.query_monitor_cursor();
    write_varlink_reply(
        stream,
        &continued(Value::object([("ready", Value::Bool(true))])),
    )?;
    loop {
        if stop_requested() || native::socket_disconnected(stream.as_raw_fd())? {
            return Ok(());
        }
        let Some(event) = resolver.wait_query_event(cursor, Duration::from_millis(250)) else {
            continue;
        };
        cursor = event.sequence;
        write_varlink_reply(stream, &continued(monitor_query_event(event)))?;
    }
}

fn serve_dns_configuration(stream: &mut UnixStream, resolver: &Resolver) -> io::Result<()> {
    let mut generation = resolver.configuration_generation();
    write_varlink_reply(stream, &continued(dns_configuration_parameters(resolver)))?;
    loop {
        if stop_requested() || native::socket_disconnected(stream.as_raw_fd())? {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
        let current = resolver.configuration_generation();
        if current == generation {
            continue;
        }
        generation = current;
        write_varlink_reply(stream, &continued(dns_configuration_parameters(resolver)))?;
    }
}

fn dns_configuration_parameters(resolver: &Resolver) -> Value {
    dump_dns_configuration(resolver)
        .get("parameters")
        .cloned()
        .unwrap_or_else(|| Value::Object(JsonObject::new()))
}

fn continued(parameters: Value) -> Value {
    Value::object([("parameters", parameters), ("continues", Value::Bool(true))])
}

fn write_varlink_reply(stream: &mut UnixStream, reply: &Value) -> io::Result<()> {
    stream.write_all(reply.to_json().as_bytes())?;
    stream.write_all(&[0])
}

fn set_log_level(service_control: bool, parameters: &Value) -> Value {
    if !service_control {
        return error("org.varlink.service.PermissionDenied");
    }
    let level = match parameters.get("level") {
        Some(Value::Null) => 6,
        Some(Value::Number(level)) => match i32::try_from(*level) {
            Ok(level) if (0..=7).contains(&level) => level,
            _ => return invalid_parameter("level"),
        },
        Some(_) | None => return invalid_parameter("level"),
    };
    if !LogControlState::global().set_level(level) {
        return invalid_parameter("level");
    }
    success(Value::Object(JsonObject::new()))
}

fn get_environment(service_control: bool) -> Value {
    if !service_control {
        return error("org.varlink.service.PermissionDenied");
    }
    match collect_environment() {
        Ok(environment) => success(Value::object([(
            "environment",
            Value::Array(environment.into_iter().map(Value::String).collect()),
        )])),
        Err(()) => error("io.rustd.service.InconsistentEnvironment"),
    }
}

fn collect_environment() -> Result<Vec<String>, ()> {
    collect_environment_entries(native::environment_entries())
}

fn collect_environment_entries<I>(raw_entries: I) -> Result<Vec<String>, ()>
where
    I: IntoIterator<Item = Vec<u8>>,
{
    let mut entries = Vec::new();
    let mut indices = HashMap::new();
    let max_length = native::environment_max_length();
    for entry in raw_entries {
        if entry.len() > max_length.saturating_sub(1) {
            return Err(());
        }
        let Some(separator) = entry.iter().position(|byte| *byte == b'=') else {
            return Err(());
        };
        let key_bytes = &entry[..separator];
        let value_bytes = &entry[separator + 1..];
        if !valid_environment_name(key_bytes) {
            return Err(());
        }
        if value_bytes.len() > max_length.saturating_sub(3) {
            return Err(());
        }
        let key = std::str::from_utf8(key_bytes).map_err(|_| ())?;
        let value = std::str::from_utf8(value_bytes).map_err(|_| ())?;
        let assignment = format!("{key}={value}");
        if let Some(index) = indices.get(key).copied() {
            entries[index] = assignment;
        } else {
            indices.insert(key.to_owned(), entries.len());
            entries.push(assignment);
        }
    }
    Ok(entries)
}

fn valid_environment_name(name: &[u8]) -> bool {
    let Some((&first, rest)) = name.split_first() else {
        return false;
    };
    (first == b'_' || first.is_ascii_alphabetic())
        && rest
            .iter()
            .all(|byte| *byte == b'_' || byte.is_ascii_alphanumeric())
}

pub fn dispatch(input: &str, resolver: &Resolver) -> Value {
    dispatch_with_access(input, resolver, false)
}

fn dispatch_with_access(input: &str, resolver: &Resolver, can_control: bool) -> Value {
    dispatch_for_endpoint(input, resolver, can_control, VarlinkEndpoint::Any)
}

fn dispatch_for_endpoint(
    input: &str,
    resolver: &Resolver,
    can_control: bool,
    endpoint: VarlinkEndpoint,
) -> Value {
    dispatch_for_endpoint_with_access(input, resolver, can_control, false, endpoint)
}

fn dispatch_for_endpoint_with_access(
    input: &str,
    resolver: &Resolver,
    can_control: bool,
    service_control: bool,
    endpoint: VarlinkEndpoint,
) -> Value {
    let Ok(request) = json::parse(input) else {
        return invalid_parameter("message");
    };
    let Some(method) = request.get("method").and_then(Value::as_str) else {
        return invalid_parameter("method");
    };
    if !endpoint.allows(method) {
        return error("org.varlink.service.MethodNotFound");
    }
    let parameters = request
        .get("parameters")
        .cloned()
        .unwrap_or_else(|| Value::Object(JsonObject::new()));
    if let Err(reply) = validate_method_parameters(&request, method) {
        return reply;
    }

    match method {
        "org.varlink.service.GetInfo" => success(Value::object([
            ("vendor", Value::String("SisyphusAeolides".to_owned())),
            ("product", Value::String("rustd-resolved".to_owned())),
            ("version", Value::String(crate::VERSION.to_owned())),
            (
                "url",
                Value::String("https://github.com/SisyphusAeolides/rustd-resolved".to_owned()),
            ),
            ("interfaces", Value::Array(endpoint.interfaces())),
        ])),
        "org.varlink.service.GetInterfaceDescription" => {
            let description = parameters
                .get("interface")
                .and_then(Value::as_str)
                .and_then(|interface| endpoint.description(interface));
            description.map_or_else(
                || error("org.varlink.service.InterfaceNotFound"),
                |description| {
                    success(Value::object([(
                        "description",
                        Value::String(description.to_owned()),
                    )]))
                },
            )
        }
        "io.rustd.service.Ping" => success(Value::Object(JsonObject::new())),
        "io.rustd.service.Reload" => {
            if service_control {
                crate::daemon::request_reload();
                success(Value::Object(JsonObject::new()))
            } else {
                error("org.varlink.service.PermissionDenied")
            }
        }
        "io.rustd.service.SetLogLevel" => set_log_level(service_control, &parameters),
        "io.rustd.service.GetEnvironment" => get_environment(service_control),
        "io.rustd.Resolve.ResolveHostname" => resolve_hostname(&parameters, resolver),
        "io.rustd.Resolve.ResolveAddress" => resolve_address(&parameters, resolver),
        "io.rustd.Resolve.ResolveRecord" => resolve_record(&parameters, resolver),
        "io.rustd.Resolve.ResolveService" => resolve_service(&parameters, resolver),
        "io.rustd.Resolve.DumpDNSConfiguration" => dump_dns_configuration(resolver),
        "io.rustd.Resolve.Monitor.DumpCache" => monitor_dump_cache(can_control, resolver),
        "io.rustd.Resolve.Monitor.DumpServerState" => {
            monitor_dump_server_state(can_control, resolver)
        }
        "io.rustd.Resolve.Monitor.DumpStatistics" => monitor_dump_statistics(can_control, resolver),
        "io.rustd.Resolve.Monitor.ResetStatistics" => {
            monitor_reset_statistics(can_control, resolver)
        }
        "io.rustd.Resolve.FlushCaches" => control(can_control, || resolver.flush_cache()),
        "io.rustd.Resolve.ResetServerFeatures" => {
            control(can_control, || resolver.reset_server_features())
        }
        "io.rustd.Resolve.ResetStatistics" => control(can_control, || resolver.reset_statistics()),
        "io.rustd.Resolve.GetStatistics" => statistics(resolver),
        _ => error("org.varlink.service.MethodNotFound"),
    }
}

include!("varlink_dns_configuration.rs");
include!("varlink_monitor.rs");

fn resolve_hostname(parameters: &Value, resolver: &Resolver) -> Value {
    let Some(name) = parameters.get("name").and_then(Value::as_str) else {
        return invalid_parameter("name");
    };
    if make_query(name, TYPE_A, 0).is_err() {
        return invalid_parameter("name");
    }
    let family = match optional_i32(parameters, "family", 0) {
        Ok(value @ (0 | 2 | 10)) => value,
        Ok(_) => return invalid_parameter("family"),
        Err(error) => return error,
    };
    let ifindex = match optional_ifindex(parameters, "ifindex") {
        Ok(value) if value >= 0 => value,
        Ok(_) => return invalid_parameter("ifindex"),
        Err(error) => return error,
    };
    let flags = match optional_u64(parameters, "flags", 0) {
        Ok(value) if crate::resolver::query_flags_are_valid(value, RUSTD_RESOLVE_NO_SEARCH) => {
            value
        }
        Ok(_) | Err(_) => return invalid_parameter("flags"),
    };

    match resolver.lookup_name_on_link_with_request_flags(
        name,
        family,
        (ifindex > 0).then_some(ifindex),
        flags,
    ) {
        Ok(result) => {
            let addresses = result
                .addresses
                .into_iter()
                .zip(result.address_ifindices)
                .map(|(address, answer_ifindex)| {
                    resolved_address(address, answer_ifindex.or((ifindex > 0).then_some(ifindex)))
                })
                .collect();
            success(Value::object([
                ("addresses", Value::Array(addresses)),
                ("name", Value::String(result.canonical_name)),
                ("flags", Value::Number(i128::from(result.flags))),
            ]))
        }
        Err(error) => resolver_error(&error),
    }
}

fn resolve_address(parameters: &Value, resolver: &Resolver) -> Value {
    let Some(values) = parameters.get("address").and_then(Value::as_array) else {
        return invalid_parameter("address");
    };
    let family = match required_i32(parameters, "family") {
        Ok(value @ (2 | 10)) => value,
        Ok(_) => return invalid_parameter("family"),
        Err(error) => return error,
    };
    let ifindex = match optional_ifindex(parameters, "ifindex") {
        Ok(value) if value >= 0 => value,
        Ok(_) => return invalid_parameter("ifindex"),
        Err(error) => return error,
    };
    let flags = match optional_u64(parameters, "flags", 0) {
        Ok(value) if crate::resolver::query_flags_are_valid(value, 0) => value,
        Ok(_) | Err(_) => return invalid_parameter("flags"),
    };
    let Some(octets) = values
        .iter()
        .map(|value| value.as_u64().and_then(|number| u8::try_from(number).ok()))
        .collect::<Option<Vec<_>>>()
    else {
        return invalid_parameter("address");
    };
    let address = match (family, octets.as_slice()) {
        (2, [a, b, c, d]) => IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)),
        (10, bytes) if bytes.len() == 16 => {
            let mut address = [0; 16];
            address.copy_from_slice(bytes);
            IpAddr::V6(Ipv6Addr::from(address))
        }
        _ => return error("io.rustd.Resolve.BadAddressSize"),
    };

    match resolver.lookup_address_on_link_with_request_flags(
        address,
        (ifindex > 0).then_some(ifindex),
        flags,
    ) {
        Ok(result) => {
            let names = result
                .names
                .into_iter()
                .zip(result.name_ifindices)
                .map(|(name, answer_ifindex)| {
                    resolved_name(name, answer_ifindex.unwrap_or(ifindex).max(0))
                })
                .collect();
            success(Value::object([
                ("names", Value::Array(names)),
                ("flags", Value::Number(i128::from(result.flags))),
            ]))
        }
        Err(error) => resolver_error(&error),
    }
}

#[derive(Debug)]
struct ServiceQuestion {
    owner: String,
    unicast_owner: String,
    name: Option<String>,
    service_type: String,
    domain: String,
}

#[derive(Debug)]
struct ServiceRequest {
    question: ServiceQuestion,
    family: i32,
    ifindex: i32,
    flags: u64,
}

#[derive(Debug)]
struct ServiceEntries {
    values: Vec<Value>,
    root_target: bool,
    last_address_error: Option<ResolveError>,
}

type ServiceRecordResult = Result<(Vec<u8>, String, u64, Option<i32>), ResolveError>;

fn resolve_service(parameters: &Value, resolver: &Resolver) -> Value {
    let mut request = match service_request(parameters) {
        Ok(request) => request,
        Err(error) => return error,
    };
    if resolver.config().refuse_record_types.contains(&TYPE_SRV) {
        return error("io.rustd.Resolve.QueryRefused");
    }
    apply_refused_service_flags(&mut request, resolver);
    let (srv_result, txt_result) = resolve_service_primary_records(resolver, &request);
    let (srv_response, srv_canonical_name, srv_flags, _) = match srv_result {
        Ok(response) => response,
        Err(error) => return resolver_error(&error),
    };
    let Ok(records) = extract_service_records_for_name(&srv_response, &srv_canonical_name) else {
        return error("io.rustd.Resolve.InvalidReply");
    };
    let Some((name, service_type, domain)) = split_service_owner(&srv_canonical_name) else {
        return error("io.rustd.Resolve.InconsistentServiceRecords");
    };
    let canonical_question = ServiceQuestion {
        owner: srv_canonical_name.clone(),
        unicast_owner: srv_canonical_name,
        name,
        service_type,
        domain,
    };
    let entries = resolve_service_entries(records, resolver, &request);
    if entries.values.is_empty() {
        if entries.root_target {
            return error("io.rustd.Resolve.ServiceNotProvided");
        }
        if let Some(address_error) = entries.last_address_error {
            return resolver_error(&address_error);
        }
        return error("io.rustd.Resolve.NoSuchResourceRecord");
    }

    let mut output = service_parameters(entries.values);
    let txt_flags = match add_service_txt(&mut output, &canonical_question.owner, txt_result) {
        Ok(flags) => flags,
        Err(error) => return error,
    };
    let response_flags = txt_flags.map_or(srv_flags, |flags| {
        crate::resolver::merge_parallel_response_flags(Some(srv_flags), flags)
    });
    add_service_metadata(&mut output, &canonical_question, response_flags);
    success(Value::Object(output))
}

fn resolve_service_primary_records(
    resolver: &Resolver,
    request: &ServiceRequest,
) -> (ServiceRecordResult, Option<ServiceRecordResult>) {
    let lookup = |rr_type, after_grouped_hook| {
        let lookup = if after_grouped_hook {
            Resolver::resolve_record_on_link_with_request_flags_and_canonical_dual_after_grouped_hook
        } else {
            Resolver::resolve_record_on_link_with_request_flags_and_canonical_dual
        };
        lookup(
            resolver,
            &request.question.owner,
            &request.question.unicast_owner,
            CLASS_IN,
            rr_type,
            (request.ifindex > 0).then_some(request.ifindex),
            request.flags | RUSTD_RESOLVE_NO_SEARCH,
        )
    };
    if request.flags & RUSTD_RESOLVE_NO_TXT != 0 {
        return (lookup(TYPE_SRV, false), None);
    }
    let grouped = resolver.grouped_hook_record_response_dual(
        &request.question.owner,
        &request.question.unicast_owner,
        &[TYPE_SRV, TYPE_TXT],
        (request.ifindex > 0).then_some(request.ifindex),
        request.flags | RUSTD_RESOLVE_NO_SEARCH,
    );
    match grouped {
        Err(error) => (Err(error), None),
        Ok((_, Some((response, flags, response_ifindex)))) => {
            let (rcode, extended_dns_error_code, extended_dns_error_message) =
                match crate::resolver::response_full_rcode(&response) {
                    Ok(value) => value,
                    Err(error) => return (Err(error), None),
                };
            if rcode != 0 {
                let make_error =
                    |extended_dns_error_message: Option<String>| ResolveError::DnsError {
                        rcode,
                        query: request.question.owner.clone(),
                        extended_dns_error_code,
                        extended_dns_error_message,
                    };
                return (
                    Err(make_error(extended_dns_error_message.clone())),
                    Some(Err(make_error(extended_dns_error_message))),
                );
            }
            let canonical_name = match wire::classify_redirect_answer(&response) {
                Ok(wire::RedirectAnswer::Direct { canonical_name, .. }) => canonical_name,
                Ok(wire::RedirectAnswer::Redirect { .. }) => {
                    return (
                        Err(ResolveError::NoSuchResourceRecord),
                        Some(Err(ResolveError::NoSuchResourceRecord)),
                    )
                }
                Ok(wire::RedirectAnswer::NoData) => {
                    return (
                        Err(ResolveError::NoSuchResourceRecord),
                        Some(Err(ResolveError::NoSuchResourceRecord)),
                    )
                }
                Err(error) => return (Err(error.into()), None),
            };
            let result = || {
                Ok((
                    response.clone(),
                    canonical_name.clone(),
                    flags,
                    response_ifindex,
                ))
            };
            (result(), Some(result()))
        }
        Ok((grouped_hook_checked, None)) => resolve_service_primary_records_parallel(
            |rr_type| lookup(rr_type, grouped_hook_checked),
            true,
        ),
    }
}

fn resolve_service_primary_records_parallel(
    lookup: impl Fn(u16) -> ServiceRecordResult + Sync,
    include_txt: bool,
) -> (ServiceRecordResult, Option<ServiceRecordResult>) {
    if !include_txt {
        return (lookup(TYPE_SRV), None);
    }
    let cancellation = crate::query_cancel::current();
    thread::scope(|scope| {
        let txt =
            scope.spawn(|| crate::query_cancel::with_optional(cancellation, || lookup(TYPE_TXT)));
        let srv = lookup(TYPE_SRV);
        let txt = txt
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
        (srv, Some(txt))
    })
}

fn apply_refused_service_flags(request: &mut ServiceRequest, resolver: &Resolver) {
    let refused = &resolver.config().refuse_record_types;
    if refused.contains(&TYPE_A) && refused.contains(&TYPE_AAAA) {
        request.flags |= RUSTD_RESOLVE_NO_ADDRESS;
    }
    if refused.contains(&TYPE_TXT) {
        request.flags |= RUSTD_RESOLVE_NO_TXT;
    }
}

fn service_request(parameters: &Value) -> Result<ServiceRequest, Value> {
    let name = optional_string(parameters, "name")?;
    let service_type = optional_string(parameters, "type")?;
    let domain = parameters
        .get("domain")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_parameter("domain"))?;
    let family @ (0 | 2 | 10) = optional_i32(parameters, "family", 0)? else {
        return Err(invalid_parameter("family"));
    };
    let ifindex = optional_ifindex(parameters, "ifindex")?;
    if ifindex < 0 {
        return Err(invalid_parameter("ifindex"));
    }
    let flags = optional_u64(parameters, "flags", 0)?;
    if !crate::resolver::query_flags_are_valid(
        flags,
        RUSTD_RESOLVE_NO_ADDRESS | RUSTD_RESOLVE_NO_TXT,
    ) {
        return Err(invalid_parameter("flags"));
    }
    if name
        .as_deref()
        .is_some_and(|value| !service_instance_is_valid(value))
    {
        return Err(invalid_parameter("name"));
    }
    if service_type
        .as_deref()
        .is_some_and(|value| !service_type_is_valid(value))
    {
        return Err(invalid_parameter("type"));
    }
    if name.is_some() && service_type.is_none() {
        return Err(invalid_parameter("type"));
    }
    let Some(question) = service_question(name.as_deref(), service_type.as_deref(), domain) else {
        return Err(invalid_parameter("domain"));
    };
    Ok(ServiceRequest {
        question,
        family,
        ifindex,
        flags,
    })
}

fn resolve_service_entries(
    records: crate::wire::ServiceRecords,
    resolver: &Resolver,
    request: &ServiceRequest,
) -> ServiceEntries {
    let mut root_target = false;
    let mut values = Vec::new();
    let mut last_address_error = None;
    for record in records.srv {
        if record.target.text() == "." {
            root_target = true;
            continue;
        }
        let mut fields = JsonObject::from([
            (
                "priority".to_owned(),
                Value::Number(i128::from(record.priority)),
            ),
            (
                "weight".to_owned(),
                Value::Number(i128::from(record.weight)),
            ),
            ("port".to_owned(), Value::Number(i128::from(record.port))),
            (
                "hostname".to_owned(),
                Value::String(record.target.text().to_owned()),
            ),
        ]);
        if request.flags & RUSTD_RESOLVE_NO_ADDRESS == 0 {
            if std::env::var_os("RUSTD_RESOLVED_QUERY_DIAGNOSTICS").is_some() {
                eprintln!(
                    "rustd-resolved: ResolveService target={:?} family={} ifindex={} flags={:#x}",
                    record.target.text(),
                    request.family,
                    request.ifindex,
                    request.flags
                );
            }
            let lookup = match resolver.lookup_name_on_link_with_request_flags(
                record.target.text(),
                request.family,
                (request.ifindex > 0).then_some(request.ifindex),
                request.flags | RUSTD_RESOLVE_NO_SEARCH,
            ) {
                Ok(lookup) => lookup,
                Err(error) => {
                    last_address_error = Some(error);
                    continue;
                }
            };
            let addresses = lookup
                .addresses
                .into_iter()
                .zip(lookup.address_ifindices)
                .map(|(address, answer_ifindex)| {
                    resolved_service_address(
                        address,
                        answer_ifindex.or((request.ifindex > 0).then_some(request.ifindex)),
                    )
                })
                .collect();
            fields.insert(
                "canonicalName".to_owned(),
                Value::String(lookup.canonical_name),
            );
            fields.insert("addresses".to_owned(), Value::Array(addresses));
        }
        values.push(Value::Object(fields));
    }
    ServiceEntries {
        values,
        root_target,
        last_address_error,
    }
}

fn service_parameters(services: Vec<Value>) -> JsonObject {
    JsonObject::from([("services".to_owned(), Value::Array(services))])
}

fn add_service_metadata(output: &mut JsonObject, question: &ServiceQuestion, response_flags: u64) {
    output.insert(
        "canonical".to_owned(),
        Value::object([
            (
                "name",
                question
                    .name
                    .as_ref()
                    .map_or(Value::Null, |name| Value::String(name.clone())),
            ),
            ("type", Value::String(question.service_type.clone())),
            ("domain", Value::String(question.domain.clone())),
        ]),
    );
    output.insert(
        "flags".to_owned(),
        Value::Number(i128::from(response_flags)),
    );
}

fn add_service_txt(
    output: &mut JsonObject,
    owner: &str,
    result: Option<ServiceRecordResult>,
) -> Result<Option<u64>, Value> {
    let Some(result) = result else {
        return Ok(None);
    };
    let (response, _, response_flags, _) = match result {
        Ok(response) => response,
        Err(_) => return Ok(None),
    };
    let Ok(records) = extract_service_records_for_name(&response, owner) else {
        return Err(error("io.rustd.Resolve.InvalidReply"));
    };
    if !records.txt.is_empty() {
        output.insert(
            "txt".to_owned(),
            Value::Array(
                records
                    .txt
                    .iter()
                    .map(|item| Value::String(octescape(item)))
                    .collect(),
            ),
        );
    }
    Ok(Some(response_flags))
}

fn resolved_address(address: IpAddr, ifindex: Option<i32>) -> Value {
    let (family, bytes): (i32, Vec<u8>) = match address {
        IpAddr::V4(address) => (2, address.octets().to_vec()),
        IpAddr::V6(address) => (10, address.octets().to_vec()),
    };
    let mut fields = JsonObject::new();
    if let Some(ifindex) = ifindex.filter(|value| *value > 0) {
        fields.insert("ifindex".to_owned(), Value::Number(i128::from(ifindex)));
    }
    fields.insert("family".to_owned(), Value::Number(i128::from(family)));
    fields.insert(
        "address".to_owned(),
        Value::Array(
            bytes
                .into_iter()
                .map(|byte| Value::Number(i128::from(byte)))
                .collect(),
        ),
    );
    Value::Object(fields)
}

fn resolved_service_address(address: IpAddr, ifindex: Option<i32>) -> Value {
    let (family, bytes): (i32, Vec<u8>) = match address {
        IpAddr::V4(address) => (2, address.octets().to_vec()),
        IpAddr::V6(address) => (10, address.octets().to_vec()),
    };
    let mut fields = JsonObject::new();
    if let Some(ifindex) = ifindex.filter(|value| *value > 0) {
        fields.insert("ifindex".to_owned(), Value::Number(i128::from(ifindex)));
    }
    fields.insert("family".to_owned(), Value::Number(i128::from(family)));
    fields.insert(
        "address".to_owned(),
        Value::Array(
            bytes
                .into_iter()
                .map(|byte| Value::Number(i128::from(byte)))
                .collect(),
        ),
    );
    Value::Object(fields)
}

fn resolved_name(name: String, ifindex: i32) -> Value {
    let mut fields = JsonObject::from([("name".to_owned(), Value::String(name))]);
    if ifindex > 0 {
        fields.insert("ifindex".to_owned(), Value::Number(i128::from(ifindex)));
    }
    Value::Object(fields)
}

fn service_question(
    name: Option<&str>,
    service_type: Option<&str>,
    domain: &str,
) -> Option<ServiceQuestion> {
    let name = name.filter(|value| !value.is_empty());
    let service_type = service_type.filter(|value| !value.is_empty());
    if make_query(domain, TYPE_SRV, 0).is_err()
        || name.is_some_and(|value| !service_instance_is_valid(value))
    {
        return None;
    }

    let (canonical_name, canonical_type, canonical_domain, owner, unicast_owner) =
        if let Some(service_type) = service_type {
            if !service_type_is_valid(service_type) {
                return None;
            }
            let service_type = service_type.strip_suffix('.').unwrap_or(service_type);
            let escaped_name = name
                .map(str::as_bytes)
                .map(crate::wire::escape_label)
                .transpose()
                .ok()?;
            let prefix = if let Some(name) = &escaped_name {
                format!("{name}.{service_type}")
            } else {
                service_type.to_owned()
            };
            let owner = if domain == "." {
                prefix.clone()
            } else {
                format!("{prefix}.{domain}")
            };
            let unicast_domain =
                crate::idna_name::to_ascii(domain).unwrap_or_else(|_| domain.to_owned());
            let unicast_owner = if unicast_domain == "." {
                prefix
            } else {
                format!("{prefix}.{unicast_domain}")
            };
            (
                name.map(str::to_owned),
                service_type.to_ascii_lowercase(),
                domain
                    .strip_suffix('.')
                    .filter(|domain| !domain.is_empty())
                    .unwrap_or(domain)
                    .to_ascii_lowercase(),
                owner,
                unicast_owner,
            )
        } else {
            if name.is_some() {
                return None;
            }
            let owner = domain.to_owned();
            let (name, service_type, canonical_domain) = split_service_owner(domain)
                .unwrap_or_else(|| (None, String::new(), domain.to_owned()));
            (name, service_type, canonical_domain, owner.clone(), owner)
        };
    make_query(&owner, TYPE_SRV, 0).ok()?;
    make_query(&unicast_owner, TYPE_SRV, 0).ok()?;
    Some(ServiceQuestion {
        owner,
        unicast_owner,
        name: canonical_name,
        service_type: canonical_type,
        domain: canonical_domain,
    })
}

fn split_service_owner(owner: &str) -> Option<(Option<String>, String, String)> {
    let labels: Vec<_> = owner.split('.').collect();
    for index in 0..labels.len().saturating_sub(1) {
        let candidate = format!("{}.{}", labels[index], labels[index + 1]);
        if !service_type_is_valid(&candidate) {
            continue;
        }
        let domain = match labels.get(index + 2..)? {
            [] | [""] => ".".to_owned(),
            labels => labels.join("."),
        };
        if index > 1 {
            return None;
        }
        let name = (index == 1)
            .then(|| crate::wire::decode_label(labels[0]).ok())
            .flatten()
            .and_then(|label| String::from_utf8(label).ok());
        if index == 1 && name.is_none() {
            return None;
        }
        if name
            .as_deref()
            .is_some_and(|value| !service_instance_is_valid(value))
        {
            return None;
        }
        return Some((
            name,
            candidate.to_ascii_lowercase(),
            domain.to_ascii_lowercase(),
        ));
    }
    None
}

fn service_instance_is_valid(value: &str) -> bool {
    !value.is_empty() && value.len() <= 63 && !value.chars().any(char::is_control)
}

fn service_type_is_valid(value: &str) -> bool {
    let value = value.strip_suffix('.').unwrap_or(value);
    !value.ends_with('.') && crate::mdns::parity_dnssd::DnsSdServiceType::parse(value).is_ok()
}

fn octescape(input: &[u8]) -> String {
    let mut output = String::new();
    for &byte in input {
        if (0x20..=0x7e).contains(&byte) && byte != b'\\' {
            output.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(output, "\\{byte:03o}");
        }
    }
    output
}

fn resolve_record(parameters: &Value, resolver: &Resolver) -> Value {
    let Some(name) = parameters.get("name").and_then(Value::as_str) else {
        return invalid_parameter("name");
    };
    if make_query(name, TYPE_A, 0).is_err() {
        return invalid_parameter("name");
    }
    let class = match optional_u16(parameters, "class", CLASS_IN) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let rr_type = match required_u16(parameters, "type") {
        Ok(0 | 41 | 46 | 249 | 250) => {
            return error("io.rustd.Resolve.ResourceRecordTypeInvalidForQuery")
        }
        Ok(251 | 252) => return error("io.rustd.Resolve.ZoneTransfersNotPermitted"),
        Ok(value) if crate::wire::record_type_is_obsolete(value) => {
            return error("io.rustd.Resolve.ResourceRecordTypeObsolete")
        }
        Ok(value) => value,
        Err(error) => return error,
    };
    let ifindex = match optional_ifindex(parameters, "ifindex") {
        Ok(value) if value >= 0 => value,
        Ok(_) => return invalid_parameter("ifindex"),
        Err(error) => return error,
    };
    let request_flags = match optional_u64(parameters, "flags", 0) {
        Ok(value) if crate::resolver::query_flags_are_valid(value, RUSTD_RESOLVE_NO_SEARCH) => {
            value
        }
        Ok(_) | Err(_) => return invalid_parameter("flags"),
    };

    let (response, canonical_name, flags, response_ifindex) = match resolver
        .resolve_record_on_link_with_request_flags_and_canonical(
            name,
            class,
            rr_type,
            (ifindex > 0).then_some(ifindex),
            request_flags
                | RUSTD_RESOLVE_NO_SEARCH
                | crate::resolve_flags::flags::RUSTD_RESOLVE_REQUIRE_PRIMARY
                | crate::resolve_flags::flags::RUSTD_RESOLVE_CLAMP_TTL,
        ) {
        Ok(response) => response,
        Err(error) => return resolver_error(&error),
    };
    let records = match extract_matching_answer_records(&response, &canonical_name, class, rr_type)
    {
        Ok(records) if !records.is_empty() => records,
        Ok(_) => return error("io.rustd.Resolve.NoSuchResourceRecord"),
        Err(_) => return error("io.rustd.Resolve.InvalidReply"),
    };
    let rrs = records
        .into_iter()
        .map(|record| {
            let mut fields = JsonObject::new();
            if let Some(answer_ifindex) = response_ifindex.or((ifindex > 0).then_some(ifindex)) {
                fields.insert(
                    "ifindex".to_owned(),
                    Value::Number(i128::from(answer_ifindex)),
                );
            }
            if let Some(value) = resource_record_json(&record) {
                fields.insert("rr".to_owned(), value);
            }
            fields.insert("raw".to_owned(), Value::String(base64(&record.raw)));
            Value::Object(fields)
        })
        .collect();

    success(Value::object([
        ("rrs", Value::Array(rrs)),
        ("flags", Value::Number(i128::from(flags))),
    ]))
}

include!("varlink_resource_record.rs");

fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(char::from(ALPHABET[usize::from(first >> 2)]));
        output.push(char::from(
            ALPHABET[usize::from(((first & 0x03) << 4) | (second >> 4))],
        ));
        if chunk.len() > 1 {
            output.push(char::from(
                ALPHABET[usize::from(((second & 0x0f) << 2) | (third >> 6))],
            ));
        } else {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(char::from(ALPHABET[usize::from(third & 0x3f)]));
        } else {
            output.push('=');
        }
    }
    output
}

fn control(can_control: bool, operation: impl FnOnce()) -> Value {
    if !can_control {
        return error("org.varlink.service.PermissionDenied");
    }
    operation();
    success(Value::Object(JsonObject::new()))
}

fn statistics(resolver: &Resolver) -> Value {
    let statistics = resolver.stats();
    success(Value::object([
        (
            "transactions",
            Value::Number(i128::from(statistics.transactions)),
        ),
        (
            "cacheHits",
            Value::Number(i128::from(statistics.cache_hits)),
        ),
        (
            "cacheMisses",
            Value::Number(i128::from(statistics.cache_misses)),
        ),
        ("failures", Value::Number(i128::from(statistics.failures))),
        (
            "localAnswers",
            Value::Number(i128::from(statistics.local_answers)),
        ),
        (
            "cacheEntries",
            Value::Number(i128::try_from(statistics.cache_entries).unwrap_or(i128::MAX)),
        ),
    ]))
}

fn required_u16(parameters: &Value, key: &str) -> Result<u16, Value> {
    parameters
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|value| u16::try_from(value).ok())
        .ok_or_else(|| invalid_parameter(key))
}

fn optional_u16(parameters: &Value, key: &str, default: u16) -> Result<u16, Value> {
    match parameters.get(key) {
        None => Ok(default),
        Some(Value::Null) => Ok(u16::MAX),
        Some(value) => value
            .as_u64()
            .and_then(|value| u16::try_from(value).ok())
            .ok_or_else(|| invalid_parameter(key)),
    }
}

fn optional_u64(parameters: &Value, key: &str, default: u64) -> Result<u64, Value> {
    match parameters.get(key) {
        None => Ok(default),
        Some(value) => value.as_u64().ok_or_else(|| invalid_parameter(key)),
    }
}

fn optional_string(parameters: &Value, key: &str) -> Result<Option<String>, Value> {
    match parameters.get(key) {
        None => Ok(None),
        Some(value) => value
            .as_str()
            .map(|value| (!value.is_empty()).then_some(value.to_owned()))
            .ok_or_else(|| invalid_parameter(key)),
    }
}

fn required_i32(parameters: &Value, key: &str) -> Result<i32, Value> {
    parameters
        .get(key)
        .and_then(Value::as_i64)
        .and_then(|value| i32::try_from(value).ok())
        .ok_or_else(|| invalid_parameter(key))
}

fn optional_i32(parameters: &Value, key: &str, default: i32) -> Result<i32, Value> {
    match parameters.get(key) {
        None => Ok(default),
        Some(value) => value
            .as_i64()
            .and_then(|value| i32::try_from(value).ok())
            .ok_or_else(|| invalid_parameter(key)),
    }
}

fn optional_ifindex(parameters: &Value, key: &str) -> Result<i32, Value> {
    match parameters.get(key) {
        None | Some(Value::Null) => Ok(0),
        Some(value) => value
            .as_i64()
            .and_then(|value| i32::try_from(value).ok())
            .ok_or_else(|| invalid_parameter(key)),
    }
}

fn resolver_error(error_value: &ResolveError) -> Value {
    if let ResolveError::DnssecValidationFailed {
        result,
        extended_dns_error_code,
        extended_dns_error_message,
    } = error_value
    {
        let mut parameters = JsonObject::new();
        parameters.insert("result".to_owned(), Value::String(result.clone()));
        if let Some(code) = extended_dns_error_code {
            parameters.insert(
                "extendedDNSErrorCode".to_owned(),
                Value::Number(i128::from(*code)),
            );
        }
        if let Some(message) = extended_dns_error_message {
            parameters.insert(
                "extendedDNSErrorMessage".to_owned(),
                Value::String(message.clone()),
            );
        }
        return Value::object([
            (
                "error",
                Value::String("io.rustd.Resolve.DNSSECValidationFailed".to_owned()),
            ),
            ("parameters", Value::Object(parameters)),
        ]);
    }
    if let ResolveError::DnsError {
        rcode,
        extended_dns_error_code,
        extended_dns_error_message,
        ..
    } = error_value
    {
        let mut parameters = JsonObject::new();
        parameters.insert("rcode".to_owned(), Value::Number(i128::from(*rcode)));
        if let Some(code) = extended_dns_error_code {
            parameters.insert(
                "extendedDNSErrorCode".to_owned(),
                Value::Number(i128::from(*code)),
            );
        }
        if let Some(message) = extended_dns_error_message {
            parameters.insert(
                "extendedDNSErrorMessage".to_owned(),
                Value::String(message.clone()),
            );
        }
        return Value::object([
            (
                "error",
                Value::String("io.rustd.Resolve.DNSError".to_owned()),
            ),
            ("parameters", Value::Object(parameters)),
        ]);
    }
    error(error_value.varlink_id())
}

fn success(parameters: Value) -> Value {
    Value::object([("parameters", parameters)])
}

fn error(identifier: &str) -> Value {
    Value::object([
        ("error", Value::String(identifier.to_owned())),
        ("parameters", Value::Object(JsonObject::new())),
    ])
}

fn invalid_parameter(parameter: &str) -> Value {
    Value::object([
        (
            "error",
            Value::String("org.varlink.service.InvalidParameter".to_owned()),
        ),
        (
            "parameters",
            Value::object([("parameter", Value::String(parameter.to_owned()))]),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, ValidationMode};
    use std::net::UdpSocket;
    use std::time::Instant;

    #[test]
    fn quiet_varlink_subscription_stops_when_its_client_disconnects() {
        let resolver = Resolver::new(Config::default());
        let (mut client, mut server) = UnixStream::pair().expect("Varlink socket pair");
        let (subscription_done, wait_for_subscription) = mpsc::channel();
        let subscription = thread::spawn(move || {
            let result = serve_dns_configuration(&mut server, &resolver);
            subscription_done.send(result).expect("subscription result");
        });

        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("subscription read timeout");
        let mut byte = [0];
        loop {
            client
                .read_exact(&mut byte)
                .expect("initial subscription reply");
            if byte[0] == 0 {
                break;
            }
        }
        drop(client);

        wait_for_subscription
            .recv_timeout(Duration::from_secs(1))
            .expect("closed subscription")
            .expect("clean subscription disconnect");
        subscription.join().expect("subscription thread");
    }

    #[test]
    fn closing_a_varlink_client_aborts_only_its_active_query() {
        let upstream = UdpSocket::bind("127.0.0.1:0").expect("mock DNS bind");
        upstream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("mock DNS timeout");
        let upstream_address = upstream.local_addr().expect("mock DNS address");
        let (query_seen, wait_for_query) = mpsc::channel();
        let (release_upstream, hold_upstream) = mpsc::channel();
        let upstream_worker = thread::spawn(move || {
            let mut packet = [0; 2048];
            upstream.recv_from(&mut packet).expect("mock DNS query");
            query_seen.send(()).expect("signal active query");
            let _ = hold_upstream.recv_timeout(Duration::from_secs(3));
        });

        let resolver = Arc::new(Resolver::new(Config {
            upstreams: vec![upstream_address],
            fallback_upstreams: Vec::new(),
            cache: false,
            attempts: 1,
            query_timeout: Duration::from_secs(5),
            read_etc_hosts: false,
            read_static_records: false,
            dnssec: ValidationMode::No,
            ..Config::default()
        }));
        let observed_resolver = Arc::clone(&resolver);
        let (mut client, server) = UnixStream::pair().expect("Varlink socket pair");
        let (connection_done, wait_for_connection) = mpsc::channel();
        let connection = thread::spawn(move || {
            let result = serve_connection(server, resolver, VarlinkEndpoint::Resolve);
            connection_done.send(result).expect("connection result");
        });

        let request = format!(
            r#"{{"method":"io.rustd.Resolve.ResolveHostname","parameters":{{"name":"disconnect.example","family":2,"flags":{}}}}}"#,
            RUSTD_RESOLVE_NO_SEARCH
        );
        client
            .write_all(request.as_bytes())
            .expect("Varlink request");
        client.write_all(&[0]).expect("Varlink terminator");
        wait_for_query
            .recv_timeout(Duration::from_secs(2))
            .expect("active upstream query");
        drop(client);

        wait_for_connection
            .recv_timeout(Duration::from_secs(1))
            .expect("closed Varlink connection")
            .expect("clean Varlink disconnect");
        let deadline = Instant::now() + Duration::from_secs(1);
        while observed_resolver.stats().current_transactions != 0 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(observed_resolver.stats().current_transactions, 0);

        release_upstream.send(()).expect("release mock DNS server");
        connection.join().expect("Varlink connection thread");
        upstream_worker.join().expect("mock DNS server");
    }

    #[test]
    fn control_methods_use_the_pinned_polkit_actions() {
        for (method, action) in [
            (
                "io.rustd.Resolve.Monitor.DumpCache",
                "io.rustd.resolve.dump-cache",
            ),
            (
                "io.rustd.Resolve.Monitor.DumpServerState",
                "io.rustd.resolve.dump-server-state",
            ),
            (
                "io.rustd.Resolve.Monitor.DumpStatistics",
                "io.rustd.resolve.dump-statistics",
            ),
            (
                "io.rustd.Resolve.Monitor.ResetStatistics",
                "io.rustd.resolve.reset-statistics",
            ),
            (
                "io.rustd.Resolve.FlushCaches",
                "io.rustd.resolve.flush-caches",
            ),
            (
                "io.rustd.Resolve.ResetServerFeatures",
                "io.rustd.resolve.reset-server-features",
            ),
        ] {
            assert_eq!(control_action(method), Some(action));
        }
    }

    #[test]
    fn browse_domains_use_the_pinned_general_dns_name_rules() {
        for domain in [
            ".",
            "local.",
            "-dash.local",
            "dash-.local",
            "[printer].local",
            "bücher.local",
            r"escaped\046label.local",
        ] {
            assert!(valid_dns_domain(domain), "rejected {domain:?}");
        }
        for domain in ["", "local..", ".local", "bad\\", "bad\nname.local"] {
            assert!(!valid_dns_domain(domain), "accepted {domain:?}");
        }
    }

    #[test]
    fn interactive_authorization_is_read_from_parameters_only() {
        let allowed =
            json::parse(r#"{"parameters":{"allowInteractiveAuthentication":true}}"#).unwrap();
        let top_level =
            json::parse(r#"{"allowInteractiveAuthentication":true,"parameters":{}}"#).unwrap();
        assert!(allow_interactive(&allowed));
        assert!(!allow_interactive(&top_level));
    }

    #[test]
    fn monitor_socket_is_a_sibling_of_the_resolve_socket() {
        assert_eq!(
            monitor_path_for(Path::new("/run/rustd/resolve/io.rustd.Resolve")),
            PathBuf::from("/run/rustd/resolve/io.rustd.Resolve.Monitor")
        );
        assert_eq!(
            monitor_path_for(Path::new("/tmp/resolved-test.sock")),
            PathBuf::from("/tmp/resolved-test.sock.Monitor")
        );
    }

    #[test]
    fn socket_endpoints_expose_only_their_pinned_interface() {
        let resolver = Resolver::new(Config::default());
        let request = r#"{"method":"org.varlink.service.GetInfo","parameters":{}}"#;
        let resolve = dispatch_for_endpoint(request, &resolver, false, VarlinkEndpoint::Resolve);
        let resolve_interfaces = resolve
            .get("parameters")
            .and_then(|parameters| parameters.get("interfaces"))
            .and_then(Value::as_array)
            .expect("Resolve interfaces");
        assert!(resolve_interfaces
            .iter()
            .any(|value| value.as_str() == Some("io.rustd.Resolve")));
        assert!(!resolve_interfaces
            .iter()
            .any(|value| value.as_str() == Some("io.rustd.Resolve.Monitor")));

        let monitor = dispatch_for_endpoint(request, &resolver, false, VarlinkEndpoint::Monitor);
        let monitor_interfaces = monitor
            .get("parameters")
            .and_then(|parameters| parameters.get("interfaces"))
            .and_then(Value::as_array)
            .expect("Monitor interfaces");
        assert!(monitor_interfaces
            .iter()
            .any(|value| value.as_str() == Some("io.rustd.Resolve.Monitor")));
        assert!(!monitor_interfaces
            .iter()
            .any(|value| value.as_str() == Some("io.rustd.Resolve")));

        let denied = dispatch_for_endpoint(
            r#"{"method":"io.rustd.Resolve.ResolveHostname","parameters":{"name":"localhost"}}"#,
            &resolver,
            false,
            VarlinkEndpoint::Monitor,
        );
        assert_eq!(
            denied.get("error").and_then(Value::as_str),
            Some("org.varlink.service.MethodNotFound")
        );
    }

    #[test]
    fn activation_descriptor_selection_matches_named_varlink_listeners() {
        assert_eq!(
            activated_varlink_fds(0, None).expect("no activation"),
            (Vec::new(), Vec::new())
        );
        assert_eq!(
            activated_varlink_fds(1, None).expect("unnamed activation"),
            (Vec::new(), Vec::new())
        );
        assert_eq!(
            activated_varlink_fds(1, Some("varlink-monitor")).expect("monitor activation"),
            (Vec::new(), vec![3])
        );
        assert_eq!(
            activated_varlink_fds(2, Some("varlink:varlink-monitor")).expect("named activation"),
            (vec![3], vec![4])
        );
        assert_eq!(
            activated_varlink_fds(2, Some("varlink-monitor:varlink"))
                .expect("reverse named activation"),
            (vec![4], vec![3])
        );
        assert_eq!(
            activated_varlink_fds(3, Some("varlink::varlink-monitor"))
                .expect("empty-name activation slot ignored"),
            (vec![3], vec![5])
        );
        assert_eq!(
            activated_varlink_fds(4, Some("varlink:other:varlink:varlink-monitor"))
                .expect("multiple and unrelated activation"),
            (vec![3, 5], vec![6])
        );
        assert_eq!(
            activated_varlink_fds(3, Some("varlink:varlink:other"))
                .expect("duplicate varlink activation"),
            (vec![3, 4], Vec::new())
        );
        assert_eq!(
            activated_varlink_fds(1, Some(""))
                .expect("empty LISTEN_FDNAMES keeps descriptors unassigned"),
            (Vec::new(), Vec::new())
        );
        assert_eq!(
            activated_varlink_fds(1, Some("other")).expect("unrelated activation"),
            (Vec::new(), Vec::new())
        );
        assert!(activated_varlink_fds(2, Some("varlink")).is_err());
        assert!(activated_varlink_fds(3, Some("varlink")).is_err());
        assert!(activated_varlink_fds(1, Some("varlink:")).is_err());
        assert!(activated_varlink_fds(2, Some("varlink::")).is_err());
    }

    #[test]
    fn fallback_listener_plan_respects_socket_activation_context() {
        let path = Path::new("/run/rustd/resolve/io.rustd.Resolve");
        let monitor = path.with_file_name("io.rustd.Resolve.Monitor");
        let same_path = Path::new("/tmp/rustd-resolved/io.rustd.Resolve");

        assert_eq!(
            fallback_listener_plan(false, path, &monitor, 0, 0),
            (true, true)
        );
        assert_eq!(
            fallback_listener_plan(false, same_path, same_path, 0, 0),
            (true, false)
        );
        assert_eq!(
            fallback_listener_plan(true, path, &monitor, 0, 0),
            (false, false)
        );
        assert_eq!(
            fallback_listener_plan(false, path, &monitor, 1, 0),
            (false, true)
        );
        assert_eq!(
            fallback_listener_plan(true, path, &monitor, 1, 0),
            (false, false)
        );
        assert_eq!(
            fallback_listener_plan(true, path, &monitor, 0, 1),
            (false, false)
        );
    }

    #[test]
    fn activated_descriptors_distinguish_listeners_from_connections() {
        let directory = std::env::temp_dir().join(format!(
            "rustd-resolved-varlink-activation-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).expect("activation directory");
        let listener = UnixListener::bind(directory.join("listener")).expect("Unix listener");
        let activated = activated_socket_from_fd(listener.into_raw_fd()).expect("listener socket");
        assert!(matches!(activated, ActivatedVarlinkSocket::Listener(_)));

        let (stream, peer) = UnixStream::pair().expect("Unix connection");
        let activated = activated_socket_from_fd(stream.into_raw_fd()).expect("connection socket");
        assert!(matches!(activated, ActivatedVarlinkSocket::Connection(_)));
        drop(peer);
        fs::remove_dir_all(directory).expect("remove activation directory");
    }

    #[test]
    fn maintenance_call_requires_privileged_peer() {
        let resolver = Resolver::new(Config::default());
        let reply = dispatch(
            r#"{"method":"io.rustd.Resolve.FlushCaches","parameters":{}}"#,
            &resolver,
        );
        assert_eq!(
            reply.get("error").and_then(Value::as_str),
            Some("org.varlink.service.PermissionDenied")
        );
    }

    #[test]
    fn unspecified_reply_ifindices_are_omitted_for_stock_nss() {
        let resolver = Resolver::new(Config::default());
        let hostname = dispatch(
            r#"{"method":"io.rustd.Resolve.ResolveHostname","parameters":{"name":"localhost","flags":0,"ifindex":0}}"#,
            &resolver,
        );
        let address_ifindex = hostname
            .get("parameters")
            .and_then(|parameters| parameters.get("addresses"))
            .and_then(Value::as_array)
            .and_then(|addresses| addresses.first())
            .and_then(|address| address.get("ifindex"));
        assert_eq!(address_ifindex, None);

        let reverse = dispatch(
            r#"{"method":"io.rustd.Resolve.ResolveAddress","parameters":{"family":2,"address":[127,0,0,1],"flags":0,"ifindex":0}}"#,
            &resolver,
        );
        let name_ifindex = reverse
            .get("parameters")
            .and_then(|parameters| parameters.get("names"))
            .and_then(Value::as_array)
            .and_then(|names| names.first())
            .and_then(|name| name.get("ifindex"));
        assert_eq!(name_ifindex, None);
    }

    #[test]
    fn monitor_subscriptions_require_more_and_emit_continued_replies() {
        let request = r#"{"method":"io.rustd.Resolve.Monitor.SubscribeQueryResults","more":true,"parameters":{}}"#;
        assert_eq!(
            subscription_method(request),
            Some(SubscriptionMethod::QueryResults)
        );
        let reply = continued(Value::object([("ready", Value::Bool(true))]));
        assert_eq!(reply.get("continues").and_then(Value::as_bool), Some(true));
        assert_eq!(
            reply
                .get("parameters")
                .and_then(|parameters| parameters.get("ready"))
                .and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn base64_uses_standard_padding() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
    }

    #[test]
    fn resolve_record_returns_raw_record_data() {
        let resolver = Resolver::new(Config::default());
        let reply = dispatch(
            r#"{"method":"io.rustd.Resolve.ResolveRecord","parameters":{"name":"localhost","class":1,"type":1}}"#,
            &resolver,
        );
        let rrs = reply
            .get("parameters")
            .and_then(|parameters| parameters.get("rrs"))
            .and_then(Value::as_array)
            .expect("resource records");
        assert!(!rrs.is_empty());
        assert!(rrs[0]
            .get("raw")
            .and_then(Value::as_str)
            .is_some_and(|raw| !raw.is_empty()));
        let rr = rrs[0].get("rr").expect("structured resource record");
        assert_eq!(
            rr.get("key")
                .and_then(|key| key.get("name"))
                .and_then(Value::as_str),
            Some("localhost")
        );
        assert_eq!(
            rr.get("address").and_then(Value::as_array),
            Some(
                [127_u8, 0, 0, 1]
                    .iter()
                    .map(|byte| Value::Number(i128::from(*byte)))
                    .collect::<Vec<_>>()
                    .as_slice()
            )
        );
        let flags = reply
            .get("parameters")
            .and_then(|parameters| parameters.get("flags"))
            .and_then(Value::as_u64)
            .expect("reply flags");
        assert_ne!(flags & RUSTD_RESOLVE_DNS, 0);
        assert_ne!(
            flags & crate::resolve_flags::flags::RUSTD_RESOLVE_SYNTHETIC,
            0
        );
        assert_eq!(
            flags & crate::resolve_flags::flags::RUSTD_RESOLVE_NO_VALIDATE,
            0
        );
    }

    #[test]
    fn resolve_methods_reject_output_only_request_flags() {
        let resolver = Resolver::new(Config::default());
        let reply = dispatch(
            r#"{"method":"io.rustd.Resolve.ResolveHostname","parameters":{"name":"localhost","flags":8388608}}"#,
            &resolver,
        );
        assert_eq!(
            reply.get("error").and_then(Value::as_str),
            Some("org.varlink.service.InvalidParameter")
        );
        assert_eq!(
            reply
                .get("parameters")
                .and_then(|parameters| parameters.get("parameter"))
                .and_then(Value::as_str),
            Some("flags")
        );
    }

    #[test]
    fn method_parameter_dispatch_rejects_unknown_fields_before_execution() {
        let resolver = Resolver::new(Config::default());
        for request in [
            r#"{"method":"io.rustd.Resolve.ResolveHostname","parameters":{"name":"localhost","unexpected":1}}"#,
            r#"{"method":"io.rustd.Resolve.FlushCaches","parameters":{"unexpected":1}}"#,
        ] {
            let reply = dispatch(request, &resolver);
            assert_eq!(
                reply.get("error").and_then(Value::as_str),
                Some("org.varlink.service.InvalidParameter")
            );
            assert_eq!(
                reply
                    .get("parameters")
                    .and_then(|parameters| parameters.get("parameter"))
                    .and_then(Value::as_str),
                Some("unexpected")
            );
        }

        let subscription = json::parse(
            r#"{"method":"io.rustd.Resolve.BrowseServices","more":true,"parameters":{"unexpected":1}}"#,
        )
        .expect("subscription request");
        assert!(
            validate_method_parameters(&subscription, "io.rustd.Resolve.BrowseServices").is_err()
        );
    }

    #[test]
    fn resolve_method_family_errors_match_the_pinned_contract() {
        let resolver = Resolver::new(Config::default());
        for request in [
            r#"{"method":"io.rustd.Resolve.ResolveHostname","parameters":{"name":"localhost","family":7}}"#,
            r#"{"method":"io.rustd.Resolve.ResolveAddress","parameters":{"family":7,"address":[127,0,0,1]}}"#,
        ] {
            let reply = dispatch(request, &resolver);
            assert_eq!(
                reply.get("error").and_then(Value::as_str),
                Some("org.varlink.service.InvalidParameter")
            );
            assert_eq!(
                reply
                    .get("parameters")
                    .and_then(|parameters| parameters.get("parameter"))
                    .and_then(Value::as_str),
                Some("family")
            );
        }

        let reply = dispatch(
            r#"{"method":"io.rustd.Resolve.ResolveAddress","parameters":{"family":2,"address":[127,0,0]}}"#,
            &resolver,
        );
        assert_eq!(
            reply.get("error").and_then(Value::as_str),
            Some("io.rustd.Resolve.BadAddressSize")
        );
    }

    #[test]
    fn resolve_record_type_and_class_validation_matches_v261() {
        let resolver = Resolver::new(Config::default());
        for (rr_type, expected) in [
            (46, "io.rustd.Resolve.ResourceRecordTypeInvalidForQuery"),
            (3, "io.rustd.Resolve.ResourceRecordTypeObsolete"),
            (251, "io.rustd.Resolve.ZoneTransfersNotPermitted"),
        ] {
            let reply = dispatch(
                &format!(
                    r#"{{"method":"io.rustd.Resolve.ResolveRecord","parameters":{{"name":"localhost","class":1,"type":{rr_type}}}}}"#
                ),
                &resolver,
            );
            assert_eq!(reply.get("error").and_then(Value::as_str), Some(expected));
        }

        let reply = dispatch(
            r#"{"method":"io.rustd.Resolve.ResolveRecord","parameters":{"name":"localhost","class":3,"type":1}}"#,
            &resolver,
        );
        assert_ne!(
            reply.get("error").and_then(Value::as_str),
            Some("org.varlink.service.InvalidParameter")
        );
    }

    #[test]
    fn malformed_dns_names_fail_before_other_lookup_parameters() {
        let resolver = Resolver::new(Config::default());
        for request in [
            r#"{"method":"io.rustd.Resolve.ResolveHostname","parameters":{"name":"bad..name","family":7}}"#,
            r#"{"method":"io.rustd.Resolve.ResolveRecord","parameters":{"name":"bad\\","type":0}}"#,
        ] {
            let reply = dispatch(request, &resolver);
            assert_eq!(
                reply.get("error").and_then(Value::as_str),
                Some("org.varlink.service.InvalidParameter")
            );
            assert_eq!(
                reply
                    .get("parameters")
                    .and_then(|parameters| parameters.get("parameter"))
                    .and_then(Value::as_str),
                Some("name")
            );
        }
    }

    #[test]
    fn refused_high_level_questions_return_query_refused() {
        let mut config = Config::default();
        config
            .apply_text("[Resolve]\nRefuseRecordTypes=AAAA\n")
            .expect("refuse configuration");
        let resolver = Resolver::new(config);
        let reply = dispatch(
            r#"{"method":"io.rustd.Resolve.ResolveRecord","parameters":{"name":"localhost","class":1,"type":28}}"#,
            &resolver,
        );
        assert_eq!(
            reply.get("error").and_then(Value::as_str),
            Some("io.rustd.Resolve.QueryRefused")
        );

        let reply = dispatch(
            r#"{"method":"io.rustd.Resolve.ResolveHostname","parameters":{"name":"localhost","family":10}}"#,
            &resolver,
        );
        assert_eq!(
            reply.get("error").and_then(Value::as_str),
            Some("io.rustd.Resolve.QueryRefused")
        );
    }

    #[test]
    fn refused_service_auxiliary_types_set_implicit_flags() {
        let mut config = Config::default();
        config
            .apply_text("[Resolve]\nRefuseRecordTypes=A AAAA TXT\n")
            .expect("refuse configuration");
        let resolver = Resolver::new(config);
        let mut request = service_request(&Value::object([
            ("type", Value::String("_demo._tcp".to_owned())),
            ("domain", Value::String("example.test".to_owned())),
        ]))
        .expect("service request");
        apply_refused_service_flags(&mut request, &resolver);
        assert_ne!(request.flags & RUSTD_RESOLVE_NO_ADDRESS, 0);
        assert_ne!(request.flags & RUSTD_RESOLVE_NO_TXT, 0);
    }

    #[test]
    fn service_reply_flags_do_not_echo_input_only_controls() {
        let question =
            service_question(None, Some("_demo._tcp"), "example.test").expect("service question");
        let response_flags =
            RUSTD_RESOLVE_DNS | crate::resolve_flags::flags::RUSTD_RESOLVE_FROM_NETWORK;
        let mut output = JsonObject::new();

        add_service_metadata(&mut output, &question, response_flags);

        assert_eq!(
            output.get("flags").and_then(Value::as_u64),
            Some(response_flags)
        );
        assert_eq!(
            response_flags & (RUSTD_RESOLVE_NO_ADDRESS | RUSTD_RESOLVE_NO_TXT),
            0
        );
    }

    #[test]
    #[cfg(feature = "idna-name")]
    fn service_questions_escape_utf8_instances_and_idna_domains() {
        let question = service_question(Some("Café.Desk"), Some("_demo._tcp"), "bücher.example")
            .expect("internationalized service question");
        assert_eq!(
            question.owner,
            r"Caf\195\169\046Desk._demo._tcp.bücher.example"
        );
        assert_eq!(
            question.unicast_owner,
            r"Caf\195\169\046Desk._demo._tcp.xn--bcher-kva.example"
        );
        assert_eq!(
            split_service_owner(&question.owner),
            Some((
                Some("Café.Desk".to_owned()),
                "_demo._tcp".to_owned(),
                "bücher.example".to_owned(),
            ))
        );
    }

    #[test]
    fn service_questions_accept_absolute_and_presplit_owners() {
        let root =
            service_question(None, Some("_demo._tcp."), ".").expect("root-domain service question");
        assert_eq!(root.owner, "_demo._tcp");
        assert_eq!(
            split_service_owner(&root.owner),
            Some((None, "_demo._tcp".to_owned(), ".".to_owned()))
        );

        let presplit =
            service_question(None, None, "arbitrary.example.").expect("pre-split service owner");
        assert_eq!(presplit.owner, "arbitrary.example.");
        assert!(presplit.service_type.is_empty());
        assert!(service_question(None, Some("_demo._tcp"), "example..").is_none());
    }

    #[test]
    fn refused_srv_rejects_service_without_starting_a_query() {
        let mut config = Config::default();
        config
            .apply_text("[Resolve]\nRefuseRecordTypes=SRV\n")
            .expect("refuse configuration");
        let resolver = Resolver::new(config);
        let reply = dispatch(
            r#"{"method":"io.rustd.Resolve.ResolveService","parameters":{"type":"_demo._tcp","domain":"example.test"}}"#,
            &resolver,
        );
        assert_eq!(
            reply.get("error").and_then(Value::as_str),
            Some("io.rustd.Resolve.QueryRefused")
        );
    }

    #[test]
    fn refusing_only_one_address_family_does_not_disable_addresses() {
        let mut config = Config::default();
        config
            .apply_text("[Resolve]\nRefuseRecordTypes=AAAA\n")
            .expect("refuse configuration");
        let resolver = Resolver::new(config);
        let mut request = service_request(&Value::object([
            ("type", Value::String("_demo._tcp".to_owned())),
            ("domain", Value::String("example.test".to_owned())),
        ]))
        .expect("service request");
        apply_refused_service_flags(&mut request, &resolver);
        assert_eq!(request.flags & RUSTD_RESOLVE_NO_ADDRESS, 0);
    }

    #[test]
    fn nullable_input_dispatch_matches_systemd_sentinels() {
        let resolver = Resolver::new(Config::default());
        for (request, parameter) in [
            (
                r#"{"method":"io.rustd.Resolve.ResolveService","parameters":{"name":null,"type":"_demo._tcp","domain":"example.test"}}"#,
                "name",
            ),
            (
                r#"{"method":"io.rustd.Resolve.ResolveHostname","parameters":{"name":"localhost","family":null}}"#,
                "family",
            ),
            (
                r#"{"method":"io.rustd.Resolve.ResolveHostname","parameters":{"name":"localhost","flags":null}}"#,
                "flags",
            ),
        ] {
            let reply = dispatch(request, &resolver);
            assert_eq!(
                reply.get("error").and_then(Value::as_str),
                Some("org.varlink.service.InvalidParameter")
            );
            assert_eq!(
                reply
                    .get("parameters")
                    .and_then(|parameters| parameters.get("parameter"))
                    .and_then(Value::as_str),
                Some(parameter)
            );
        }

        let reply = dispatch(
            r#"{"method":"io.rustd.Resolve.ResolveHostname","parameters":{"name":"localhost","ifindex":null}}"#,
            &resolver,
        );
        assert!(reply.get("error").is_none(), "{}", reply.to_json());

        let resolver = Resolver::new(Config {
            upstreams: Vec::new(),
            fallback_upstreams: Vec::new(),
            read_etc_hosts: false,
            ..Config::default()
        });
        let reply = dispatch(
            r#"{"method":"io.rustd.Resolve.ResolveRecord","parameters":{"name":"localhost","class":null,"type":1}}"#,
            &resolver,
        );
        assert_eq!(
            reply.get("error").and_then(Value::as_str),
            Some("io.rustd.Resolve.NoNameServers")
        );
    }

    #[test]
    fn get_info_lists_pinned_generic_and_resolve_interfaces() {
        let resolver = Resolver::new(Config::default());
        let reply = dispatch_for_endpoint(
            r#"{"method":"org.varlink.service.GetInfo","parameters":{}}"#,
            &resolver,
            false,
            VarlinkEndpoint::Resolve,
        );
        let interfaces = reply
            .get("parameters")
            .and_then(|parameters| parameters.get("interfaces"))
            .and_then(Value::as_array)
            .expect("interfaces");
        assert_eq!(
            interfaces
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>(),
            vec![
                "io.rustd",
                "io.rustd.Resolve",
                "io.rustd.service",
                "org.varlink.service"
            ]
        );

        let monitor = dispatch_for_endpoint(
            r#"{"method":"org.varlink.service.GetInfo","parameters":{}}"#,
            &resolver,
            false,
            VarlinkEndpoint::Monitor,
        );
        let monitor_interfaces = monitor
            .get("parameters")
            .and_then(|parameters| parameters.get("interfaces"))
            .and_then(Value::as_array)
            .expect("monitor interfaces");
        assert_eq!(
            monitor_interfaces
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>(),
            vec![
                "io.rustd",
                "io.rustd.Resolve.Monitor",
                "org.varlink.service"
            ]
        );

        let description = dispatch_for_endpoint(
            r#"{"method":"org.varlink.service.GetInterfaceDescription","parameters":{"interface":"io.rustd.service"}}"#,
            &resolver,
            false,
            VarlinkEndpoint::Resolve,
        );
        assert_eq!(
            description
                .get("parameters")
                .and_then(|parameters| parameters.get("description"))
                .and_then(Value::as_str),
            Some(SERVICE_INTERFACE_DESCRIPTION)
        );
    }

    #[test]
    fn generic_service_methods_have_pinned_shapes_and_access_controls() {
        let resolver = Resolver::new(Config::default());
        let ping = dispatch(
            r#"{"method":"io.rustd.service.Ping","parameters":{}}"#,
            &resolver,
        );
        assert_eq!(ping.get("error"), None);

        for request in [
            r#"{"method":"io.rustd.service.Reload","parameters":{}}"#,
            r#"{"method":"io.rustd.service.SetLogLevel","parameters":{"level":6}}"#,
            r#"{"method":"io.rustd.service.GetEnvironment","parameters":{}}"#,
        ] {
            let reply = dispatch(request, &resolver);
            assert_eq!(
                reply.get("error").and_then(Value::as_str),
                Some("org.varlink.service.PermissionDenied"),
                "{}",
                reply.to_json()
            );
        }

        let reload = dispatch_for_endpoint_with_access(
            r#"{"method":"io.rustd.service.Reload","parameters":{}}"#,
            &resolver,
            false,
            true,
            VarlinkEndpoint::Resolve,
        );
        assert_eq!(reload.get("error"), None, "{}", reload.to_json());
        assert!(crate::daemon::take_reload_for_test());

        let log_level = dispatch_for_endpoint_with_access(
            r#"{"method":"io.rustd.service.SetLogLevel","parameters":{"level":7}}"#,
            &resolver,
            false,
            true,
            VarlinkEndpoint::Resolve,
        );
        assert_eq!(log_level.get("error"), None, "{}", log_level.to_json());
        assert_eq!(LogControlState::global().level(), 7);
        let reset_log_level = dispatch_for_endpoint_with_access(
            r#"{"method":"io.rustd.service.SetLogLevel","parameters":{"level":null}}"#,
            &resolver,
            false,
            true,
            VarlinkEndpoint::Resolve,
        );
        assert_eq!(reset_log_level.get("error"), None);
        assert_eq!(LogControlState::global().level(), 6);

        let environment = dispatch_for_endpoint_with_access(
            r#"{"method":"io.rustd.service.GetEnvironment","parameters":{}}"#,
            &resolver,
            false,
            true,
            VarlinkEndpoint::Resolve,
        );
        let values = environment
            .get("parameters")
            .and_then(|parameters| parameters.get("environment"))
            .and_then(Value::as_array)
            .expect("environment array");
        assert!(values.iter().all(|value| {
            value
                .as_str()
                .is_some_and(|assignment| assignment.contains('='))
        }));

        let invalid_level = dispatch_for_endpoint_with_access(
            r#"{"method":"io.rustd.service.SetLogLevel","parameters":{"level":-1}}"#,
            &resolver,
            false,
            true,
            VarlinkEndpoint::Resolve,
        );
        assert_eq!(
            invalid_level.get("error").and_then(Value::as_str),
            Some("org.varlink.service.InvalidParameter")
        );
    }

    #[test]
    fn generic_environment_name_validation_is_fail_closed() {
        assert!(valid_environment_name(b"A"));
        assert!(valid_environment_name(b"_A_9"));
        assert!(!valid_environment_name(b""));
        assert!(!valid_environment_name(b"9A"));
        assert!(!valid_environment_name(b"A-B"));
        assert!(!valid_environment_name(b"A=B"));
    }

    #[test]
    fn generic_environment_projection_rejects_inconsistent_raw_entries() {
        assert!(
            collect_environment_entries(vec![b"A=one".to_vec(), b"A=two".to_vec()])
                .expect("valid environment")
                .eq(&["A=two".to_owned()])
        );
        assert!(collect_environment_entries(vec![b"NO_SEPARATOR".to_vec()]).is_err());
        assert!(collect_environment_entries(vec![b"BAD-NAME=value".to_vec()]).is_err());
        assert!(collect_environment_entries(vec![b"BAD_UTF8=\xFF".to_vec()]).is_err());
    }

    #[test]
    fn generic_service_methods_use_authenticated_varlink_socket() {
        let resolver = Arc::new(Resolver::new(Config::default()));
        let (mut client, server) = UnixStream::pair().expect("Varlink socket pair");
        let worker = thread::spawn(move || {
            serve_connection(server, resolver, VarlinkEndpoint::Resolve)
                .expect("Varlink service connection")
        });

        let ping = socket_call(
            &mut client,
            r#"{"method":"io.rustd.service.Ping","parameters":{}}"#,
        );
        assert_eq!(ping.get("error"), None);

        let environment = socket_call(
            &mut client,
            r#"{"method":"io.rustd.service.GetEnvironment","parameters":{}}"#,
        );
        assert!(environment
            .get("parameters")
            .and_then(|parameters| parameters.get("environment"))
            .and_then(Value::as_array)
            .is_some());

        let set_level = socket_call(
            &mut client,
            r#"{"method":"io.rustd.service.SetLogLevel","parameters":{"level":7}}"#,
        );
        assert_eq!(set_level.get("error"), None, "{}", set_level.to_json());
        let reset_level = socket_call(
            &mut client,
            r#"{"method":"io.rustd.service.SetLogLevel","parameters":{"level":null}}"#,
        );
        assert_eq!(reset_level.get("error"), None);

        let reload = socket_call(
            &mut client,
            r#"{"method":"io.rustd.service.Reload","parameters":{"allowInteractiveAuthentication":true}}"#,
        );
        assert_eq!(reload.get("error"), None, "{}", reload.to_json());
        assert!(crate::daemon::take_reload_for_test());

        drop(client);
        worker.join().expect("Varlink service worker");
    }

    fn socket_call(client: &mut UnixStream, request: &str) -> Value {
        client
            .write_all(request.as_bytes())
            .expect("Varlink request");
        client.write_all(&[0]).expect("Varlink terminator");
        let mut response = Vec::new();
        let mut byte = [0];
        loop {
            client.read_exact(&mut byte).expect("Varlink response");
            if byte[0] == 0 {
                break;
            }
            response.push(byte[0]);
        }
        json::parse(std::str::from_utf8(&response).expect("UTF-8 Varlink response"))
            .expect("JSON Varlink response")
    }

    fn spawn_service_server() -> (std::net::SocketAddr, thread::JoinHandle<()>) {
        use crate::wire::{encode_name, first_question, question_end, TYPE_A};
        use std::net::UdpSocket;

        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind test DNS server");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set test timeout");
        let address = socket.local_addr().expect("test DNS address");
        let worker = thread::spawn(move || {
            let mut buffer = [0; 4096];
            for _ in 0..3 {
                let Ok((length, peer)) = socket.recv_from(&mut buffer) else {
                    return;
                };
                let query = &buffer[..length];
                let question = first_question(query).expect("test question");
                let end = question_end(query).expect("test question end");
                let mut response = query[..end].to_vec();
                response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
                response[6..8].copy_from_slice(&1u16.to_be_bytes());
                response[8..12].fill(0);

                let rdata = match question.rr_type {
                    TYPE_SRV => {
                        let mut rdata = Vec::new();
                        rdata.extend_from_slice(&10u16.to_be_bytes());
                        rdata.extend_from_slice(&20u16.to_be_bytes());
                        rdata.extend_from_slice(&631u16.to_be_bytes());
                        rdata.extend_from_slice(
                            &encode_name("host.example.test").expect("service target"),
                        );
                        rdata
                    }
                    TYPE_TXT => {
                        let item = b"path=/";
                        let mut rdata = vec![u8::try_from(item.len()).expect("TXT length")];
                        rdata.extend_from_slice(item);
                        rdata
                    }
                    TYPE_A => vec![192, 0, 2, 10],
                    other => panic!("unexpected test query type {other}"),
                };
                response.extend_from_slice(&[0xc0, 0x0c]);
                response.extend_from_slice(&question.rr_type.to_be_bytes());
                response.extend_from_slice(&CLASS_IN.to_be_bytes());
                response.extend_from_slice(&60u32.to_be_bytes());
                response.extend_from_slice(
                    &u16::try_from(rdata.len())
                        .expect("test RDATA length")
                        .to_be_bytes(),
                );
                response.extend_from_slice(&rdata);
                socket
                    .send_to(&response, peer)
                    .expect("send test DNS response");
            }
        });
        (address, worker)
    }

    fn spawn_internationalized_service_server() -> (std::net::SocketAddr, thread::JoinHandle<()>) {
        use crate::wire::{encode_name, first_question, question_end};
        use std::net::UdpSocket;

        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind IDNA service server");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set IDNA service timeout");
        let address = socket.local_addr().expect("IDNA service address");
        let worker = thread::spawn(move || {
            let mut buffer = [0; 4096];
            let (length, peer) = socket.recv_from(&mut buffer).expect("IDNA service query");
            let query = &buffer[..length];
            let question = first_question(query).expect("IDNA service question");
            assert_eq!(question.rr_type, TYPE_SRV);
            assert_eq!(
                question.name.text(),
                r"Caf\195\169\046Desk._demo._tcp.xn--bcher-kva.example"
            );
            let end = question_end(query).expect("IDNA service question end");
            let mut response = query[..end].to_vec();
            response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
            response[6..8].copy_from_slice(&1u16.to_be_bytes());
            response[8..12].fill(0);
            let mut rdata = Vec::new();
            rdata.extend_from_slice(&10u16.to_be_bytes());
            rdata.extend_from_slice(&20u16.to_be_bytes());
            rdata.extend_from_slice(&443u16.to_be_bytes());
            rdata.extend_from_slice(&encode_name("host.example").expect("service target"));
            response.extend_from_slice(&[0xc0, 0x0c]);
            response.extend_from_slice(&TYPE_SRV.to_be_bytes());
            response.extend_from_slice(&CLASS_IN.to_be_bytes());
            response.extend_from_slice(&60u32.to_be_bytes());
            response.extend_from_slice(
                &u16::try_from(rdata.len())
                    .expect("IDNA SRV RDATA length")
                    .to_be_bytes(),
            );
            response.extend_from_slice(&rdata);
            socket
                .send_to(&response, peer)
                .expect("IDNA service response");
        });
        (address, worker)
    }

    fn spawn_service_server_with_failed_txt() -> (std::net::SocketAddr, thread::JoinHandle<()>) {
        use crate::wire::{encode_name, first_question, question_end};
        use std::net::UdpSocket;

        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind partial service server");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set partial service timeout");
        let address = socket.local_addr().expect("partial service address");
        let worker = thread::spawn(move || {
            let mut buffer = [0; 4096];
            let mut seen = std::collections::BTreeSet::new();
            for _ in 0..2 {
                let (length, peer) = socket
                    .recv_from(&mut buffer)
                    .expect("partial service query");
                let query = &buffer[..length];
                let question = first_question(query).expect("partial service question");
                assert!(matches!(question.rr_type, TYPE_SRV | TYPE_TXT));
                assert!(seen.insert(question.rr_type));
                let end = question_end(query).expect("partial service question end");
                let mut response = query[..end].to_vec();
                response[8..12].fill(0);
                if question.rr_type == TYPE_TXT {
                    response[2..4].copy_from_slice(&0x8182u16.to_be_bytes());
                    response[6..8].fill(0);
                } else {
                    response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
                    response[6..8].copy_from_slice(&1u16.to_be_bytes());
                    let mut rdata = Vec::new();
                    rdata.extend_from_slice(&10u16.to_be_bytes());
                    rdata.extend_from_slice(&20u16.to_be_bytes());
                    rdata.extend_from_slice(&443u16.to_be_bytes());
                    rdata.extend_from_slice(
                        &encode_name("host.example.test").expect("partial service target"),
                    );
                    response.extend_from_slice(&[0xc0, 0x0c]);
                    response.extend_from_slice(&TYPE_SRV.to_be_bytes());
                    response.extend_from_slice(&CLASS_IN.to_be_bytes());
                    response.extend_from_slice(&60u32.to_be_bytes());
                    response.extend_from_slice(
                        &u16::try_from(rdata.len())
                            .expect("partial SRV RDATA length")
                            .to_be_bytes(),
                    );
                    response.extend_from_slice(&rdata);
                }
                socket
                    .send_to(&response, peer)
                    .expect("partial service response");
            }
        });
        (address, worker)
    }

    fn spawn_redirected_service_server() -> (std::net::SocketAddr, thread::JoinHandle<()>) {
        use crate::wire::{encode_name, first_question, question_end, TYPE_A, TYPE_CNAME};
        use std::net::UdpSocket;

        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind redirected service server");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set redirected service timeout");
        let address = socket.local_addr().expect("redirected service address");
        let worker = thread::spawn(move || {
            let mut buffer = [0; 4096];
            for _ in 0..5 {
                let (length, peer) = socket
                    .recv_from(&mut buffer)
                    .expect("receive redirected service query");
                let query = &buffer[..length];
                let question = first_question(query).expect("redirected service question");
                let end = question_end(query).expect("redirected service question end");
                let mut response = query[..end].to_vec();
                response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
                response[8..12].fill(0);

                let mut answers: Vec<(Vec<u8>, u16, Vec<u8>)> = Vec::new();
                match (question.name.text(), question.rr_type) {
                    ("_demo._tcp.example.test", TYPE_SRV | TYPE_TXT) => answers.push((
                        vec![0xc0, 0x0c],
                        TYPE_CNAME,
                        encode_name("_demo._tcp.canonical.test").expect("canonical service"),
                    )),
                    ("_demo._tcp.canonical.test", TYPE_SRV) => {
                        let mut srv = Vec::new();
                        srv.extend_from_slice(&10u16.to_be_bytes());
                        srv.extend_from_slice(&20u16.to_be_bytes());
                        srv.extend_from_slice(&631u16.to_be_bytes());
                        srv.extend_from_slice(
                            &encode_name("host.canonical.test").expect("service target"),
                        );
                        answers.push((vec![0xc0, 0x0c], TYPE_SRV, srv.clone()));
                        answers.push((
                            encode_name("_other._tcp.canonical.test").expect("unrelated service"),
                            TYPE_SRV,
                            srv,
                        ));
                    }
                    ("_demo._tcp.canonical.test", TYPE_TXT) => {
                        let item = b"canonical=yes";
                        let mut txt = vec![u8::try_from(item.len()).expect("TXT length")];
                        txt.extend_from_slice(item);
                        answers.push((vec![0xc0, 0x0c], TYPE_TXT, txt.clone()));
                        answers.push((
                            encode_name("_other._tcp.canonical.test").expect("unrelated service"),
                            TYPE_TXT,
                            txt,
                        ));
                    }
                    ("host.canonical.test", TYPE_A) => {
                        answers.push((vec![0xc0, 0x0c], TYPE_A, vec![192, 0, 2, 20]))
                    }
                    other => panic!("unexpected redirected service query {other:?}"),
                }

                response[6..8].copy_from_slice(
                    &u16::try_from(answers.len())
                        .expect("answer count")
                        .to_be_bytes(),
                );
                for (owner, rr_type, rdata) in answers {
                    response.extend_from_slice(&owner);
                    response.extend_from_slice(&rr_type.to_be_bytes());
                    response.extend_from_slice(&CLASS_IN.to_be_bytes());
                    response.extend_from_slice(&60u32.to_be_bytes());
                    response.extend_from_slice(
                        &u16::try_from(rdata.len())
                            .expect("redirected service RDATA length")
                            .to_be_bytes(),
                    );
                    response.extend_from_slice(&rdata);
                }
                socket
                    .send_to(&response, peer)
                    .expect("send redirected service response");
            }
        });
        (address, worker)
    }

    #[test]
    fn resolve_service_returns_srv_txt_and_addresses() {
        let (server, worker) = spawn_service_server();
        let config = Config {
            upstreams: Vec::new(),
            fallback_upstreams: Vec::new(),
            query_timeout: Duration::from_secs(1),
            attempts: 1,
            cache: false,
            read_etc_hosts: false,
            ..Config::default()
        };
        let resolver = Resolver::new(config);
        resolver
            .set_link_dns(7, vec![server])
            .expect("set service link DNS");
        resolver
            .set_link_domains(
                7,
                vec![crate::config::Domain {
                    name: "example.test".to_owned(),
                    route_only: true,
                }],
            )
            .expect("set service route domain");
        let reply = dispatch(
            r#"{"method":"io.rustd.Resolve.ResolveService","parameters":{"type":"_demo._tcp","domain":"example.test","family":2}}"#,
            &resolver,
        );
        worker.join().expect("test DNS worker");

        assert!(reply.get("error").is_none(), "{}", reply.to_json());
        let parameters = reply.get("parameters").expect("reply parameters");
        let services = parameters
            .get("services")
            .and_then(Value::as_array)
            .expect("services");
        assert_eq!(services.len(), 1);
        assert_eq!(
            services[0].get("hostname").and_then(Value::as_str),
            Some("host.example.test")
        );
        assert_eq!(
            services[0]
                .get("addresses")
                .and_then(Value::as_array)
                .and_then(|addresses| addresses.first())
                .and_then(|address| address.get("ifindex"))
                .and_then(Value::as_i64),
            Some(7)
        );
        assert_eq!(
            services[0]
                .get("addresses")
                .and_then(Value::as_array)
                .and_then(|addresses| addresses.first())
                .and_then(|address| address.get("family"))
                .and_then(Value::as_i64),
            Some(2)
        );
        assert_eq!(
            parameters
                .get("txt")
                .and_then(Value::as_array)
                .and_then(|txt| txt.first())
                .and_then(Value::as_str),
            Some("path=/")
        );
        assert!(
            reply.to_json().contains(
                r#""services":[{"priority":10,"weight":20,"port":631,"hostname":"host.example.test","canonicalName":"host.example.test","addresses":[{"ifindex":7,"family":2,"address":[192,0,2,10]}]}],"txt":["path=/"],"canonical":{"name":null,"type":"_demo._tcp","domain":"example.test"},"flags":"#
            ),
            "{}",
            reply.to_json()
        );
    }

    #[test]
    #[cfg(feature = "idna-name")]
    fn resolve_service_uses_utf8_instance_and_idna_domain_on_unicast() {
        let (server, worker) = spawn_internationalized_service_server();
        let resolver = Resolver::new(Config {
            upstreams: vec![server],
            fallback_upstreams: Vec::new(),
            query_timeout: Duration::from_secs(1),
            attempts: 1,
            cache: false,
            read_etc_hosts: false,
            read_static_records: false,
            dnssec: crate::config::ValidationMode::No,
            ..Config::default()
        });
        let flags = RUSTD_RESOLVE_NO_ADDRESS | RUSTD_RESOLVE_NO_TXT;
        let reply = dispatch(
            &format!(
                r#"{{"method":"io.rustd.Resolve.ResolveService","parameters":{{"name":"Café.Desk","type":"_demo._tcp","domain":"bücher.example","flags":{flags}}}}}"#
            ),
            &resolver,
        );
        worker.join().expect("IDNA service worker");
        assert!(reply.get("error").is_none(), "{}", reply.to_json());
        let canonical = reply
            .get("parameters")
            .and_then(|parameters| parameters.get("canonical"))
            .expect("canonical service");
        assert_eq!(
            canonical.get("name").and_then(Value::as_str),
            Some("Café.Desk")
        );
        assert_eq!(
            canonical.get("domain").and_then(Value::as_str),
            Some("xn--bcher-kva.example")
        );
    }

    #[test]
    fn resolve_service_keeps_srv_success_when_txt_fails() {
        let (server, worker) = spawn_service_server_with_failed_txt();
        let resolver = Resolver::new(Config {
            upstreams: vec![server],
            fallback_upstreams: Vec::new(),
            query_timeout: Duration::from_secs(1),
            attempts: 1,
            cache: false,
            read_etc_hosts: false,
            read_static_records: false,
            dnssec: crate::config::ValidationMode::No,
            ..Config::default()
        });
        let reply = dispatch(
            &format!(
                r#"{{"method":"io.rustd.Resolve.ResolveService","parameters":{{"type":"_demo._tcp","domain":"example.test","flags":{RUSTD_RESOLVE_NO_ADDRESS}}}}}"#
            ),
            &resolver,
        );
        worker.join().expect("partial service worker");
        assert!(reply.get("error").is_none(), "{}", reply.to_json());
        let parameters = reply.get("parameters").expect("service parameters");
        assert_eq!(
            parameters
                .get("services")
                .and_then(Value::as_array)
                .map(|values| values.len()),
            Some(1)
        );
        assert!(parameters.get("txt").is_none());
    }

    #[test]
    fn resolve_service_uses_the_post_redirect_owner_and_ignores_unrelated_records() {
        let (server, worker) = spawn_redirected_service_server();
        let config = Config {
            upstreams: Vec::new(),
            fallback_upstreams: Vec::new(),
            query_timeout: Duration::from_secs(1),
            attempts: 1,
            cache: false,
            read_etc_hosts: false,
            ..Config::default()
        };
        let resolver = Resolver::new(config);
        resolver
            .set_link_dns(7, vec![server])
            .expect("set redirected service link DNS");
        let reply = dispatch(
            r#"{"method":"io.rustd.Resolve.ResolveService","parameters":{"type":"_demo._tcp","domain":"example.test","family":2,"ifindex":7}}"#,
            &resolver,
        );
        worker.join().expect("redirected service worker");

        assert!(reply.get("error").is_none(), "{}", reply.to_json());
        let parameters = reply.get("parameters").expect("reply parameters");
        assert_eq!(
            parameters
                .get("services")
                .and_then(Value::as_array)
                .map(|values| values.len()),
            Some(1)
        );
        assert_eq!(
            parameters
                .get("txt")
                .and_then(Value::as_array)
                .map(|values| values.len()),
            Some(1)
        );
        let canonical = parameters.get("canonical").expect("canonical service");
        assert_eq!(canonical.get("name"), Some(&Value::Null));
        assert_eq!(
            canonical.get("type").and_then(Value::as_str),
            Some("_demo._tcp")
        );
        assert_eq!(
            canonical.get("domain").and_then(Value::as_str),
            Some("canonical.test")
        );
    }

    #[test]
    fn service_question_supports_dns_sd_and_plain_srv_names() {
        let dns_sd = service_question(Some("Printer"), Some("_ipp._tcp"), "example.test")
            .expect("DNS-SD question");
        assert_eq!(dns_sd.owner, "Printer._ipp._tcp.example.test");
        assert_eq!(dns_sd.name.as_deref(), Some("Printer"));
        assert_eq!(dns_sd.service_type, "_ipp._tcp");
        assert_eq!(dns_sd.domain, "example.test");

        let plain =
            service_question(None, None, "_ldap._tcp.example.test").expect("plain SRV question");
        assert_eq!(plain.owner, "_ldap._tcp.example.test");
        assert_eq!(plain.name, None);
        assert_eq!(plain.service_type, "_ldap._tcp");
        assert_eq!(plain.domain, "example.test");
    }

    #[test]
    fn service_question_rejects_name_without_type() {
        assert!(service_question(Some("Printer"), None, "example.test").is_none());
    }

    #[test]
    fn pinned_error_identifiers_and_dnssec_parameters_are_exact() {
        let errors = [
            ResolveError::QueryAborted,
            ResolveError::QueryRefused,
            ResolveError::MaxAttemptsReached,
            ResolveError::ResourceRecordTypeUnsupported,
            ResolveError::NoTrustAnchor,
            ResolveError::StubLoop,
            ResolveError::ResourceRecordTypeObsolete,
            ResolveError::InconsistentServiceRecords,
        ];
        let identifiers: Vec<_> = errors.iter().map(ResolveError::varlink_id).collect();
        assert_eq!(
            identifiers,
            vec![
                "io.rustd.Resolve.QueryAborted",
                "io.rustd.Resolve.QueryRefused",
                "io.rustd.Resolve.MaxAttemptsReached",
                "io.rustd.Resolve.ResourceRecordTypeUnsupported",
                "io.rustd.Resolve.NoTrustAnchor",
                "io.rustd.Resolve.StubLoop",
                "io.rustd.Resolve.ResourceRecordTypeObsolete",
                "io.rustd.Resolve.InconsistentServiceRecords",
            ]
        );

        for (error_value, expected) in [
            (
                ResolveError::Wire(crate::wire::WireError::ShortPacket),
                "io.rustd.Resolve.InvalidReply",
            ),
            (
                ResolveError::Protocol("malformed reply"),
                "io.rustd.Resolve.InvalidReply",
            ),
            (
                ResolveError::Link(crate::routing::LinkError::NoSuchLink(99)),
                "io.rustd.Resolve.NoSource",
            ),
            (
                ResolveError::Io(io::Error::new(io::ErrorKind::ConnectionRefused, "offline")),
                "io.rustd.Resolve.NetworkDown",
            ),
        ] {
            assert_eq!(error_value.varlink_id(), expected);
            assert!(INTERFACE_DESCRIPTION.contains(&format!(
                "error {}(",
                expected.trim_start_matches("io.rustd.Resolve.")
            )));
        }

        let dnssec = ResolveError::DnssecValidationFailed {
            result: "bogus".to_owned(),
            extended_dns_error_code: Some(6),
            extended_dns_error_message: Some("signature expired".to_owned()),
        };
        let reply = resolver_error(&dnssec);
        assert_eq!(
            reply.get("error").and_then(Value::as_str),
            Some("io.rustd.Resolve.DNSSECValidationFailed")
        );
        let parameters = reply.get("parameters").expect("DNSSEC error parameters");
        assert_eq!(
            parameters.get("result").and_then(Value::as_str),
            Some("bogus")
        );
        assert_eq!(
            parameters
                .get("extendedDNSErrorCode")
                .and_then(Value::as_u64),
            Some(6)
        );
        assert_eq!(
            parameters
                .get("extendedDNSErrorMessage")
                .and_then(Value::as_str),
            Some("signature expired")
        );

        let dnssec_without_message = ResolveError::DnssecValidationFailed {
            result: "upstream-failure".to_owned(),
            extended_dns_error_code: Some(6),
            extended_dns_error_message: None,
        };
        assert_eq!(
            resolver_error(&dnssec_without_message).to_json(),
            r#"{"error":"io.rustd.Resolve.DNSSECValidationFailed","parameters":{"result":"upstream-failure","extendedDNSErrorCode":6}}"#
        );

        let censored = ResolveError::DnsError {
            rcode: 2,
            query: "censored.example".to_owned(),
            extended_dns_error_code: Some(16),
            extended_dns_error_message: Some("Nothing to see here!".to_owned()),
        };
        assert_eq!(
            resolver_error(&censored).to_json(),
            r#"{"error":"io.rustd.Resolve.DNSError","parameters":{"rcode":2,"extendedDNSErrorCode":16,"extendedDNSErrorMessage":"Nothing to see here!"}}"#
        );
    }

    #[test]
    fn interface_description_lists_pinned_error_identifiers() {
        let resolver = Resolver::new(Config::default());
        let reply = dispatch(
            r#"{"method":"org.varlink.service.GetInterfaceDescription","parameters":{"interface":"io.rustd.Resolve"}}"#,
            &resolver,
        );
        let description = reply
            .get("parameters")
            .and_then(|parameters| parameters.get("description"))
            .and_then(Value::as_str)
            .expect("interface description");
        for symbol in [
            "DNSSECValidationFailed",
            "InconsistentServiceRecords",
            "NoTrustAnchor",
            "QueryAborted",
            "QueryRefused",
            "ResourceRecordTypeObsolete",
            "StubLoop",
        ] {
            assert!(description.contains(symbol), "missing {symbol}");
        }
    }

    #[test]
    fn txt_octescape_preserves_printable_bytes() {
        assert_eq!(octescape(b"path=/"), "path=/");
        assert_eq!(octescape(&[0, b'\\', 0xff]), "\\000\\134\\377");
    }
}
