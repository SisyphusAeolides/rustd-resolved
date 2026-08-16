// SPDX-License-Identifier: LGPL-2.1-or-later
//! RustD-native Varlink transport in front of the shared resolver core.
//!
//! The public sockets speak only RustD names for introspection and native
//! callers. A private mode-0700 directory hosts the canonical dispatcher so
//! the mature resolver implementation stays single-sourced while migration
//! compatibility remains unreachable as a public socket path.

use rustd_resolved::bounded_executor::varlink_executor;
use rustd_resolved::daemon::stop_requested;
use rustd_resolved::json::{self, Value};
use rustd_resolved::native;
use rustd_resolved::resolver::Resolver;
use rustd_resolved::varlink::VarlinkServer;
use rustd_resolved::varlink_namespace::{
    canonical_method, compatibility_description, compatibility_method, native_description,
    native_method, COMPAT_ROOT_INTERFACE, NATIVE_ROOT_INTERFACE,
};
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

const MAX_MESSAGE_SIZE: usize = 1024 * 1024;
const CORE_DIRECTORY: &str = ".rustd-resolved-core";
const CORE_RESOLVE_SOCKET: &str = "io.rustd.Resolve";
const CORE_MONITOR_SOCKET: &str = "io.rustd.Resolve.Monitor";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Endpoint {
    Resolve,
    Monitor,
}

#[derive(Debug)]
enum ActivatedSocket {
    Listener(UnixListener),
    Connection(UnixStream),
}

#[derive(Debug)]
pub struct NativeVarlinkServer {
    path: PathBuf,
    monitor_path: PathBuf,
    resolver: Arc<Resolver>,
    activated: Vec<ActivatedSocket>,
    activated_monitor: Vec<ActivatedSocket>,
}

impl NativeVarlinkServer {
    pub fn new(path: impl Into<PathBuf>, resolver: Arc<Resolver>) -> io::Result<Self> {
        let names = env::var("LISTEN_FDNAMES").ok();
        let count = native::listen_fds()?;
        let (main_indices, monitor_indices) = classify_activation(count, names.as_deref())?;
        let activated = take_sockets(&main_indices)?;
        let activated_monitor = take_sockets(&monitor_indices)?;
        let path = path.into();
        let monitor_path = monitor_path_for(&path);
        Ok(Self {
            path,
            monitor_path,
            resolver,
            activated,
            activated_monitor,
        })
    }

    pub fn run(&self) -> io::Result<()> {
        let parent = self.path.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Varlink path has no parent directory",
            )
        })?;
        let core_directory = parent.join(CORE_DIRECTORY);
        prepare_core_directory(&core_directory)?;
        let core_path = core_directory.join(CORE_RESOLVE_SOCKET);
        let core_monitor_path = core_directory.join(CORE_MONITOR_SOCKET);

        let core = VarlinkServer::new(core_path.clone(), Arc::clone(&self.resolver))?;
        let (core_result_tx, core_result_rx) = mpsc::channel();
        let core_thread = thread::Builder::new()
            .name("rustd-resolved-varlink-core".to_owned())
            .spawn(move || {
                let result = core.run();
                let _ = core_result_tx.send(result);
            })?;

        if let Err(error) = wait_for_core(&core_path, &core_monitor_path, &core_result_rx) {
            let _ = core_thread.join();
            return Err(error);
        }

        let result = self.serve_public(&core_path, &core_monitor_path);
        if stop_requested() {
            let _ = core_thread.join();
        }
        let _ = fs::remove_file(&core_path);
        let _ = fs::remove_file(&core_monitor_path);
        let _ = fs::remove_dir(&core_directory);
        result
    }

    fn serve_public(&self, core_path: &Path, core_monitor_path: &Path) -> io::Result<()> {
        let main_is_activated = !self.activated.is_empty();
        let monitor_is_activated = !self.activated_monitor.is_empty();
        let mut listeners = activated_listeners(&self.activated)?;
        let mut monitor_listeners = activated_listeners(&self.activated_monitor)?;
        let remove_main = !main_is_activated;
        let remove_monitor = !monitor_is_activated && self.monitor_path != self.path;

        if remove_main {
            listeners.push(bind_public_listener(&self.path)?);
        }
        if remove_monitor {
            monitor_listeners.push(bind_public_listener(&self.monitor_path)?);
        }
        for listener in listeners.iter().chain(monitor_listeners.iter()) {
            listener.set_nonblocking(true)?;
        }

        serve_activated_connections(
            &self.activated,
            core_path,
            Endpoint::Resolve,
            "rustd-resolved-varlink-client",
        )?;
        serve_activated_connections(
            &self.activated_monitor,
            core_monitor_path,
            Endpoint::Monitor,
            "rustd-resolved-varlink-monitor-client",
        )?;

        while !stop_requested() {
            let mut accepted = false;
            for listener in &listeners {
                accepted |= accept_connection(
                    listener,
                    core_path,
                    Endpoint::Resolve,
                    "rustd-resolved-varlink-client",
                )?;
            }
            for listener in &monitor_listeners {
                accepted |= accept_connection(
                    listener,
                    core_monitor_path,
                    Endpoint::Monitor,
                    "rustd-resolved-varlink-monitor-client",
                )?;
            }
            if !accepted {
                thread::sleep(Duration::from_millis(25));
            }
        }

        if remove_main {
            let _ = fs::remove_file(&self.path);
        }
        if remove_monitor {
            let _ = fs::remove_file(&self.monitor_path);
        }
        Ok(())
    }
}

fn classify_activation(count: usize, names: Option<&str>) -> io::Result<(Vec<usize>, Vec<usize>)> {
    if count == 0 {
        return Ok((Vec::new(), Vec::new()));
    }
    let names = names.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "activated Varlink descriptors require LISTEN_FDNAMES",
        )
    })?;
    let names: Vec<_> = names.split(':').collect();
    if names.len() != count {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "activated Varlink descriptor names do not match descriptor count",
        ));
    }
    let mut main = Vec::new();
    let mut monitor = Vec::new();
    for (index, name) in names.into_iter().enumerate() {
        match name {
            "varlink" => main.push(index),
            "varlink-monitor" => monitor.push(index),
            _ => {}
        }
    }
    Ok((main, monitor))
}

fn take_sockets(indices: &[usize]) -> io::Result<Vec<ActivatedSocket>> {
    indices
        .iter()
        .map(|index| {
            let offset = i32::try_from(*index).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "activation descriptor index overflow",
                )
            })?;
            let fd = 3_i32.checked_add(offset).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "activation descriptor overflow",
                )
            })?;
            activated_socket_from_fd(fd)
        })
        .collect()
}

fn activated_socket_from_fd(fd: RawFd) -> io::Result<ActivatedSocket> {
    if native::socket_accepting(fd)? {
        // SAFETY: activation indices are unique and ownership is transferred once.
        let listener = unsafe { UnixListener::from_raw_fd(fd) };
        let _ = listener.local_addr()?;
        Ok(ActivatedSocket::Listener(listener))
    } else {
        // SAFETY: activation indices are unique and ownership is transferred once.
        let stream = unsafe { UnixStream::from_raw_fd(fd) };
        let _ = stream.peer_addr()?;
        Ok(ActivatedSocket::Connection(stream))
    }
}

fn activated_listeners(sockets: &[ActivatedSocket]) -> io::Result<Vec<UnixListener>> {
    sockets
        .iter()
        .filter_map(|socket| match socket {
            ActivatedSocket::Listener(listener) => Some(listener.try_clone()),
            ActivatedSocket::Connection(_) => None,
        })
        .collect()
}

fn serve_activated_connections(
    sockets: &[ActivatedSocket],
    core_path: &Path,
    endpoint: Endpoint,
    thread_name: &str,
) -> io::Result<()> {
    for socket in sockets {
        if let ActivatedSocket::Connection(stream) = socket {
            spawn_proxy(
                stream.try_clone()?,
                core_path.to_path_buf(),
                endpoint,
                thread_name,
            )?;
        }
    }
    Ok(())
}

fn accept_connection(
    listener: &UnixListener,
    core_path: &Path,
    endpoint: Endpoint,
    thread_name: &str,
) -> io::Result<bool> {
    match listener.accept() {
        Ok((stream, _)) => {
            spawn_proxy(stream, core_path.to_path_buf(), endpoint, thread_name)?;
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
        Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(false),
        Err(error) => Err(error),
    }
}

fn spawn_proxy(
    client: UnixStream,
    core_path: PathBuf,
    endpoint: Endpoint,
    thread_name: &str,
) -> io::Result<()> {
    let peer_key = varlink_frontend_peer_key(&client);
    if !varlink_executor().try_submit(peer_key, move || {
        if let Err(error) = proxy_connection(client, &core_path, endpoint) {
            eprintln!("rustd-resolved: native Varlink proxy failed: {error}");
        }
    }) {
        eprintln!("rustd-resolved: rejected {thread_name} Varlink connection: executor overloaded");
    }
    Ok(())
}

fn varlink_frontend_peer_key(stream: &UnixStream) -> u64 {
    use std::hash::{Hash, Hasher};
    if let Ok(credentials) = native::peer_credentials(stream.as_raw_fd()) {
        return u64::from(credentials.uid) << 32 | u64::from(credentials.pid);
    }
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    if let Ok(address) = stream.peer_addr() {
        if let Some(path) = address.as_pathname() {
            path.hash(&mut hasher);
        }
    }
    hasher.finish()
}

fn proxy_connection(
    mut client: UnixStream,
    core_path: &Path,
    endpoint: Endpoint,
) -> io::Result<()> {
    client.set_read_timeout(Some(Duration::from_secs(30)))?;
    client.set_write_timeout(Some(Duration::from_secs(30)))?;
    let mut core = connect_core(core_path)?;
    core.set_read_timeout(Some(Duration::from_millis(250)))?;
    core.set_write_timeout(Some(Duration::from_secs(30)))?;

    let mut client_pending = Vec::new();
    let mut core_pending = Vec::new();
    loop {
        let Some(request_frame) = read_frame(&mut client, &mut client_pending)? else {
            return Ok(());
        };
        let request = prepare_request(&request_frame, endpoint);
        core.write_all(request.encoded.as_bytes())?;
        core.write_all(&[0])?;

        let Some(reply_frame) = read_core_frame(&mut core, &mut core_pending, client.as_raw_fd())?
        else {
            return Ok(());
        };
        write_client_reply(&mut client, &reply_frame, request.native_reply)?;

        if reply_continues(&reply_frame) {
            loop {
                let Some(reply_frame) =
                    read_core_frame(&mut core, &mut core_pending, client.as_raw_fd())?
                else {
                    return Ok(());
                };
                write_client_reply(&mut client, &reply_frame, request.native_reply)?;
                if !reply_continues(&reply_frame) {
                    break;
                }
            }
        }
    }
}

#[derive(Debug)]
struct PreparedRequest {
    encoded: String,
    native_reply: bool,
}

fn prepare_request(input: &str, _endpoint: Endpoint) -> PreparedRequest {
    let Ok(Value::Object(mut request)) = json::parse(input) else {
        return PreparedRequest {
            encoded: input.to_owned(),
            native_reply: true,
        };
    };

    let mut compatibility_reply = false;
    if let Some(method) = request
        .get("method")
        .and_then(Value::as_str)
        .map(str::to_owned)
    {
        compatibility_reply |= method.starts_with(COMPAT_ROOT_INTERFACE);
        let canonical = canonical_method(&method);
        if canonical != method {
            request.insert("method".to_owned(), Value::String(canonical.into_owned()));
        }
    }

    if let Some(Value::Object(mut parameters)) = request.get("parameters").cloned() {
        if let Some(interface) = parameters
            .get("interface")
            .and_then(Value::as_str)
            .map(str::to_owned)
        {
            compatibility_reply |= interface.starts_with(COMPAT_ROOT_INTERFACE);
            let canonical = canonical_method(&interface);
            if canonical != interface {
                parameters.insert(
                    "interface".to_owned(),
                    Value::String(canonical.into_owned()),
                );
            }
        }
        request.insert("parameters".to_owned(), Value::Object(parameters));
    }

    let encoded = Value::Object(request).to_json();
    PreparedRequest {
        encoded,
        native_reply: !compatibility_reply,
    }
}

fn write_client_reply(client: &mut UnixStream, reply: &str, native_reply: bool) -> io::Result<()> {
    let reply = if native_reply {
        transform_reply_to_native(reply)
    } else {
        transform_reply_to_compatibility(reply)
    };
    client.write_all(reply.as_bytes())?;
    client.write_all(&[0])
}

fn transform_reply_to_native(input: &str) -> String {
    let Ok(Value::Object(mut reply)) = json::parse(input) else {
        return input.to_owned();
    };

    if let Some(error) = reply
        .get("error")
        .and_then(Value::as_str)
        .map(str::to_owned)
    {
        let native = native_method(&error);
        if native != error {
            reply.insert("error".to_owned(), Value::String(native.into_owned()));
        }
    }

    if let Some(Value::Object(mut parameters)) = reply.get("parameters").cloned() {
        if let Some(Value::Array(interfaces)) = parameters.get("interfaces").cloned() {
            let interfaces = interfaces
                .into_iter()
                .map(|value| match value {
                    Value::String(interface) => {
                        Value::String(native_method(&interface).into_owned())
                    }
                    other => other,
                })
                .collect();
            parameters.insert("interfaces".to_owned(), Value::Array(interfaces));
        }
        if let Some(description) = parameters
            .get("description")
            .and_then(Value::as_str)
            .map(str::to_owned)
        {
            parameters.insert(
                "description".to_owned(),
                Value::String(native_description(&description).into_owned()),
            );
        }
        reply.insert("parameters".to_owned(), Value::Object(parameters));
    }
    Value::Object(reply).to_json()
}

fn transform_reply_to_compatibility(input: &str) -> String {
    let Ok(Value::Object(mut reply)) = json::parse(input) else {
        return input.to_owned();
    };

    if let Some(error) = reply
        .get("error")
        .and_then(Value::as_str)
        .map(str::to_owned)
    {
        let compatibility = compatibility_method(&error);
        if compatibility != error {
            reply.insert(
                "error".to_owned(),
                Value::String(compatibility.into_owned()),
            );
        }
    }

    if let Some(Value::Object(mut parameters)) = reply.get("parameters").cloned() {
        if let Some(Value::Array(interfaces)) = parameters.get("interfaces").cloned() {
            let interfaces = interfaces
                .into_iter()
                .map(|value| match value {
                    Value::String(interface) => {
                        Value::String(compatibility_method(&interface).into_owned())
                    }
                    other => other,
                })
                .collect();
            parameters.insert("interfaces".to_owned(), Value::Array(interfaces));
        }
        if let Some(description) = parameters
            .get("description")
            .and_then(Value::as_str)
            .map(str::to_owned)
        {
            parameters.insert(
                "description".to_owned(),
                Value::String(compatibility_description(&description).into_owned()),
            );
        }
        reply.insert("parameters".to_owned(), Value::Object(parameters));
    }
    Value::Object(reply).to_json()
}

fn reply_continues(reply: &str) -> bool {
    json::parse(reply)
        .ok()
        .and_then(|value| value.get("continues").and_then(Value::as_bool))
        == Some(true)
}

fn read_core_frame(
    core: &mut UnixStream,
    pending: &mut Vec<u8>,
    client_fd: RawFd,
) -> io::Result<Option<String>> {
    loop {
        match read_frame(core, pending) {
            Ok(frame) => return Ok(frame),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                if stop_requested() || native::socket_disconnected(client_fd)? {
                    return Ok(None);
                }
            }
            Err(error) => return Err(error),
        }
    }
}

fn read_frame(stream: &mut UnixStream, pending: &mut Vec<u8>) -> io::Result<Option<String>> {
    let mut chunk = [0_u8; 8192];
    loop {
        if let Some(end) = pending.iter().position(|byte| *byte == 0) {
            let frame: Vec<_> = pending.drain(..=end).collect();
            return String::from_utf8(frame[..frame.len() - 1].to_vec())
                .map(Some)
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "Varlink frame is not UTF-8")
                });
        }
        let length = stream.read(&mut chunk)?;
        if length == 0 {
            if pending.is_empty() {
                return Ok(None);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unterminated Varlink frame",
            ));
        }
        pending.extend_from_slice(&chunk[..length]);
        if pending.len() > MAX_MESSAGE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Varlink frame is too large",
            ));
        }
    }
}

fn connect_core(path: &Path) -> io::Result<UnixStream> {
    for _ in 0..100 {
        match UnixStream::connect(path) {
            Ok(stream) => return Ok(stream),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                ) =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "private resolver Varlink core did not become available",
    ))
}

fn wait_for_core(
    resolve_path: &Path,
    monitor_path: &Path,
    result_rx: &mpsc::Receiver<io::Result<()>>,
) -> io::Result<()> {
    for _ in 0..200 {
        if resolve_path.exists() && monitor_path.exists() {
            return Ok(());
        }
        match result_rx.try_recv() {
            Ok(Ok(())) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "private resolver Varlink core stopped during startup",
                ));
            }
            Ok(Err(error)) => return Err(error),
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "private resolver Varlink core startup channel closed",
                ));
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "private resolver Varlink core did not create its sockets",
    ))
}

fn prepare_core_directory(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "private Varlink core path is not a directory",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => fs::create_dir(path)?,
        Err(error) => return Err(error),
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

fn bind_public_listener(path: &Path) -> io::Result<UnixListener> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => fs::remove_file(path)?,
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "refusing to replace a non-socket Varlink path",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o666))?;
    Ok(listener)
}

fn monitor_path_for(path: &Path) -> PathBuf {
    let mut monitor = path.as_os_str().to_owned();
    monitor.push(".Monitor");
    PathBuf::from(monitor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activation_names_are_routed_without_guessing() {
        assert_eq!(
            classify_activation(2, Some("varlink:varlink-monitor")).unwrap(),
            (vec![0], vec![1])
        );
        assert!(classify_activation(1, None).is_err());
        assert!(classify_activation(2, Some("varlink")).is_err());
    }

    #[test]
    fn native_request_is_canonicalized_for_shared_core() {
        let prepared = prepare_request(
            r#"{"method":"io.rustd.Resolve.ResolveHostname","parameters":{"name":"example.com"}}"#,
            Endpoint::Resolve,
        );
        assert!(prepared.native_reply);
        assert!(prepared
            .encoded
            .contains("io.rustd.Resolve.ResolveHostname"));
        assert!(!prepared
            .encoded
            .contains("io.systemd.Resolve.ResolveHostname"));
    }

    #[test]
    fn native_introspection_interface_is_canonicalized() {
        let prepared = prepare_request(
            r#"{"method":"org.varlink.service.GetInterfaceDescription","parameters":{"interface":"io.rustd.Resolve"}}"#,
            Endpoint::Resolve,
        );
        assert!(prepared.native_reply);
        assert!(prepared.encoded.contains("io.rustd.Resolve"));
    }

    #[test]
    fn transition_compatibility_request_keeps_compatibility_error_namespace() {
        let prepared = prepare_request(
            r#"{"method":"io.systemd.Resolve.ResolveHostname","parameters":{"name":"example.com"}}"#,
            Endpoint::Resolve,
        );
        assert!(!prepared.native_reply);
        assert!(prepared
            .encoded
            .contains("io.rustd.Resolve.ResolveHostname"));
        assert!(!prepared
            .encoded
            .contains("io.systemd.Resolve.ResolveHostname"));
    }

    #[test]
    fn compatibility_reply_translates_native_core_metadata() {
        let reply = transform_reply_to_compatibility(
            r#"{"error":"io.rustd.Resolve.DNSError","parameters":{"interfaces":["io.rustd","io.rustd.Resolve","io.rustd.service"],"description":"interface io.rustd.Resolve\nerror io.rustd.Resolve.DNSError()"}}"#,
        );
        assert!(reply.contains("io.systemd.Resolve.DNSError"));
        assert!(reply.contains("io.systemd.service"));
        assert!(reply.contains("interface io.systemd.Resolve"));
    }

    #[test]
    fn native_reply_rebrands_only_protocol_metadata() {
        let reply = transform_reply_to_native(
            r#"{"error":"io.systemd.Resolve.DNSError","parameters":{"interfaces":["io.systemd","io.systemd.Resolve","io.systemd.service"],"description":"interface io.systemd.Resolve\nerror io.systemd.Resolve.DNSError()","name":"io.systemd.Resolve.example"}}"#,
        );
        assert!(reply.contains("io.rustd.Resolve.DNSError"));
        assert!(reply.contains("io.rustd.service"));
        assert!(reply.contains("interface io.rustd.Resolve"));
        assert!(reply.contains("io.systemd.Resolve.example"));
    }

    #[test]
    fn monitor_socket_is_native_suffix() {
        assert_eq!(
            monitor_path_for(Path::new("/run/rustd/resolve/io.rustd.Resolve")),
            PathBuf::from("/run/rustd/resolve/io.rustd.Resolve.Monitor")
        );
    }

    #[test]
    fn protocol_roots_are_distinct() {
        assert_eq!(NATIVE_ROOT_INTERFACE, "io.rustd");
        assert_eq!(COMPAT_ROOT_INTERFACE, "io.systemd");
    }
}
