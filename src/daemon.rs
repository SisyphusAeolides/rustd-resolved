// SPDX-License-Identifier: LGPL-2.1-or-later
use crate::bounded_executor::{peer_key_from_socket_addr, tcp_executor};
use crate::config::{Config, SupportMode};
use crate::native;
use crate::resolver::{QueryMode, Resolver};
use std::env;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const MAX_UDP_PACKET: usize = 65_535;
const UDP_QUEUE_PER_WORKER: usize = 256;
static LOCAL_STOP: AtomicBool = AtomicBool::new(false);
static LOCAL_RELOAD: AtomicBool = AtomicBool::new(false);

#[derive(Debug)]
struct UdpJob {
    socket: Arc<UdpSocket>,
    packet: Vec<u8>,
    peer: SocketAddr,
    mode: QueryMode,
}

#[derive(Debug)]
struct UdpEndpoint {
    socket: Arc<UdpSocket>,
    mode: QueryMode,
}

#[derive(Debug)]
struct TcpEndpoint {
    listener: TcpListener,
    mode: QueryMode,
}

#[derive(Debug)]
struct UdpDispatcher {
    senders: Vec<SyncSender<UdpJob>>,
    next: AtomicUsize,
}

#[derive(Debug)]
struct ListenerRuntime {
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl ListenerRuntime {
    fn start(
        config: &Config,
        dispatcher: &Arc<UdpDispatcher>,
        resolver: &Arc<Resolver>,
    ) -> io::Result<Self> {
        let (udp_endpoints, tcp_endpoints) = bind_configured_endpoints(config)?;
        let mut runtime = Self {
            stop: Arc::new(AtomicBool::new(false)),
            threads: Vec::new(),
        };
        for (index, endpoint) in udp_endpoints.into_iter().enumerate() {
            let dispatcher = Arc::clone(dispatcher);
            let stop = Arc::clone(&runtime.stop);
            runtime.threads.push(
                thread::Builder::new()
                    .name(format!("resolved-udp-listener-{index}"))
                    .spawn(move || udp_listener(&endpoint, &dispatcher, &stop))?,
            );
        }
        for (index, endpoint) in tcp_endpoints.into_iter().enumerate() {
            let resolver = Arc::clone(resolver);
            let stop = Arc::clone(&runtime.stop);
            runtime.threads.push(
                thread::Builder::new()
                    .name(format!("resolved-tcp-listener-{index}"))
                    .spawn(move || tcp_listener(&endpoint, &resolver, &stop))?,
            );
        }
        Ok(runtime)
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        join_all(std::mem::take(&mut self.threads));
    }
}

impl Drop for ListenerRuntime {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl UdpDispatcher {
    fn new(senders: Vec<SyncSender<UdpJob>>) -> Self {
        Self {
            senders,
            next: AtomicUsize::new(0),
        }
    }

    fn dispatch(&self, mut job: UdpJob) -> bool {
        if self.senders.is_empty() {
            return false;
        }

        let start = self.next.fetch_add(1, Ordering::Relaxed) % self.senders.len();
        let mut connected = false;
        for offset in 0..self.senders.len() {
            let index = (start + offset) % self.senders.len();
            match self.senders[index].try_send(job) {
                Ok(()) => return true,
                Err(TrySendError::Full(returned)) => {
                    connected = true;
                    job = returned;
                }
                Err(TrySendError::Disconnected(returned)) => job = returned,
            }
        }

        connected
    }
}

#[derive(Debug)]
struct Watchdog {
    interval: Duration,
    next: Instant,
}

impl Watchdog {
    fn from_environment() -> Option<Self> {
        let usec = env::var("WATCHDOG_USEC").ok();
        let pid = env::var("WATCHDOG_PID").ok();
        let interval = watchdog_interval(usec.as_deref(), pid.as_deref(), std::process::id())?;
        let next = Instant::now().checked_add(interval)?;
        Some(Self { interval, next })
    }

    fn ping_if_due(&mut self) {
        let now = Instant::now();
        if now < self.next {
            return;
        }
        let _ = native::notify("WATCHDOG=1");
        self.next = now.checked_add(self.interval).unwrap_or(now);
    }

    fn sleep_duration(&self) -> Duration {
        self.interval.min(Duration::from_millis(200))
    }
}

pub fn request_stop() {
    LOCAL_STOP.store(true, Ordering::SeqCst);
}

pub fn request_reload() {
    LOCAL_RELOAD.store(true, Ordering::SeqCst);
    crate::lifecycle::RELOAD.store(true, Ordering::SeqCst);
}

fn take_reload() -> bool {
    let native = native::take_reload();
    let local = LOCAL_RELOAD.swap(false, Ordering::SeqCst);
    let landing = crate::lifecycle::RELOAD.swap(false, Ordering::SeqCst);
    native || local || landing
}

#[cfg(test)]
pub(crate) fn take_reload_for_test() -> bool {
    take_reload()
}

pub fn stop_requested() -> bool {
    LOCAL_STOP.load(Ordering::SeqCst) || native::stop_requested()
}

pub fn install_signal_handlers() -> io::Result<()> {
    native::install_signal_handlers()
}

pub fn run_stub(resolver: &Arc<Resolver>) -> io::Result<()> {
    run_stub_with_config(resolver, None)
}

pub fn run_stub_with_config(
    resolver: &Arc<Resolver>,
    config_path: Option<&Path>,
) -> io::Result<()> {
    let llmnr_runtime = crate::llmnr::LlmnrRuntime::start(Arc::clone(resolver))?;
    let mut mdns_responder = if resolver.global_multicast_dns_mode() == SupportMode::No {
        None
    } else {
        crate::mdns::responder::MdnsResponder::start_from_environment(Arc::clone(resolver))?
    };
    let workers = resolver.config().workers;
    let mut senders = Vec::with_capacity(workers);
    let mut threads = Vec::new();
    for index in 0..workers {
        let (sender, receiver) = mpsc::sync_channel::<UdpJob>(UDP_QUEUE_PER_WORKER);
        senders.push(sender);
        let resolver = Arc::clone(resolver);
        threads.push(
            thread::Builder::new()
                .name(format!("resolved-udp-worker-{index}"))
                .spawn(move || udp_worker(&resolver, &receiver))?,
        );
    }
    let dispatcher = Arc::new(UdpDispatcher::new(senders));
    let mut listeners = ListenerRuntime::start(&resolver.config(), &dispatcher, resolver)?;

    let mut watchdog = Watchdog::from_environment();
    let _ = native::notify("READY=1\nSTATUS=Processing requests");
    while !stop_requested() {
        if take_reload() {
            let _ = native::notify_reloading("Reloading resolver configuration");
            if let Some(path) = config_path {
                let config = match Config::load(path) {
                    Ok(config) => config,
                    Err(error) => {
                        eprintln!("rustd-resolved: failed to reload configuration: {error}");
                        let mut config = Config::default();
                        config.dns_delegates = crate::dns_delegate::load_system();
                        config
                    }
                };
                let previous = resolver.config();
                let listeners_changed = listener_configuration_changed(&previous, &config);
                resolver.reload_config(config.clone());
                if listeners_changed {
                    listeners.shutdown();
                    listeners = match ListenerRuntime::start(&config, &dispatcher, resolver) {
                        Ok(runtime) => runtime,
                        Err(error) => {
                            eprintln!("rustd-resolved: failed to reload stub listeners: {error}");
                            ListenerRuntime::start(&previous, &dispatcher, resolver)?
                        }
                    };
                }
                if resolver.global_multicast_dns_mode() == SupportMode::No {
                    drop(mdns_responder.take());
                } else if mdns_responder.is_none() {
                    match crate::mdns::responder::MdnsResponder::start_from_environment(Arc::clone(
                        resolver,
                    )) {
                        Ok(responder) => mdns_responder = responder,
                        Err(error) => {
                            eprintln!("rustd-resolved: failed to restart mDNS responder: {error}")
                        }
                    }
                }
                if let Err(error) = config.write_runtime_resolv_confs() {
                    eprintln!("rustd-resolved: failed to publish reloaded configuration: {error}");
                }
            }
            if let Err(error) = crate::netlink::synchronize(resolver) {
                eprintln!("rustd-resolved: failed to refresh kernel link state: {error}");
            }
            if let Err(error) = crate::networkd::synchronize(resolver) {
                eprintln!("rustd-resolved: failed to refresh networkd DNS state: {error}");
            }
            if let Err(error) = resolver.reload_hosts() {
                eprintln!("rustd-resolved: failed to reload hosts database: {error}");
            }
            if let Err(error) = crate::mdns::dnssd_runtime::force_reload() {
                eprintln!("rustd-resolved: failed to reload DNS-SD services: {error}");
            }
            let _ = native::notify("READY=1\nSTATUS=Processing requests");
        }
        if let Some(watchdog) = watchdog.as_mut() {
            watchdog.ping_if_due();
        }
        let sleep_duration = watchdog
            .as_ref()
            .map_or(Duration::from_millis(200), Watchdog::sleep_duration);
        thread::sleep(sleep_duration);
    }
    let _ = native::notify("STOPPING=1\nSTATUS=Shutting down");
    drop(mdns_responder);
    drop(llmnr_runtime);
    listeners.shutdown();
    drop(dispatcher);
    join_all(threads);
    Ok(())
}

fn bind_endpoints(
    addresses: &[SocketAddr],
    mode: QueryMode,
    udp_enabled: bool,
    tcp_enabled: bool,
    ignore_addr_in_use: bool,
    udp_endpoints: &mut Vec<UdpEndpoint>,
    tcp_endpoints: &mut Vec<TcpEndpoint>,
) -> io::Result<()> {
    for &address in addresses {
        if udp_enabled {
            match UdpSocket::bind(address) {
                Ok(udp) => {
                    udp.set_read_timeout(Some(Duration::from_millis(250)))?;
                    udp_endpoints.push(UdpEndpoint {
                        socket: Arc::new(udp),
                        mode,
                    });
                }
                Err(error) if ignore_addr_in_use && error.kind() == io::ErrorKind::AddrInUse => {}
                Err(error) => return Err(error),
            }
        }

        if tcp_enabled {
            match TcpListener::bind(address) {
                Ok(tcp) => {
                    tcp.set_nonblocking(true)?;
                    tcp_endpoints.push(TcpEndpoint {
                        listener: tcp,
                        mode,
                    });
                }
                Err(error) if ignore_addr_in_use && error.kind() == io::ErrorKind::AddrInUse => {}
                Err(error) => return Err(error),
            }
        }
    }
    Ok(())
}

fn bind_configured_endpoints(config: &Config) -> io::Result<(Vec<UdpEndpoint>, Vec<TcpEndpoint>)> {
    let mut udp_endpoints = Vec::new();
    let mut tcp_endpoints = Vec::new();
    let stub_mode = config.dns_stub_listener;
    bind_endpoints(
        &config.listeners,
        QueryMode::Full,
        stub_mode.udp_enabled(),
        stub_mode.tcp_enabled(),
        true,
        &mut udp_endpoints,
        &mut tcp_endpoints,
    )?;
    bind_endpoints(
        &config.proxy_listeners,
        QueryMode::Proxy,
        stub_mode.udp_enabled(),
        stub_mode.tcp_enabled(),
        true,
        &mut udp_endpoints,
        &mut tcp_endpoints,
    )?;
    for listener in &config.dns_stub_listener_extra {
        bind_endpoints(
            &[listener.address()],
            QueryMode::Full,
            listener.udp_enabled(),
            listener.tcp_enabled(),
            false,
            &mut udp_endpoints,
            &mut tcp_endpoints,
        )?;
    }
    Ok((udp_endpoints, tcp_endpoints))
}

fn listener_configuration_changed(previous: &Config, current: &Config) -> bool {
    previous.listeners != current.listeners
        || previous.proxy_listeners != current.proxy_listeners
        || previous.dns_stub_listener != current.dns_stub_listener
        || previous.dns_stub_listener_extra != current.dns_stub_listener_extra
}

fn udp_listener(endpoint: &UdpEndpoint, dispatcher: &UdpDispatcher, local_stop: &AtomicBool) {
    let mut buffer = vec![0; MAX_UDP_PACKET];
    while !stop_requested() && !local_stop.load(Ordering::SeqCst) {
        match endpoint.socket.recv_from(&mut buffer) {
            Ok((length, peer)) => {
                let job = UdpJob {
                    socket: Arc::clone(&endpoint.socket),
                    packet: buffer[..length].to_vec(),
                    peer,
                    mode: endpoint.mode,
                };
                if !dispatcher.dispatch(job) {
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => {
                eprintln!("rustd-resolved: UDP receive failed: {error}");
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn udp_worker(resolver: &Resolver, receiver: &Receiver<UdpJob>) {
    while !stop_requested() {
        let job = match receiver.recv_timeout(Duration::from_millis(250)) {
            Ok(job) => job,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        };
        let response = match resolver.query_or_servfail(&job.packet, job.mode) {
            Ok(response) => response,
            Err(error) => {
                eprintln!(
                    "rustd-resolved: rejected UDP query from {}: {error}",
                    job.peer
                );
                continue;
            }
        };
        if let Err(error) = job.socket.send_to(&response, job.peer) {
            eprintln!("rustd-resolved: UDP reply failed: {error}");
        }
    }
}

fn tcp_listener(endpoint: &TcpEndpoint, resolver: &Arc<Resolver>, local_stop: &AtomicBool) {
    while !stop_requested() && !local_stop.load(Ordering::SeqCst) {
        match endpoint.listener.accept() {
            Ok((stream, peer)) => {
                let resolver = Arc::clone(resolver);
                let mode = endpoint.mode;
                let peer_key = peer_key_from_socket_addr(peer);
                if !tcp_executor().try_submit(peer_key, move || {
                    if let Err(error) = tcp_client(stream, &resolver, mode) {
                        eprintln!("rustd-resolved: TCP client {peer} failed: {error}");
                    }
                }) {
                    eprintln!("rustd-resolved: rejected TCP client {peer}: executor overloaded");
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                eprintln!("rustd-resolved: TCP accept failed: {error}");
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn tcp_client(mut stream: TcpStream, resolver: &Resolver, mode: QueryMode) -> io::Result<()> {
    stream.set_read_timeout(Some(resolver.config().query_timeout))?;
    stream.set_write_timeout(Some(resolver.config().query_timeout))?;
    for _ in 0..128 {
        let mut length = [0; 2];
        match stream.read_exact(&mut length) {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::BrokenPipe
                ) =>
            {
                return Ok(());
            }
            Err(error) => return Err(error),
        }
        let length = usize::from(u16::from_be_bytes(length));
        if length == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "zero-length DNS-over-TCP frame",
            ));
        }
        let mut query = vec![0; length];
        stream.read_exact(&mut query)?;
        let response = resolver
            .query_or_servfail(&query, mode)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let response_length = u16::try_from(response.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "DNS response is too large"))?;
        stream.write_all(&response_length.to_be_bytes())?;
        stream.write_all(&response)?;
    }
    Ok(())
}

fn watchdog_interval(
    watchdog_usec: Option<&str>,
    watchdog_pid: Option<&str>,
    current_pid: u32,
) -> Option<Duration> {
    if let Some(pid) = watchdog_pid {
        if pid.parse::<u32>().ok()? != current_pid {
            return None;
        }
    }
    let usec = watchdog_usec?.parse::<u64>().ok()?;
    if usec == 0 {
        return None;
    }
    Some(Duration::from_micros((usec / 2).max(1)))
}

fn join_all(threads: Vec<JoinHandle<()>>) {
    for thread in threads {
        let _ = thread.join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_udp_job(socket: &Arc<UdpSocket>) -> UdpJob {
        UdpJob {
            socket: Arc::clone(socket),
            packet: vec![0; 12],
            peer: socket.local_addr().expect("test UDP address"),
            mode: QueryMode::Full,
        }
    }

    #[test]
    fn udp_dispatcher_spreads_jobs_across_worker_queues() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").expect("bind test UDP socket"));
        let (first_sender, first_receiver) = mpsc::sync_channel(1);
        let (second_sender, second_receiver) = mpsc::sync_channel(1);
        let dispatcher = UdpDispatcher::new(vec![first_sender, second_sender]);

        assert!(dispatcher.dispatch(test_udp_job(&socket)));
        assert!(dispatcher.dispatch(test_udp_job(&socket)));
        assert!(first_receiver.try_recv().is_ok());
        assert!(second_receiver.try_recv().is_ok());
    }

    #[test]
    fn udp_dispatcher_detects_when_all_workers_disconnect() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").expect("bind test UDP socket"));
        let (first_sender, first_receiver) = mpsc::sync_channel(1);
        let (second_sender, second_receiver) = mpsc::sync_channel(1);
        drop(first_receiver);
        drop(second_receiver);
        let dispatcher = UdpDispatcher::new(vec![first_sender, second_sender]);

        assert!(!dispatcher.dispatch(test_udp_job(&socket)));
    }

    #[test]
    fn occupied_primary_udp_socket_is_ignored() {
        let occupied = UdpSocket::bind("127.0.0.1:0").expect("occupy UDP address");
        let address = occupied.local_addr().expect("occupied UDP address");
        let mut udp_endpoints = Vec::new();
        let mut tcp_endpoints = Vec::new();
        bind_endpoints(
            &[address],
            QueryMode::Full,
            true,
            false,
            true,
            &mut udp_endpoints,
            &mut tcp_endpoints,
        )
        .expect("ignore occupied primary UDP socket");
        assert!(udp_endpoints.is_empty());

        let error = bind_endpoints(
            &[address],
            QueryMode::Full,
            true,
            false,
            false,
            &mut udp_endpoints,
            &mut tcp_endpoints,
        )
        .expect_err("explicit occupied UDP socket must fail");
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
    }

    #[test]
    fn occupied_primary_tcp_socket_is_ignored() {
        let occupied = TcpListener::bind("127.0.0.1:0").expect("occupy TCP address");
        let address = occupied.local_addr().expect("occupied TCP address");
        let mut udp_endpoints = Vec::new();
        let mut tcp_endpoints = Vec::new();
        bind_endpoints(
            &[address],
            QueryMode::Full,
            false,
            true,
            true,
            &mut udp_endpoints,
            &mut tcp_endpoints,
        )
        .expect("ignore occupied primary TCP socket");
        assert!(tcp_endpoints.is_empty());

        let error = bind_endpoints(
            &[address],
            QueryMode::Full,
            false,
            true,
            false,
            &mut udp_endpoints,
            &mut tcp_endpoints,
        )
        .expect_err("explicit occupied TCP socket must fail");
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
    }

    #[test]
    fn listener_reload_detection_covers_every_socket_setting() {
        let previous = Config::default();
        let mut current = previous.clone();
        assert!(!listener_configuration_changed(&previous, &current));

        current
            .dns_stub_listener_extra
            .push(crate::config::DnsStubListenerExtra::parse("127.0.0.153").expect("listener"));
        assert!(listener_configuration_changed(&previous, &current));

        current = previous.clone();
        current.dns_stub_listener = crate::config::DnsStubListenerMode::Udp;
        assert!(listener_configuration_changed(&previous, &current));

        current = previous.clone();
        current
            .listeners
            .push("127.0.0.153:53".parse().expect("address"));
        assert!(listener_configuration_changed(&previous, &current));

        current = previous.clone();
        current
            .proxy_listeners
            .push("127.0.0.154:53".parse().expect("address"));
        assert!(listener_configuration_changed(&previous, &current));
    }

    #[test]
    fn listener_runtime_releases_sockets_for_reload() {
        let probe = UdpSocket::bind("127.0.0.1:0").expect("reserve UDP address");
        let address = probe.local_addr().expect("UDP address");
        drop(probe);

        let config = Config {
            listeners: vec![address],
            proxy_listeners: Vec::new(),
            dns_stub_listener: crate::config::DnsStubListenerMode::Udp,
            dns_stub_listener_extra: Vec::new(),
            ..Config::default()
        };
        let resolver = Arc::new(Resolver::new(config.clone()));
        let (sender, receiver) = mpsc::sync_channel(1);
        let dispatcher = Arc::new(UdpDispatcher::new(vec![sender]));
        let mut runtime =
            ListenerRuntime::start(&config, &dispatcher, &resolver).expect("start listeners");
        assert_eq!(
            UdpSocket::bind(address)
                .expect_err("listener must own UDP address")
                .kind(),
            io::ErrorKind::AddrInUse
        );

        runtime.shutdown();
        UdpSocket::bind(address).expect("released UDP address");
        drop(receiver);
    }

    #[test]
    fn watchdog_uses_half_the_configured_period() {
        assert_eq!(
            watchdog_interval(Some("1000000"), None, 42),
            Some(Duration::from_millis(500))
        );
        assert_eq!(
            watchdog_interval(Some("1000000"), Some("42"), 42),
            Some(Duration::from_millis(500))
        );
    }

    #[test]
    fn watchdog_rejects_invalid_or_foreign_configuration() {
        assert_eq!(watchdog_interval(None, None, 42), None);
        assert_eq!(watchdog_interval(Some("0"), None, 42), None);
        assert_eq!(watchdog_interval(Some("invalid"), None, 42), None);
        assert_eq!(watchdog_interval(Some("1000"), Some("invalid"), 42), None);
        assert_eq!(watchdog_interval(Some("1000"), Some("7"), 42), None);
    }

    #[test]
    fn watchdog_never_uses_a_zero_ping_interval() {
        assert_eq!(
            watchdog_interval(Some("1"), None, 42),
            Some(Duration::from_micros(1))
        );
    }
}
