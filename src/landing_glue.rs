//! Process entry orchestration: publish resolv.conf, control plane, dataplane, lifecycle.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use parking_lot::RwLock;
use tracing::{error, info, warn};

use crate::config::Config;
use crate::daemon::stop_requested;
use crate::dbus::DbusServer;
use crate::lifecycle;
use crate::resolvconf_publish::{GlobalDnsState, ResolvConfMode, ResolvConfPublisher};
use crate::resolver::Resolver;
use crate::server_features::FeatureTable;
use crate::split_dns::SplitDnsTable;
use crate::supremacy::dataplane::{Dataplane, DataplaneConfig};
use crate::supremacy::obs::{serve_metrics, FlightRecorder, Metrics};
use crate::supremacy::resolver::SupremacyResolver;
use crate::synthetic::HostsTable;
use crate::varlink::VarlinkServer;

#[derive(Clone, Debug)]
pub struct LandingConfig {
    pub stub_addr: SocketAddr,
    pub stub_addr_alt: Option<SocketAddr>,
    pub workers: usize,
    pub run_dir: PathBuf,
    pub metrics_addr: Option<String>,
    pub shm_l1: bool,
    pub swr: bool,
    pub search: Vec<String>,
    pub uplink: Vec<IpAddr>,
    pub hosts_path: PathBuf,
    pub hostname: String,
    pub watchdog_secs: u64,
}

impl Default for LandingConfig {
    fn default() -> Self {
        let metrics = std::env::var("RUSTD_RESOLVED_METRICS")
            .ok()
            .filter(|s| !s.is_empty());
        let shm = std::env::var("RUSTD_RESOLVED_SHM")
            .map(|v| v != "0" && v != "false")
            .unwrap_or(true);
        let hostname = crate::native::kernel_hostname().unwrap_or_else(|| "localhost".into());
        let stub_addr = std::env::var("RUSTD_RESOLVED_STUB_ADDR")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| SocketAddr::from((Ipv4Addr::new(127, 0, 0, 53), 53)));
        let stub_addr_alt = std::env::var("RUSTD_RESOLVED_STUB_ADDR_ALT")
            .ok()
            .and_then(|s| s.parse().ok())
            .map(Some)
            .unwrap_or_else(|| Some(SocketAddr::from((Ipv4Addr::new(127, 0, 0, 54), 53))));
        let run_dir = std::env::var("RUSTD_RESOLVED_RUN_DIR")
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/run/systemd/resolve"));
        Self {
            stub_addr,
            stub_addr_alt,
            workers: std::env::var("RUSTD_RESOLVED_WORKERS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            run_dir,
            metrics_addr: metrics,
            shm_l1: shm,
            swr: std::env::var("RUSTD_RESOLVED_SWR")
                .map(|v| v != "0")
                .unwrap_or(true),
            search: vec![],
            uplink: vec![],
            hosts_path: PathBuf::from("/etc/hosts"),
            hostname,
            watchdog_secs: 15,
        }
    }
}

/// Shared daemon state for control plane + dataplane.
#[allow(missing_debug_implementations)]
pub struct DaemonState {
    pub core: Arc<SupremacyResolver>,
    pub publisher: ResolvConfPublisher,
    pub dns_state: RwLock<GlobalDnsState>,
    pub split: RwLock<SplitDnsTable>,
    pub features: Arc<FeatureTable>,
    pub hosts: RwLock<HostsTable>,
    pub flight: Arc<FlightRecorder>,
    pub metrics: Arc<Metrics>,
    pub hostname: RwLock<String>,
}

impl DaemonState {
    pub fn from_landing(landing: &LandingConfig, backend: Arc<Resolver>) -> Arc<Self> {
        let core = SupremacyResolver::new_with_shm(backend, landing.shm_l1);
        let metrics = Arc::clone(&core.metrics);
        let hosts_text = std::fs::read_to_string(&landing.hosts_path).unwrap_or_default();
        let hosts = HostsTable::parse_hosts_file(&hosts_text);
        let publisher = ResolvConfPublisher {
            run_dir: landing.run_dir.clone(),
            mode: ResolvConfMode::Stub,
            ..Default::default()
        };
        let dns_state = GlobalDnsState {
            search: landing.search.clone(),
            uplink_servers: landing.uplink.clone(),
            options: vec!["edns0".into(), "trust-ad".into()],
            banner: Some("rustd-resolved".into()),
            llmnr_hostname: Some(landing.hostname.clone()),
        };
        Arc::new(Self {
            core,
            publisher,
            dns_state: RwLock::new(dns_state),
            split: RwLock::new(SplitDnsTable {
                search: landing.search.clone(),
                allow_default: true,
                ..Default::default()
            }),
            features: Arc::new(FeatureTable::new()),
            hosts: RwLock::new(hosts),
            flight: FlightRecorder::new(2048),
            metrics,
            hostname: RwLock::new(landing.hostname.clone()),
        })
    }

    pub fn republish_resolv(&self) {
        let st = self.dns_state.read().clone();
        self.publisher.republish_lossy(&st);
    }

    pub fn reload_hosts(&self, path: &std::path::Path) {
        match std::fs::read_to_string(path) {
            Ok(t) => {
                *self.hosts.write() = HostsTable::parse_hosts_file(&t);
                info!("reloaded hosts file");
            }
            Err(e) => warn!(error = %e, "hosts reload failed"),
        }
    }

    pub fn flush_all(&self) {
        self.core.flush_all();
        self.features.reset_all();
        info!("flushed caches and server features");
    }
}

pub async fn run(landing: LandingConfig) -> anyhow::Result<()> {
    crate::log_control::initialize();
    lifecycle::install_signal_handlers();
    lifecycle::spawn_watchdog_loop(Duration::from_secs(landing.watchdog_secs));

    let control_resolver = Arc::new(Resolver::new(Config::default()));
    let state = DaemonState::from_landing(&landing, Arc::clone(&control_resolver));
    state.republish_resolv();

    let _networkd_thread = crate::networkd::spawn(Arc::clone(&control_resolver))
        .map_err(|error| anyhow::anyhow!("networkd monitor: {error}"))?;

    // Metrics
    if let Some(addr) = landing.metrics_addr.clone() {
        let m = Arc::clone(&state.metrics);
        info!(%addr, "metrics listening");
        tokio::spawn(async move {
            if let Err(e) = serve_metrics(m, &addr).await {
                error!(error = %e, "metrics server stopped");
            }
        });
    }

    // Control-plane tasks: D-Bus server
    {
        let dbus_server = DbusServer::new(Arc::clone(&control_resolver));
        info!("spawning D-Bus server");
        thread::Builder::new()
            .name("resolved-dbus".to_owned())
            .spawn(move || {
                if let Err(error) = dbus_server.run() {
                    error!(error = %error, "D-Bus server failed");
                    stop_requested();
                }
            })
            .expect("failed to spawn D-Bus server thread");
    }

    // Control-plane tasks: Varlink server
    {
        let varlink_path = landing.run_dir.join("io.rustd.Resolve");
        info!("spawning Varlink server at {}", varlink_path.display());
        let varlink_server = VarlinkServer::new(varlink_path, Arc::clone(&control_resolver))
            .expect("failed to create Varlink server");
        thread::Builder::new()
            .name("resolved-varlink".to_owned())
            .spawn(move || {
                if let Err(error) = varlink_server.run() {
                    error!(error = %error, "Varlink server failed");
                    stop_requested();
                }
            })
            .expect("failed to spawn Varlink server thread");
    }

    // Lifecycle flags
    {
        let st = Arc::clone(&state);
        let hosts_path = landing.hosts_path.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_millis(250));
            loop {
                iv.tick().await;
                if lifecycle::stop_requested() {
                    lifecycle::sd_notify_stopping();
                    break;
                }
                if lifecycle::take_reload() {
                    lifecycle::sd_notify_status("reloading");
                    st.reload_hosts(&hosts_path);
                    st.flush_all();
                    crate::static_records::invalidate_system();
                    st.republish_resolv();
                    lifecycle::sd_notify_status("running");
                }
                if lifecycle::take_flush() {
                    st.flush_all();
                }
                if lifecycle::take_dump_stats() {
                    let text = st.metrics.prometheus_text();
                    info!(target: "stats", "{text}");
                }
            }
        });
    }

    lifecycle::sd_notify_ready();
    lifecycle::sd_notify_status("running");
    info!(
        stub = %landing.stub_addr,
        workers = landing.workers,
        "rustd-resolved ready"
    );

    let workers = if landing.workers == 0 {
        std::thread::available_parallelism()
            .map(|n| n.get().clamp(2, 16))
            .unwrap_or(4)
    } else {
        landing.workers.max(1)
    };

    let dp = Arc::new(Dataplane {
        cfg: DataplaneConfig {
            bind: landing.stub_addr,
            workers,
            recvmmsg_batch: 32,
        },
        cache: Arc::clone(&state.core.cache),
        resolver: Arc::clone(&state.core),
    });

    // Optional second bind 127.0.0.54
    if let Some(alt) = landing.stub_addr_alt {
        let dp2 = Arc::new(Dataplane {
            cfg: DataplaneConfig {
                bind: alt,
                workers: workers.max(1) / 2 + 1,
                recvmmsg_batch: 16,
            },
            cache: Arc::clone(&state.core.cache),
            resolver: Arc::clone(&state.core),
        });
        tokio::spawn(async move {
            if let Err(e) = dp2.run().await {
                error!(error = %e, "alt stub dataplane exited");
            }
        });
    }

    // Block on primary dataplane
    let result = dp.run().await;
    lifecycle::sd_notify_stopping();
    result.map_err(|e| anyhow::anyhow!("dataplane: {e}"))
}
