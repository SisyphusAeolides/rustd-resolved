//! SupremacyResolver — cache + SWR + NSEC agg + metrics + SHM publish hooks.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tracing::debug;

use crate::nss_backend::{build_address_answer, name_to_wire_lower, wire_to_presentation};
use crate::resolver::Resolver;
use crate::supremacy::budget::{QueryBudget, QueryClass};
use crate::supremacy::l2_cache::{CKey, CVal, DnssecMark, L2Cache};
use crate::supremacy::nsec_agg::{AggAnswer, AggressiveNsec};
use crate::supremacy::obs::{FlightEvent, FlightRecorder, Metrics};
use crate::supremacy::prefetch::PrefetchEngine;
use crate::supremacy::shm::{ShmAddr, ShmPublisher};
use crate::supremacy::sigcache::SigCache;
use crate::supremacy::swr::{decide_swr, SwrConfig, SwrDecision};
use crate::supremacy::transport_pool::TransportPool;
use crate::wire;
use parking_lot::Mutex;

#[derive(Debug)]
pub enum SupremacyErr {
    Budget,
    Upstream(String),
    DnssecBogus,
    PolicyBlackhole,
    Name(String),
    Internal(String),
}

impl std::fmt::Display for SupremacyErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Budget => write!(f, "query budget exhausted"),
            Self::Upstream(s) => write!(f, "upstream: {s}"),
            Self::DnssecBogus => write!(f, "dnssec bogus"),
            Self::PolicyBlackhole => write!(f, "policy blackhole"),
            Self::Name(s) => write!(f, "name: {s}"),
            Self::Internal(s) => write!(f, "internal: {s}"),
        }
    }
}

impl std::error::Error for SupremacyErr {}

pub struct SupremacyResolver {
    backend: Arc<Resolver>,
    pub cache: Arc<L2Cache>,
    pub nsec: Arc<AggressiveNsec>,
    pub sigcache: Arc<SigCache>,
    pub pool: Arc<TransportPool>,
    pub prefetch: Arc<PrefetchEngine>,
    pub metrics: Arc<Metrics>,
    pub flight: Arc<FlightRecorder>,
    pub shm: Mutex<Option<ShmPublisher>>,
    pub swr: SwrConfig,
}

impl SupremacyResolver {
    pub fn new(backend: Arc<Resolver>) -> Arc<Self> {
        Self::new_with_shm(backend, true)
    }

    /// Construct the research resolver with explicit shared-memory policy.
    ///
    /// The production compatibility daemon does not compile this module. A
    /// research build must still be able to disable the publisher so an
    /// operator cannot accidentally create the optional NSS cache merely by
    /// setting unrelated supremacy options.
    pub fn new_with_shm(backend: Arc<Resolver>, shm_enabled: bool) -> Arc<Self> {
        let swr = SwrConfig::default();
        Arc::new(Self {
            backend,
            cache: L2Cache::new(6, 8192, swr.clone()),
            nsec: AggressiveNsec::new(),
            sigcache: Arc::new(SigCache::new(65536)),
            pool: TransportPool::new(4, 4096),
            prefetch: PrefetchEngine::new(),
            metrics: Arc::new(Metrics::default()),
            flight: FlightRecorder::new(2048),
            shm: Mutex::new(if shm_enabled {
                ShmPublisher::create().ok()
            } else {
                None
            }),
            swr,
        })
    }

    pub fn flush_all(&self) {
        self.cache.flush();
    }

    pub async fn resolve_name(
        &self,
        name: &str,
        qtype: u16,
        qclass: u16,
        class: QueryClass,
    ) -> Result<CVal, SupremacyErr> {
        let wire = name_to_wire_lower(name).map_err(|e| SupremacyErr::Name(e.to_string()))?;
        let key = CKey {
            owner: Bytes::from(wire),
            qtype,
            qclass,
            cd: false,
        };
        self.resolve_key(key, class).await
    }

    pub async fn resolve_key(&self, key: CKey, class: QueryClass) -> Result<CVal, SupremacyErr> {
        let start = Instant::now();
        self.metrics
            .queries_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let budget = QueryBudget::new(class);
        let now = Instant::now();

        let ent = self.cache.get_entry(&key);
        match decide_swr(ent.as_ref(), now, &self.swr, &budget) {
            SwrDecision::Serve(v, kick) => {
                if ent.as_ref().map(|e| now >= e.expires).unwrap_or(false) {
                    self.metrics
                        .swr_served
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                } else {
                    self.metrics
                        .cache_hits
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                self.prefetch.record_hit(&key);
                if kick {
                    debug!(?key, "schedule background refresh");
                    // spawn refresh using pool — integrate with your upstream list
                }
                self.metrics.record_latency(start.elapsed());
                return Ok(v);
            }
            SwrDecision::MustFetch => {}
        }

        match self.nsec.lookup(&key.owner, key.qtype, now) {
            AggAnswer::NxDomain => {
                self.metrics
                    .nsec_agg_hits
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let v = CVal {
                    rcode: 3,
                    answer: Bytes::from(build_soa_nxbits(&key.owner, key.qtype)),
                    dnssec: DnssecMark::Secure,
                    min_ttl: 60,
                    from_upstream: 0,
                };
                self.cache.put(key, v.clone(), Duration::from_secs(60), now);
                return Ok(v);
            }
            AggAnswer::NoData => {
                self.metrics
                    .nsec_agg_hits
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let v = CVal {
                    rcode: 0,
                    answer: Bytes::new(),
                    dnssec: DnssecMark::Insecure,
                    min_ttl: 60,
                    from_upstream: 0,
                };
                return Ok(v);
            }
            AggAnswer::Miss => {}
        }

        if budget.expired() {
            self.metrics
                .budget_expired
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if let Some((v, true)) = self.cache.get(&key, now) {
                self.metrics
                    .swr_served
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Ok(v);
            }
            return Err(SupremacyErr::Budget);
        }

        match self.fetch_upstream(&key, &budget).await {
            Ok(v) => {
                self.cache.put(
                    key.clone(),
                    v.clone(),
                    Duration::from_secs(v.min_ttl.max(1) as u64),
                    Instant::now(),
                );
                self.publish_shm_if_address(&key, &v);
                self.metrics
                    .upstream_ok
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.metrics.record_latency(start.elapsed());
                Ok(v)
            }
            Err(e) => {
                self.metrics
                    .upstream_fail
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if let Some((v, true)) = self.cache.get(&key, Instant::now()) {
                    self.metrics
                        .swr_served
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return Ok(v);
                }
                self.flight.push(FlightEvent {
                    at: Instant::now(),
                    qname: format!("{:?}", key.owner),
                    qtype: key.qtype,
                    err: e.to_string(),
                    upstream: None,
                    budget_ms_left: budget.remaining().as_millis() as u64,
                    wire_hex_prefix: String::new(),
                });
                Err(e)
            }
        }
    }

    async fn fetch_upstream(&self, key: &CKey, budget: &QueryBudget) -> Result<CVal, SupremacyErr> {
        if budget.expired() {
            return Err(SupremacyErr::Budget);
        }
        let name = wire_to_presentation(&key.owner)
            .map_err(|error| SupremacyErr::Name(error.to_string()))?;
        let backend = Arc::clone(&self.backend);
        let qtype = key.qtype;
        let qclass = key.qclass;
        let checking_disabled = key.cd;
        let remaining = budget.remaining().max(Duration::from_millis(1));
        let query = tokio::task::spawn_blocking(move || {
            backend.resolve_record_with_class(&name, qclass, qtype)
        });
        let response = tokio::time::timeout(remaining, query)
            .await
            .map_err(|_| SupremacyErr::Budget)?
            .map_err(|error| SupremacyErr::Internal(format!("resolver worker: {error}")))?
            .map_err(|error| SupremacyErr::Upstream(error.to_string()))?;
        cache_value_from_response(response, checking_disabled)
    }

    fn publish_shm_if_address(&self, key: &CKey, val: &CVal) {
        if !matches!(key.qtype, wire::TYPE_A | wire::TYPE_AAAA) {
            return;
        }

        let negative = val.rcode != 0;
        let mut addresses = Vec::new();
        if !negative {
            let records = match wire::extract_address_records(&val.answer, None) {
                Ok(records) => records,
                Err(error) => {
                    debug!(error = %error, "unable to publish resolver answer to SHM");
                    return;
                }
            };
            for address in records.addresses.into_iter().filter(|address| {
                matches!(
                    (key.qtype, address),
                    (wire::TYPE_A, std::net::IpAddr::V4(_))
                        | (wire::TYPE_AAAA, std::net::IpAddr::V6(_))
                )
            }) {
                match ShmAddr::from_ip(address, 0) {
                    Ok(address) => addresses.push(address),
                    Err(error) => {
                        debug!(error = %error, "unable to encode resolver address for SHM");
                        return;
                    }
                }
            }
        }

        let mut publisher = self.shm.lock();
        let Some(publisher) = publisher.as_mut() else {
            return;
        };
        if let Err(error) = publisher.publish_addrs(
            &key.owner,
            key.qtype,
            key.qclass,
            val.rcode,
            &addresses,
            Duration::from_secs(u64::from(val.min_ttl.max(1))),
            val.dnssec == DnssecMark::Secure,
            negative || addresses.is_empty(),
        ) {
            debug!(error = %error, "unable to publish resolver answer to SHM");
        }
    }
}

fn cache_value_from_response(
    response: Vec<u8>,
    checking_disabled: bool,
) -> Result<CVal, SupremacyErr> {
    let header = wire::Header::parse(&response)
        .map_err(|error| SupremacyErr::Upstream(format!("invalid DNS response: {error}")))?;
    if !header.is_response() {
        return Err(SupremacyErr::Upstream(
            "resolver returned a DNS query instead of a response".into(),
        ));
    }
    let min_ttl = wire::extract_answer_records(&response)
        .ok()
        .and_then(|records| records.into_iter().map(|record| record.ttl).min())
        .unwrap_or(30)
        .max(1);
    let dnssec = if checking_disabled {
        DnssecMark::Indeterminate
    } else if header.authentic_data() {
        DnssecMark::Secure
    } else {
        DnssecMark::Insecure
    };
    Ok(CVal {
        rcode: u8::try_from(header.response_code()).unwrap_or(2),
        answer: Bytes::from(response),
        dnssec,
        min_ttl,
        from_upstream: 1,
    })
}

fn build_soa_nxbits(owner: &[u8], qtype: u16) -> Vec<u8> {
    // Minimal empty NXDOMAIN-ish message; real code copies SOA from authority.
    let mut v = vec![0u8; 12];
    v[2] = 0x80;
    v[3] = 0x03; // NXDOMAIN
    v[5] = 1;
    v.extend_from_slice(owner);
    v.extend_from_slice(&qtype.to_be_bytes());
    v.extend_from_slice(&1u16.to_be_bytes());
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_shared_memory_never_creates_a_publisher() {
        let backend = Arc::new(Resolver::new(crate::config::Config::default()));
        let resolver = SupremacyResolver::new_with_shm(backend, false);
        assert!(resolver.shm.lock().is_none());
    }

    #[test]
    fn response_conversion_preserves_wire_dnssec_and_ttl() {
        let query = wire::make_query("example.test", wire::TYPE_A, 0x1234).unwrap();
        let mut response = wire::local_response(
            &query,
            &[wire::LocalRecord::A("192.0.2.44".parse().unwrap())],
            45,
        )
        .unwrap();
        wire::set_authenticated_data(&mut response, true).unwrap();
        let value = cache_value_from_response(response.clone(), false).unwrap();
        assert_eq!(value.rcode, 0);
        assert_eq!(value.min_ttl, 45);
        assert_eq!(value.dnssec, DnssecMark::Secure);
        assert_eq!(value.answer.as_ref(), response.as_slice());

        let unchecked = cache_value_from_response(response, true).unwrap();
        assert_eq!(unchecked.dnssec, DnssecMark::Indeterminate);
    }
}
