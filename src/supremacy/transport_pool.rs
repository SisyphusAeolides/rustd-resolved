//! Connection pools — kill per-query TLS handshakes.
#![allow(missing_debug_implementations)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use parking_lot::Mutex;
use tokio::sync::Semaphore;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TrKind {
    Udp,
    Tcp,
    Dot,
    Doh,
    Doq,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Endpoint {
    pub kind: TrKind,
    pub addr: SocketAddr,
    pub sni: Option<String>,
    pub doh_url: Option<String>,
    pub ifindex: i32,
}

pub struct PooledConn {
    pub ep: Endpoint,
    pub last_used: Instant,
    // real: quinn::Connection | tokio_rustls client | h3
    pub healthy: bool,
    pub in_flight: u32,
}

pub struct TransportPool {
    conns: Mutex<HashMap<Endpoint, Vec<PooledConn>>>,
    max_per_ep: usize,
    idle: Duration,
    global_inflight: Arc<Semaphore>,
}

impl TransportPool {
    pub fn new(max_per_ep: usize, max_global: usize) -> Arc<Self> {
        Arc::new(Self {
            conns: Mutex::new(HashMap::new()),
            max_per_ep,
            idle: Duration::from_secs(90),
            global_inflight: Arc::new(Semaphore::new(max_global)),
        })
    }

    pub async fn exchange(
        &self,
        ep: &Endpoint,
        query: Bytes,
        timeout: Duration,
    ) -> Result<(Bytes, Duration), PoolErr> {
        let _permit = self
            .global_inflight
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| PoolErr::Shutdown)?;
        let start = Instant::now();
        match ep.kind {
            TrKind::Udp => self.exchange_udp(ep, query, timeout).await,
            TrKind::Tcp => self.exchange_tcp(ep, query, timeout).await,
            TrKind::Dot => self.exchange_dot(ep, query, timeout).await,
            TrKind::Doh => self.exchange_doh(ep, query, timeout).await,
            TrKind::Doq => self.exchange_doq(ep, query, timeout).await,
        }
        .map(|b| (b, start.elapsed()))
    }

    async fn exchange_udp(&self, ep: &Endpoint, q: Bytes, t: Duration) -> Result<Bytes, PoolErr> {
        use tokio::net::UdpSocket;
        let sock = UdpSocket::bind("0.0.0.0:0").await.map_err(PoolErr::Io)?;
        sock.connect(ep.addr).await.map_err(PoolErr::Io)?;
        sock.send(&q).await.map_err(PoolErr::Io)?;
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(t, sock.recv(&mut buf))
            .await
            .map_err(|_| PoolErr::Timeout)?
            .map_err(PoolErr::Io)?;
        Ok(Bytes::copy_from_slice(&buf[..n]))
    }

    async fn exchange_tcp(&self, ep: &Endpoint, q: Bytes, t: Duration) -> Result<Bytes, PoolErr> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;
        let mut s = tokio::time::timeout(t, TcpStream::connect(ep.addr))
            .await
            .map_err(|_| PoolErr::Timeout)?
            .map_err(PoolErr::Io)?;
        let mut framed = Vec::with_capacity(2 + q.len());
        framed.extend_from_slice(&(q.len() as u16).to_be_bytes());
        framed.extend_from_slice(&q);
        s.write_all(&framed).await.map_err(PoolErr::Io)?;
        let mut lh = [0u8; 2];
        s.read_exact(&mut lh).await.map_err(PoolErr::Io)?;
        let len = u16::from_be_bytes(lh) as usize;
        let mut body = vec![0u8; len];
        s.read_exact(&mut body).await.map_err(PoolErr::Io)?;
        Ok(Bytes::from(body))
    }

    async fn exchange_dot(&self, ep: &Endpoint, q: Bytes, t: Duration) -> Result<Bytes, PoolErr> {
        // Production: rustls ClientConfig + pool of TlsStream<TcpStream>
        // Session tickets, keepalive, length-prefix DNS same as TCP
        let _ = (ep, q, t);
        Err(PoolErr::Unimplemented("DoT pool — wire rustls"))
    }

    async fn exchange_doh(&self, ep: &Endpoint, q: Bytes, t: Duration) -> Result<Bytes, PoolErr> {
        // POST application/dns-message to ep.doh_url
        // hyper / reqwest with connection pool, HTTP/2 + optional h3
        let _ = (ep, q, t);
        Err(PoolErr::Unimplemented("DoH pool"))
    }

    async fn exchange_doq(&self, ep: &Endpoint, q: Bytes, t: Duration) -> Result<Bytes, PoolErr> {
        // quinn DNS-over-QUIC RFC 9250
        let _ = (ep, q, t);
        Err(PoolErr::Unimplemented("DoQ"))
    }

    pub fn reap_idle(&self) {
        let now = Instant::now();
        let mut g = self.conns.lock();
        for v in g.values_mut() {
            v.retain(|c| c.healthy && now.duration_since(c.last_used) < self.idle);
        }
    }
}

#[derive(Debug)]
pub enum PoolErr {
    Io(std::io::Error),
    Timeout,
    Shutdown,
    Unimplemented(&'static str),
    Tls(String),
}
