// SPDX-License-Identifier: LGPL-2.1-or-later
use crate::cache_x::{CacheKey as XKey, GlobalCache, Lookup};
use crate::wire::{age_ttls, cache_lifetime, rewrite_id, Header, WireError};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheScope {
    Global,
    Fallback,
    Link(i32),
    Delegate(usize),
}

impl CacheScope {
    const LINK_TAG: u64 = 1 << 63;
    const DELEGATE_TAG: u64 = 1 << 62;

    fn encode(self) -> u64 {
        match self {
            Self::Global => 0,
            Self::Fallback => 1,
            Self::Link(ifindex) => Self::LINK_TAG | u64::from(ifindex.unsigned_abs()),
            Self::Delegate(index) => {
                Self::DELEGATE_TAG
                    | u64::try_from(index)
                        .unwrap_or(Self::DELEGATE_TAG - 1)
                        .min(Self::DELEGATE_TAG - 1)
            }
        }
    }

    fn decode(value: u64) -> Self {
        if value & Self::LINK_TAG != 0 {
            Self::Link(i32::try_from(value & !Self::LINK_TAG).unwrap_or(i32::MAX))
        } else if value & Self::DELEGATE_TAG != 0 {
            Self::Delegate(usize::try_from(value & !Self::DELEGATE_TAG).unwrap_or(usize::MAX))
        } else if value == 1 {
            Self::Fallback
        } else {
            Self::Global
        }
    }
}

impl From<crate::routing::ScopeKind> for CacheScope {
    fn from(scope: crate::routing::ScopeKind) -> Self {
        match scope {
            crate::routing::ScopeKind::Global => Self::Global,
            crate::routing::ScopeKind::Fallback => Self::Fallback,
            crate::routing::ScopeKind::Link(ifindex) => Self::Link(ifindex),
            crate::routing::ScopeKind::Delegate(index) => Self::Delegate(index),
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CacheKey {
    pub name: Vec<u8>,
    pub rr_type: u16,
    pub class: u16,
    pub checking_disabled: bool,
    pub route: u64,
}

#[derive(Clone, Debug)]
pub struct CacheSnapshot {
    pub name: Vec<u8>,
    pub rr_type: u16,
    pub class: u16,
    pub rcode: u8,
    pub response: Vec<u8>,
    pub remaining: Duration,
    pub scope: CacheScope,
}

pub struct Cache {
    global: GlobalCache,
    capacity: usize,
    maximum_ttl: Duration,
    store_negative: bool,
}

impl std::fmt::Debug for Cache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cache")
            .field("capacity", &self.capacity)
            .field("maximum_ttl", &self.maximum_ttl)
            .field("store_negative", &self.store_negative)
            .finish_non_exhaustive()
    }
}

impl Cache {
    pub fn new(
        capacity: usize,
        maximum_ttl: Duration,
        stale_retention: Duration,
        store_negative: bool,
    ) -> Self {
        Self {
            // we use 4 shard bits (16 shards)
            global: GlobalCache::new(4, (capacity / 16).max(1), stale_retention),
            capacity,
            maximum_ttl,
            store_negative,
        }
    }

    fn to_xkey(key: &CacheKey) -> XKey {
        XKey {
            owner: Arc::from(key.name.clone().into_boxed_slice()),
            qtype: key.rr_type,
            qclass: key.class,
            checking_disabled: key.checking_disabled,
            route: key.route,
        }
    }

    pub fn get(&self, key: &CacheKey, id: u16, allow_stale: bool) -> Option<Vec<u8>> {
        self.get_scoped(key, id, allow_stale)
            .map(|(packet, _)| packet)
    }

    pub fn get_scoped(
        &self,
        key: &CacheKey,
        id: u16,
        allow_stale: bool,
    ) -> Option<(Vec<u8>, Option<i32>)> {
        let now = Instant::now();
        let lookup = self.global.lookup(&Self::to_xkey(key), now);
        let entry = match lookup {
            Lookup::Fresh(e) => e,
            Lookup::Stale(e) if allow_stale => e,
            _ => return None,
        };

        let is_stale = now >= entry.expires_at;
        let elapsed = now.saturating_duration_since(entry.inserted).as_secs();
        let elapsed = u32::try_from(elapsed).unwrap_or(u32::MAX);

        let mut packet = entry.answer.to_vec();
        if rewrite_id(&mut packet, id).is_err() || age_ttls(&mut packet, elapsed, is_stale).is_err()
        {
            return None;
        }
        Some((packet, entry.source_ifindex))
    }

    pub fn insert(&self, key: CacheKey, response: &[u8]) -> Result<bool, WireError> {
        self.insert_scoped(key, response, None, CacheScope::Global)
    }

    pub fn insert_scoped(
        &self,
        key: CacheKey,
        response: &[u8],
        source_ifindex: Option<i32>,
        source_scope: CacheScope,
    ) -> Result<bool, WireError> {
        let header = Header::parse(response)?;
        if !header.is_response() || header.truncated() {
            return Ok(false);
        }

        let rcode = header.response_code();
        let negative = rcode != 0 || header.answer_count == 0;
        if negative && !self.store_negative {
            return Ok(false);
        }

        let ttl = match rcode {
            0 | 3 => {
                let Some(ttl_seconds) = cache_lifetime(response)? else {
                    return Ok(false);
                };
                Duration::from_secs(u64::from(ttl_seconds))
            }
            _ => return Ok(false),
        }
        .min(self.maximum_ttl);

        if ttl.is_zero() || self.capacity == 0 {
            return Ok(false);
        }

        let mut packet = response.to_vec();
        rewrite_id(&mut packet, 0)?;

        let xkey = Self::to_xkey(&key);
        self.global.insert_with_scope(
            xkey,
            rcode as u8,
            Arc::from(packet.into_boxed_slice()),
            ttl,
            false,
            source_ifindex,
            source_scope.encode(),
            Instant::now(),
        );

        Ok(true)
    }

    pub fn flush(&self) {
        self.global.flush();
    }

    pub fn set_stale_retention(&self, stale_retention: Duration) {
        self.global.set_stale_window(stale_retention);
    }

    pub fn len(&self) -> usize {
        self.global.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn snapshot(&self) -> Vec<CacheSnapshot> {
        let now = Instant::now();
        self.global
            .snapshot(now)
            .into_iter()
            .map(|(key, entry)| CacheSnapshot {
                name: key.owner.as_ref().to_vec(),
                rr_type: key.qtype,
                class: key.qclass,
                rcode: entry.rcode,
                response: entry.answer.as_ref().to_vec(),
                remaining: entry
                    .expires_at
                    .checked_duration_since(now)
                    .unwrap_or_default(),
                scope: CacheScope::decode(entry.source_scope),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{local_response, make_query, LocalRecord, TYPE_A};
    use std::net::Ipv4Addr;

    fn key() -> CacheKey {
        CacheKey {
            name: vec![7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0],
            rr_type: TYPE_A,
            class: 1,
            checking_disabled: false,
            route: 0,
        }
    }

    fn servfail_response(id: u16) -> Vec<u8> {
        let mut response = make_query("example", TYPE_A, id).expect("query");
        response[2] |= 0x80;
        response[3] = (response[3] & 0xf0) | 2;
        response
    }

    #[test]
    fn rewrites_transaction_identity() {
        let cache = Cache::new(16, Duration::from_secs(60), Duration::ZERO, true);
        let query = make_query("example", TYPE_A, 7).expect("query");
        let response = local_response(&query, &[LocalRecord::A(Ipv4Addr::new(192, 0, 2, 1))], 30)
            .expect("response");
        assert!(cache.insert(key(), &response).expect("cache insert"));
        let hit = cache.get(&key(), 99, false).expect("cache hit");
        assert_eq!(&hit[..2], &99u16.to_be_bytes());
    }

    #[test]
    fn concurrent_hits_keep_transaction_ids_isolated() {
        let cache = std::sync::Arc::new(Cache::new(
            16,
            Duration::from_secs(60),
            Duration::ZERO,
            true,
        ));
        let query = make_query("example", TYPE_A, 7).expect("query");
        let response = local_response(&query, &[LocalRecord::A(Ipv4Addr::new(192, 0, 2, 1))], 30)
            .expect("response");
        assert!(cache.insert(key(), &response).expect("cache insert"));

        let mut workers = Vec::new();
        for id in 100u16..116 {
            let cache = std::sync::Arc::clone(&cache);
            workers.push(std::thread::spawn(move || {
                let hit = cache.get(&key(), id, false).expect("cache hit");
                assert_eq!(&hit[..2], &id.to_be_bytes());
            }));
        }
        for worker in workers {
            worker.join().expect("cache worker");
        }
    }

    #[test]
    fn checking_mode_is_part_of_the_cache_key() {
        let cache = Cache::new(16, Duration::from_secs(60), Duration::ZERO, true);
        let query = make_query("example", TYPE_A, 7).expect("query");
        let response = local_response(&query, &[LocalRecord::A(Ipv4Addr::new(192, 0, 2, 1))], 30)
            .expect("response");
        assert!(cache.insert(key(), &response).expect("cache insert"));

        let mut different_mode = key();
        different_mode.checking_disabled = true;
        assert!(cache.get(&different_mode, 99, false).is_none());
    }

    #[test]
    fn routing_scope_is_part_of_the_cache_key() {
        let cache = Cache::new(16, Duration::from_secs(60), Duration::ZERO, true);
        let query = make_query("example", TYPE_A, 7).expect("query");
        let response = local_response(&query, &[LocalRecord::A(Ipv4Addr::new(192, 0, 2, 1))], 30)
            .expect("response");
        assert!(cache.insert(key(), &response).expect("cache insert"));

        let mut different_route = key();
        different_route.route = 1;
        assert!(cache.get(&different_route, 99, false).is_none());
    }

    #[test]
    fn source_interface_survives_cache_storage() {
        let cache = Cache::new(16, Duration::from_secs(60), Duration::ZERO, true);
        let query = make_query("example", TYPE_A, 7).expect("query");
        let response = local_response(&query, &[LocalRecord::A(Ipv4Addr::new(192, 0, 2, 1))], 30)
            .expect("response");
        assert!(cache
            .insert_scoped(key(), &response, Some(7), CacheScope::Link(7))
            .expect("cache insert"));
        let (hit, ifindex) = cache.get_scoped(&key(), 99, false).expect("cache hit");
        assert_eq!(&hit[..2], &99u16.to_be_bytes());
        assert_eq!(ifindex, Some(7));
        assert_eq!(cache.snapshot()[0].scope, CacheScope::Link(7));
    }

    #[test]
    fn servfail_is_never_cached() {
        let cache = Cache::new(16, Duration::from_secs(60), Duration::ZERO, true);
        let response = servfail_response(7);
        assert!(!cache.insert(key(), &response).expect("SERVFAIL insert"));
        assert!(cache.is_empty());
    }

    #[test]
    fn no_negative_mode_rejects_servfail() {
        let cache = Cache::new(16, Duration::from_secs(60), Duration::ZERO, false);
        let response = servfail_response(7);
        assert!(!cache.insert(key(), &response).expect("SERVFAIL insert"));
        assert!(cache.is_empty());
    }
}
