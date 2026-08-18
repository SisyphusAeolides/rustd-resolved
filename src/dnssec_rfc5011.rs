// SPDX-License-Identifier: LGPL-2.1-or-later

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use tracing::{debug, info};

const PERSISTENCE_VERSION: u32 = 1;
const REVOKE_FLAG: u16 = 1 << 7;
const SEP_FLAG: u16 = 1;
const ZONE_FLAG: u16 = 1 << 8;
const DEFAULT_ADD_HOLD_DOWN: Duration = Duration::from_secs(30 * 24 * 60 * 60);
const DEFAULT_REMOVE_HOLD_DOWN: Duration = Duration::from_secs(30 * 24 * 60 * 60);

pub type AnchorId = Vec<u8>;

/// RFC 5011 trust-anchor state retained by the resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustAnchorState {
    AddHoldDown,
    Valid,
    Missing,
    Revoked,
    RemoveHoldDown,
}

/// One DNSKEY observed at a trust point in a DNSKEY RRset that has already
/// been validated by an existing trust anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedDnskey {
    pub owner: String,
    pub flags: u16,
    pub algorithm: u8,
    pub key_tag: u16,
    pub public_key: Vec<u8>,
    pub original_ttl: u32,
    /// True only when this key's revoked-form DNSKEY authenticated an
    /// RRSIG(DNSKEY) over the observed RRset with its own public key.
    pub authenticated_self_revocation: bool,
}

impl ObservedDnskey {
    #[must_use]
    pub fn anchor_id(&self) -> AnchorId {
        anchor_id(&self.owner, self.flags, self.algorithm, &self.public_key)
    }

    #[must_use]
    pub fn is_sep(&self) -> bool {
        self.flags & (ZONE_FLAG | SEP_FLAG) == (ZONE_FLAG | SEP_FLAG)
    }

    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.flags & REVOKE_FLAG != 0
    }
}

/// A single DNSKEY trust anchor tracked by the RFC 5011 manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustAnchorEntry {
    pub state: TrustAnchorState,
    pub owner: String,
    pub key_tag: u16,
    pub flags: u16,
    pub algorithm: u8,
    pub public_key: Vec<u8>,
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
    pub last_state_change: SystemTime,
    pub add_hold_down_time: Duration,
    /// Anchors that authenticated the DNSKEY RRset when this candidate first
    /// entered AddHoldDown. If every known validator is later revoked before
    /// acceptance, RFC 5011 requires the addition process to be reset.
    pub acceptance_validators: Vec<AnchorId>,
}

impl TrustAnchorEntry {
    #[must_use]
    pub fn anchor_id(&self) -> AnchorId {
        anchor_id(&self.owner, self.flags, self.algorithm, &self.public_key)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedAnchors {
    version: u32,
    anchors: HashMap<AnchorId, TrustAnchorEntry>,
}

/// Manages RFC 5011 trust-anchor state, hold-down timers, and persistence.
///
/// This module deliberately manages keys only after the caller has validated
/// the trust-point DNSKEY RRset through the normal DNSSEC path. Resolution
/// behavior remains outside this state machine.
#[derive(Debug)]
pub struct TrustAnchorManager {
    anchors: HashMap<AnchorId, TrustAnchorEntry>,
    minimum_add_hold_down: Duration,
    remove_hold_down: Duration,
    persistence_path: PathBuf,
}

impl Default for TrustAnchorManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TrustAnchorManager {
    /// Creates a manager with the RFC 5011 default 30-day hold-down values.
    #[must_use]
    pub fn new() -> Self {
        Self::with_parameters(
            "/var/lib/rustd/resolved/rfc5011-trust-anchors.bin",
            DEFAULT_ADD_HOLD_DOWN,
            DEFAULT_REMOVE_HOLD_DOWN,
        )
    }

    /// Creates a manager with the default hold-down values and a custom
    /// persistence path.
    #[must_use]
    pub fn with_path<P: AsRef<Path>>(path: P) -> Self {
        Self::with_parameters(path, DEFAULT_ADD_HOLD_DOWN, DEFAULT_REMOVE_HOLD_DOWN)
    }

    /// Creates a manager with explicit hold-down values. This is used by
    /// deterministic state-machine tests and by release rollover campaigns.
    #[must_use]
    pub fn with_parameters<P: AsRef<Path>>(
        path: P,
        minimum_add_hold_down: Duration,
        remove_hold_down: Duration,
    ) -> Self {
        Self {
            anchors: HashMap::new(),
            minimum_add_hold_down,
            remove_hold_down,
            persistence_path: path.as_ref().to_path_buf(),
        }
    }

    /// Loads versioned RFC 5011 state from disk.
    pub fn load_from_disk(&mut self) -> Result<()> {
        if !self.persistence_path.exists() {
            debug!("RFC5011 persistence file not found; starting with configured anchors");
            return Ok(());
        }
        let data = fs::read(&self.persistence_path)?;
        let persisted: PersistedAnchors = bincode::deserialize(&data)?;
        if persisted.version != PERSISTENCE_VERSION {
            anyhow::bail!(
                "unsupported RFC5011 persistence version {}",
                persisted.version
            );
        }
        self.anchors = persisted.anchors;
        Ok(())
    }

    /// Saves versioned state atomically. The temporary file is private and
    /// fsync'd before rename so a crash cannot publish a partial database.
    pub fn save_to_disk(&self) -> Result<()> {
        if let Some(parent) = self.persistence_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let temp_path = self.persistence_path.with_extension("tmp");
        let data = bincode::serialize(&PersistedAnchors {
            version: PERSISTENCE_VERSION,
            anchors: self.anchors.clone(),
        })?;
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&temp_path)?;
        file.write_all(&data)?;
        file.sync_all()?;
        fs::rename(&temp_path, &self.persistence_path)?;
        if let Some(parent) = self.persistence_path.parent() {
            if let Ok(directory) = fs::File::open(parent) {
                let _ = directory.sync_all();
            }
        }
        Ok(())
    }

    /// Seeds an already-configured DNSKEY as a Valid anchor. Configured
    /// anchors do not pass through AddHoldDown because their trust is an
    /// explicit local administrative decision.
    pub fn seed_valid_anchor(&mut self, key: &ObservedDnskey, now: SystemTime) -> AnchorId {
        let id = key.anchor_id();
        self.anchors.insert(
            id.clone(),
            TrustAnchorEntry {
                state: TrustAnchorState::Valid,
                owner: canonical_owner(&key.owner),
                key_tag: key.key_tag,
                flags: key.flags & !REVOKE_FLAG,
                algorithm: key.algorithm,
                public_key: key.public_key.clone(),
                first_seen: now,
                last_seen: now,
                last_state_change: now,
                add_hold_down_time: self.minimum_add_hold_down,
                acceptance_validators: Vec::new(),
            },
        );
        id
    }

    /// Applies one validated trust-point DNSKEY RRset.
    ///
    /// The caller MUST supply only an RRset already authenticated by the
    /// existing DNSSEC trust path. `validating_anchor_ids` identifies the
    /// anchors that established that authentication. The function never
    /// promotes AddHoldDown solely because time elapsed: the candidate must
    /// be present in this post-expiry validated observation.
    pub fn observe_validated_rrset(
        &mut self,
        keys: &[ObservedDnskey],
        validating_anchor_ids: &[AnchorId],
        now: SystemTime,
    ) -> bool {
        let observed: HashMap<AnchorId, &ObservedDnskey> =
            keys.iter().map(|key| (key.anchor_id(), key)).collect();
        let mut changed = false;
        let tracked_ids: Vec<AnchorId> = self.anchors.keys().cloned().collect();
        let mut reset_additions = Vec::new();
        let mut purge_revoked = Vec::new();

        for id in tracked_ids {
            let Some(snapshot) = self.anchors.get(&id).cloned() else {
                continue;
            };
            let present = observed.get(&id).copied();
            match snapshot.state {
                TrustAnchorState::AddHoldDown => {
                    let validators_revoked = !snapshot.acceptance_validators.is_empty()
                        && snapshot.acceptance_validators.iter().all(|validator| {
                            matches!(
                                self.anchors.get(validator).map(|entry| entry.state),
                                Some(TrustAnchorState::Revoked | TrustAnchorState::RemoveHoldDown)
                            )
                        });
                    if present.is_none() || validators_revoked {
                        reset_additions.push(id.clone());
                        changed = true;
                        continue;
                    }
                    let key = present.expect("presence checked above");
                    if key.is_revoked() {
                        reset_additions.push(id.clone());
                        changed = true;
                        continue;
                    }
                    if let Some(entry) = self.anchors.get_mut(&id) {
                        entry.last_seen = now;
                        if now
                            .duration_since(entry.first_seen)
                            .is_ok_and(|elapsed| elapsed >= entry.add_hold_down_time)
                        {
                            entry.state = TrustAnchorState::Valid;
                            entry.last_state_change = now;
                            entry.acceptance_validators.clear();
                            info!(owner = %entry.owner, key_tag = entry.key_tag, "RFC5011 anchor became valid");
                            changed = true;
                        }
                    }
                }
                TrustAnchorState::Valid | TrustAnchorState::Missing => match present {
                    Some(key) if key.is_revoked() && key.authenticated_self_revocation => {
                        if let Some(entry) = self.anchors.get_mut(&id) {
                            entry.state = TrustAnchorState::Revoked;
                            entry.flags |= REVOKE_FLAG;
                            entry.key_tag = key.key_tag;
                            entry.last_seen = now;
                            entry.last_state_change = now;
                            info!(owner = %entry.owner, key_tag = entry.key_tag, "RFC5011 anchor revoked");
                            changed = true;
                        }
                    }
                    Some(key) if !key.is_revoked() => {
                        if let Some(entry) = self.anchors.get_mut(&id) {
                            entry.last_seen = now;
                            if entry.state == TrustAnchorState::Missing {
                                entry.state = TrustAnchorState::Valid;
                                entry.last_state_change = now;
                                changed = true;
                            }
                        }
                    }
                    Some(_) => {
                        // A REVOKE bit without the key's own authenticated
                        // RRSIG(DNSKEY) cannot revoke the anchor.
                    }
                    None => {
                        if let Some(entry) = self.anchors.get_mut(&id) {
                            if entry.state != TrustAnchorState::Missing {
                                entry.state = TrustAnchorState::Missing;
                                entry.last_state_change = now;
                                changed = true;
                            }
                        }
                    }
                },
                TrustAnchorState::Revoked => {
                    if present.is_none() {
                        if let Some(entry) = self.anchors.get_mut(&id) {
                            entry.state = TrustAnchorState::RemoveHoldDown;
                            entry.last_state_change = now;
                            changed = true;
                        }
                    } else if let Some(entry) = self.anchors.get_mut(&id) {
                        entry.last_seen = now;
                    }
                }
                TrustAnchorState::RemoveHoldDown => {
                    if present.is_some() {
                        if let Some(entry) = self.anchors.get_mut(&id) {
                            entry.state = TrustAnchorState::Revoked;
                            entry.last_seen = now;
                            entry.last_state_change = now;
                            changed = true;
                        }
                    } else if now
                        .duration_since(snapshot.last_state_change)
                        .is_ok_and(|elapsed| elapsed >= self.remove_hold_down)
                    {
                        purge_revoked.push(id.clone());
                        changed = true;
                    }
                }
            }
        }

        for id in reset_additions.into_iter().chain(purge_revoked) {
            self.anchors.remove(&id);
        }

        if !validating_anchor_ids.is_empty() {
            for key in keys {
                let id = key.anchor_id();
                if self.anchors.contains_key(&id) || !key.is_sep() || key.is_revoked() {
                    continue;
                }
                let ttl_hold_down = Duration::from_secs(u64::from(key.original_ttl));
                let add_hold_down_time = self.minimum_add_hold_down.max(ttl_hold_down);
                self.anchors.insert(
                    id,
                    TrustAnchorEntry {
                        state: TrustAnchorState::AddHoldDown,
                        owner: canonical_owner(&key.owner),
                        key_tag: key.key_tag,
                        flags: key.flags & !REVOKE_FLAG,
                        algorithm: key.algorithm,
                        public_key: key.public_key.clone(),
                        first_seen: now,
                        last_seen: now,
                        last_state_change: now,
                        add_hold_down_time,
                        acceptance_validators: validating_anchor_ids.to_vec(),
                    },
                );
                changed = true;
            }
        }

        changed
    }

    /// Performs database-only cleanup for revoked keys that have already
    /// entered RemoveHoldDown. It never promotes AddHoldDown keys.
    pub fn process_timers(&mut self, now: SystemTime) -> bool {
        let before = self.anchors.len();
        self.anchors.retain(|_, entry| {
            !(entry.state == TrustAnchorState::RemoveHoldDown
                && now
                    .duration_since(entry.last_state_change)
                    .is_ok_and(|elapsed| elapsed >= self.remove_hold_down))
        });
        before != self.anchors.len()
    }

    /// Returns anchors that remain usable for DNSSEC validation. Missing keys
    /// remain trusted until an authenticated RFC 5011 revocation is observed.
    #[must_use]
    pub fn valid_anchors(&self) -> Vec<&TrustAnchorEntry> {
        self.anchors
            .values()
            .filter(|entry| {
                matches!(
                    entry.state,
                    TrustAnchorState::Valid | TrustAnchorState::Missing
                )
            })
            .collect()
    }

    /// Returns permanently revoked key identities. The DNSSEC anchor loader
    /// must exclude these identities even if an older static anchor file is
    /// still present.
    #[must_use]
    pub fn revoked_anchor_ids(&self) -> Vec<AnchorId> {
        self.anchors
            .iter()
            .filter_map(|(id, entry)| {
                matches!(
                    entry.state,
                    TrustAnchorState::Revoked | TrustAnchorState::RemoveHoldDown
                )
                .then(|| id.clone())
            })
            .collect()
    }

    #[must_use]
    pub fn entry(&self, id: &[u8]) -> Option<&TrustAnchorEntry> {
        self.anchors.get(id)
    }
}

#[must_use]
pub fn anchor_id(owner: &str, flags: u16, algorithm: u8, public_key: &[u8]) -> AnchorId {
    let owner = canonical_owner(owner);
    let normalized_flags = flags & !REVOKE_FLAG;
    let mut id = Vec::with_capacity(owner.len() + public_key.len() + 4);
    id.extend_from_slice(owner.as_bytes());
    id.push(0);
    id.extend_from_slice(&normalized_flags.to_be_bytes());
    id.push(algorithm);
    id.extend_from_slice(public_key);
    id
}

fn canonical_owner(owner: &str) -> String {
    let mut owner = owner.trim().trim_end_matches('.').to_ascii_lowercase();
    if owner.is_empty() {
        return ".".to_owned();
    }
    owner.push('.');
    owner
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(tag: u16, flags: u16, ttl: u32) -> ObservedDnskey {
        ObservedDnskey {
            owner: ".".to_owned(),
            flags,
            algorithm: 8,
            key_tag: tag,
            public_key: vec![tag as u8, (tag >> 8) as u8, 0xaa, 0x55],
            original_ttl: ttl,
            authenticated_self_revocation: false,
        }
    }

    fn manager(path: &Path) -> TrustAnchorManager {
        TrustAnchorManager::with_parameters(path, Duration::from_secs(10), Duration::from_secs(10))
    }

    #[test]
    fn revoke_bit_does_not_change_anchor_identity() {
        let normal = key(1, ZONE_FLAG | SEP_FLAG, 1);
        let revoked = ObservedDnskey {
            flags: normal.flags | REVOKE_FLAG,
            ..normal.clone()
        };
        assert_eq!(normal.anchor_id(), revoked.anchor_id());
    }

    #[test]
    fn add_requires_post_hold_down_validated_observation() {
        let temporary = tempfile::tempdir().unwrap();
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let mut manager = manager(&temporary.path().join("anchors.bin"));
        let root = key(100, ZONE_FLAG | SEP_FLAG, 1);
        let root_id = manager.seed_valid_anchor(&root, start);
        let candidate = key(200, ZONE_FLAG | SEP_FLAG, 1);
        let candidate_id = candidate.anchor_id();

        assert!(manager.observe_validated_rrset(
            &[root.clone(), candidate.clone()],
            std::slice::from_ref(&root_id),
            start,
        ));
        assert_eq!(
            manager.entry(&candidate_id).unwrap().state,
            TrustAnchorState::AddHoldDown
        );

        assert!(!manager.process_timers(start + Duration::from_secs(20)));
        assert_eq!(
            manager.entry(&candidate_id).unwrap().state,
            TrustAnchorState::AddHoldDown
        );

        assert!(manager.observe_validated_rrset(
            &[root, candidate],
            std::slice::from_ref(&root_id),
            start + Duration::from_secs(20),
        ));
        assert_eq!(
            manager.entry(&candidate_id).unwrap().state,
            TrustAnchorState::Valid
        );
    }

    #[test]
    fn candidate_disappearance_resets_add_hold_down() {
        let temporary = tempfile::tempdir().unwrap();
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let mut manager = manager(&temporary.path().join("anchors.bin"));
        let root = key(100, ZONE_FLAG | SEP_FLAG, 1);
        let root_id = manager.seed_valid_anchor(&root, start);
        let candidate = key(200, ZONE_FLAG | SEP_FLAG, 1);
        let candidate_id = candidate.anchor_id();

        manager.observe_validated_rrset(
            &[root.clone(), candidate],
            std::slice::from_ref(&root_id),
            start,
        );
        assert!(manager.observe_validated_rrset(
            &[root],
            std::slice::from_ref(&root_id),
            start + Duration::from_secs(5),
        ));
        assert!(manager.entry(&candidate_id).is_none());
    }

    #[test]
    fn revoke_requires_authenticated_self_signature_and_is_permanent() {
        let temporary = tempfile::tempdir().unwrap();
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let mut manager = manager(&temporary.path().join("anchors.bin"));
        let anchor = key(100, ZONE_FLAG | SEP_FLAG, 1);
        let id = manager.seed_valid_anchor(&anchor, start);
        let unauthenticated = ObservedDnskey {
            flags: anchor.flags | REVOKE_FLAG,
            key_tag: 101,
            ..anchor.clone()
        };

        assert!(!manager.observe_validated_rrset(
            std::slice::from_ref(&unauthenticated),
            std::slice::from_ref(&id),
            start + Duration::from_secs(1),
        ));
        assert_eq!(manager.entry(&id).unwrap().state, TrustAnchorState::Valid);

        let authenticated = ObservedDnskey {
            authenticated_self_revocation: true,
            ..unauthenticated
        };
        assert!(manager.observe_validated_rrset(
            std::slice::from_ref(&authenticated),
            std::slice::from_ref(&id),
            start + Duration::from_secs(2),
        ));
        assert_eq!(manager.entry(&id).unwrap().state, TrustAnchorState::Revoked);
        assert!(manager.valid_anchors().is_empty());

        assert!(!manager.observe_validated_rrset(
            std::slice::from_ref(&anchor),
            &[],
            start + Duration::from_secs(3),
        ));
        assert_eq!(manager.entry(&id).unwrap().state, TrustAnchorState::Revoked);
    }

    #[test]
    fn missing_valid_anchor_remains_trusted_until_revoked() {
        let temporary = tempfile::tempdir().unwrap();
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let mut manager = manager(&temporary.path().join("anchors.bin"));
        let anchor = key(100, ZONE_FLAG | SEP_FLAG, 1);
        let id = manager.seed_valid_anchor(&anchor, start);

        assert!(manager.observe_validated_rrset(&[], std::slice::from_ref(&id), start));
        assert_eq!(manager.entry(&id).unwrap().state, TrustAnchorState::Missing);
        assert_eq!(manager.valid_anchors().len(), 1);

        assert!(manager.observe_validated_rrset(
            std::slice::from_ref(&anchor),
            std::slice::from_ref(&id),
            start + Duration::from_secs(1),
        ));
        assert_eq!(manager.entry(&id).unwrap().state, TrustAnchorState::Valid);
    }

    #[test]
    fn revoked_anchor_is_purged_only_after_remove_hold_down() {
        let temporary = tempfile::tempdir().unwrap();
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let mut manager = manager(&temporary.path().join("anchors.bin"));
        let anchor = key(100, ZONE_FLAG | SEP_FLAG, 1);
        let id = manager.seed_valid_anchor(&anchor, start);
        let revoked = ObservedDnskey {
            flags: anchor.flags | REVOKE_FLAG,
            key_tag: 101,
            authenticated_self_revocation: true,
            ..anchor
        };
        manager.observe_validated_rrset(
            std::slice::from_ref(&revoked),
            std::slice::from_ref(&id),
            start + Duration::from_secs(1),
        );
        assert!(manager.observe_validated_rrset(&[], &[], start + Duration::from_secs(2)));
        assert_eq!(
            manager.entry(&id).unwrap().state,
            TrustAnchorState::RemoveHoldDown
        );
        assert!(!manager.process_timers(start + Duration::from_secs(11)));
        assert!(manager.process_timers(start + Duration::from_secs(12)));
        assert!(manager.entry(&id).is_none());
    }

    #[test]
    fn persistence_round_trip_preserves_state() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("anchors.bin");
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let anchor = key(100, ZONE_FLAG | SEP_FLAG, 1);
        let id;
        {
            let mut manager = manager(&path);
            id = manager.seed_valid_anchor(&anchor, start);
            manager.save_to_disk().unwrap();
        }
        let mut restored = manager(&path);
        restored.load_from_disk().unwrap();
        assert_eq!(restored.entry(&id).unwrap().state, TrustAnchorState::Valid);
    }

    #[test]
    fn original_ttl_can_extend_add_hold_down() {
        let temporary = tempfile::tempdir().unwrap();
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let mut manager = manager(&temporary.path().join("anchors.bin"));
        let root = key(100, ZONE_FLAG | SEP_FLAG, 1);
        let root_id = manager.seed_valid_anchor(&root, start);
        let candidate = key(200, ZONE_FLAG | SEP_FLAG, 30);
        let id = candidate.anchor_id();
        manager.observe_validated_rrset(&[root, candidate], std::slice::from_ref(&root_id), start);
        assert_eq!(
            manager.entry(&id).unwrap().add_hold_down_time,
            Duration::from_secs(30)
        );
    }
}
