// SPDX-License-Identifier: LGPL-2.1-or-later
//! Runtime bridge between authenticated DNSKEY RRsets and RFC 5011 state.
//!
//! The state machine in `dnssec_rfc5011` deliberately does not perform DNSSEC
//! validation. This module keeps that separation: callers may submit an RRset
//! only after the ordinary resolver trust path authenticated it. The bridge
//! serializes load/modify/fsync/rename operations so concurrent resolver
//! workers cannot lose a trust-anchor transition.

use crate::dnssec;
use crate::dnssec_rfc5011::{AnchorId, ObservedDnskey, TrustAnchorManager};
use crate::wire::{self, ResourceRecord};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;

const DEFAULT_STATE_PATH: &str = "/var/lib/rustd/resolved/rfc5011-trust-anchors.bin";
const DNSKEY_FLAG_REVOKE: u16 = 1 << 7;

static STATE_IO_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeTrustAnchor {
    pub owner: String,
    pub flags: u16,
    pub algorithm: u8,
    pub public_key: Vec<u8>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RuntimeTrustState {
    pub valid: Vec<RuntimeTrustAnchor>,
    pub revoked_ids: Vec<AnchorId>,
}

fn state_lock() -> &'static Mutex<()> {
    STATE_IO_LOCK.get_or_init(|| Mutex::new(()))
}

fn manager_for(path: &Path) -> Result<TrustAnchorManager> {
    let mut manager = TrustAnchorManager::with_path(path);
    manager
        .load_from_disk()
        .with_context(|| format!("loading RFC5011 state from {}", path.display()))?;
    Ok(manager)
}

pub fn load_runtime_state() -> Result<RuntimeTrustState> {
    load_runtime_state_from(Path::new(DEFAULT_STATE_PATH))
}

fn load_runtime_state_from(path: &Path) -> Result<RuntimeTrustState> {
    let _guard = state_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let manager = manager_for(path)?;
    let mut valid = manager
        .valid_anchors()
        .into_iter()
        .map(|entry| RuntimeTrustAnchor {
            owner: entry.owner.clone(),
            flags: entry.flags & !DNSKEY_FLAG_REVOKE,
            algorithm: entry.algorithm,
            public_key: entry.public_key.clone(),
        })
        .collect::<Vec<_>>();
    valid.sort_by(|left, right| {
        (&left.owner, left.flags, left.algorithm, &left.public_key).cmp(&(
            &right.owner,
            right.flags,
            right.algorithm,
            &right.public_key,
        ))
    });
    let mut revoked_ids = manager.revoked_anchor_ids();
    revoked_ids.sort();
    Ok(RuntimeTrustState { valid, revoked_ids })
}

/// Record a DNSKEY RRset that the resolver has already authenticated through
/// its ordinary trust chain.
///
/// `validating_keys` MUST be the already-trusted DNSKEY records that established
/// authenticity of `dnskey_rrset`. They are seeded as administratively trusted
/// only when no RFC5011 state exists for that normalized key identity.
pub fn observe_authenticated_dnskey_rrset(
    packet: &[u8],
    dnskey_rrset: &[ResourceRecord],
    validating_keys: &[ResourceRecord],
    now: SystemTime,
) -> Result<bool> {
    observe_authenticated_dnskey_rrset_at(
        Path::new(DEFAULT_STATE_PATH),
        packet,
        dnskey_rrset,
        validating_keys,
        now,
    )
}

fn observe_authenticated_dnskey_rrset_at(
    path: &Path,
    packet: &[u8],
    dnskey_rrset: &[ResourceRecord],
    validating_keys: &[ResourceRecord],
    now: SystemTime,
) -> Result<bool> {
    if dnskey_rrset.is_empty() || validating_keys.is_empty() {
        anyhow::bail!("RFC5011 observation requires DNSKEY records and validating anchors");
    }
    let owner = dnskey_rrset[0].name.canonical_wire();
    let class = dnskey_rrset[0].class;
    if dnskey_rrset.iter().any(|record| {
        record.rr_type != wire::TYPE_DNSKEY
            || record.class != class
            || record.name.canonical_wire() != owner
    }) {
        anyhow::bail!("RFC5011 observation is not one DNSKEY RRset");
    }

    let observed = dnskey_rrset
        .iter()
        .map(|record| observed_dnskey(packet, dnskey_rrset, record, now))
        .collect::<Result<Vec<_>>>()?;
    let validators = validating_keys
        .iter()
        .map(|record| observed_dnskey_without_revocation(record))
        .collect::<Result<Vec<_>>>()?;

    let _guard = state_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut manager = manager_for(path)?;
    let mut validator_ids = Vec::with_capacity(validators.len());
    for validator in &validators {
        let id = validator.anchor_id();
        if manager.entry(&id).is_none() {
            manager.seed_valid_anchor(validator, now);
        }
        validator_ids.push(id);
    }
    validator_ids.sort();
    validator_ids.dedup();

    let changed = manager.observe_validated_rrset(&observed, &validator_ids, now);
    if changed {
        manager
            .save_to_disk()
            .with_context(|| format!("persisting RFC5011 state to {}", path.display()))?;
    }
    Ok(changed)
}

fn observed_dnskey_without_revocation(record: &ResourceRecord) -> Result<ObservedDnskey> {
    if record.rr_type != wire::TYPE_DNSKEY {
        anyhow::bail!("RFC5011 validator is not a DNSKEY record");
    }
    let parsed = wire::parse_dnskey(record)?;
    Ok(ObservedDnskey {
        owner: record.name.text().to_owned(),
        flags: parsed.flags,
        algorithm: parsed.algorithm,
        key_tag: wire::dnskey_key_tag(record)?,
        public_key: parsed.public_key.to_vec(),
        original_ttl: record.ttl,
        authenticated_self_revocation: false,
    })
}

fn observed_dnskey(
    packet: &[u8],
    rrset: &[ResourceRecord],
    record: &ResourceRecord,
    now: SystemTime,
) -> Result<ObservedDnskey> {
    let mut observed = observed_dnskey_without_revocation(record)?;
    if observed.flags & DNSKEY_FLAG_REVOKE != 0 {
        observed.authenticated_self_revocation =
            revoked_key_self_authenticates(packet, rrset, record, now)?;
    }
    Ok(observed)
}

fn revoked_key_self_authenticates(
    packet: &[u8],
    rrset: &[ResourceRecord],
    revoked_key: &ResourceRecord,
    now: SystemTime,
) -> Result<bool> {
    let key = wire::parse_dnskey(revoked_key)?;
    if key.flags & DNSKEY_FLAG_REVOKE == 0 {
        return Ok(false);
    }
    let key_tag = wire::dnskey_key_tag(revoked_key)?;
    let (_, _, records, end) = wire::parse_sections(packet)?;
    if end != packet.len() {
        anyhow::bail!("trailing data in RFC5011 DNSKEY response");
    }

    for signature_record in records.iter().filter(|record| {
        record.rr_type == wire::TYPE_RRSIG
            && record.class == revoked_key.class
            && record.name.canonical_wire() == revoked_key.name.canonical_wire()
    }) {
        let signature = wire::parse_rrsig(packet, signature_record)?;
        if signature.type_covered != wire::TYPE_DNSKEY
            || signature.algorithm != key.algorithm
            || signature.key_tag != key_tag
            || signature.signer.canonical_wire() != revoked_key.name.canonical_wire()
            || rrset
                .iter()
                .any(|record| record.ttl > signature.original_ttl)
            || !dnssec::canonical::rrsig_time_valid(&signature, now)
        {
            continue;
        }
        let signed = dnssec::canonical::canonical_signed_data(packet, signature_record, rrset)?;
        if dnssec::verify_signature(
            signature.algorithm,
            &key.public_key,
            &signed,
            &signature.signature,
        )? {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnssec_rfc5011::anchor_id;
    use crate::wire::{encode_name, parse_record, CLASS_IN, TYPE_DNSKEY};
    use std::time::{Duration, UNIX_EPOCH};

    fn dnskey(owner: &str, flags: u16, algorithm: u8, key: &[u8]) -> ResourceRecord {
        let mut rdata = Vec::with_capacity(4 + key.len());
        rdata.extend_from_slice(&flags.to_be_bytes());
        rdata.push(3);
        rdata.push(algorithm);
        rdata.extend_from_slice(key);
        let mut packet = encode_name(owner).unwrap();
        packet.extend_from_slice(&TYPE_DNSKEY.to_be_bytes());
        packet.extend_from_slice(&CLASS_IN.to_be_bytes());
        packet.extend_from_slice(&60_u32.to_be_bytes());
        packet.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
        packet.extend_from_slice(&rdata);
        parse_record(&packet, 0).unwrap()
    }

    #[test]
    fn runtime_state_exports_seeded_valid_anchor() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("rfc5011.bin");
        let key = dnskey(".", 0x0101, 15, &[7; 32]);
        let observed = observed_dnskey_without_revocation(&key).unwrap();
        let mut manager = TrustAnchorManager::with_path(&path);
        manager.seed_valid_anchor(&observed, UNIX_EPOCH + Duration::from_secs(10));
        manager.save_to_disk().unwrap();

        let state = load_runtime_state_from(&path).unwrap();
        assert_eq!(state.valid.len(), 1);
        assert_eq!(state.valid[0].owner, ".");
        assert_eq!(state.valid[0].flags, 0x0101);
        assert_eq!(state.valid[0].algorithm, 15);
        assert_eq!(state.valid[0].public_key, vec![7; 32]);
        assert!(state.revoked_ids.is_empty());
    }

    #[test]
    fn validator_seeding_uses_normalized_rfc5011_identity() {
        let key = dnskey("Example.", 0x0101, 15, &[9; 32]);
        let observed = observed_dnskey_without_revocation(&key).unwrap();
        assert_eq!(
            observed.anchor_id(),
            anchor_id("example", 0x0101, 15, &[9; 32])
        );
    }

    #[test]
    fn rejects_mixed_owner_rrsets() {
        let temporary = tempfile::tempdir().unwrap();
        let first = dnskey("a.example", 0x0101, 15, &[1; 32]);
        let second = dnskey("b.example", 0x0101, 15, &[2; 32]);
        let error = observe_authenticated_dnskey_rrset_at(
            &temporary.path().join("state.bin"),
            &[],
            &[first.clone(), second],
            &[first],
            UNIX_EPOCH,
        )
        .unwrap_err();
        assert!(error.to_string().contains("not one DNSKEY RRset"));
    }
}
