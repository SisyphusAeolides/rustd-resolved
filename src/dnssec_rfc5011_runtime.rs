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
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;

const DEFAULT_STATE_PATH: &str = "/var/lib/rustd/resolved/rfc5011-trust-anchors.bin";
const DEFAULT_RUNTIME_ANCHOR_PATH: &str = "/run/dnssec-trust-anchors.d/rustd-rfc5011.positive";
const DNSKEY_FLAG_REVOKE: u16 = 1 << 7;
// Linux open(2) flags; keep the RFC5011 state publication dependency-free.
const O_NOFOLLOW: i32 = 0o400000;
const O_CLOEXEC: i32 = 0o2000000;
const FAIL_CLOSED_ROOT_DS: &str =
    ". IN DS 0 253 2 0000000000000000000000000000000000000000000000000000000000000000";

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
    Ok(runtime_state(&manager))
}

fn runtime_state(manager: &TrustAnchorManager) -> RuntimeTrustState {
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
    RuntimeTrustState { valid, revoked_ids }
}

/// Rebuild the volatile positive-anchor file from durable RFC5011 state.
///
/// This is called after privilege drop but before resolver workers start. If no
/// durable RFC5011 database exists yet, the generated file is removed so the
/// ordinary configured/built-in bootstrap anchors remain authoritative. Once a
/// durable database exists it becomes authoritative for the managed root trust
/// point; an empty valid root set publishes a non-matching DS tombstone instead
/// of silently resurrecting a revoked built-in anchor.
pub fn publish_runtime_anchors() -> Result<()> {
    publish_runtime_anchors_from(
        Path::new(DEFAULT_STATE_PATH),
        Path::new(DEFAULT_RUNTIME_ANCHOR_PATH),
    )
}

fn publish_runtime_anchors_from(state_path: &Path, runtime_path: &Path) -> Result<()> {
    let _guard = state_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if !state_path.exists() {
        match fs::remove_file(runtime_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("removing stale RFC5011 runtime anchors"),
        }
        return Ok(());
    }
    let manager = manager_for(state_path)?;
    publish_manager_anchors(&manager, runtime_path)
}

fn publish_manager_anchors(manager: &TrustAnchorManager, runtime_path: &Path) -> Result<()> {
    let state = runtime_state(manager);
    let mut lines = state
        .valid
        .iter()
        .map(|anchor| {
            format!(
                "{} IN DNSKEY {} 3 {} {}",
                anchor.owner,
                anchor.flags,
                anchor.algorithm,
                base64_encode(&anchor.public_key)
            )
        })
        .collect::<Vec<_>>();
    if !state
        .valid
        .iter()
        .any(|anchor| canonical_owner(&anchor.owner) == ".")
    {
        lines.push(FAIL_CLOSED_ROOT_DS.to_owned());
    }
    lines.sort();
    lines.dedup();

    let parent = runtime_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("RFC5011 runtime anchor path has no parent"))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("creating RFC5011 runtime directory {}", parent.display()))?;
    let temp_path = runtime_path.with_extension(format!("tmp-{}", std::process::id()));
    let _ = fs::remove_file(&temp_path);
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(O_NOFOLLOW | O_CLOEXEC)
        .open(&temp_path)
        .with_context(|| {
            format!(
                "creating RFC5011 runtime anchor file {}",
                temp_path.display()
            )
        })?;
    for line in &lines {
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")?;
    }
    file.sync_all()?;
    drop(file);
    fs::rename(&temp_path, runtime_path).with_context(|| {
        format!(
            "publishing RFC5011 runtime anchors {} -> {}",
            temp_path.display(),
            runtime_path.display()
        )
    })?;
    if let Ok(directory) = fs::File::open(parent) {
        directory.sync_all()?;
    }
    Ok(())
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
        Path::new(DEFAULT_RUNTIME_ANCHOR_PATH),
        packet,
        dnskey_rrset,
        validating_keys,
        now,
    )
}

fn observe_authenticated_dnskey_rrset_at(
    path: &Path,
    runtime_path: &Path,
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
    if validating_keys.iter().any(|record| {
        record.rr_type != wire::TYPE_DNSKEY
            || record.class != class
            || record.name.canonical_wire() != owner
    }) {
        anyhow::bail!("RFC5011 validating key belongs to a different trust point");
    }

    let observed = dnskey_rrset
        .iter()
        .map(|record| observed_dnskey(packet, dnskey_rrset, record, now))
        .collect::<Result<Vec<_>>>()?;
    let validators = validating_keys
        .iter()
        .map(observed_dnskey_without_revocation)
        .collect::<Result<Vec<_>>>()?;

    let _guard = state_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut manager = manager_for(path)?;
    let mut validator_ids = Vec::with_capacity(validators.len());
    let mut seeded = false;
    for validator in &validators {
        let id = validator.anchor_id();
        if manager.entry(&id).is_none() {
            manager.seed_valid_anchor(validator, now);
            seeded = true;
        }
        validator_ids.push(id);
    }
    validator_ids.sort();
    validator_ids.dedup();

    let changed = manager.observe_validated_rrset(&observed, &validator_ids, now);
    if seeded || changed {
        manager
            .save_to_disk()
            .with_context(|| format!("persisting RFC5011 state to {}", path.display()))?;
    }
    // Re-publish even when the state did not change: /run may have been
    // recreated independently from the durable /var database.
    publish_manager_anchors(&manager, runtime_path)?;
    Ok(seeded || changed)
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
        public_key: parsed.public_key,
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

fn canonical_owner(owner: &str) -> String {
    let owner = owner.trim().trim_end_matches('.').to_ascii_lowercase();
    if owner.is_empty() {
        ".".to_owned()
    } else {
        format!("{owner}.")
    }
}

fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let first = chunk[0];
        let second = *chunk.get(1).unwrap_or(&0);
        let third = *chunk.get(2).unwrap_or(&0);
        let value = (u32::from(first) << 16) | (u32::from(second) << 8) | u32::from(third);
        output.push(char::from(TABLE[((value >> 18) & 0x3f) as usize]));
        output.push(char::from(TABLE[((value >> 12) & 0x3f) as usize]));
        if chunk.len() > 1 {
            output.push(char::from(TABLE[((value >> 6) & 0x3f) as usize]));
        } else {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(char::from(TABLE[(value & 0x3f) as usize]));
        } else {
            output.push('=');
        }
    }
    output
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
            &temporary.path().join("runtime.positive"),
            &[],
            &[first.clone(), second],
            &[first],
            UNIX_EPOCH,
        )
        .unwrap_err();
        assert!(error.to_string().contains("not one DNSKEY RRset"));
    }

    #[test]
    fn rejects_validator_from_other_trust_point() {
        let temporary = tempfile::tempdir().unwrap();
        let rrset = dnskey("a.example", 0x0101, 15, &[1; 32]);
        let validator = dnskey("b.example", 0x0101, 15, &[2; 32]);
        let error = observe_authenticated_dnskey_rrset_at(
            &temporary.path().join("state.bin"),
            &temporary.path().join("runtime.positive"),
            &[],
            std::slice::from_ref(&rrset),
            &[validator],
            UNIX_EPOCH,
        )
        .unwrap_err();
        assert!(error.to_string().contains("different trust point"));
    }

    #[test]
    fn base64_encoder_matches_dns_presentation_format() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
    }

    #[test]
    fn persisted_empty_root_state_publishes_fail_closed_tombstone() {
        let temporary = tempfile::tempdir().unwrap();
        let state_path = temporary.path().join("state.bin");
        let runtime_path = temporary.path().join("runtime.positive");
        let manager = TrustAnchorManager::with_path(&state_path);
        manager.save_to_disk().unwrap();
        publish_runtime_anchors_from(&state_path, &runtime_path).unwrap();
        assert_eq!(
            fs::read_to_string(runtime_path).unwrap(),
            format!("{FAIL_CLOSED_ROOT_DS}\n")
        );
    }
}
