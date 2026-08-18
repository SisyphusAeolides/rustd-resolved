// SPDX-License-Identifier: LGPL-2.1-or-later

use std::time::{Duration, SystemTime};

use rustd_resolved::dnssec_rfc5011::{
    ObservedDnskey, TrustAnchorManager, TrustAnchorState,
};

const ZONE_FLAG: u16 = 1 << 8;
const SEP_FLAG: u16 = 1;
const REVOKE_FLAG: u16 = 1 << 7;

fn key(tag: u16, marker: u8) -> ObservedDnskey {
    ObservedDnskey {
        owner: ".".to_owned(),
        flags: ZONE_FLAG | SEP_FLAG,
        algorithm: 15,
        key_tag: tag,
        public_key: vec![marker; 32],
        original_ttl: 1,
        authenticated_self_revocation: false,
    }
}

fn manager(path: &std::path::Path) -> TrustAnchorManager {
    TrustAnchorManager::with_parameters(path, Duration::from_secs(10), Duration::from_secs(10))
}

fn reopen(path: &std::path::Path) -> TrustAnchorManager {
    let mut manager = manager(path);
    manager.load_from_disk().expect("reload RFC5011 durable state");
    manager
}

#[test]
fn rollover_revocation_and_purge_survive_every_restart_boundary() {
    let temporary = tempfile::tempdir().expect("temporary RFC5011 state root");
    let state_path = temporary.path().join("anchors.bin");
    let start = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);

    let old = key(10_001, 0x11);
    let new = key(20_002, 0x22);
    let old_id = old.anchor_id();
    let new_id = new.anchor_id();

    // Bootstrap the administratively trusted anchor and persist it.
    let mut state = manager(&state_path);
    assert_eq!(state.seed_valid_anchor(&old, start), old_id);
    state.save_to_disk().expect("persist bootstrap anchor");
    drop(state);

    // A restart must retain the old anchor. Observe the replacement key and
    // begin AddHoldDown under authentication from the existing anchor.
    let mut state = reopen(&state_path);
    assert_eq!(state.entry(&old_id).unwrap().state, TrustAnchorState::Valid);
    assert!(state.observe_validated_rrset(
        &[old.clone(), new.clone()],
        std::slice::from_ref(&old_id),
        start + Duration::from_secs(1),
    ));
    assert_eq!(
        state.entry(&new_id).unwrap().state,
        TrustAnchorState::AddHoldDown
    );
    state.save_to_disk().expect("persist add hold-down");
    drop(state);

    // Another restart must not reset the hold-down timer. A validated RRset
    // observed after expiry promotes the replacement key to Valid.
    let mut state = reopen(&state_path);
    assert_eq!(
        state.entry(&new_id).unwrap().state,
        TrustAnchorState::AddHoldDown
    );
    assert!(state.observe_validated_rrset(
        &[old.clone(), new.clone()],
        std::slice::from_ref(&old_id),
        start + Duration::from_secs(12),
    ));
    assert_eq!(state.entry(&new_id).unwrap().state, TrustAnchorState::Valid);
    assert_eq!(state.valid_anchors().len(), 2);
    state.save_to_disk().expect("persist accepted replacement anchor");
    drop(state);

    // The old key may be revoked only by its authenticated revoked-form key.
    let revoked_old = ObservedDnskey {
        flags: old.flags | REVOKE_FLAG,
        key_tag: old.key_tag.wrapping_add(1),
        authenticated_self_revocation: true,
        ..old.clone()
    };
    let mut state = reopen(&state_path);
    assert!(state.observe_validated_rrset(
        &[revoked_old],
        std::slice::from_ref(&new_id),
        start + Duration::from_secs(13),
    ));
    assert_eq!(state.entry(&old_id).unwrap().state, TrustAnchorState::Revoked);
    assert_eq!(state.entry(&new_id).unwrap().state, TrustAnchorState::Missing);
    assert!(state.revoked_anchor_ids().contains(&old_id));
    state.save_to_disk().expect("persist authenticated revocation");
    drop(state);

    // The replacement key returns, while the revoked key disappears. The old
    // key enters RemoveHoldDown and cannot become trusted again after restart.
    let mut state = reopen(&state_path);
    assert!(state.observe_validated_rrset(
        std::slice::from_ref(&new),
        std::slice::from_ref(&new_id),
        start + Duration::from_secs(14),
    ));
    assert_eq!(state.entry(&old_id).unwrap().state, TrustAnchorState::RemoveHoldDown);
    assert_eq!(state.entry(&new_id).unwrap().state, TrustAnchorState::Valid);
    assert_eq!(state.valid_anchors().len(), 1);
    state.save_to_disk().expect("persist remove hold-down");
    drop(state);

    // A final restart followed by expiry permanently removes the old key while
    // leaving the replacement as the sole usable trust anchor.
    let mut state = reopen(&state_path);
    assert!(!state.process_timers(start + Duration::from_secs(23)));
    assert!(state.process_timers(start + Duration::from_secs(24)));
    assert!(state.entry(&old_id).is_none());
    assert_eq!(state.entry(&new_id).unwrap().state, TrustAnchorState::Valid);
    assert_eq!(state.valid_anchors().len(), 1);
    state.save_to_disk().expect("persist final rollover state");
    drop(state);

    let state = reopen(&state_path);
    assert!(state.entry(&old_id).is_none());
    assert_eq!(state.entry(&new_id).unwrap().state, TrustAnchorState::Valid);
    assert_eq!(state.valid_anchors().len(), 1);
}
