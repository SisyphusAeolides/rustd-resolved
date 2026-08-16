// SPDX-License-Identifier: LGPL-2.1-or-later

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use tracing::{debug, error, info};

/// RFC 5011 Trust Anchor State
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustAnchorState {
    AddHoldDown,
    RemoveHoldDown,
    Valid,
    Revoked,
}

/// A single trust anchor entry tracked by the RFC 5011 manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustAnchorEntry {
    pub state: TrustAnchorState,
    pub key_tag: u16,
    pub algorithm: u8,
    pub digest_type: u8,
    pub digest: Vec<u8>,
    pub public_key: Vec<u8>,
    pub last_state_change: SystemTime,
}

/// Manages RFC 5011 trust anchors, handling hold-down timers and persistence.
///
/// RFC 5011 automation is experimental and disabled unless
/// `RUSTD_RESOLVED_RFC5011=1` is set in the environment.
#[derive(Debug, Serialize, Deserialize)]
pub struct TrustAnchorManager {
    anchors: HashMap<Vec<u8>, TrustAnchorEntry>,
    hold_down_time: Duration,
    persistence_path: PathBuf,
}

impl Default for TrustAnchorManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TrustAnchorManager {
    /// Returns whether RFC 5011 trust-anchor management is enabled.
    pub fn enabled() -> bool {
        matches!(
            std::env::var("RUSTD_RESOLVED_RFC5011").ok().as_deref(),
            Some("1") | Some("yes") | Some("true")
        )
    }

    /// Creates a new TrustAnchorManager with default settings (30 days hold-down).
    pub fn new() -> Self {
        Self {
            anchors: HashMap::new(),
            hold_down_time: Duration::from_secs(30 * 24 * 60 * 60), // 30 days
            persistence_path: PathBuf::from("/var/lib/rustd/resolved/rfc5011-trust-anchors.bin"),
        }
    }

    /// Creates a new TrustAnchorManager with a custom persistence path.
    pub fn with_path<P: AsRef<Path>>(path: P) -> Self {
        Self {
            anchors: HashMap::new(),
            hold_down_time: Duration::from_secs(30 * 24 * 60 * 60), // 30 days
            persistence_path: path.as_ref().to_path_buf(),
        }
    }

    /// Loads the trust anchors from disk using bincode.
    pub fn load_from_disk(&mut self) -> Result<()> {
        if !self.persistence_path.exists() {
            debug!("Trust anchor persistence file not found, starting fresh.");
            return Ok(());
        }

        let data = fs::read(&self.persistence_path)?;
        match bincode::deserialize::<HashMap<Vec<u8>, TrustAnchorEntry>>(&data) {
            Ok(loaded) => {
                info!("Successfully loaded trust anchors from disk.");
                self.anchors = loaded;
            }
            Err(e) => {
                error!("Failed to deserialize trust anchors: {}", e);
                return Err(anyhow::anyhow!("Deserialization error: {}", e));
            }
        }
        Ok(())
    }

    /// Saves the trust anchors to disk using an atomic write (temp file + rename).
    pub fn save_to_disk(&self) -> Result<()> {
        if let Some(parent) = self.persistence_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }

        let temp_path = self.persistence_path.with_extension("tmp");
        let data = bincode::serialize(&self.anchors)?;

        let mut file = fs::File::create(&temp_path)?;
        file.write_all(&data)?;
        file.sync_all()?;
        
        fs::rename(temp_path, &self.persistence_path)?;
        debug!("Successfully saved trust anchors to disk.");
        Ok(())
    }

    /// Checks all trust anchors and updates their state if the hold-down timer has expired.
    /// Returns true if any state changed, meaning a save might be required.
    pub fn process_timers(&mut self) -> bool {
        let mut changed = false;
        let now = SystemTime::now();
        let hold_down_time = self.hold_down_time;
        
        self.anchors.retain(|_key, entry| {
            let mut keep = true;
            if let Ok(elapsed) = now.duration_since(entry.last_state_change) {
                if elapsed >= hold_down_time {
                    match entry.state {
                        TrustAnchorState::AddHoldDown => {
                            info!("Trust anchor promoted to Valid state after hold-down.");
                            entry.state = TrustAnchorState::Valid;
                            entry.last_state_change = now;
                            changed = true;
                        }
                        TrustAnchorState::RemoveHoldDown => {
                            info!("Trust anchor removed after hold-down.");
                            keep = false;
                            changed = true;
                        }
                        _ => {}
                    }
                }
            }
            keep
        });
        
        changed
    }

    /// Add or update a trust anchor.
    pub fn update_anchor(&mut self, id: Vec<u8>, entry: TrustAnchorEntry) {
        self.anchors.insert(id, entry);
    }
}
