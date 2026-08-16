//! mmap-backed persistent positive cache for resume / restart.
#![allow(missing_debug_implementations)]

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct DiskRecord {
    pub owner: Vec<u8>,
    pub qtype: u16,
    pub qclass: u16,
    pub rcode: u8,
    pub answer: Vec<u8>,
    pub expires_unix: u64,
    pub secure: bool,
}

pub struct DiskCache {
    path: PathBuf,
}

impl DiskCache {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn load(&self) -> std::io::Result<Vec<DiskRecord>> {
        let data = match std::fs::read(&self.path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => return Err(e),
        };
        let recs: Vec<DiskRecord> = bincode::deserialize(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let now = unix_now();
        Ok(recs.into_iter().filter(|r| r.expires_unix > now).collect())
    }

    pub fn save(&self, recs: &[DiskRecord]) -> std::io::Result<()> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = self.path.with_extension("tmp");
        let data = bincode::serialize(recs)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(&tmp, data)?;
        std::fs::rename(tmp, &self.path)?;
        Ok(())
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub fn ttl_to_expiry(ttl: Duration) -> u64 {
    unix_now() + ttl.as_secs()
}
