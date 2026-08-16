//! Publish hot resolver answers to shared memory for lock-free NSS reads.
//!
//! The file is a versioned Linux ABI shared with `nss/nss_resolve_shm.c`.
//! A global even/odd sequence protects header updates, while each bucket is
//! invalidated before its payload and metadata are replaced. The payload is
//! deliberately limited to an owner name and address bytes; DNSSEC keys and
//! signatures are never serialized into this optional NSS cache.
#![allow(missing_debug_implementations)]

use std::fs::{File, OpenOptions};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{fence, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use memmap2::{Mmap, MmapMut, MmapOptions};

pub const SHM_PATH: &str = "/dev/shm/rustd-resolved-l1";
pub const SHM_MAGIC: u64 = 0x5253_4C31_4E53_5301;
pub const SHM_VERSION: u32 = 1;
pub const N_BUCKETS: usize = 65_536;
pub const ARENA_SIZE: usize = 16 * 1024 * 1024;
const STALE_WINDOW: Duration = Duration::from_secs(30);
const O_NOFOLLOW: i32 = 0o400_000;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ShmHeader {
    pub magic: u64,
    pub version: u32,
    pub n_buckets: u32,
    pub arena_off: u32,
    pub arena_size: u32,
    pub write_gen: u64,
    pub arena_used: u32,
    pub _pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ShmBucket {
    pub gen: u64,
    pub hash: u64,
    pub off: u32,
    pub len: u32,
    pub expires_ms: u64,
    pub flags: u32,
    pub qtype: u16,
    pub qclass: u16,
    pub rcode: u8,
    pub n_addrs: u8,
    pub _pad: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShmAddr {
    pub family: u8,
    pub _pad: u8,
    pub scope_id: u16,
    pub addr: [u8; 16],
}

impl ShmAddr {
    pub fn from_ip(address: IpAddr, scope_id: u32) -> io::Result<Self> {
        let scope_id = u16::try_from(scope_id).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "IPv6 scope identifier exceeds the shared-memory ABI",
            )
        })?;
        let mut output = Self {
            scope_id,
            ..Self::default()
        };
        match address {
            IpAddr::V4(address) => {
                output.family = 4;
                output.addr[..4].copy_from_slice(&address.octets());
            }
            IpAddr::V6(address) => {
                output.family = 6;
                output.addr.copy_from_slice(&address.octets());
            }
        }
        Ok(output)
    }

    pub fn ip(self) -> Option<IpAddr> {
        match self.family {
            4 => Some(IpAddr::V4(Ipv4Addr::new(
                self.addr[0],
                self.addr[1],
                self.addr[2],
                self.addr[3],
            ))),
            6 => Some(IpAddr::V6(Ipv6Addr::from(self.addr))),
            _ => None,
        }
    }
}

const _: () = assert!(std::mem::size_of::<ShmHeader>() == 40);
const _: () = assert!(std::mem::align_of::<ShmHeader>() >= std::mem::align_of::<u64>());
const _: () = assert!(std::mem::size_of::<ShmBucket>() == 48);
const _: () = assert!(std::mem::align_of::<ShmBucket>() >= std::mem::align_of::<u64>());
const _: () = assert!(std::mem::size_of::<ShmAddr>() == 20);
const _: () = assert!(std::mem::size_of::<AtomicU64>() == std::mem::size_of::<u64>());
const _: () = assert!(std::mem::align_of::<AtomicU64>() == std::mem::align_of::<u64>());

pub struct ShmPublisher {
    path: PathBuf,
    mmap: MmapMut,
    n_buckets: usize,
    arena_off: usize,
    arena_size: usize,
}

impl ShmPublisher {
    pub fn create() -> io::Result<Self> {
        Self::create_at(SHM_PATH, N_BUCKETS, ARENA_SIZE)
    }

    pub fn create_at(
        path: impl AsRef<Path>,
        n_buckets: usize,
        arena_size: usize,
    ) -> io::Result<Self> {
        validate_layout(n_buckets, arena_size)?;
        let path = path.as_ref();
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }

        let header_size = std::mem::size_of::<ShmHeader>();
        let buckets_size = n_buckets
            .checked_mul(std::mem::size_of::<ShmBucket>())
            .ok_or_else(layout_overflow)?;
        let arena_off = header_size
            .checked_add(buckets_size)
            .ok_or_else(layout_overflow)?;
        let total = arena_off
            .checked_add(arena_size)
            .ok_or_else(layout_overflow)?;
        let total_u64 = u64::try_from(total).map_err(|_| layout_overflow())?;

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o644)
            .custom_flags(O_NOFOLLOW)
            .open(path)?;
        // `mode` is filtered by the process umask. Set the final mode
        // explicitly so the documented public-cache ABI remains 0644.
        file.set_permissions(std::fs::Permissions::from_mode(0o644))?;
        file.set_len(total_u64)?;
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "shared-memory path is not a regular file",
            ));
        }

        // SAFETY: the file is exclusively created, sized to `total`, and kept
        // open while the mapping is established.
        let mut mmap = unsafe { MmapOptions::new().len(total).map_mut(&file)? };
        mmap.fill(0);
        let header = ShmHeader {
            magic: SHM_MAGIC,
            version: SHM_VERSION,
            n_buckets: u32::try_from(n_buckets).map_err(|_| layout_overflow())?,
            arena_off: u32::try_from(arena_off).map_err(|_| layout_overflow())?,
            arena_size: u32::try_from(arena_size).map_err(|_| layout_overflow())?,
            write_gen: 2,
            arena_used: 0,
            _pad: 0,
        };
        // SAFETY: the mapping begins at an address aligned for `ShmHeader`,
        // and the validated mapping is large enough for the value.
        unsafe { std::ptr::write(mmap.as_mut_ptr().cast::<ShmHeader>(), header) };
        mmap.flush()?;

        Ok(Self {
            path: path.to_path_buf(),
            mmap,
            n_buckets,
            arena_off,
            arena_size,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn publish_addrs(
        &mut self,
        owner_wire: &[u8],
        qtype: u16,
        qclass: u16,
        rcode: u8,
        addrs: &[ShmAddr],
        ttl: Duration,
        secure: bool,
        negative: bool,
    ) -> io::Result<()> {
        self.publish_addrs_with_stale(
            owner_wire, qtype, qclass, rcode, addrs, ttl, secure, negative, false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn publish_addrs_with_stale(
        &mut self,
        owner_wire: &[u8],
        qtype: u16,
        qclass: u16,
        rcode: u8,
        addrs: &[ShmAddr],
        ttl: Duration,
        secure: bool,
        negative: bool,
        stale_ok: bool,
    ) -> io::Result<()> {
        if owner_wire.is_empty() || owner_wire.len() > u8::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "owner wire name is empty or exceeds 255 octets",
            ));
        }
        if addrs.len() > u8::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many addresses for the shared-memory ABI",
            ));
        }
        if addrs.iter().any(|address| address.ip().is_none()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "shared-memory address has an invalid family",
            ));
        }

        let address_bytes = addrs
            .len()
            .checked_mul(std::mem::size_of::<ShmAddr>())
            .ok_or_else(layout_overflow)?;
        let need = 1usize
            .checked_add(owner_wire.len())
            .and_then(|length| length.checked_add(address_bytes))
            .ok_or_else(layout_overflow)?;
        if need > self.arena_size || need > u32::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "shared-memory entry exceeds the payload arena",
            ));
        }

        let current_generation = self.header_generation().load(Ordering::Acquire);
        let odd_generation = if current_generation & 1 == 0 {
            current_generation.wrapping_add(1)
        } else {
            current_generation.wrapping_add(2)
        };
        self.header_generation()
            .store(odd_generation, Ordering::Release);
        fence(Ordering::SeqCst);

        let mut arena_used = self.read_arena_used();
        if arena_used as usize + need > self.arena_size {
            self.invalidate_all_buckets();
            arena_used = 0;
        }
        let offset = arena_used;
        let next_used = usize::try_from(offset)
            .ok()
            .and_then(|offset| offset.checked_add(need))
            .and_then(|used| u32::try_from(used).ok())
            .ok_or_else(layout_overflow)?;
        self.write_arena_used(next_used);

        let payload_start = self
            .arena_off
            .checked_add(offset as usize)
            .ok_or_else(layout_overflow)?;
        let payload_end = payload_start
            .checked_add(need)
            .ok_or_else(layout_overflow)?;
        let payload = &mut self.mmap[payload_start..payload_end];
        payload[0] = owner_wire.len() as u8;
        payload[1..1 + owner_wire.len()].copy_from_slice(owner_wire);
        let mut cursor = 1 + owner_wire.len();
        for address in addrs {
            // SAFETY: `ShmAddr` is a plain repr(C) value and the source lives
            // for the duration of this copy.
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    (address as *const ShmAddr).cast::<u8>(),
                    std::mem::size_of::<ShmAddr>(),
                )
            };
            payload[cursor..cursor + bytes.len()].copy_from_slice(bytes);
            cursor += bytes.len();
        }

        let hash = hash_key(owner_wire, qtype, qclass);
        let bucket_index = hash as usize & (self.n_buckets - 1);
        let bucket_pointer = self.bucket_pointer(bucket_index);
        bucket_generation(bucket_pointer).store(0, Ordering::Release);
        fence(Ordering::SeqCst);

        let expires_ms = system_now_ms().saturating_add(duration_milliseconds(ttl));
        let mut flags = 0u32;
        if stale_ok {
            flags |= 1;
        }
        if negative {
            flags |= 2;
        }
        if secure {
            flags |= 4;
        }
        let metadata = ShmBucket {
            gen: 0,
            hash,
            off: offset,
            len: need as u32,
            expires_ms,
            flags,
            qtype,
            qclass,
            rcode,
            n_addrs: addrs.len() as u8,
            _pad: 0,
        };
        write_bucket_metadata(bucket_pointer, &metadata);
        fence(Ordering::Release);

        let stable_generation = odd_generation.wrapping_add(1) & !1;
        bucket_generation(bucket_pointer).store(stable_generation, Ordering::Release);
        self.header_generation()
            .store(stable_generation, Ordering::Release);
        Ok(())
    }

    fn header_pointer(&self) -> *mut ShmHeader {
        self.mmap.as_ptr().cast_mut().cast::<ShmHeader>()
    }

    fn header_generation(&self) -> &AtomicU64 {
        // SAFETY: the field is naturally aligned, has the same layout as
        // `AtomicU64`, and all accesses after initialization use atomics.
        unsafe { &*std::ptr::addr_of!((*self.header_pointer()).write_gen).cast::<AtomicU64>() }
    }

    fn read_arena_used(&self) -> u32 {
        // SAFETY: the header lies within the validated mapping. The global
        // sequence is odd while this mutable field is changed.
        unsafe { std::ptr::read_volatile(std::ptr::addr_of!((*self.header_pointer()).arena_used)) }
    }

    fn write_arena_used(&mut self, value: u32) {
        // SAFETY: the header lies within the validated mutable mapping and the
        // global sequence is odd during the write.
        unsafe {
            std::ptr::write_volatile(
                std::ptr::addr_of_mut!((*self.header_pointer()).arena_used),
                value,
            );
        }
    }

    fn bucket_pointer(&self, index: usize) -> *mut ShmBucket {
        debug_assert!(index < self.n_buckets);
        // SAFETY: `index` is bounded by the validated bucket table.
        unsafe {
            self.mmap
                .as_ptr()
                .add(std::mem::size_of::<ShmHeader>())
                .cast_mut()
                .cast::<ShmBucket>()
                .add(index)
        }
    }

    fn invalidate_all_buckets(&self) {
        for index in 0..self.n_buckets {
            bucket_generation(self.bucket_pointer(index)).store(0, Ordering::Release);
        }
        fence(Ordering::SeqCst);
    }
}

pub fn hash_key(owner: &[u8], qtype: u16, qclass: u16) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for &byte in owner {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash ^= u64::from(qtype) << 16;
    hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    hash ^= u64::from(qclass);
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(0xff51_afd7_ed55_8ccd);
    hash ^= hash >> 33;
    hash
}

pub struct ShmReader {
    mmap: Mmap,
}

impl ShmReader {
    pub fn open() -> io::Result<Self> {
        Self::open_at(SHM_PATH)
    }

    pub fn open_at(path: impl AsRef<Path>) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW)
            .open(path)?;
        validate_shared_file(&file)?;
        // SAFETY: the file is a regular file and remains open while the
        // read-only mapping is established.
        let mmap = unsafe { MmapOptions::new().map(&file)? };
        Ok(Self { mmap })
    }

    pub fn lookup(
        &self,
        owner: &[u8],
        qtype: u16,
        qclass: u16,
    ) -> Option<(u8, Vec<ShmAddr>, bool)> {
        let header = self.header_snapshot()?;
        let hash = hash_key(owner, qtype, qclass);
        let bucket_index = hash as usize & (header.n_buckets as usize - 1);
        let bucket_pointer = self.bucket_pointer(bucket_index)?;

        for _ in 0..4 {
            let bucket = bucket_snapshot(bucket_pointer)?;
            if bucket.gen == 0
                || bucket.hash != hash
                || bucket.qtype != qtype
                || bucket.qclass != qclass
            {
                return None;
            }
            if !entry_is_fresh(bucket.expires_ms, bucket.flags) {
                return None;
            }

            let relative_end = (bucket.off as usize).checked_add(bucket.len as usize)?;
            if relative_end > header.arena_used as usize
                || relative_end > header.arena_size as usize
            {
                return None;
            }
            let payload_start = (header.arena_off as usize).checked_add(bucket.off as usize)?;
            let payload_end = payload_start.checked_add(bucket.len as usize)?;
            let payload = self.mmap.get(payload_start..payload_end)?;
            let owner_length = usize::from(*payload.first()?);
            let addresses_length =
                usize::from(bucket.n_addrs).checked_mul(std::mem::size_of::<ShmAddr>())?;
            let minimum_length = 1usize
                .checked_add(owner_length)?
                .checked_add(addresses_length)?;
            if minimum_length > payload.len()
                || owner_length != owner.len()
                || payload.get(1..1 + owner_length)? != owner
            {
                return None;
            }

            let mut addresses = Vec::with_capacity(usize::from(bucket.n_addrs));
            let mut cursor = 1 + owner_length;
            for _ in 0..bucket.n_addrs {
                let end = cursor.checked_add(std::mem::size_of::<ShmAddr>())?;
                let bytes = payload.get(cursor..end)?;
                let mut address = ShmAddr::default();
                // SAFETY: both buffers are valid for exactly `size_of` bytes
                // and do not overlap.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        bytes.as_ptr(),
                        (&mut address as *mut ShmAddr).cast::<u8>(),
                        std::mem::size_of::<ShmAddr>(),
                    );
                }
                address.ip()?;
                addresses.push(address);
                cursor = end;
            }

            fence(Ordering::Acquire);
            if bucket_generation(bucket_pointer).load(Ordering::Acquire) == bucket.gen {
                return Some((bucket.rcode, addresses, bucket.flags & 4 != 0));
            }
        }
        None
    }

    fn header_snapshot(&self) -> Option<ShmHeader> {
        if self.mmap.len() < std::mem::size_of::<ShmHeader>() {
            return None;
        }
        let pointer = self.mmap.as_ptr().cast::<ShmHeader>();
        let generation = header_generation(pointer);
        for _ in 0..4 {
            let before = generation.load(Ordering::Acquire);
            if before == 0 || before & 1 != 0 {
                std::hint::spin_loop();
                continue;
            }
            let snapshot = read_header_fields(pointer, before);
            fence(Ordering::Acquire);
            let after = generation.load(Ordering::Acquire);
            if before == after && valid_header(&snapshot, self.mmap.len()) {
                return Some(snapshot);
            }
        }
        None
    }

    fn bucket_pointer(&self, index: usize) -> Option<*const ShmBucket> {
        let offset = std::mem::size_of::<ShmHeader>()
            .checked_add(index.checked_mul(std::mem::size_of::<ShmBucket>())?)?;
        self.mmap
            .get(offset..offset + std::mem::size_of::<ShmBucket>())?;
        // SAFETY: the bounds check above proves the complete bucket is mapped.
        Some(unsafe { self.mmap.as_ptr().add(offset).cast::<ShmBucket>() })
    }
}

fn validate_layout(n_buckets: usize, arena_size: usize) -> io::Result<()> {
    if n_buckets == 0 || !n_buckets.is_power_of_two() || n_buckets > u32::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "shared-memory bucket count must be a nonzero power of two",
        ));
    }
    if arena_size == 0 || arena_size > u32::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "shared-memory arena size is invalid",
        ));
    }
    Ok(())
}

fn validate_shared_file(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "shared-memory path is not a regular file",
        ));
    }
    if metadata.len() < std::mem::size_of::<ShmHeader>() as u64 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "shared-memory file is shorter than its header",
        ));
    }
    Ok(())
}

fn valid_header(header: &ShmHeader, mapping_length: usize) -> bool {
    if header.magic != SHM_MAGIC
        || header.version != SHM_VERSION
        || header.n_buckets == 0
        || !header.n_buckets.is_power_of_two()
        || header.arena_used > header.arena_size
    {
        return false;
    }
    let buckets_length = (header.n_buckets as usize).checked_mul(std::mem::size_of::<ShmBucket>());
    let Some(expected_arena_offset) =
        buckets_length.and_then(|length| std::mem::size_of::<ShmHeader>().checked_add(length))
    else {
        return false;
    };
    if header.arena_off as usize != expected_arena_offset {
        return false;
    }
    (header.arena_off as usize)
        .checked_add(header.arena_size as usize)
        .is_some_and(|end| end <= mapping_length)
}

fn read_header_fields(pointer: *const ShmHeader, generation: u64) -> ShmHeader {
    // SAFETY: the caller proved the mapping contains a complete header. The
    // volatile reads are guarded by the even/odd sequence field.
    unsafe {
        ShmHeader {
            magic: std::ptr::read_volatile(std::ptr::addr_of!((*pointer).magic)),
            version: std::ptr::read_volatile(std::ptr::addr_of!((*pointer).version)),
            n_buckets: std::ptr::read_volatile(std::ptr::addr_of!((*pointer).n_buckets)),
            arena_off: std::ptr::read_volatile(std::ptr::addr_of!((*pointer).arena_off)),
            arena_size: std::ptr::read_volatile(std::ptr::addr_of!((*pointer).arena_size)),
            write_gen: generation,
            arena_used: std::ptr::read_volatile(std::ptr::addr_of!((*pointer).arena_used)),
            _pad: std::ptr::read_volatile(std::ptr::addr_of!((*pointer)._pad)),
        }
    }
}

fn bucket_snapshot(pointer: *const ShmBucket) -> Option<ShmBucket> {
    let generation = bucket_generation(pointer);
    for _ in 0..4 {
        let before = generation.load(Ordering::Acquire);
        if before == 0 {
            return None;
        }
        // SAFETY: the caller proved the mapping contains a complete bucket;
        // all mutable metadata is guarded by `gen`.
        let snapshot = unsafe {
            ShmBucket {
                gen: before,
                hash: std::ptr::read_volatile(std::ptr::addr_of!((*pointer).hash)),
                off: std::ptr::read_volatile(std::ptr::addr_of!((*pointer).off)),
                len: std::ptr::read_volatile(std::ptr::addr_of!((*pointer).len)),
                expires_ms: std::ptr::read_volatile(std::ptr::addr_of!((*pointer).expires_ms)),
                flags: std::ptr::read_volatile(std::ptr::addr_of!((*pointer).flags)),
                qtype: std::ptr::read_volatile(std::ptr::addr_of!((*pointer).qtype)),
                qclass: std::ptr::read_volatile(std::ptr::addr_of!((*pointer).qclass)),
                rcode: std::ptr::read_volatile(std::ptr::addr_of!((*pointer).rcode)),
                n_addrs: std::ptr::read_volatile(std::ptr::addr_of!((*pointer).n_addrs)),
                _pad: std::ptr::read_volatile(std::ptr::addr_of!((*pointer)._pad)),
            }
        };
        fence(Ordering::Acquire);
        if generation.load(Ordering::Acquire) == before {
            return Some(snapshot);
        }
    }
    None
}

fn write_bucket_metadata(pointer: *mut ShmBucket, metadata: &ShmBucket) {
    // SAFETY: the bucket is invalidated before this call. The repr(C) fields
    // following `gen` are contiguous and are copied without touching the
    // generation field itself.
    unsafe {
        let destination = pointer.cast::<u8>().add(std::mem::size_of::<u64>());
        let source = (metadata as *const ShmBucket)
            .cast::<u8>()
            .add(std::mem::size_of::<u64>());
        std::ptr::copy_nonoverlapping(
            source,
            destination,
            std::mem::size_of::<ShmBucket>() - std::mem::size_of::<u64>(),
        );
    }
}

fn header_generation(pointer: *const ShmHeader) -> &'static AtomicU64 {
    // SAFETY: the ABI asserts equal size/alignment, and the mapped header lives
    // at least as long as any reader using the returned reference.
    unsafe { &*std::ptr::addr_of!((*pointer).write_gen).cast::<AtomicU64>() }
}

fn bucket_generation(pointer: *const ShmBucket) -> &'static AtomicU64 {
    // SAFETY: the ABI asserts equal size/alignment, and the mapped bucket lives
    // at least as long as any reader using the returned reference.
    unsafe { &*std::ptr::addr_of!((*pointer).gen).cast::<AtomicU64>() }
}

fn entry_is_fresh(expires_ms: u64, flags: u32) -> bool {
    let now = system_now_ms();
    if now <= expires_ms {
        return true;
    }
    flags & 1 != 0 && now.saturating_sub(expires_ms) <= duration_milliseconds(STALE_WINDOW)
}

fn duration_milliseconds(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn system_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, duration_milliseconds)
}

fn layout_overflow() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "shared-memory layout overflow")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn owner() -> Vec<u8> {
        vec![
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 4, b't', b'e', b's', b't', 0,
        ]
    }

    #[test]
    fn hash_matches_the_c_abi_fixture() {
        assert_eq!(hash_key(&owner(), 1, 1), 0xd6a3_4bfb_5757_0ef4);
    }

    #[test]
    fn publishes_and_reads_valid_addresses() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cache");
        let mut publisher = ShmPublisher::create_at(&path, 8, 4096).unwrap();
        assert_eq!(publisher_file_mode(&path), 0o644);
        let addresses = [
            ShmAddr::from_ip("192.0.2.123".parse().unwrap(), 0).unwrap(),
            ShmAddr::from_ip("2001:db8::123".parse().unwrap(), 7).unwrap(),
        ];
        publisher
            .publish_addrs(
                &owner(),
                1,
                1,
                0,
                &addresses,
                Duration::from_secs(60),
                true,
                false,
            )
            .unwrap();
        let reader = ShmReader::open_at(&path).unwrap();
        let (rcode, actual, secure) = reader.lookup(&owner(), 1, 1).unwrap();
        assert_eq!(rcode, 0);
        assert_eq!(actual, addresses);
        assert!(secure);
    }

    fn publisher_file_mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn arena_wrap_invalidates_old_buckets() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cache");
        let mut publisher = ShmPublisher::create_at(&path, 8, 63).unwrap();
        let first_owner = owner();
        let second_owner = vec![6, b's', b'e', b'c', b'o', b'n', b'd', 0];
        let address = [ShmAddr::from_ip("192.0.2.1".parse().unwrap(), 0).unwrap()];
        publisher
            .publish_addrs(
                &first_owner,
                1,
                1,
                0,
                &address,
                Duration::from_secs(60),
                false,
                false,
            )
            .unwrap();
        publisher
            .publish_addrs(
                &second_owner,
                1,
                1,
                0,
                &address,
                Duration::from_secs(60),
                false,
                false,
            )
            .unwrap();
        let reader = ShmReader::open_at(&path).unwrap();
        assert!(reader.lookup(&first_owner, 1, 1).is_none());
        assert!(reader.lookup(&second_owner, 1, 1).is_some());
    }

    #[test]
    fn rejects_invalid_layout_and_scope_ids() {
        let directory = tempfile::tempdir().unwrap();
        assert!(ShmPublisher::create_at(directory.path().join("bad"), 7, 4096).is_err());
        assert!(ShmAddr::from_ip("fe80::1".parse().unwrap(), u32::MAX).is_err());
    }
}
