// SPDX-License-Identifier: LGPL-2.1-or-later
use std::ffi::{CStr, CString};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::fd::RawFd;
use std::os::raw::{c_char, c_int, c_void};
use std::time::Duration;

const IFNAME_MAX: usize = 16;
const LINK_SNAPSHOT_RETRIES: usize = 4;
const ADDRESS_SNAPSHOT_RETRIES: usize = 4;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct NativeLinkSnapshot {
    ifindex: i32,
    flags: u32,
    mtu: u32,
    operstate: u8,
    has_ipv4_global: u8,
    has_ipv4_link_local: u8,
    has_ipv6_global: u8,
    has_ipv6_link_local: u8,
    ifname: [c_char; IFNAME_MAX],
}

impl Default for NativeLinkSnapshot {
    fn default() -> Self {
        Self {
            ifindex: 0,
            flags: 0,
            mtu: 0,
            operstate: 0,
            has_ipv4_global: 0,
            has_ipv4_link_local: 0,
            has_ipv6_global: 0,
            has_ipv6_link_local: 0,
            ifname: [0; IFNAME_MAX],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct NativeMdnsPacketInfo {
    ifindex: i32,
    source_port: u16,
    family: u8,
    destination_multicast: u8,
    hop_limit: i32,
    scope_id: u32,
    source: [u8; 16],
    destination: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct NativeAddressInfo {
    ifindex: i32,
    flags: u32,
    family: u8,
    prefix_length: u8,
    scope: u8,
    _pad: u8,
    scope_id: u32,
    address: [u8; 16],
}

extern "C" {
    fn resolved_notify(state: *const c_char) -> c_int;
    fn resolved_monotonic_usec(result: *mut u64) -> c_int;
    fn resolved_listen_fds() -> c_int;
    fn resolved_socket_accepting(fd: c_int) -> c_int;
    fn resolved_socket_disconnected(fd: c_int) -> c_int;
    fn resolved_install_signal_handlers() -> c_int;
    fn resolved_take_reload() -> c_int;
    fn resolved_should_stop() -> c_int;
    fn resolved_uid() -> u32;
    fn resolved_environment() -> *mut *mut c_char;
    fn resolved_environment_max_length() -> u64;
    fn resolved_peer_credentials(fd: c_int, pid: *mut u32, uid: *mut u32, gid: *mut u32) -> c_int;
    fn resolved_pidfd_open(pid: u32) -> c_int;
    fn resolved_kernel_hostname(buffer: *mut c_char, capacity: usize) -> i64;
    fn resolved_drop_privileges(user: *const c_char, runtime_directory: *const c_char) -> c_int;
    fn resolved_mdns_open(family: c_int, port: u16) -> c_int;
    fn resolved_mdns_join(fd: c_int, family: c_int, ifindex: c_int, join: c_int) -> c_int;
    fn resolved_mdns_recv(
        fd: c_int,
        buffer: *mut c_void,
        capacity: usize,
        packet_info: *mut NativeMdnsPacketInfo,
    ) -> i64;
    fn resolved_mdns_send(
        fd: c_int,
        buffer: *const c_void,
        length: usize,
        family: c_int,
        ifindex: c_int,
        destination: *const u8,
        port: u16,
        scope_id: u32,
    ) -> i64;
    fn resolved_address_snapshot(entries: *mut NativeAddressInfo, capacity: usize) -> i64;
    fn resolved_udp_connect(
        address: *const c_char,
        port: u16,
        scope_id: u32,
        ifindex: c_int,
        firewall_mark: u32,
    ) -> c_int;
    fn resolved_tcp_connect(
        address: *const c_char,
        port: u16,
        scope_id: u32,
        ifindex: c_int,
        firewall_mark: u32,
        timeout_msec: u32,
    ) -> c_int;
    fn resolved_udp_path_mtu(fd: c_int, ipv6: c_int) -> c_int;
    fn resolved_udp_enable_recvfragsize(fd: c_int, ipv6: c_int) -> c_int;
    fn resolved_udp_recv(
        fd: c_int,
        buffer: *mut c_void,
        capacity: usize,
        fragment_size: *mut u32,
    ) -> i64;
    fn resolved_dns_udp_payload_size(
        path_mtu: u32,
        ipv6: c_int,
        loopback: c_int,
        fragmented: c_int,
        received_udp_fragment_max: u32,
    ) -> u16;
    fn resolved_link_snapshot(entries: *mut NativeLinkSnapshot, capacity: usize) -> i64;
    fn resolved_rtnl_open() -> c_int;
    fn resolved_rtnl_wait(fd: c_int, timeout_msec: u32) -> c_int;
    fn resolved_networkd_open() -> c_int;
    fn resolved_networkd_wait(fd: c_int, timeout_msec: u32) -> c_int;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerCredentials {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkInfo {
    pub ifindex: i32,
    pub ifname: String,
    pub flags: u32,
    pub mtu: u32,
    pub operstate: u8,
    pub has_ipv4_global: bool,
    pub has_ipv4_link_local: bool,
    pub has_ipv6_global: bool,
    pub has_ipv6_link_local: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MdnsPacketInfo {
    pub ifindex: i32,
    pub source: SocketAddr,
    pub destination: IpAddr,
    pub hop_limit: i32,
    pub destination_multicast: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddressInfo {
    pub ifindex: i32,
    pub flags: u32,
    pub address: IpAddr,
    pub prefix_length: u8,
    pub scope: u8,
    pub scope_id: u32,
}

pub fn kernel_hostname() -> Option<String> {
    let mut buffer = [0_u8; 256];
    // SAFETY: the helper receives a writable buffer and never writes beyond its capacity.
    let length =
        unsafe { resolved_kernel_hostname(buffer.as_mut_ptr().cast::<c_char>(), buffer.len()) };
    let length = usize::try_from(length).ok()?;
    String::from_utf8(buffer[..length].to_vec()).ok()
}

pub fn pidfd_open(pid: u32) -> io::Result<RawFd> {
    // SAFETY: the function accepts one scalar and returns a newly owned descriptor on success.
    result(unsafe { resolved_pidfd_open(pid) })
}

pub fn socket_disconnected(fd: RawFd) -> io::Result<bool> {
    // SAFETY: the descriptor is borrowed and the native helper only polls and peeks it.
    result(unsafe { resolved_socket_disconnected(fd) }).map(|value| value != 0)
}

pub fn install_signal_handlers() -> io::Result<()> {
    // SAFETY: the function takes no pointers and returns an errno-style integer.
    result(unsafe { resolved_install_signal_handlers() }).map(|_| ())
}

pub fn drop_privileges(user: &str, runtime_directory: &std::path::Path) -> io::Result<bool> {
    use std::os::unix::ffi::OsStrExt as _;

    let user = CString::new(user)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "user name contains NUL"))?;
    let runtime_directory =
        CString::new(runtime_directory.as_os_str().as_bytes()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "runtime directory contains NUL",
            )
        })?;
    // SAFETY: both values are non-null, NUL-terminated strings valid for the call.
    result(unsafe { resolved_drop_privileges(user.as_ptr(), runtime_directory.as_ptr()) })
        .map(|value| value != 0)
}

pub fn stop_requested() -> bool {
    // SAFETY: the function takes no pointers and only reads signal-safe state.
    unsafe { resolved_should_stop() != 0 }
}

pub fn uid() -> u32 {
    // SAFETY: the helper takes no pointers and returns the process real UID.
    unsafe { resolved_uid() }
}

pub fn environment_entries() -> Vec<Vec<u8>> {
    let mut entries = Vec::new();
    // SAFETY: the native helper returns the process `environ` pointer. Each
    // entry is a NUL-terminated string for the lifetime of this snapshot.
    let mut cursor = unsafe { resolved_environment() };
    if cursor.is_null() {
        return entries;
    }
    loop {
        // SAFETY: `cursor` points into the NULL-terminated environ array.
        let entry = unsafe { *cursor };
        if entry.is_null() {
            break;
        }
        // SAFETY: each environ entry is NUL-terminated by the C ABI.
        entries.push(unsafe { CStr::from_ptr(entry) }.to_bytes().to_vec());
        // SAFETY: the array has at least one more pointer until its NULL terminator.
        cursor = unsafe { cursor.add(1) };
    }
    entries
}

pub fn environment_max_length() -> usize {
    usize::try_from(unsafe { resolved_environment_max_length() }).unwrap_or(usize::MAX)
}

pub fn take_reload() -> bool {
    // SAFETY: the function takes no pointers and atomically consumes signal state.
    unsafe { resolved_take_reload() != 0 }
}

pub fn listen_fds() -> io::Result<usize> {
    // SAFETY: the function takes no pointers and returns an errno-style integer.
    let count = result(unsafe { resolved_listen_fds() })?;
    usize::try_from(count).map_err(|_| io::Error::from_raw_os_error(libc_einval()))
}

pub fn socket_accepting(fd: c_int) -> io::Result<bool> {
    // SAFETY: the descriptor is borrowed for the duration of getsockopt and is not mutated.
    result(unsafe { resolved_socket_accepting(fd) }).map(|value| value != 0)
}

pub fn notify(state: &str) -> io::Result<bool> {
    let state = CString::new(state)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "notification contains NUL"))?;
    // SAFETY: CString guarantees a non-null, NUL-terminated pointer for this call.
    result(unsafe { resolved_notify(state.as_ptr()) }).map(|value| value != 0)
}

pub fn notify_reloading(status: &str) -> io::Result<bool> {
    let mut monotonic_usec = 0_u64;
    // SAFETY: the output points to a valid u64 for the duration of the call.
    result(unsafe { resolved_monotonic_usec(&mut monotonic_usec) })?;
    notify(&reloading_state(status, monotonic_usec))
}

fn reloading_state(status: &str, monotonic_usec: u64) -> String {
    format!("RELOADING=1\nMONOTONIC_USEC={monotonic_usec}\nSTATUS={status}")
}

pub fn mdns_open(ipv6: bool, port: u16) -> io::Result<RawFd> {
    let family = if ipv6 { 10 } else { 2 };
    // SAFETY: all arguments are plain values and a successful return is an owned descriptor.
    result(unsafe { resolved_mdns_open(family, port) })
}

pub fn mdns_join(fd: RawFd, ipv6: bool, ifindex: i32, join: bool) -> io::Result<()> {
    let family = if ipv6 { 10 } else { 2 };
    // SAFETY: the descriptor is borrowed and the remaining arguments are plain values.
    result(unsafe { resolved_mdns_join(fd, family, ifindex, bool_to_c_int(join)) }).map(|_| ())
}

pub fn mdns_recv(fd: RawFd, buffer: &mut [u8]) -> io::Result<(usize, MdnsPacketInfo)> {
    if buffer.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "mDNS receive buffer must not be empty",
        ));
    }
    let mut packet = NativeMdnsPacketInfo::default();
    // SAFETY: the buffer and packet-info outputs are valid and writable for the call.
    let length = signed_result(unsafe {
        resolved_mdns_recv(
            fd,
            buffer.as_mut_ptr().cast::<c_void>(),
            buffer.len(),
            &mut packet,
        )
    })?;
    let length =
        usize::try_from(length).map_err(|_| io::Error::from_raw_os_error(libc_einval()))?;
    if length > buffer.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native mDNS receive exceeded the supplied buffer",
        ));
    }
    Ok((length, mdns_packet_info(packet)?))
}

pub fn mdns_send(
    fd: RawFd,
    buffer: &[u8],
    destination: SocketAddr,
    ifindex: i32,
) -> io::Result<usize> {
    if buffer.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "mDNS packet must not be empty",
        ));
    }
    let mut address = [0; 16];
    let (family, scope_id) = match destination {
        SocketAddr::V4(destination) => {
            address[..4].copy_from_slice(&destination.ip().octets());
            (2, 0)
        }
        SocketAddr::V6(destination) => {
            address.copy_from_slice(&destination.ip().octets());
            (10, destination.scope_id())
        }
    };
    // SAFETY: buffer and address remain valid for the duration of the send call.
    let length = signed_result(unsafe {
        resolved_mdns_send(
            fd,
            buffer.as_ptr().cast::<c_void>(),
            buffer.len(),
            family,
            ifindex,
            address.as_ptr(),
            destination.port(),
            scope_id,
        )
    })?;
    usize::try_from(length).map_err(|_| io::Error::from_raw_os_error(libc_einval()))
}

pub fn address_snapshot() -> io::Result<Vec<AddressInfo>> {
    let mut capacity = address_snapshot_count()?;
    for _ in 0..ADDRESS_SNAPSHOT_RETRIES {
        let mut entries = vec![NativeAddressInfo::default(); capacity.max(1)];
        // SAFETY: entries points to `entries.len()` writable, correctly aligned ABI records.
        let count = signed_result(unsafe {
            resolved_address_snapshot(entries.as_mut_ptr(), entries.len())
        })?;
        let count =
            usize::try_from(count).map_err(|_| io::Error::from_raw_os_error(libc_einval()))?;
        if count > entries.len() {
            capacity = count;
            continue;
        }
        entries.truncate(count);
        return entries.into_iter().map(address_info).collect();
    }
    Err(io::Error::other(
        "kernel address set changed repeatedly during snapshot",
    ))
}

pub fn udp_connect(
    server: SocketAddr,
    ifindex: Option<i32>,
    firewall_mark: u32,
) -> io::Result<RawFd> {
    let address = CString::new(server.ip().to_string())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid DNS server address"))?;
    let scope_id = match server {
        SocketAddr::V4(_) => 0,
        SocketAddr::V6(address) => address.scope_id(),
    };
    // SAFETY: CString provides a valid pointer for the duration of the call; all other values are scalars.
    result(unsafe {
        resolved_udp_connect(
            address.as_ptr(),
            server.port(),
            scope_id,
            ifindex.unwrap_or(0),
            firewall_mark,
        )
    })
}

pub fn tcp_connect(
    server: SocketAddr,
    ifindex: Option<i32>,
    firewall_mark: u32,
    timeout: Duration,
) -> io::Result<RawFd> {
    let address = CString::new(server.ip().to_string())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid DNS server address"))?;
    let scope_id = match server {
        SocketAddr::V4(_) => 0,
        SocketAddr::V6(address) => address.scope_id(),
    };
    let timeout_msec = u32::try_from(timeout.as_millis())
        .unwrap_or(u32::MAX)
        .max(1);
    // SAFETY: CString provides a valid pointer for the duration of the call; all other values are scalars.
    result(unsafe {
        resolved_tcp_connect(
            address.as_ptr(),
            server.port(),
            scope_id,
            ifindex.unwrap_or(0),
            firewall_mark,
            timeout_msec,
        )
    })
}

pub fn udp_path_mtu(fd: c_int, ipv6: bool) -> io::Result<u32> {
    // SAFETY: the descriptor is borrowed for the duration of the getsockopt call.
    let mtu = result(unsafe { resolved_udp_path_mtu(fd, bool_to_c_int(ipv6)) })?;
    u32::try_from(mtu).map_err(|_| io::Error::from_raw_os_error(libc_einval()))
}

pub fn enable_udp_fragment_size(fd: c_int, ipv6: bool) -> io::Result<bool> {
    // SAFETY: the descriptor is borrowed and the function only changes a socket option.
    result(unsafe { resolved_udp_enable_recvfragsize(fd, bool_to_c_int(ipv6)) })
        .map(|value| value != 0)
}

pub fn udp_recv(fd: c_int, buffer: &mut [u8]) -> io::Result<(usize, u32)> {
    let mut fragment_size = 0;
    // SAFETY: the buffer is valid and writable for exactly `buffer.len()` bytes.
    let length = unsafe {
        resolved_udp_recv(
            fd,
            buffer.as_mut_ptr().cast::<c_void>(),
            buffer.len(),
            &mut fragment_size,
        )
    };
    if length < 0 {
        let errno = i32::try_from(-length).unwrap_or(libc_einval());
        return Err(io::Error::from_raw_os_error(errno));
    }
    let length =
        usize::try_from(length).map_err(|_| io::Error::from_raw_os_error(libc_einval()))?;
    if length > buffer.len() {
        return Err(io::Error::from_raw_os_error(libc_einval()));
    }
    Ok((length, fragment_size))
}

#[must_use]
pub fn dns_udp_payload_size(
    path_mtu: Option<u32>,
    ipv6: bool,
    loopback: bool,
    fragmented: bool,
    received_udp_fragment_max: u32,
) -> u16 {
    // SAFETY: all arguments are plain values and the function has no side effects.
    unsafe {
        resolved_dns_udp_payload_size(
            path_mtu.unwrap_or(0),
            bool_to_c_int(ipv6),
            bool_to_c_int(loopback),
            bool_to_c_int(fragmented),
            received_udp_fragment_max,
        )
    }
}

pub fn link_snapshot() -> io::Result<Vec<LinkInfo>> {
    let mut capacity = snapshot_count()?;
    for _ in 0..LINK_SNAPSHOT_RETRIES {
        let mut entries = vec![NativeLinkSnapshot::default(); capacity.max(1)];
        // SAFETY: entries points to `entries.len()` writable, correctly aligned ABI records.
        let count =
            signed_result(unsafe { resolved_link_snapshot(entries.as_mut_ptr(), entries.len()) })?;
        let count =
            usize::try_from(count).map_err(|_| io::Error::from_raw_os_error(libc_einval()))?;
        if count > entries.len() {
            capacity = count;
            continue;
        }
        entries.truncate(count);
        return entries.into_iter().map(link_info).collect();
    }
    Err(io::Error::other(
        "kernel link set changed repeatedly during snapshot",
    ))
}

pub fn rtnl_open() -> io::Result<RawFd> {
    // SAFETY: the function takes no pointers and returns an owned descriptor or negative errno.
    result(unsafe { resolved_rtnl_open() })
}

pub fn rtnl_wait(fd: RawFd, timeout: Duration) -> io::Result<bool> {
    let timeout_msec = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
    // SAFETY: the descriptor is borrowed for the duration of poll/recv draining.
    result(unsafe { resolved_rtnl_wait(fd, timeout_msec) }).map(|value| value != 0)
}

pub fn networkd_open() -> io::Result<RawFd> {
    // SAFETY: the function takes no pointers and returns an owned descriptor or negative errno.
    result(unsafe { resolved_networkd_open() })
}

pub fn networkd_wait(fd: RawFd, timeout: Duration) -> io::Result<bool> {
    let timeout_msec = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
    // SAFETY: the descriptor is borrowed for the duration of poll/read draining.
    result(unsafe { resolved_networkd_wait(fd, timeout_msec) }).map(|value| value != 0)
}

pub fn peer_credentials(fd: c_int) -> io::Result<PeerCredentials> {
    let mut process_id = 0;
    let mut user_id = 0;
    let mut group_id = 0;
    // SAFETY: all output pointers refer to initialized writable u32 values.
    result(unsafe { resolved_peer_credentials(fd, &mut process_id, &mut user_id, &mut group_id) })?;
    Ok(PeerCredentials {
        pid: process_id,
        uid: user_id,
        gid: group_id,
    })
}

fn address_snapshot_count() -> io::Result<usize> {
    // SAFETY: a null pointer with zero capacity requests the required record count.
    let count = signed_result(unsafe { resolved_address_snapshot(std::ptr::null_mut(), 0) })?;
    usize::try_from(count).map_err(|_| io::Error::from_raw_os_error(libc_einval()))
}

fn mdns_packet_info(packet: NativeMdnsPacketInfo) -> io::Result<MdnsPacketInfo> {
    if packet.ifindex <= 0 || packet.source_port == 0 || !(0..=255).contains(&packet.hop_limit) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native mDNS packet metadata is invalid",
        ));
    }
    let (source, destination) = match packet.family {
        4 => {
            let source = Ipv4Addr::new(
                packet.source[0],
                packet.source[1],
                packet.source[2],
                packet.source[3],
            );
            let destination = Ipv4Addr::new(
                packet.destination[0],
                packet.destination[1],
                packet.destination[2],
                packet.destination[3],
            );
            (
                SocketAddr::new(IpAddr::V4(source), packet.source_port),
                IpAddr::V4(destination),
            )
        }
        6 => {
            let source = Ipv6Addr::from(packet.source);
            let destination = Ipv6Addr::from(packet.destination);
            let source = SocketAddr::V6(SocketAddrV6::new(
                source,
                packet.source_port,
                0,
                packet.scope_id,
            ));
            (source, IpAddr::V6(destination))
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "native mDNS packet has an unsupported address family",
            ));
        }
    };
    Ok(MdnsPacketInfo {
        ifindex: packet.ifindex,
        source,
        destination,
        hop_limit: packet.hop_limit,
        destination_multicast: packet.destination_multicast != 0,
    })
}

fn address_info(entry: NativeAddressInfo) -> io::Result<AddressInfo> {
    if entry.ifindex <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "kernel returned an invalid address interface index",
        ));
    }
    let address = match entry.family {
        4 if entry.prefix_length <= 32 => IpAddr::V4(Ipv4Addr::new(
            entry.address[0],
            entry.address[1],
            entry.address[2],
            entry.address[3],
        )),
        6 if entry.prefix_length <= 128 => IpAddr::V6(Ipv6Addr::from(entry.address)),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "kernel returned an invalid address family or prefix length",
            ));
        }
    };
    Ok(AddressInfo {
        ifindex: entry.ifindex,
        flags: entry.flags,
        address,
        prefix_length: entry.prefix_length,
        scope: entry.scope,
        scope_id: entry.scope_id,
    })
}

fn snapshot_count() -> io::Result<usize> {
    // SAFETY: a null pointer with zero capacity requests the required record count.
    let count = signed_result(unsafe { resolved_link_snapshot(std::ptr::null_mut(), 0) })?;
    usize::try_from(count).map_err(|_| io::Error::from_raw_os_error(libc_einval()))
}

fn link_info(snapshot: NativeLinkSnapshot) -> io::Result<LinkInfo> {
    let end = snapshot
        .ifname
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(snapshot.ifname.len());
    let bytes = snapshot.ifname[..end]
        .iter()
        .copied()
        .map(u8::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "kernel interface name contains non-ASCII bytes",
            )
        })?;
    let ifname = String::from_utf8(bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "kernel interface name is not UTF-8",
        )
    })?;
    if snapshot.ifindex <= 0 || ifname.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "kernel returned an invalid interface snapshot",
        ));
    }
    Ok(LinkInfo {
        ifindex: snapshot.ifindex,
        ifname,
        flags: snapshot.flags,
        mtu: snapshot.mtu,
        operstate: snapshot.operstate,
        has_ipv4_global: snapshot.has_ipv4_global != 0,
        has_ipv4_link_local: snapshot.has_ipv4_link_local != 0,
        has_ipv6_global: snapshot.has_ipv6_global != 0,
        has_ipv6_link_local: snapshot.has_ipv6_link_local != 0,
    })
}

fn signed_result(value: i64) -> io::Result<i64> {
    if value < 0 {
        let errno = i32::try_from(-value).unwrap_or(libc_einval());
        Err(io::Error::from_raw_os_error(errno))
    } else {
        Ok(value)
    }
}

fn result(value: c_int) -> io::Result<c_int> {
    if value < 0 {
        Err(io::Error::from_raw_os_error(-value))
    } else {
        Ok(value)
    }
}

const fn bool_to_c_int(value: bool) -> c_int {
    if value {
        1
    } else {
        0
    }
}

const fn libc_einval() -> i32 {
    22
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    #[test]
    fn reload_notification_has_notify_reload_contract() {
        assert_eq!(
            reloading_state("Reloading resolver configuration", 1_234_567),
            "RELOADING=1\nMONOTONIC_USEC=1234567\nSTATUS=Reloading resolver configuration"
        );
    }

    #[test]
    fn kernel_hostname_comes_from_the_active_uts_namespace() {
        let expected = std::fs::read_to_string("/proc/sys/kernel/hostname")
            .expect("kernel hostname")
            .trim()
            .to_owned();
        assert_eq!(kernel_hostname().as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn kernel_link_snapshot_contains_named_links() {
        let links = link_snapshot().expect("kernel link snapshot");
        assert!(!links.is_empty());
        assert!(links
            .iter()
            .all(|link| link.ifindex > 0 && !link.ifname.is_empty()));
    }

    #[test]
    fn rtnl_monitor_socket_opens() {
        let fd = rtnl_open().expect("RTNL socket");
        // SAFETY: rtnl_open returns a new owned descriptor.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        assert!(!rtnl_wait(owned.as_raw_fd(), Duration::ZERO).expect("RTNL poll"));
    }

    #[test]
    fn link_dns_monitor_socket_opens() {
        let fd = networkd_open().expect("link DNS monitor socket");
        // SAFETY: networkd_open returns a new owned descriptor.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        assert!(!networkd_wait(owned.as_raw_fd(), Duration::ZERO).expect("networkd poll"));
    }
}
