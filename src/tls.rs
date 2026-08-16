// SPDX-License-Identifier: LGPL-2.1-or-later
use std::ffi::CString;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::os::raw::{c_char, c_int, c_void};
use std::ptr::NonNull;
use std::time::Duration;

const LINUX_EIO: i32 = 5;

#[repr(C)]
struct NativeTlsStream {
    _private: [u8; 0],
}

extern "C" {
    fn resolved_tls_connect(
        address: *const c_char,
        port: u16,
        scope_id: u32,
        ifindex: c_int,
        firewall_mark: u32,
        server_name: *const c_char,
        strict: c_int,
        timeout_msec: u32,
        ret: *mut *mut NativeTlsStream,
    ) -> c_int;
    fn resolved_tls_set_timeout(stream: *mut NativeTlsStream, timeout_msec: u32) -> c_int;
    fn resolved_tls_read(stream: *mut NativeTlsStream, buffer: *mut c_void, capacity: usize)
        -> i64;
    fn resolved_tls_write(
        stream: *mut NativeTlsStream,
        buffer: *const c_void,
        length: usize,
    ) -> i64;
    fn resolved_tls_free(stream: *mut NativeTlsStream);
}

pub struct TlsStream {
    raw: NonNull<NativeTlsStream>,
}

impl fmt::Debug for TlsStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsStream")
            .field("raw", &self.raw)
            .finish()
    }
}

// SAFETY: the native SSL object is exclusively owned by TlsStream and is never accessed concurrently.
unsafe impl Send for TlsStream {}

impl TlsStream {
    pub fn connect(
        server: SocketAddr,
        ifindex: Option<i32>,
        firewall_mark: u32,
        server_name: Option<&str>,
        strict: bool,
        timeout: Duration,
    ) -> io::Result<Self> {
        let address = CString::new(server.ip().to_string()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid DNS server address")
        })?;
        let server_name = server_name
            .map(CString::new)
            .transpose()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "server name contains NUL"))?;
        let scope_id = match server {
            SocketAddr::V4(_) => 0,
            SocketAddr::V6(address) => address.scope_id(),
        };
        let timeout_msec = duration_milliseconds(timeout);
        let mut raw = std::ptr::null_mut();
        // SAFETY: all C strings and output storage are valid for the duration of the call.
        let result = unsafe {
            resolved_tls_connect(
                address.as_ptr(),
                server.port(),
                scope_id,
                ifindex.unwrap_or(0),
                firewall_mark,
                server_name
                    .as_ref()
                    .map_or(std::ptr::null(), |name| name.as_ptr()),
                i32::from(strict),
                timeout_msec,
                &mut raw,
            )
        };
        if result < 0 {
            return Err(io::Error::from_raw_os_error(native_errno(i64::from(
                result,
            ))));
        }
        let raw = NonNull::new(raw).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS connector returned a null stream",
            )
        })?;
        Ok(Self { raw })
    }

    pub fn set_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        // SAFETY: raw is a live exclusively owned native TLS stream.
        let result =
            unsafe { resolved_tls_set_timeout(self.raw.as_ptr(), duration_milliseconds(timeout)) };
        native_result(result).map(|_| ())
    }

    pub fn write_all(&mut self, mut buffer: &[u8]) -> io::Result<()> {
        while !buffer.is_empty() {
            // SAFETY: raw is live and buffer points to `buffer.len()` readable bytes.
            let written = unsafe {
                resolved_tls_write(
                    self.raw.as_ptr(),
                    buffer.as_ptr().cast::<c_void>(),
                    buffer.len(),
                )
            };
            let written = signed_io_result(written, buffer.len())?;
            if written == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "TLS stream closed",
                ));
            }
            buffer = &buffer[written..];
        }
        Ok(())
    }

    pub fn read_exact(&mut self, mut buffer: &mut [u8]) -> io::Result<()> {
        while !buffer.is_empty() {
            // SAFETY: raw is live and buffer points to `buffer.len()` writable bytes.
            let read = unsafe {
                resolved_tls_read(
                    self.raw.as_ptr(),
                    buffer.as_mut_ptr().cast::<c_void>(),
                    buffer.len(),
                )
            };
            let read = signed_io_result(read, buffer.len())?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "TLS stream closed",
                ));
            }
            let (_, rest) = buffer.split_at_mut(read);
            buffer = rest;
        }
        Ok(())
    }
}

impl Drop for TlsStream {
    fn drop(&mut self) {
        // SAFETY: raw was returned by resolved_tls_connect and is owned exactly once by this value.
        unsafe { resolved_tls_free(self.raw.as_ptr()) };
    }
}

fn duration_milliseconds(duration: Duration) -> u32 {
    u32::try_from(duration.as_millis())
        .unwrap_or(u32::MAX)
        .max(1)
}

fn native_errno(result: i64) -> i32 {
    result
        .checked_neg()
        .and_then(|errno| i32::try_from(errno).ok())
        .filter(|errno| *errno > 0)
        .unwrap_or(LINUX_EIO)
}

fn native_result(result: c_int) -> io::Result<c_int> {
    if result < 0 {
        Err(io::Error::from_raw_os_error(native_errno(i64::from(
            result,
        ))))
    } else {
        Ok(result)
    }
}

fn signed_io_result(result: i64, capacity: usize) -> io::Result<usize> {
    if result < 0 {
        return Err(io::Error::from_raw_os_error(native_errno(result)));
    }
    let length = usize::try_from(result)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid TLS I/O length"))?;
    if length > capacity {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native TLS I/O length exceeds buffer capacity",
        ));
    }
    Ok(length)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_tls_length_cannot_exceed_buffer_capacity() {
        let error = signed_io_result(9, 8).expect_err("oversized native TLS length");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn native_tls_negative_extreme_maps_to_io_error() {
        let error = signed_io_result(i64::MIN, 8).expect_err("invalid native TLS errno");
        assert_eq!(error.raw_os_error(), Some(LINUX_EIO));
    }

    #[test]
    fn native_tls_length_within_capacity_is_accepted() {
        assert_eq!(signed_io_result(8, 8).expect("valid TLS length"), 8);
    }
}
