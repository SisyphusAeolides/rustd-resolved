// SPDX-License-Identifier: LGPL-2.1-or-later
use std::ffi::CString;
use std::io;
use std::os::raw::{c_char, c_int};

extern "C" {
    fn resolved_ifindex_from_name(name: *const c_char) -> c_int;
    fn resolved_ifname_from_index(ifindex: c_int, name: *mut c_char) -> c_int;
}

pub fn resolve_ifindex(value: &str) -> io::Result<i32> {
    let name = CString::new(value)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface contains NUL"))?;
    // SAFETY: CString provides a valid NUL-terminated interface name for the duration of the call.
    let result = unsafe { resolved_ifindex_from_name(name.as_ptr()) };
    if result < 0 {
        Err(io::Error::from_raw_os_error(-result))
    } else {
        Ok(result)
    }
}

pub fn resolve_ifname(ifindex: i32) -> io::Result<String> {
    let mut buffer = vec![0; 16]; // IF_NAMESIZE is typically 16
    let result = unsafe { resolved_ifname_from_index(ifindex, buffer.as_mut_ptr() as *mut c_char) };
    if result < 0 {
        Err(io::Error::from_raw_os_error(-result))
    } else {
        let c_str = unsafe { std::ffi::CStr::from_ptr(buffer.as_ptr() as *const c_char) };
        Ok(c_str.to_string_lossy().into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existing_numeric_ifindices_are_accepted() {
        let loopback = resolve_ifindex("lo").expect("loopback ifindex");
        assert_eq!(
            resolve_ifindex(&loopback.to_string()).expect("ifindex"),
            loopback
        );
        assert!(resolve_ifindex("0").is_err());
        assert!(resolve_ifindex("2147483647").is_err());
    }

    #[test]
    fn loopback_name_resolves() {
        assert!(resolve_ifindex("lo").expect("loopback ifindex") > 0);
    }
}
