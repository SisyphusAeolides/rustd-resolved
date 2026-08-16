// SPDX-License-Identifier: LGPL-2.1-or-later
use crate::native::{self, PeerCredentials};
use std::collections::HashMap;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::{Fd, Value as PolkitValue};

const POLKIT_BUS: &str = "org.freedesktop.PolicyKit1";
const POLKIT_PATH: &str = "/org/freedesktop/PolicyKit1/Authority";
const POLKIT_INTERFACE: &str = "org.freedesktop.PolicyKit1.Authority";
const POLKIT_ALLOW_USER_INTERACTION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthorizationDecision {
    Authorized,
    PermissionDenied,
    InteractiveAuthenticationRequired,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct VarlinkAuthorization {
    credentials: PeerCredentials,
}

impl VarlinkAuthorization {
    pub(crate) const fn new(credentials: PeerCredentials) -> Self {
        Self { credentials }
    }

    pub(crate) fn authorize(self, action: &str, allow_interactive: bool) -> AuthorizationDecision {
        if self.credentials.uid == 0 {
            return AuthorizationDecision::Authorized;
        }
        self.check_polkit(action, allow_interactive)
            .unwrap_or(AuthorizationDecision::PermissionDenied)
    }

    pub(crate) fn service_owner(self) -> bool {
        self.credentials.uid == 0 || self.credentials.uid == native::uid()
    }

    fn check_polkit(
        self,
        action: &str,
        allow_interactive: bool,
    ) -> zbus::Result<AuthorizationDecision> {
        let raw_pidfd = native::pidfd_open(self.credentials.pid).map_err(zbus::Error::from)?;
        // SAFETY: pidfd_open returned a new descriptor and ownership is transferred exactly once.
        let pidfd = unsafe { OwnedFd::from_raw_fd(raw_pidfd) };
        let subject_details = HashMap::from([
            ("pidfd", PolkitValue::from(Fd::from(pidfd.as_raw_fd()))),
            (
                "uid",
                PolkitValue::from(i32::try_from(self.credentials.uid).unwrap_or(i32::MAX)),
            ),
        ]);
        let subject = ("unix-process", subject_details);
        let details = HashMap::<String, String>::new();
        let flags = if allow_interactive {
            POLKIT_ALLOW_USER_INTERACTION
        } else {
            0
        };
        let connection = Connection::system()?;
        let proxy = Proxy::new(&connection, POLKIT_BUS, POLKIT_PATH, POLKIT_INTERFACE)?;
        let (authorized, challenge, _): (bool, bool, HashMap<String, String>) =
            proxy.call("CheckAuthorization", &(subject, action, details, flags, ""))?;
        Ok(if authorized {
            AuthorizationDecision::Authorized
        } else if challenge && !allow_interactive {
            AuthorizationDecision::InteractiveAuthenticationRequired
        } else {
            AuthorizationDecision::PermissionDenied
        })
    }
}
