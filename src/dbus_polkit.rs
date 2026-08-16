// SPDX-License-Identifier: LGPL-2.1-or-later
use std::collections::HashMap as PolkitMap;

use zbus::blocking::Proxy as BlockingProxy;
use zbus::zvariant::Value as PolkitValue;
use zbus::MessageFlags;

const POLKIT_BUS: &str = "org.freedesktop.PolicyKit1";
const POLKIT_PATH: &str = "/org/freedesktop/PolicyKit1/Authority";
const POLKIT_INTERFACE: &str = "org.freedesktop.PolicyKit1.Authority";
const DBUS_BUS: &str = "org.freedesktop.DBus";
const DBUS_PATH: &str = "/org/freedesktop/DBus";
const DBUS_INTERFACE: &str = "org.freedesktop.DBus";
const POLKIT_ALLOW_USER_INTERACTION: u32 = 1;

#[derive(Debug, Default)]
struct DbusAuthorization {
    connection: Mutex<Option<Connection>>,
}

impl DbusAuthorization {
    fn new() -> zbus::Result<Self> {
        Ok(Self::default())
    }

    fn connection(&self) -> Result<Connection, DbusError> {
        let mut guard = self
            .connection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(connection) = guard.as_ref() {
            return Ok(connection.clone());
        }
        let connection = Connection::system()
            .map_err(|error| DbusError::AccessDenied(error.to_string()))?;
        *guard = Some(connection.clone());
        Ok(connection)
    }

    fn authorize(
        &self,
        header: &MessageHeader<'_>,
        action: &str,
        details: PolkitMap<String, String>,
    ) -> Result<(), DbusError> {
        self.authorize_with_good_user(header, action, details, None)
    }

    fn authorize_good_user(
        &self,
        header: &MessageHeader<'_>,
        action: &str,
        details: PolkitMap<String, String>,
        good_user: u32,
    ) -> Result<(), DbusError> {
        self.authorize_with_good_user(header, action, details, Some(good_user))
    }

    fn authorize_with_good_user(
        &self,
        header: &MessageHeader<'_>,
        action: &str,
        details: PolkitMap<String, String>,
        good_user: Option<u32>,
    ) -> Result<(), DbusError> {
        let sender = header
            .sender()
            .map_err(|error| DbusError::AccessDenied(error.to_string()))?
            .ok_or_else(|| DbusError::AccessDenied("D-Bus caller has no unique name".to_owned()))?
            .as_str();

        let sender_uid = self.sender_uid(sender)?;
        if sender_uid == 0 || good_user == Some(sender_uid) {
            return Ok(());
        }

        let subject_details = PolkitMap::from([("name", PolkitValue::from(sender))]);
        let subject = ("system-bus-name", subject_details);
        let flags = if header
            .primary()
            .flags()
            .contains(MessageFlags::AllowInteractiveAuth)
        {
            POLKIT_ALLOW_USER_INTERACTION
        } else {
            0
        };
        let connection = self.connection()?;
        let proxy = BlockingProxy::new(
            &connection,
            POLKIT_BUS,
            POLKIT_PATH,
            POLKIT_INTERFACE,
        )
        .map_err(|error| DbusError::AccessDenied(error.to_string()))?;
        let (authorized, challenge, _): (bool, bool, PolkitMap<String, String>) = proxy
            .call(
                "CheckAuthorization",
                &(subject, action, details, flags, ""),
            )
            .map_err(|error| DbusError::AccessDenied(error.to_string()))?;
        if authorized {
            Ok(())
        } else if challenge && flags == 0 {
            Err(DbusError::InteractiveAuthorizationRequired(
                "the operation requires interactive authorization".to_owned(),
            ))
        } else {
            Err(DbusError::AccessDenied(format!(
                "caller is not authorized for {action}"
            )))
        }
    }

    fn sender_uid(&self, sender: &str) -> Result<u32, DbusError> {
        let connection = self.connection()?;
        let proxy = BlockingProxy::new(
            &connection,
            DBUS_BUS,
            DBUS_PATH,
            DBUS_INTERFACE,
        )
        .map_err(|error| DbusError::AccessDenied(error.to_string()))?;
        proxy
            .call("GetConnectionUnixUser", &(sender,))
            .map_err(|error| DbusError::AccessDenied(error.to_string()))
    }
}

fn interface_details(resolver: &Resolver, ifindex: i32) -> PolkitMap<String, String> {
    let interface = resolver
        .link(ifindex)
        .and_then(|link| link.kernel.map(|kernel| kernel.ifname))
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| ifindex.to_string());
    PolkitMap::from([("interface".to_owned(), interface)])
}

fn no_details() -> PolkitMap<String, String> {
    PolkitMap::new()
}
