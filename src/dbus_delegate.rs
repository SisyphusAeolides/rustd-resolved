// SPDX-License-Identifier: LGPL-2.1-or-later
#[derive(Debug)]
struct DnsDelegateObject {
    delegate: crate::dns_delegate::DnsDelegate,
}

#[dbus_interface(name = "org.freedesktop.resolve1.DnsDelegate")]
impl DnsDelegateObject {
    #[dbus_interface(property, name = "DNS")]
    fn dns(&self) -> Vec<(i32, i32, Vec<u8>, u16, String)> {
        manager_dns_ex(&self.delegate.servers, 0)
    }

    #[dbus_interface(property, name = "CurrentDNSServer")]
    fn current_dns_server(&self) -> (i32, i32, Vec<u8>, u16, String) {
        self.delegate.servers.first().map_or(
            (0, AF_UNSPEC, Vec::new(), 0, String::new()),
            |server| manager_dns_ex_entry(0, server),
        )
    }

    #[dbus_interface(property, name = "Domains")]
    fn domains(&self) -> Vec<(String, bool)> {
        self.delegate
            .domains
            .iter()
            .map(|domain| (domain.name.clone(), domain.route_only))
            .collect()
    }

    #[dbus_interface(property, name = "DefaultRoute")]
    fn default_route(&self) -> bool {
        self.delegate.default_route.unwrap_or(false)
    }
}

fn register_delegate_objects(connection: &Connection, resolver: &Resolver) -> zbus::Result<()> {
    for delegate in &resolver.config().dns_delegates {
        let path = delegate_object_path(&delegate.id)
            .map_err(|error| zbus::Error::Failure(error.to_string()))?;
        connection.object_server().at(
            path.as_str(),
            DnsDelegateObject {
                delegate: delegate.clone(),
            },
        )?;
    }
    Ok(())
}

fn delegate_object_path(id: &str) -> Result<OwnedObjectPath, DbusError> {
    if id.is_empty() || id.len() > 255 || matches!(id, "." | "..") || id.contains('/') {
        return Err(DbusError::InvalidArgs(format!(
            "DNS delegate identifier '{id}' is invalid"
        )));
    }
    let encoded = encode_bus_label(id);
    OwnedObjectPath::try_from(format!("{DELEGATE_PATH_PREFIX}/{encoded}"))
        .map_err(|error| DbusError::InvalidArgs(error.to_string()))
}
