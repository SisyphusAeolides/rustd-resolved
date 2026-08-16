// SPDX-License-Identifier: LGPL-2.1-or-later
#[derive(Debug)]
struct DnssdServiceObject {
    id: String,
    authorization: Arc<DbusAuthorization>,
}

#[dbus_interface(name = "org.freedesktop.resolve1.DnssdService")]
impl DnssdServiceObject {
    fn unregister(
        &self,
        #[zbus(header)] header: MessageHeader<'_>,
    ) -> Result<(), DbusError> {
        let originator_uid = crate::mdns::dnssd_runtime::dynamic_originator(&self.id)
            .ok_or_else(|| DbusError::NoSuchDnssdService(self.id.clone()))?;
        self.authorization.authorize_good_user(
            &header,
            "org.freedesktop.resolve1.unregister-service",
            no_details(),
            originator_uid,
        )?;
        crate::mdns::dnssd_runtime::unregister_dynamic(&self.id)
            .map_err(map_dynamic_service_error)
    }

    #[dbus_interface(signal)]
    async fn conflicted(context: &zbus::SignalContext<'_>) -> zbus::Result<()>;
}

fn synchronize_dnssd_objects(
    connection: &Connection,
    authorization: &Arc<DbusAuthorization>,
    registered: &mut BTreeSet<String>,
) -> zbus::Result<()> {
    let current = crate::mdns::dnssd_runtime::dynamic_ids();
    for id in current.difference(registered) {
        let path = dnssd_object_path(id)
            .map_err(|error| zbus::Error::Failure(error.to_string()))?;
        connection.object_server().at(
            path.as_str(),
            DnssdServiceObject {
                id: id.clone(),
                authorization: Arc::clone(authorization),
            },
        )?;
    }
    for id in registered.difference(&current).cloned().collect::<Vec<_>>() {
        let path = dnssd_object_path(&id)
            .map_err(|error| zbus::Error::Failure(error.to_string()))?;
        connection
            .object_server()
            .remove::<DnssdServiceObject, _>(path.as_str())?;
    }
    *registered = current;
    Ok(())
}

fn emit_dnssd_conflicts(connection: &Connection) -> zbus::Result<()> {
    for id in crate::mdns::dnssd_runtime::take_conflicts() {
        let path = dnssd_object_path(&id)
            .map_err(|error| zbus::Error::Failure(error.to_string()))?;
        connection.emit_signal(
            None::<&str>,
            path.as_str(),
            "org.freedesktop.resolve1.DnssdService",
            "Conflicted",
            &(),
        )?;
    }
    Ok(())
}

fn remove_vanished_dnssd_services(
    bus: &zbus::blocking::fdo::DBusProxy<'_>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    for owner in crate::mdns::dnssd_runtime::dynamic_owners() {
        let name = zbus::names::BusName::try_from(owner.as_str())?;
        if !bus.name_has_owner(name)? {
            crate::mdns::dnssd_runtime::unregister_dynamic_owner(&owner);
        }
    }
    Ok(())
}

fn dnssd_object_path(id: &str) -> Result<OwnedObjectPath, DbusError> {
    if id.is_empty() || id.len() > 255 || matches!(id, "." | "..") || id.contains('/') {
        return Err(DbusError::InvalidArgs(format!(
            "DNS-SD service identifier '{id}' is invalid"
        )));
    }
    let encoded = encode_bus_label(id);
    OwnedObjectPath::try_from(format!("{DNSSD_PATH_PREFIX}/{encoded}"))
        .map_err(|error| DbusError::InvalidArgs(error.to_string()))
}

fn dnssd_id_from_path(path: &OwnedObjectPath) -> Result<String, DbusError> {
    crate::mdns::dnssd_runtime::dynamic_ids()
        .into_iter()
        .find(|id| {
            dnssd_object_path(id)
                .is_ok_and(|candidate| candidate.as_str() == path.as_str())
        })
        .ok_or_else(|| {
            DbusError::NoSuchDnssdService(format!(
                "DNS-SD service with object path '{}' does not exist",
                path.as_str()
            ))
        })
}

fn map_dynamic_service_error(
    error: crate::mdns::dnssd_runtime::DynamicServiceError,
) -> DbusError {
    use crate::mdns::dnssd_runtime::DynamicServiceError;
    match error {
        DynamicServiceError::AlreadyExists => DbusError::DnssdServiceExists(error.to_string()),
        DynamicServiceError::NotFound => DbusError::NoSuchDnssdService(error.to_string()),
        DynamicServiceError::InvalidIdentifier
        | DynamicServiceError::InvalidNameTemplate
        | DynamicServiceError::InvalidTxtKey
        | DynamicServiceError::Service(_) => DbusError::InvalidArgs(error.to_string()),
    }
}

fn map_registration_error(
    error: crate::mdns::dnssd_runtime::DynamicServiceError,
    id: &str,
    service_type: &str,
) -> DbusError {
    use crate::mdns::dnssd_runtime::DynamicServiceError;
    use crate::mdns::parity_dnssd::DnsSdError;

    match error {
        DynamicServiceError::InvalidIdentifier => DbusError::InvalidArgs(format!(
            "DNS-SD service identifier '{id}' is invalid"
        )),
        DynamicServiceError::Service(DnsSdError::InvalidServiceType) => {
            DbusError::InvalidArgs(format!("DNS-SD service type '{service_type}' is invalid"))
        }
        DynamicServiceError::AlreadyExists => {
            DbusError::DnssdServiceExists(format!("DNS-SD service '{id}' exists already"))
        }
        error => map_dynamic_service_error(error),
    }
}
