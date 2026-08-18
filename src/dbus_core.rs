// SPDX-License-Identifier: LGPL-2.1-or-later
use crate::config::{DnsServerSpec, Domain, SupportMode, TlsMode, ValidationMode};
use crate::daemon::stop_requested;
use crate::dbus_resolve1_abi::flags::{
    SD_RESOLVED_DNS, SD_RESOLVED_LLMNR_IPV4, SD_RESOLVED_LLMNR_IPV6,
    SD_RESOLVED_MDNS_IPV4, SD_RESOLVED_MDNS_IPV6, SD_RESOLVED_NO_ADDRESS,
    SD_RESOLVED_NO_SEARCH, SD_RESOLVED_NO_TXT,
};
use crate::resolver::{AddressLookup, NameLookup, ResolveError, Resolver};
use crate::routing::{LinkError, LinkState};
use crate::log_control::LogControlState;
use crate::wire::{
    extract_answer_records, extract_service_records_for_name, CLASS_IN, TYPE_A, TYPE_AAAA,
    TYPE_SRV, TYPE_TXT,
};
use std::collections::{BTreeSet, HashMap};
use std::convert::TryFrom;
use std::error::Error;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use zbus::blocking::{Connection, ConnectionBuilder};
use zbus::dbus_interface;
use zbus::zvariant::OwnedObjectPath;
use zbus::MessageHeader;

const BUS_NAME: &str = "org.freedesktop.resolve1";
const MANAGER_PATH: &str = "/org/freedesktop/resolve1";
const LOG_CONTROL_PATH: &str = "/org/freedesktop/LogControl1";
const LINK_PATH_PREFIX: &str = "/org/freedesktop/resolve1/link";
const DNSSD_PATH_PREFIX: &str = "/org/freedesktop/resolve1/dnssd";
const DELEGATE_PATH_PREFIX: &str = "/org/freedesktop/resolve1/dns_delegate";
const AF_UNSPEC: i32 = 0;
const AF_INET: i32 = 2;
const AF_INET6: i32 = 10;
const DNS_PORT: u16 = 53;
type ClientQueryRegistry = Arc<Mutex<HashMap<String, Vec<crate::query_cancel::QueryCancellation>>>>;

#[derive(Debug)]
pub struct DbusServer {
    resolver: Arc<Resolver>,
    log_control: Arc<LogControlState>,
}

impl DbusServer {
    pub fn new(resolver: Arc<Resolver>) -> Self {
        Self {
            resolver,
            log_control: LogControlState::global(),
        }
    }

    pub fn run(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let authorization = Arc::new(DbusAuthorization::new()?);
        let client_queries = ClientQueryRegistry::default();
        let manager = ManagerObject {
            resolver: Arc::clone(&self.resolver),
            authorization: Arc::clone(&authorization),
            client_queries: Arc::clone(&client_queries),
        };
        let log_control = LogControlObject {
            state: Arc::clone(&self.log_control),
        };
        let connection = ConnectionBuilder::system()?
            .name(BUS_NAME)?
            .serve_at(MANAGER_PATH, manager)?
            .serve_at(LOG_CONTROL_PATH, log_control)?
            .build()?;
        let bus = zbus::blocking::fdo::DBusProxy::new(&connection)?;
        register_delegate_objects(&connection, &self.resolver)?;
        let mut registered = BTreeSet::new();
        let mut registered_services = BTreeSet::new();

        while !stop_requested() {
            cancel_vanished_client_queries(&bus, &client_queries)?;
            remove_vanished_dnssd_services(&bus)?;
            synchronize_link_objects(
                &connection,
                &self.resolver,
                &authorization,
                &mut registered,
            )?;
            synchronize_dnssd_objects(
                &connection,
                &authorization,
                &mut registered_services,
            )?;
            emit_dnssd_conflicts(&connection)?;
            thread::sleep(Duration::from_millis(100));
        }
        Ok(())
    }
}

#[derive(Debug)]
struct LogControlObject {
    state: Arc<LogControlState>,
}

#[dbus_interface(name = "org.freedesktop.LogControl1")]
impl LogControlObject {
    #[dbus_interface(property, name = "LogLevel")]
    fn log_level(&self) -> String {
        self.state.level_name().to_owned()
    }

    #[dbus_interface(property, name = "LogLevel")]
    fn set_log_level(&mut self, level: &str) -> zbus::fdo::Result<()> {
        if !valid_log_level(level) {
            return Err(zbus::fdo::Error::InvalidArgs(format!(
                "Invalid log level '{level}'"
            )));
        }
        self.state.set_level_name(level);
        Ok(())
    }

    #[dbus_interface(property, name = "LogTarget")]
    fn log_target(&self) -> String {
        self.state.target()
    }

    #[dbus_interface(property, name = "LogTarget")]
    fn set_log_target(&mut self, target: &str) -> zbus::fdo::Result<()> {
        if !valid_log_target(target) {
            return Err(zbus::fdo::Error::InvalidArgs(format!(
                "Invalid log target '{target}'"
            )));
        }
        self.state.set_target(target);
        Ok(())
    }

    #[dbus_interface(property, name = "SyslogIdentifier")]
    fn syslog_identifier(&self) -> &str {
        "systemd-resolved"
    }
}

fn valid_log_level(level: &str) -> bool {
    matches!(
        level,
        "emerg" | "alert" | "crit" | "err" | "warning" | "notice" | "info" | "debug"
    )
}

fn valid_log_target(target: &str) -> bool {
    matches!(
        target,
        "console"
            | "console-prefixed"
            | "kmsg"
            | "journal"
            | "journal-or-kmsg"
            | "syslog"
            | "syslog-or-kmsg"
            | "auto"
            | "null"
    )
}

#[derive(Debug, zbus::DBusError)]
#[dbus_error(prefix = "org.freedesktop")]
enum DbusError {
    #[dbus_error(zbus_error)]
    ZBus(zbus::Error),
    #[dbus_error(name = "resolve1.NoNameServers")]
    NoNameServers(String),
    #[dbus_error(name = "resolve1.InvalidReply")]
    InvalidReply(String),
    #[dbus_error(name = "resolve1.CNameLoop")]
    CNameLoop(String),
    #[dbus_error(name = "resolve1.Aborted")]
    Aborted(String),
    #[dbus_error(name = "resolve1.NoSuchRR")]
    NoSuchResourceRecord(String),
    #[dbus_error(name = "resolve1.NoSuchService")]
    NoSuchService(String),
    #[dbus_error(name = "resolve1.InconsistentServiceRecords")]
    InconsistentServiceRecords(String),
    #[dbus_error(name = "resolve1.DnssecFailed")]
    DnssecFailed(String),
    #[dbus_error(name = "resolve1.NoTrustAnchor")]
    NoTrustAnchor(String),
    #[dbus_error(name = "resolve1.NoSuchDnssdService")]
    NoSuchDnssdService(String),
    #[dbus_error(name = "resolve1.NoSuchDelegate")]
    NoSuchDelegate(String),
    #[dbus_error(name = "resolve1.DnssdServiceExists")]
    DnssdServiceExists(String),
    #[dbus_error(name = "resolve1.ResourceRecordTypeUnsupported")]
    ResourceRecordTypeUnsupported(String),
    #[dbus_error(name = "resolve1.NoSuchLink")]
    NoSuchLink(String),
    #[dbus_error(name = "resolve1.LinkBusy")]
    LinkBusy(String),
    #[dbus_error(name = "resolve1.NetworkDown")]
    NetworkDown(String),
    #[dbus_error(name = "resolve1.NoSource")]
    NoSource(String),
    #[dbus_error(name = "resolve1.StubLoop")]
    StubLoop(String),
    #[dbus_error(name = "DBus.Error.InvalidArgs")]
    InvalidArgs(String),
    #[dbus_error(name = "DBus.Error.NotSupported")]
    NotSupported(String),
    #[dbus_error(name = "DBus.Error.Timeout")]
    Timeout(String),
    #[dbus_error(name = "DBus.Error.AccessDenied")]
    AccessDenied(String),
    #[dbus_error(name = "DBus.Error.InteractiveAuthorizationRequired")]
    InteractiveAuthorizationRequired(String),
    #[dbus_error(name = "resolve1.DnsError.FORMERR")]
    DnsFormErr(String),
    #[dbus_error(name = "resolve1.DnsError.SERVFAIL")]
    DnsServFail(String),
    #[dbus_error(name = "resolve1.DnsError.NXDOMAIN")]
    DnsNxDomain(String),
    #[dbus_error(name = "resolve1.DnsError.NOTIMP")]
    DnsNotImp(String),
    #[dbus_error(name = "resolve1.DnsError.REFUSED")]
    DnsRefused(String),
    #[dbus_error(name = "resolve1.DnsError.YXDOMAIN")]
    DnsYxDomain(String),
    #[dbus_error(name = "resolve1.DnsError.YRRSET")]
    DnsYrrset(String),
    #[dbus_error(name = "resolve1.DnsError.NXRRSET")]
    DnsNxrrset(String),
    #[dbus_error(name = "resolve1.DnsError.NOTAUTH")]
    DnsNotAuth(String),
    #[dbus_error(name = "resolve1.DnsError.NOTZONE")]
    DnsNotZone(String),
    #[dbus_error(name = "resolve1.DnsError.BADVERS")]
    DnsBadVers(String),
    #[dbus_error(name = "resolve1.DnsError.BADKEY")]
    DnsBadKey(String),
    #[dbus_error(name = "resolve1.DnsError.BADTIME")]
    DnsBadTime(String),
    #[dbus_error(name = "resolve1.DnsError.BADMODE")]
    DnsBadMode(String),
    #[dbus_error(name = "resolve1.DnsError.BADNAME")]
    DnsBadName(String),
    #[dbus_error(name = "resolve1.DnsError.BADALG")]
    DnsBadAlg(String),
    #[dbus_error(name = "resolve1.DnsError.BADTRUNC")]
    DnsBadTrunc(String),
    #[dbus_error(name = "resolve1.DnsError.BADCOOKIE")]
    DnsBadCookie(String),
}

impl From<DbusError> for zbus::fdo::Error {
    fn from(error: DbusError) -> Self {
        Self::Failed(error.to_string())
    }
}

#[derive(Debug)]
struct ManagerObject {
    resolver: Arc<Resolver>,
    authorization: Arc<DbusAuthorization>,
    client_queries: ClientQueryRegistry,
}

#[derive(Debug)]
struct RegisteredClientQuery {
    owner: String,
    cancellation: crate::query_cancel::QueryCancellation,
    registry: ClientQueryRegistry,
}

impl RegisteredClientQuery {
    fn new(header: &MessageHeader<'_>, registry: &ClientQueryRegistry) -> Result<Self, DbusError> {
        let owner = header
            .sender()
            .map_err(|error| DbusError::InvalidArgs(error.to_string()))?
            .ok_or_else(|| DbusError::InvalidArgs("D-Bus query has no sender".to_owned()))?
            .as_str()
            .to_owned();
        let cancellation = crate::query_cancel::QueryCancellation::default();
        registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(owner.clone())
            .or_default()
            .push(cancellation.clone());
        Ok(Self {
            owner,
            cancellation,
            registry: Arc::clone(registry),
        })
    }
}

impl Drop for RegisteredClientQuery {
    fn drop(&mut self) {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let remove_owner = if let Some(queries) = registry.get_mut(&self.owner) {
            queries.retain(|query| !query.same_as(&self.cancellation));
            queries.is_empty()
        } else {
            false
        };
        if remove_owner {
            registry.remove(&self.owner);
        }
    }
}

fn cancel_vanished_client_queries(
    bus: &zbus::blocking::fdo::DBusProxy<'_>,
    registry: &ClientQueryRegistry,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let owners = registry
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    for owner in owners {
        let name = zbus::names::BusName::try_from(owner.as_str())?;
        if !bus.name_has_owner(name)? {
            cancel_client_queries(registry, &owner);
        }
    }
    Ok(())
}

fn cancel_client_queries(registry: &ClientQueryRegistry, owner: &str) {
    let queries = registry
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(owner)
        .unwrap_or_default();
    for query in queries {
        query.cancel();
    }
}
