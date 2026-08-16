// SPDX-License-Identifier: LGPL-2.1-or-later
#[dbus_interface(name = "org.freedesktop.resolve1.Manager")]
impl ManagerObject {
    #[dbus_interface(out_args("addresses", "canonical", "flags"))]
    fn resolve_hostname(
        &self,
        ifindex: i32,
        name: &str,
        family: i32,
        flags: u64,
        #[zbus(header)] header: MessageHeader<'_>,
    ) -> Result<(Vec<(i32, i32, Vec<u8>)>, String, u64), DbusError> {
        validate_lookup_ifindex(ifindex)?;
        validate_family(family)?;
        if !crate::resolver::query_flags_are_valid(flags, SD_RESOLVED_NO_SEARCH) {
            return Err(DbusError::InvalidArgs("invalid flags parameter".to_owned()));
        }
        if crate::wire::make_query(name, TYPE_A, 0).is_err() {
            return Err(DbusError::InvalidArgs(format!(
                "invalid hostname '{name}'"
            )));
        }
        let query = RegisteredClientQuery::new(&header, &self.client_queries)?;
        let lookup = crate::query_cancel::with(query.cancellation.clone(), || {
            self.resolver
                .lookup_name_on_link_with_request_flags(
                    name,
                    family,
                    positive_ifindex(ifindex),
                    flags,
                )
                .map_err(map_resolve_error)
        })?;
        Ok(name_lookup_reply(lookup, ifindex))
    }

    #[dbus_interface(out_args("names", "flags"))]
    fn resolve_address(
        &self,
        ifindex: i32,
        family: i32,
        address: Vec<u8>,
        flags: u64,
        #[zbus(header)] header: MessageHeader<'_>,
    ) -> Result<(Vec<(i32, String)>, u64), DbusError> {
        validate_lookup_ifindex(ifindex)?;
        if !crate::resolver::query_flags_are_valid(flags, 0) {
            return Err(DbusError::InvalidArgs("invalid flags parameter".to_owned()));
        }
        let address = decode_address(family, &address)?;
        let query = RegisteredClientQuery::new(&header, &self.client_queries)?;
        let lookup = crate::query_cancel::with(query.cancellation.clone(), || {
            self.resolver
                .lookup_address_on_link_with_request_flags(
                    address,
                    positive_ifindex(ifindex),
                    flags,
                )
                .map_err(map_resolve_error)
        })?;
        Ok(address_lookup_reply(lookup, ifindex))
    }

    #[dbus_interface(out_args("records", "flags"))]
    fn resolve_record(
        &self,
        ifindex: i32,
        name: &str,
        class: u16,
        r#type: u16,
        flags: u64,
        #[zbus(header)] header: MessageHeader<'_>,
    ) -> Result<(Vec<(i32, u16, u16, Vec<u8>)>, u64), DbusError> {
        validate_lookup_ifindex(ifindex)?;
        if crate::wire::make_query(name, TYPE_A, 0).is_err() {
            return Err(DbusError::InvalidArgs(format!("invalid name '{name}'")));
        }
        if matches!(r#type, 0 | 41 | 46 | 249 | 250) {
            return Err(DbusError::InvalidArgs(format!(
                "resource record type {type} may not be used in a query",
                type = r#type
            )));
        }
        if matches!(r#type, 251 | 252) {
            return Err(DbusError::NotSupported(
                "zone transfers are not permitted".to_owned(),
            ));
        }
        if crate::wire::record_type_is_obsolete(r#type) {
            return Err(DbusError::NotSupported(format!(
                "DNS resource record type {type} is obsolete",
                type = r#type
            )));
        }
        if !crate::resolver::query_flags_are_valid(flags, SD_RESOLVED_NO_SEARCH) {
            return Err(DbusError::InvalidArgs("invalid flags parameter".to_owned()));
        }
        let query = RegisteredClientQuery::new(&header, &self.client_queries)?;
        let (response, response_flags, response_ifindex) =
            crate::query_cancel::with(query.cancellation.clone(), || {
                self.resolver
                    .resolve_record_on_link_with_request_flags_and_metadata(
                        name,
                        class,
                        r#type,
                        positive_ifindex(ifindex),
                        flags
                            | SD_RESOLVED_NO_SEARCH
                            | crate::dbus_resolve1_abi::flags::SD_RESOLVED_REQUIRE_PRIMARY
                            | crate::dbus_resolve1_abi::flags::SD_RESOLVED_CLAMP_TTL,
                    )
                    .map_err(map_resolve_error)
            })?;
        let records = extract_answer_records(&response)
            .map_err(|error| DbusError::InvalidReply(error.to_string()))?
            .into_iter()
            .map(|record| {
                (
                    response_ifindex.unwrap_or(ifindex).max(0),
                    record.class,
                    record.rr_type,
                    record.raw,
                )
            })
            .collect();
        Ok((records, response_flags))
    }

    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    #[dbus_interface(out_args(
        "srv_data",
        "txt_data",
        "canonical_name",
        "canonical_type",
        "canonical_domain",
        "flags"
    ))]
    fn resolve_service(
        &self,
        ifindex: i32,
        name: &str,
        r#type: &str,
        domain: &str,
        family: i32,
        flags: u64,
        #[zbus(header)] header: MessageHeader<'_>,
    ) -> Result<
        (
            Vec<(u16, u16, u16, String, Vec<(i32, i32, Vec<u8>)>, String)>,
            Vec<Vec<u8>>,
            String,
            String,
            String,
            u64,
        ),
        DbusError,
    > {
        validate_lookup_ifindex(ifindex)?;
        validate_family(family)?;
        let query = RegisteredClientQuery::new(&header, &self.client_queries)?;
        crate::query_cancel::with(query.cancellation.clone(), || {
            resolve_service_reply(&self.resolver, ifindex, name, r#type, domain, family, flags)
        })
    }

    #[dbus_interface(out_args("path"))]
    fn get_link(&self, ifindex: i32) -> Result<(OwnedObjectPath,), DbusError> {
        self.resolver.link(ifindex).ok_or_else(|| {
            DbusError::NoSuchLink(format!("no state exists for interface {ifindex}"))
        })?;
        Ok((link_object_path(ifindex)?,))
    }

    #[dbus_interface(name = "SetLinkDNS")]
    async fn set_link_dns(
        &self,
        ifindex: i32,
        addresses: Vec<(i32, Vec<u8>)>,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
        #[zbus(header)] header: MessageHeader<'_>,
    ) -> Result<(), DbusError> {
        let servers = decode_dns_servers(addresses, DNS_PORT)?;
        self.authorization.authorize(
            &header,
            "org.freedesktop.resolve1.set-dns-servers",
            interface_details(&self.resolver, ifindex),
        )?;
        self.resolver
            .set_link_dns(ifindex, servers)
            .map_err(map_link_error)?;
        ensure_link_object_registered(
            object_server,
            &self.resolver,
            &self.authorization,
            ifindex,
        )
        .await
    }

    #[dbus_interface(name = "SetLinkDNSEx")]
    async fn set_link_dns_ex(
        &self,
        ifindex: i32,
        addresses: Vec<(i32, Vec<u8>, u16, String)>,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
        #[zbus(header)] header: MessageHeader<'_>,
    ) -> Result<(), DbusError> {
        let servers = decode_dns_server_specs(addresses)?;
        self.authorization.authorize(
            &header,
            "org.freedesktop.resolve1.set-dns-servers",
            interface_details(&self.resolver, ifindex),
        )?;
        self.resolver
            .set_link_dns_specs(ifindex, servers)
            .map_err(map_link_error)?;
        ensure_link_object_registered(
            object_server,
            &self.resolver,
            &self.authorization,
            ifindex,
        )
        .await
    }

    async fn set_link_domains(
        &self,
        ifindex: i32,
        domains: Vec<(String, bool)>,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
        #[zbus(header)] header: MessageHeader<'_>,
    ) -> Result<(), DbusError> {
        self.authorization.authorize(
            &header,
            "org.freedesktop.resolve1.set-domains",
            interface_details(&self.resolver, ifindex),
        )?;
        self.resolver
            .set_link_domains(
                ifindex,
                domains
                    .into_iter()
                    .map(|(name, route_only)| Domain { name, route_only })
                    .collect(),
            )
            .map_err(map_link_error)?;
        ensure_link_object_registered(
            object_server,
            &self.resolver,
            &self.authorization,
            ifindex,
        )
        .await
    }

    async fn set_link_default_route(
        &self,
        ifindex: i32,
        enable: bool,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
        #[zbus(header)] header: MessageHeader<'_>,
    ) -> Result<(), DbusError> {
        self.authorization.authorize(
            &header,
            "org.freedesktop.resolve1.set-default-route",
            interface_details(&self.resolver, ifindex),
        )?;
        self.resolver
            .set_link_default_route(ifindex, Some(enable))
            .map_err(map_link_error)?;
        ensure_link_object_registered(
            object_server,
            &self.resolver,
            &self.authorization,
            ifindex,
        )
        .await
    }

    #[dbus_interface(name = "SetLinkLLMNR")]
    async fn set_link_llmnr(
        &self,
        ifindex: i32,
        mode: &str,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
        #[zbus(header)] header: MessageHeader<'_>,
    ) -> Result<(), DbusError> {
        let mode = parse_support_mode(mode)?;
        self.authorization.authorize(
            &header,
            "org.freedesktop.resolve1.set-llmnr",
            interface_details(&self.resolver, ifindex),
        )?;
        self.resolver
            .set_link_llmnr(ifindex, mode)
            .map_err(map_link_error)?;
        ensure_link_object_registered(
            object_server,
            &self.resolver,
            &self.authorization,
            ifindex,
        )
        .await
    }

    #[dbus_interface(name = "SetLinkMulticastDNS")]
    async fn set_link_multicast_dns(
        &self,
        ifindex: i32,
        mode: &str,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
        #[zbus(header)] header: MessageHeader<'_>,
    ) -> Result<(), DbusError> {
        let mode = parse_support_mode(mode)?;
        self.authorization.authorize(
            &header,
            "org.freedesktop.resolve1.set-mdns",
            interface_details(&self.resolver, ifindex),
        )?;
        self.resolver
            .set_link_multicast_dns(ifindex, mode)
            .map_err(map_link_error)?;
        ensure_link_object_registered(
            object_server,
            &self.resolver,
            &self.authorization,
            ifindex,
        )
        .await
    }

    #[dbus_interface(name = "SetLinkDNSOverTLS")]
    async fn set_link_dns_over_tls(
        &self,
        ifindex: i32,
        mode: &str,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
        #[zbus(header)] header: MessageHeader<'_>,
    ) -> Result<(), DbusError> {
        let mode = parse_tls_mode(mode)?;
        self.authorization.authorize(
            &header,
            "org.freedesktop.resolve1.set-dns-over-tls",
            interface_details(&self.resolver, ifindex),
        )?;
        self.resolver
            .set_link_dns_over_tls_override(ifindex, mode)
            .map_err(map_link_error)?;
        ensure_link_object_registered(
            object_server,
            &self.resolver,
            &self.authorization,
            ifindex,
        )
        .await
    }

    #[dbus_interface(name = "SetLinkDNSSEC")]
    async fn set_link_dnssec(
        &self,
        ifindex: i32,
        mode: &str,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
        #[zbus(header)] header: MessageHeader<'_>,
    ) -> Result<(), DbusError> {
        let mode = parse_validation_mode(mode)?;
        self.authorization.authorize(
            &header,
            "org.freedesktop.resolve1.set-dnssec",
            interface_details(&self.resolver, ifindex),
        )?;
        self.resolver
            .set_link_dnssec_override(ifindex, mode)
            .map_err(map_link_error)?;
        ensure_link_object_registered(
            object_server,
            &self.resolver,
            &self.authorization,
            ifindex,
        )
        .await
    }

    #[dbus_interface(name = "SetLinkDNSSECNegativeTrustAnchors")]
    async fn set_link_dnssec_negative_trust_anchors(
        &self,
        ifindex: i32,
        names: Vec<String>,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
        #[zbus(header)] header: MessageHeader<'_>,
    ) -> Result<(), DbusError> {
        self.authorization.authorize(
            &header,
            "org.freedesktop.resolve1.set-dnssec-negative-trust-anchors",
            interface_details(&self.resolver, ifindex),
        )?;
        self.resolver
            .set_link_dnssec_negative_trust_anchors(ifindex, names)
            .map_err(map_link_error)?;
        ensure_link_object_registered(
            object_server,
            &self.resolver,
            &self.authorization,
            ifindex,
        )
        .await
    }

    fn revert_link(
        &self,
        ifindex: i32,
        #[zbus(header)] header: MessageHeader<'_>,
    ) -> Result<(), DbusError> {
        self.authorization.authorize(
            &header,
            "org.freedesktop.resolve1.revert",
            interface_details(&self.resolver, ifindex),
        )?;
        self.resolver.revert_link(ifindex).map_err(map_link_error)
    }

    #[allow(clippy::too_many_arguments)]
    #[dbus_interface(out_args("service_path"))]
    fn register_service(
        &self,
        id: &str,
        name_template: &str,
        r#type: &str,
        service_port: u16,
        service_priority: u16,
        service_weight: u16,
        txt_datas: Vec<HashMap<String, Vec<u8>>>,
        #[zbus(header)] header: MessageHeader<'_>,
    ) -> Result<(OwnedObjectPath,), DbusError> {
        if self.resolver.config().multicast_dns != SupportMode::Yes {
            return Err(DbusError::NotSupported(
                "Support for MulticastDNS is disabled".to_owned(),
            ));
        }
        let owner = header
            .sender()
            .map_err(|error| DbusError::InvalidArgs(error.to_string()))?
            .ok_or_else(|| {
                DbusError::InvalidArgs("D-Bus service registration has no sender".to_owned())
            })?
            .as_str()
            .to_owned();
        let originator_uid = self.authorization.sender_uid(&owner)?;
        let spec = crate::mdns::dnssd_runtime::DynamicServiceSpec {
            id: id.to_owned(),
            name_template: name_template.to_owned(),
            service_type: r#type.to_owned(),
            port: service_port,
            priority: service_priority,
            weight: service_weight,
            txt_data: txt_datas,
        };
        crate::mdns::dnssd_runtime::validate_dynamic_registration(&spec)
            .map_err(|error| map_registration_error(error, id, r#type))?;
        self.authorization.authorize(
            &header,
            "org.freedesktop.resolve1.register-service",
            no_details(),
        )?;
        crate::mdns::dnssd_runtime::register_dynamic(spec, owner, originator_uid)
            .map_err(|error| map_registration_error(error, id, r#type))?;
        Ok((dnssd_object_path(id)?,))
    }

    fn unregister_service(
        &self,
        service_path: OwnedObjectPath,
        #[zbus(header)] header: MessageHeader<'_>,
    ) -> Result<(), DbusError> {
        let id = dnssd_id_from_path(&service_path)?;
        let originator_uid = crate::mdns::dnssd_runtime::dynamic_originator(&id)
            .ok_or_else(|| DbusError::NoSuchDnssdService(id.clone()))?;
        self.authorization.authorize_good_user(
            &header,
            "org.freedesktop.resolve1.unregister-service",
            no_details(),
            originator_uid,
        )?;
        crate::mdns::dnssd_runtime::unregister_dynamic(&id)
            .map_err(map_dynamic_service_error)
    }

    #[dbus_interface(out_args("path"))]
    fn get_delegate(&self, id: &str) -> Result<(OwnedObjectPath,), DbusError> {
        self.resolver
            .config()
            .dns_delegates
            .iter()
            .find(|delegate| delegate.id == id)
            .ok_or_else(|| DbusError::NoSuchDelegate(format!("Delegate '{id}' not known")))?;
        Ok((delegate_object_path(id)?,))
    }

    #[dbus_interface(out_args("delegates"))]
    fn list_delegates(&self) -> (Vec<(String, OwnedObjectPath)>,) {
        (
            self.resolver
                .config()
                .dns_delegates
                .iter()
                .filter_map(|delegate| {
                    delegate_object_path(&delegate.id)
                        .ok()
                        .map(|path| (delegate.id.clone(), path))
                })
                .collect(),
        )
    }

    fn reset_statistics(
        &self,
        #[zbus(header)] header: MessageHeader<'_>,
    ) -> Result<(), DbusError> {
        self.authorization.authorize(
            &header,
            "org.freedesktop.resolve1.reset-statistics",
            no_details(),
        )?;
        self.resolver.reset_statistics();
        Ok(())
    }

    fn flush_caches(&self, #[zbus(header)] header: MessageHeader<'_>) -> Result<(), DbusError> {
        self.authorization.authorize(
            &header,
            "org.freedesktop.resolve1.flush-caches",
            no_details(),
        )?;
        self.resolver.flush_cache();
        Ok(())
    }

    fn reset_server_features(
        &self,
        #[zbus(header)] header: MessageHeader<'_>,
    ) -> Result<(), DbusError> {
        self.authorization.authorize(
            &header,
            "org.freedesktop.resolve1.reset-server-features",
            no_details(),
        )?;
        self.resolver.reset_server_features();
        Ok(())
    }

    #[dbus_interface(property, name = "LLMNRHostname")]
    fn llmnr_hostname(&self) -> String {
        crate::native::kernel_hostname().unwrap_or_else(|| "localhost".to_owned())
    }

    #[dbus_interface(property, name = "LLMNR")]
    fn llmnr(&self) -> String {
        support_mode_string(self.resolver.global_llmnr_mode()).to_owned()
    }

    #[dbus_interface(property, name = "MulticastDNS")]
    fn multicast_dns(&self) -> String {
        support_mode_string(self.resolver.global_multicast_dns_mode()).to_owned()
    }

    #[dbus_interface(property, name = "DNSOverTLS")]
    fn dns_over_tls(&self) -> String {
        tls_mode_string(self.resolver.config().dns_over_tls).to_owned()
    }

    #[dbus_interface(property, name = "DNS")]
    fn dns(&self) -> Vec<(i32, i32, Vec<u8>)> {
        manager_dns(&self.resolver.config().configured_upstreams(), 0)
    }

    #[dbus_interface(property, name = "DNSEx")]
    fn dns_ex(&self) -> Vec<(i32, i32, Vec<u8>, u16, String)> {
        manager_dns_ex(&self.resolver.config().configured_upstream_specs(), 0)
    }

    #[dbus_interface(property, name = "FallbackDNS")]
    fn fallback_dns(&self) -> Vec<(i32, i32, Vec<u8>)> {
        manager_dns(&self.resolver.config().configured_fallback_upstreams(), 0)
    }

    #[dbus_interface(property, name = "FallbackDNSEx")]
    fn fallback_dns_ex(&self) -> Vec<(i32, i32, Vec<u8>, u16, String)> {
        manager_dns_ex(&self.resolver.config().configured_fallback_upstream_specs(), 0)
    }

    #[dbus_interface(property, name = "CurrentDNSServer")]
    fn current_dns_server(&self) -> (i32, i32, Vec<u8>) {
        self.resolver
            .config()
            .effective_upstreams()
            .first()
            .map_or((0, AF_UNSPEC, Vec::new()), |server| {
                manager_dns_entry(0, *server)
            })
    }

    #[dbus_interface(property, name = "CurrentDNSServerEx")]
    fn current_dns_server_ex(&self) -> (i32, i32, Vec<u8>, u16, String) {
        self.resolver
            .config()
            .effective_upstream_specs()
            .first()
            .map_or((0, AF_UNSPEC, Vec::new(), 0, String::new()), |server| {
                manager_dns_ex_entry(0, server)
            })
    }

    #[dbus_interface(property, name = "Domains")]
    fn domains(&self) -> Vec<(i32, String, bool)> {
        let mut domains = self
            .resolver
            .config()
            .domains
            .iter()
            .map(|domain| (0, domain.name.clone(), domain.route_only))
            .collect::<Vec<_>>();
        for link in self.resolver.links() {
            domains.extend(
                link.domains
                    .into_iter()
                    .map(|domain| (link.ifindex, domain.name, domain.route_only)),
            );
        }
        domains
    }

    #[dbus_interface(property, name = "TransactionStatistics")]
    fn transaction_statistics(&self) -> (u64, u64) {
        let statistics = self.resolver.stats();
        (statistics.current_transactions, statistics.transactions)
    }

    #[dbus_interface(property, name = "CacheStatistics")]
    fn cache_statistics(&self) -> (u64, u64, u64) {
        let stats = self.resolver.stats();
        (
            u64::try_from(stats.cache_entries).unwrap_or(u64::MAX),
            stats.cache_hits,
            stats.cache_misses,
        )
    }

    #[dbus_interface(property, name = "DNSSEC")]
    fn dnssec(&self) -> String {
        validation_mode_string(self.resolver.config().dnssec).to_owned()
    }

    #[dbus_interface(property, name = "DNSSECStatistics")]
    fn dnssec_statistics(&self) -> (u64, u64, u64, u64) {
        let statistics = self.resolver.stats();
        (
            statistics.dnssec_secure,
            statistics.dnssec_insecure,
            statistics.dnssec_bogus,
            statistics.dnssec_indeterminate,
        )
    }

    #[dbus_interface(property, name = "DNSSECSupported")]
    fn dnssec_supported(&self) -> bool {
        self.resolver.manager_dnssec_supported()
    }

    #[dbus_interface(property, name = "DNSSECNegativeTrustAnchors")]
    fn dnssec_negative_trust_anchors(&self) -> Vec<String> {
        self.resolver.dnssec_negative_trust_anchors()
    }

    #[dbus_interface(property, name = "DNSStubListener")]
    fn dns_stub_listener(&self) -> String {
        self.resolver.config().dns_stub_listener.as_str().to_owned()
    }

    #[dbus_interface(property, name = "ResolvConfMode")]
    fn resolv_conf_mode(&self) -> String {
        let config = self.resolver.config();
        crate::resolvconf_publish::system_resolv_conf_mode(&config.runtime_directory)
            .unwrap_or(crate::resolvconf_publish::ResolvConfMode::Foreign)
            .as_str()
            .to_owned()
    }
}
