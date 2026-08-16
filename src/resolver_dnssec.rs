const DNSSEC_TRUST_ANCHOR_DIRECTORIES: &[&str] = &[
    "/etc/dnssec-trust-anchors.d",
    "/run/dnssec-trust-anchors.d",
    "/usr/local/lib/dnssec-trust-anchors.d",
    "/usr/lib/dnssec-trust-anchors.d",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PositiveTrustAnchor {
    pub(crate) owner: String,
    pub(crate) data: PositiveTrustAnchorData,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PositiveTrustAnchorData {
    Ds {
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: Vec<u8>,
    },
    Dnskey(Vec<u8>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DnssecVerdict {
    Secure,
    Insecure,
    NotValidated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DnssecDenialResult {
    Found,
    Cname,
    NoData,
    NxDomain,
    OptOut,
    Missing,
}

impl Resolver {
    pub fn dnssec_negative_trust_anchors(&self) -> Vec<String> {
        let mut anchors = load_negative_trust_anchors();
        anchors.sort();
        anchors.dedup();
        anchors
    }

    fn authenticate_dns_response(
        &self,
        server: ServerKey,
        query: &[u8],
        response: &mut Vec<u8>,
        request_flags: u64,
        budget: &mut DnsAttemptBudget,
    ) -> Result<DnssecVerdict, ResolveError> {
        wire::set_authenticated_data(response, false)?;
        let mode = self.server_dnssec_mode(server);
        if mode == ValidationMode::No
            || Header::parse(query)?.checking_disabled()
            || request_flags & crate::dbus_resolve1_abi::flags::SD_RESOLVED_NO_VALIDATE != 0
            || self
                .dnssec_name_has_negative_trust_anchor(server, first_question(query)?.name.text())
        {
            return Ok(DnssecVerdict::NotValidated);
        }

        let anchors =
            if request_flags & crate::dbus_resolve1_abi::flags::SD_RESOLVED_NO_TRUST_ANCHOR != 0 {
                Vec::new()
            } else {
                load_positive_trust_anchors()
            };
        if anchors.is_empty() {
            return if mode == ValidationMode::Yes {
                Err(ResolveError::NoTrustAnchor)
            } else {
                Ok(DnssecVerdict::Insecure)
            };
        }

        let (_, _, records, end) = wire::parse_sections(response)?;
        if end != response.len() {
            return Err(WireError::TrailingData.into());
        }
        let header = Header::parse(response)?;
        let authenticated_record_count =
            usize::from(header.answer_count) + usize::from(header.authority_count);
        let authenticated_records = &records[..authenticated_record_count];
        let rrsets = substantive_rrsets(response, authenticated_records)?;
        if rrsets.is_empty() {
            return if mode == ValidationMode::Yes {
                Err(dnssec_validation_error(
                    "DNSSEC response contains no authenticated records",
                ))
            } else {
                Ok(DnssecVerdict::Insecure)
            };
        }

        let mut saw_secure = false;
        let mut trusted_key_cache = HashMap::<String, Option<Vec<wire::ResourceRecord>>>::new();
        for (owner, rr_type, class) in rrsets {
            let rrset = matching_rrset(authenticated_records, &owner, rr_type, class);
            let signatures =
                matching_signatures(response, authenticated_records, &owner, rr_type, class)?;
            if signatures.is_empty() {
                return if mode == ValidationMode::Yes {
                    Err(dnssec_validation_error("DNSSEC signature is missing"))
                } else {
                    Ok(DnssecVerdict::Insecure)
                };
            }

            let mut verified = false;
            let mut chain_was_insecure = false;
            for signature in signatures {
                let parsed = wire::parse_rrsig(response, signature)?;
                let signer = normalize_dns_name(parsed.signer.text());
                let keys = if let Some(keys) = trusted_key_cache.get(&signer) {
                    keys.clone()
                } else {
                    let keys = self.trusted_dnskeys(server, &signer, &anchors, budget)?;
                    trusted_key_cache.insert(signer.clone(), keys.clone());
                    keys
                };
                match keys {
                    Some(keys) => {
                        if verify_rrset_with_keys(response, signature, &rrset, &keys)? {
                            verified = true;
                            break;
                        }
                    }
                    None => chain_was_insecure = true,
                }
            }
            if !verified {
                if chain_was_insecure {
                    return Ok(DnssecVerdict::Insecure);
                }
                return Err(dnssec_validation_error("signature verification failed"));
            }
            saw_secure = true;
        }

        if saw_secure {
            match authenticated_response_semantics(query, response, authenticated_records)? {
                DnssecVerdict::Secure => {
                    wire::set_authenticated_data(response, true)?;
                    Ok(DnssecVerdict::Secure)
                }
                DnssecVerdict::Insecure => Ok(DnssecVerdict::Insecure),
                DnssecVerdict::NotValidated => Ok(DnssecVerdict::NotValidated),
            }
        } else {
            Ok(DnssecVerdict::Insecure)
        }
    }

    fn record_dnssec_verdict(&self, verdict: DnssecVerdict) {
        let counter = match verdict {
            DnssecVerdict::Secure => &self.counters.dnssec_secure,
            DnssecVerdict::Insecure => &self.counters.dnssec_insecure,
            DnssecVerdict::NotValidated => return,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn record_dnssec_error(&self, error: &ResolveError) {
        let counter = match error {
            ResolveError::NoTrustAnchor => &self.counters.dnssec_indeterminate,
            ResolveError::DnssecValidationFailed { .. } | ResolveError::Wire(_) => {
                &self.counters.dnssec_bogus
            }
            _ => return,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn trusted_dnskeys(
        &self,
        server: ServerKey,
        zone: &str,
        anchors: &[PositiveTrustAnchor],
        budget: &mut DnsAttemptBudget,
    ) -> Result<Option<Vec<wire::ResourceRecord>>, ResolveError> {
        if let Some(keys) = self.cached_trusted_dnskeys(server, zone) {
            return Ok(Some(keys));
        }
        let zones = dns_name_ancestors(zone);
        let Some(anchor_index) = zones.iter().enumerate().rev().find_map(|(index, owner)| {
            anchors
                .iter()
                .any(|anchor| dns_names_equal(&anchor.owner, owner))
                .then_some(index)
        }) else {
            return Ok(None);
        };
        let anchor_set = anchors
            .iter()
            .filter(|anchor| dns_names_equal(&anchor.owner, &zones[anchor_index]))
            .collect::<Vec<_>>();

        let anchor_packet =
            self.dnssec_fetch(server, &zones[anchor_index], wire::TYPE_DNSKEY, budget)?;
        let anchor_keys = records_of_type(&anchor_packet, &zones[anchor_index], wire::TYPE_DNSKEY)?;
        let anchor_signing_keys = anchor_keys
            .iter()
            .filter(|key| {
                anchor_set
                    .iter()
                    .any(|anchor| trust_anchor_matches_dnskey(anchor, key).unwrap_or(false))
            })
            .cloned()
            .collect::<Vec<_>>();
        if anchor_signing_keys.is_empty()
            || !verify_packet_rrset(
                &anchor_packet,
                &zones[anchor_index],
                wire::TYPE_DNSKEY,
                &anchor_signing_keys,
            )?
        {
            return Err(dnssec_validation_error(
                "trust anchor DNSKEY validation failed",
            ));
        }
        let mut trusted = authenticated_zone_signing_keys(&anchor_keys)?;
        if trusted.is_empty() {
            return Err(dnssec_validation_error(
                "authenticated DNSKEY RRset contains no usable zone keys",
            ));
        }
        let mut trusted_packet = anchor_packet;
        for child in zones.iter().skip(anchor_index + 1) {
            let ds_packet = self.dnssec_fetch(server, child, wire::TYPE_DS, budget)?;
            let ds_records = records_of_type(&ds_packet, child, wire::TYPE_DS)?;
            if ds_records.is_empty() {
                let denied = authenticated_ds_denial(&ds_packet, child, &trusted)?;
                let ns_packet = self.dnssec_fetch(server, child, wire::TYPE_NS, budget)?;
                if records_of_type(&ns_packet, child, wire::TYPE_NS)?.is_empty() {
                    continue;
                }
                if denied {
                    return Ok(None);
                }
                return Err(dnssec_validation_error("unsigned DNSSEC delegation denial"));
            }
            if !verify_packet_rrset(&ds_packet, child, wire::TYPE_DS, &trusted)? {
                return Err(dnssec_validation_error("DS RRset validation failed"));
            }

            let key_packet = self.dnssec_fetch(server, child, wire::TYPE_DNSKEY, budget)?;
            let keys = records_of_type(&key_packet, child, wire::TYPE_DNSKEY)?;
            if keys.is_empty() {
                return Err(dnssec_validation_error(
                    "delegated DNSKEY validation failed",
                ));
            }
            let valid_signing_keys: Vec<_> = keys
                .iter()
                .filter(|key| {
                    ds_records
                        .iter()
                        .any(|ds| crate::dnssec::ds_matches_dnskey(ds, key).unwrap_or(false))
                })
                .cloned()
                .collect();
            if valid_signing_keys.is_empty()
                || !verify_packet_rrset(&key_packet, child, wire::TYPE_DNSKEY, &valid_signing_keys)?
            {
                return Err(dnssec_validation_error(
                    "delegated DNSKEY validation failed",
                ));
            }
            trusted = authenticated_zone_signing_keys(&keys)?;
            if trusted.is_empty() {
                return Err(dnssec_validation_error(
                    "authenticated DNSKEY RRset contains no usable zone keys",
                ));
            }
            trusted_packet = key_packet;
        }
        self.cache_trusted_dnskeys(server, zone, &trusted_packet, &trusted)?;
        Ok(Some(trusted))
    }

    fn cached_trusted_dnskeys(
        &self,
        server: ServerKey,
        zone: &str,
    ) -> Option<Vec<wire::ResourceRecord>> {
        let key = DnskeyCacheKey {
            server,
            zone: normalize_dns_name(zone),
        };
        let mut cache = self
            .dnskey_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if cache
            .get(&key)
            .is_some_and(|entry| entry.expires <= Instant::now())
        {
            cache.remove(&key);
        }
        cache.get(&key).map(|entry| entry.keys.clone())
    }

    fn cache_trusted_dnskeys(
        &self,
        server: ServerKey,
        zone: &str,
        packet: &[u8],
        keys: &[wire::ResourceRecord],
    ) -> Result<(), ResolveError> {
        let lifetime = dnskey_cache_lifetime(packet, zone)?.min(self.config().cache_max_ttl);
        if lifetime.is_zero() {
            return Ok(());
        }
        let now = Instant::now();
        let Some(expires) = now.checked_add(lifetime) else {
            return Ok(());
        };
        self.dnskey_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                DnskeyCacheKey {
                    server,
                    zone: normalize_dns_name(zone),
                },
                DnskeyCacheEntry {
                    keys: keys.to_vec(),
                    expires,
                },
            );
        Ok(())
    }

    fn dnssec_fetch(
        &self,
        server: ServerKey,
        name: &str,
        rr_type: u16,
        budget: &mut DnsAttemptBudget,
    ) -> Result<Vec<u8>, ResolveError> {
        let query = make_query_with_class(name, rr_type, wire::CLASS_IN, self.transaction_id())?;
        let response = self.exchange_with_features(server, &query, budget)?;
        if std::env::var_os("RUSTD_RESOLVED_QUERY_DIAGNOSTICS").is_some() {
            eprintln!(
                "rustd-resolved: DNSSEC fetch {name} type {rr_type} from {}: {}",
                server.server(),
                dns_packet_hex(&response)
            );
        }
        Ok(response)
    }

    fn dnssec_name_has_negative_trust_anchor(&self, server: ServerKey, name: &str) -> bool {
        let mut anchors = self.dnssec_negative_trust_anchors();
        if let ScopeKind::Link(ifindex) = server.scope_kind() {
            if let Some(link) = self.routing().link(ifindex) {
                anchors.extend(link.dnssec_negative_trust_anchors.iter().cloned());
            }
        }
        negative_trust_anchor_matches(name, &anchors, &load_positive_trust_anchors())
    }
}

fn negative_trust_anchor_matches(
    name: &str,
    negative: &[String],
    positive: &[PositiveTrustAnchor],
) -> bool {
    for ancestor in dns_name_ancestors(name).into_iter().rev() {
        if negative
            .iter()
            .any(|anchor| dns_names_equal(anchor, &ancestor))
        {
            return true;
        }
        if positive
            .iter()
            .any(|anchor| dns_names_equal(&anchor.owner, &ancestor))
        {
            return false;
        }
    }
    false
}

fn dns_packet_hex(packet: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(packet.len().saturating_mul(2));
    for byte in packet {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn dnssec_validation_error(result: &str) -> ResolveError {
    ResolveError::DnssecValidationFailed {
        result: result.to_owned(),
        extended_dns_error_code: None,
        extended_dns_error_message: None,
    }
}

fn substantive_rrsets(
    packet: &[u8],
    records: &[wire::ResourceRecord],
) -> Result<Vec<(Vec<u8>, u16, u16)>, ResolveError> {
    let mut output = Vec::new();
    for record in records {
        if matches!(
            record.rr_type,
            wire::TYPE_RRSIG | wire::TYPE_OPT | wire::TYPE_TSIG
        ) {
            continue;
        }
        if record.rr_type == wire::TYPE_CNAME
            && cname_is_synthesized_from_dname(packet, record, records)?
        {
            continue;
        }
        let key = (
            record.name.canonical_wire().to_vec(),
            record.rr_type,
            record.class,
        );
        if !output.contains(&key) {
            output.push(key);
        }
    }
    Ok(output)
}

fn cname_is_synthesized_from_dname(
    packet: &[u8],
    cname: &wire::ResourceRecord,
    records: &[wire::ResourceRecord],
) -> Result<bool, ResolveError> {
    let (cname_target, end) = wire::read_name(packet, cname.rdata_offset)?;
    if end != cname.next_offset {
        return Err(WireError::InvalidRecord.into());
    }
    let mut covering = records
        .iter()
        .filter(|record| {
            record.rr_type == wire::TYPE_DNAME
                && record.class == cname.class
                && record.name.canonical_wire() != cname.name.canonical_wire()
                && cname
                    .name
                    .canonical_wire()
                    .ends_with(record.name.canonical_wire())
        })
        .collect::<Vec<_>>();
    covering.sort_by_key(|record| std::cmp::Reverse(record.name.canonical_wire().len()));
    for dname in covering {
        let (dname_target, end) = wire::read_name(packet, dname.rdata_offset)?;
        if end != dname.next_offset {
            return Err(WireError::InvalidRecord.into());
        }
        let prefix_length = cname.name.canonical_wire().len() - dname.name.canonical_wire().len();
        let mut synthesized = cname.name.canonical_wire()[..prefix_length].to_vec();
        synthesized.extend_from_slice(dname_target.canonical_wire());
        if synthesized.len() <= 255 && synthesized == cname_target.canonical_wire() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn matching_rrset(
    records: &[wire::ResourceRecord],
    owner: &[u8],
    rr_type: u16,
    class: u16,
) -> Vec<wire::ResourceRecord> {
    records
        .iter()
        .filter(|record| {
            record.name.canonical_wire() == owner
                && record.rr_type == rr_type
                && record.class == class
        })
        .cloned()
        .collect()
}

fn matching_signatures<'a>(
    packet: &[u8],
    records: &'a [wire::ResourceRecord],
    owner: &[u8],
    rr_type: u16,
    class: u16,
) -> Result<Vec<&'a wire::ResourceRecord>, ResolveError> {
    let mut output = Vec::new();
    for record in records.iter().filter(|record| {
        record.name.canonical_wire() == owner
            && record.rr_type == wire::TYPE_RRSIG
            && record.class == class
    }) {
        if wire::parse_rrsig(packet, record)?.type_covered == rr_type {
            output.push(record);
        }
    }
    Ok(output)
}

pub(crate) fn records_of_type(
    packet: &[u8],
    owner: &str,
    rr_type: u16,
) -> Result<Vec<wire::ResourceRecord>, ResolveError> {
    let (_, _, records, end) = wire::parse_sections(packet)?;
    if end != packet.len() {
        return Err(WireError::TrailingData.into());
    }
    Ok(records
        .into_iter()
        .filter(|record| record.rr_type == rr_type && dns_names_equal(record.name.text(), owner))
        .collect())
}

pub(crate) fn verify_packet_rrset(
    packet: &[u8],
    owner: &str,
    rr_type: u16,
    keys: &[wire::ResourceRecord],
) -> Result<bool, ResolveError> {
    let (_, _, records, end) = wire::parse_sections(packet)?;
    if end != packet.len() {
        return Err(WireError::TrailingData.into());
    }
    let Some(first) = records
        .iter()
        .find(|record| record.rr_type == rr_type && dns_names_equal(record.name.text(), owner))
    else {
        return Ok(false);
    };
    let rrset = matching_rrset(&records, first.name.canonical_wire(), rr_type, first.class);
    for signature in matching_signatures(
        packet,
        &records,
        first.name.canonical_wire(),
        rr_type,
        first.class,
    )? {
        if verify_rrset_with_keys(packet, signature, &rrset, keys)? {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn verify_rrset_with_keys(
    packet: &[u8],
    signature: &wire::ResourceRecord,
    rrset: &[wire::ResourceRecord],
    keys: &[wire::ResourceRecord],
) -> Result<bool, ResolveError> {
    for key in keys {
        match crate::dnssec::verify_rrsig(
            packet,
            signature,
            rrset,
            key,
            std::time::SystemTime::now(),
        ) {
            Ok(true) => return Ok(true),
            Ok(false) => {}
            Err(error) => return Err(dnssec_validation_error(&error.to_string())),
        }
    }
    Ok(false)
}

pub(crate) fn authenticated_zone_signing_keys(
    keys: &[wire::ResourceRecord],
) -> Result<Vec<wire::ResourceRecord>, ResolveError> {
    const DNSKEY_FLAG_REVOKE: u16 = 1 << 7;
    const DNSKEY_FLAG_ZONE_KEY: u16 = 1 << 8;

    let mut trusted = Vec::new();
    for key in keys {
        let parsed = wire::parse_dnskey(key)?;
        if parsed.flags & DNSKEY_FLAG_ZONE_KEY != 0 && parsed.flags & DNSKEY_FLAG_REVOKE == 0 {
            trusted.push(key.clone());
        }
    }
    Ok(trusted)
}

fn dnskey_cache_lifetime(packet: &[u8], zone: &str) -> Result<Duration, ResolveError> {
    let (_, _, records, end) = wire::parse_sections(packet)?;
    if end != packet.len() {
        return Err(WireError::TrailingData.into());
    }
    let Some(ttl) = records
        .iter()
        .filter(|record| {
            record.rr_type == wire::TYPE_DNSKEY && dns_names_equal(record.name.text(), zone)
        })
        .map(|record| record.ttl)
        .min()
    else {
        return Ok(Duration::ZERO);
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut lifetime = Duration::from_secs(u64::from(ttl));
    let mut saw_signature = false;
    for signature in records.iter().filter(|record| {
        record.rr_type == wire::TYPE_RRSIG && dns_names_equal(record.name.text(), zone)
    }) {
        let parsed = wire::parse_rrsig(packet, signature)?;
        if parsed.type_covered != wire::TYPE_DNSKEY {
            continue;
        }
        saw_signature = true;
        lifetime = lifetime.min(Duration::from_secs(
            u64::from(parsed.expiration).saturating_sub(now),
        ));
        lifetime = lifetime.min(Duration::from_secs(u64::from(parsed.original_ttl)));
    }
    Ok(if saw_signature {
        lifetime
    } else {
        Duration::ZERO
    })
}

pub(crate) fn authenticated_response_semantics(
    query: &[u8],
    response: &[u8],
    records: &[wire::ResourceRecord],
) -> Result<DnssecVerdict, ResolveError> {
    let question = first_question(query)?;
    let header = Header::parse(response)?;
    let answers = &records[..usize::from(header.answer_count)];
    let terminal_name = terminal_cname(response, answers, question.name.text())?;
    let has_redirect = !dns_names_equal(&terminal_name, question.name.text());
    let has_requested_answer = if question.rr_type == 255 {
        answers
            .iter()
            .any(|record| !matches!(record.rr_type, wire::TYPE_RRSIG | wire::TYPE_OPT))
    } else {
        answers
            .iter()
            .any(|record| record.rr_type == question.rr_type)
    };

    if header.response_code() == 3
        || (header.response_code() == 0 && !has_requested_answer && !has_redirect)
    {
        let denial = dnssec_denial_result(response, records, &terminal_name, question.rr_type)?;
        return match (header.response_code(), denial) {
            (3, DnssecDenialResult::NxDomain) | (0, DnssecDenialResult::NoData) => {
                Ok(DnssecVerdict::Secure)
            }
            (_, DnssecDenialResult::OptOut) => Ok(DnssecVerdict::Insecure),
            (3, _) => Err(dnssec_validation_error("DNSSEC NXDOMAIN proof is missing")),
            (0, _) => Err(dnssec_validation_error("DNSSEC NODATA proof is missing")),
            _ => unreachable!(),
        };
    }

    for signature in answers
        .iter()
        .filter(|record| record.rr_type == wire::TYPE_RRSIG)
    {
        let parsed = wire::parse_rrsig(response, signature)?;
        let owner_labels = dns_name_label_count(signature.name.canonical_wire())?;
        if usize::from(parsed.labels) < owner_labels
            && !wildcard_expansion_is_proven(
                response,
                records,
                signature.name.text(),
                usize::from(parsed.labels),
            )?
        {
            return Err(dnssec_validation_error(
                "DNSSEC wildcard closest-encloser proof is missing",
            ));
        }
    }
    Ok(DnssecVerdict::Secure)
}

fn terminal_cname(
    packet: &[u8],
    answers: &[wire::ResourceRecord],
    initial: &str,
) -> Result<String, ResolveError> {
    let mut current = normalize_dns_name(initial);
    let mut visited = HashSet::new();
    for _ in 0..64 {
        if !visited.insert(current.clone()) {
            return Err(WireError::CnameLoop.into());
        }
        let Some(record) = answers.iter().find(|record| {
            record.rr_type == wire::TYPE_CNAME && dns_names_equal(record.name.text(), &current)
        }) else {
            return Ok(current);
        };
        let (target, end) = wire::read_name(packet, record.rdata_offset)?;
        if end != record.next_offset {
            return Err(WireError::InvalidRecord.into());
        }
        current = normalize_dns_name(target.text());
    }
    Err(WireError::CnameLoop.into())
}

fn dnssec_denial_result(
    packet: &[u8],
    records: &[wire::ResourceRecord],
    name: &str,
    rr_type: u16,
) -> Result<DnssecDenialResult, ResolveError> {
    let nsec = nsec_denial_result(packet, records, name, rr_type)?;
    if nsec != DnssecDenialResult::Missing {
        return Ok(nsec);
    }
    nsec3_denial_result(records, name, rr_type)
}

fn nsec_denial_result(
    packet: &[u8],
    records: &[wire::ResourceRecord],
    name: &str,
    rr_type: u16,
) -> Result<DnssecDenialResult, ResolveError> {
    let nsec_records = records
        .iter()
        .filter(|record| record.rr_type == wire::TYPE_NSEC)
        .collect::<Vec<_>>();
    if nsec_records.is_empty() {
        return Ok(DnssecDenialResult::Missing);
    }

    for record in &nsec_records {
        if !dns_names_equal(record.name.text(), name) {
            continue;
        }
        let nsec = wire::parse_nsec(packet, record)?;
        if rr_type == wire::TYPE_DS && nsec.types.contains(&wire::TYPE_SOA) {
            continue;
        }
        if rr_type != wire::TYPE_DS
            && nsec.types.contains(&wire::TYPE_NS)
            && !nsec.types.contains(&wire::TYPE_SOA)
        {
            continue;
        }
        return Ok(if nsec.types.contains(&rr_type) {
            DnssecDenialResult::Found
        } else if nsec.types.contains(&wire::TYPE_CNAME) {
            DnssecDenialResult::Cname
        } else {
            DnssecDenialResult::NoData
        });
    }

    if nsec_records
        .iter()
        .any(|record| nsec_proves_empty_nonterminal(packet, record, name).unwrap_or(false))
    {
        return Ok(DnssecDenialResult::NoData);
    }

    let Some(covering) = nsec_records
        .iter()
        .copied()
        .find(|record| nsec_covers_name(packet, record, name).unwrap_or(false))
    else {
        return Ok(DnssecDenialResult::Missing);
    };
    let closest = closest_existing_ancestor(records, name).unwrap_or_else(|| {
        wire::parse_nsec(packet, covering)
            .ok()
            .and_then(|nsec| dns_name_parent(nsec.next_domain.text()))
            .unwrap_or_else(|| ".".to_owned())
    });
    let wildcard = if closest == "." {
        "*".to_owned()
    } else {
        format!("*.{closest}")
    };

    if let Some(record) = nsec_records
        .iter()
        .copied()
        .find(|record| dns_record_name_equal(record, &wildcard))
    {
        let nsec = wire::parse_nsec(packet, record)?;
        return Ok(if nsec.types.contains(&rr_type) {
            DnssecDenialResult::Found
        } else if nsec.types.contains(&wire::TYPE_CNAME) {
            DnssecDenialResult::Cname
        } else {
            DnssecDenialResult::NoData
        });
    }
    if nsec_records
        .iter()
        .any(|record| nsec_covers_name(packet, record, &wildcard).unwrap_or(false))
    {
        Ok(DnssecDenialResult::NxDomain)
    } else {
        Ok(DnssecDenialResult::Missing)
    }
}

fn dns_record_name_equal(record: &wire::ResourceRecord, name: &str) -> bool {
    wire::encode_name(&normalize_dns_name(name))
        .is_ok_and(|wire_name| record.name.canonical_wire() == wire_name.as_slice())
}

fn nsec_covers_name(
    packet: &[u8],
    record: &wire::ResourceRecord,
    name: &str,
) -> Result<bool, ResolveError> {
    let nsec = wire::parse_nsec(packet, record)?;
    let name = wire::encode_name(&normalize_dns_name(name))?;
    Ok(canonical_name_interval_covers(
        record.name.canonical_wire(),
        nsec.next_domain.canonical_wire(),
        &name,
    )?)
}

fn canonical_name_interval_covers(
    owner: &[u8],
    next: &[u8],
    name: &[u8],
) -> Result<bool, ResolveError> {
    let owner_to_next = canonical_dns_name_cmp(owner, next)?;
    let owner_to_name = canonical_dns_name_cmp(owner, name)?;
    let name_to_next = canonical_dns_name_cmp(name, next)?;
    Ok(match owner_to_next {
        std::cmp::Ordering::Less => {
            owner_to_name == std::cmp::Ordering::Less && name_to_next == std::cmp::Ordering::Less
        }
        std::cmp::Ordering::Greater => {
            owner_to_name == std::cmp::Ordering::Less || name_to_next == std::cmp::Ordering::Less
        }
        std::cmp::Ordering::Equal => owner_to_name != std::cmp::Ordering::Equal,
    })
}

fn canonical_dns_name_cmp(left: &[u8], right: &[u8]) -> Result<std::cmp::Ordering, ResolveError> {
    let left = dns_wire_labels(left)?;
    let right = dns_wire_labels(right)?;
    for (left, right) in left.iter().rev().zip(right.iter().rev()) {
        let order = left.cmp(right);
        if order != std::cmp::Ordering::Equal {
            return Ok(order);
        }
    }
    Ok(left.len().cmp(&right.len()))
}

fn dns_wire_labels(name: &[u8]) -> Result<Vec<&[u8]>, ResolveError> {
    let mut labels = Vec::new();
    let mut offset = 0;
    loop {
        let length = usize::from(
            *name
                .get(offset)
                .ok_or(WireError::InvalidName("truncated wire name".to_owned()))?,
        );
        if length == 0 {
            if offset + 1 != name.len() {
                return Err(WireError::InvalidName("trailing wire name data".to_owned()).into());
            }
            return Ok(labels);
        }
        if length > 63 {
            return Err(WireError::InvalidLabel.into());
        }
        let start = offset + 1;
        let end = start.checked_add(length).ok_or(WireError::NameTooLong)?;
        labels.push(name.get(start..end).ok_or(WireError::InvalidLabel)?);
        offset = end;
    }
}

fn dns_name_label_count(name: &[u8]) -> Result<usize, ResolveError> {
    Ok(dns_wire_labels(name)?.len())
}

fn nsec_proves_empty_nonterminal(
    packet: &[u8],
    record: &wire::ResourceRecord,
    name: &str,
) -> Result<bool, ResolveError> {
    let nsec = wire::parse_nsec(packet, record)?;
    let next = normalize_dns_name(nsec.next_domain.text());
    let Some(next_parent) = dns_name_parent(&next) else {
        return Ok(false);
    };
    if !dns_name_is_at_or_below(&next_parent, name) {
        return Ok(false);
    }
    let common = dns_name_common_suffix(record.name.text(), &next);
    Ok(dns_name_is_at_or_below(name, &common))
}

fn closest_existing_ancestor(records: &[wire::ResourceRecord], name: &str) -> Option<String> {
    dns_name_ancestors(name).into_iter().rev().find(|ancestor| {
        records.iter().any(|record| {
            !matches!(record.rr_type, wire::TYPE_RRSIG | wire::TYPE_OPT)
                && dns_name_is_at_or_below(record.name.text(), ancestor)
        })
    })
}

fn dns_name_parent(name: &str) -> Option<String> {
    let normalized = normalize_dns_name(name);
    if normalized == "." {
        None
    } else {
        Some(
            normalized
                .split_once('.')
                .map_or_else(|| ".".to_owned(), |(_, parent)| parent.to_owned()),
        )
    }
}

fn dns_name_common_suffix(left: &str, right: &str) -> String {
    let left = normalize_dns_name(left);
    let right = normalize_dns_name(right);
    let left = if left == "." {
        Vec::new()
    } else {
        left.split('.').collect::<Vec<_>>()
    };
    let right = if right == "." {
        Vec::new()
    } else {
        right.split('.').collect::<Vec<_>>()
    };
    let mut common = Vec::new();
    for (left, right) in left.iter().rev().zip(right.iter().rev()) {
        if left != right {
            break;
        }
        common.push(*left);
    }
    common.reverse();
    if common.is_empty() {
        ".".to_owned()
    } else {
        common.join(".")
    }
}

fn nsec3_denial_result(
    records: &[wire::ResourceRecord],
    name: &str,
    rr_type: u16,
) -> Result<DnssecDenialResult, ResolveError> {
    let parsed = parsed_nsec3_records(records)?;
    for (zone, _, parameters) in &parsed {
        let compatible = compatible_nsec3_records(&parsed, zone, parameters);
        let name_hash = nsec3_hash(name, parameters)?;
        if let Some((_, _, exact)) = compatible
            .iter()
            .copied()
            .find(|(_, owner_hash, _)| owner_hash.as_slice() == name_hash.as_slice())
        {
            if rr_type == wire::TYPE_DS && exact.types.contains(&wire::TYPE_SOA) {
                continue;
            }
            if rr_type != wire::TYPE_DS
                && exact.types.contains(&wire::TYPE_NS)
                && !exact.types.contains(&wire::TYPE_SOA)
            {
                continue;
            }
            return Ok(if exact.types.contains(&rr_type) {
                DnssecDenialResult::Found
            } else if exact.types.contains(&wire::TYPE_CNAME) {
                DnssecDenialResult::Cname
            } else {
                DnssecDenialResult::NoData
            });
        }

        let ancestors = dns_name_ancestors(name);
        let Some((closest_index, closest)) = ancestors
            .iter()
            .enumerate()
            .rev()
            .filter(|(_, ancestor)| dns_name_is_at_or_below(ancestor, zone))
            .find_map(|(index, ancestor)| {
                let hash = nsec3_hash(ancestor, parameters).ok()?;
                compatible
                    .iter()
                    .copied()
                    .find(|(_, owner_hash, _)| owner_hash.as_slice() == hash.as_slice())
                    .map(|(_, _, candidate)| (index, candidate))
            })
        else {
            continue;
        };
        if closest.types.contains(&wire::TYPE_DNAME)
            || (closest.types.contains(&wire::TYPE_NS) && !closest.types.contains(&wire::TYPE_SOA))
        {
            continue;
        }
        let Some(next_closer) = ancestors.get(closest_index + 1) else {
            continue;
        };
        let next_closer_hash = nsec3_hash(next_closer, parameters)?;
        let Some((_, _, next_cover)) =
            compatible.iter().copied().find(|(_, owner_hash, record)| {
                hash_interval_covers(owner_hash, &record.next_hashed_owner, &next_closer_hash)
            })
        else {
            continue;
        };
        if next_cover.flags == 1 {
            return Ok(DnssecDenialResult::OptOut);
        }

        let wildcard = if ancestors[closest_index] == "." {
            "*".to_owned()
        } else {
            format!("*.{}", ancestors[closest_index])
        };
        let wildcard_hash = nsec3_hash(&wildcard, parameters)?;
        if let Some((_, _, wildcard_exact)) = compatible
            .iter()
            .copied()
            .find(|(_, owner_hash, _)| owner_hash.as_slice() == wildcard_hash.as_slice())
        {
            return Ok(if wildcard_exact.types.contains(&rr_type) {
                DnssecDenialResult::Found
            } else if wildcard_exact.types.contains(&wire::TYPE_CNAME) {
                DnssecDenialResult::Cname
            } else {
                DnssecDenialResult::NoData
            });
        }
        if let Some((_, _, wildcard_cover)) =
            compatible.iter().copied().find(|(_, owner_hash, record)| {
                hash_interval_covers(owner_hash, &record.next_hashed_owner, &wildcard_hash)
            })
        {
            return Ok(if wildcard_cover.flags == 1 {
                DnssecDenialResult::OptOut
            } else {
                DnssecDenialResult::NxDomain
            });
        }
    }
    Ok(DnssecDenialResult::Missing)
}

// RFC 9276 Section 3.2 recommends 0 iterations for modern deployments,
// but upstream systemd-resolved and the RFC allow up to 100 iterations.
const NSEC3_MAX_ITERATIONS: u16 = 100;

fn parsed_nsec3_records(
    records: &[wire::ResourceRecord],
) -> Result<Vec<(String, Vec<u8>, wire::Nsec3Record)>, ResolveError> {
    let mut parsed = Vec::new();
    for record in records
        .iter()
        .filter(|record| record.rr_type == wire::TYPE_NSEC3)
    {
        let nsec3 = wire::parse_nsec3(record)?;
        if nsec3.hash_algorithm != 1
            || nsec3.flags > 1
            || nsec3.iterations > NSEC3_MAX_ITERATIONS
            || nsec3.next_hashed_owner.len() != 20
        {
            continue;
        }
        let Some((owner_hash, zone)) = nsec3_owner(record) else {
            continue;
        };
        if owner_hash.len() == 20 {
            parsed.push((zone, owner_hash, nsec3));
        }
    }
    Ok(parsed)
}

fn compatible_nsec3_records<'a>(
    records: &'a [(String, Vec<u8>, wire::Nsec3Record)],
    zone: &str,
    parameters: &wire::Nsec3Record,
) -> Vec<&'a (String, Vec<u8>, wire::Nsec3Record)> {
    records
        .iter()
        .filter(|(candidate_zone, _, candidate)| {
            dns_names_equal(candidate_zone, zone)
                && candidate.hash_algorithm == parameters.hash_algorithm
                && candidate.iterations == parameters.iterations
                && candidate.salt == parameters.salt
        })
        .collect()
}

fn wildcard_expansion_is_proven(
    packet: &[u8],
    records: &[wire::ResourceRecord],
    expanded_owner: &str,
    source_labels: usize,
) -> Result<bool, ResolveError> {
    let Some(closest) = dns_name_suffix(expanded_owner, source_labels) else {
        return Ok(false);
    };
    let expanded_labels = normalize_dns_name(expanded_owner).split('.').count();
    let Some(next_closer) = dns_name_suffix(expanded_owner, source_labels + 1) else {
        return Ok(false);
    };
    if source_labels >= expanded_labels {
        return Ok(false);
    }

    let nsec_records: Vec<_> = records
        .iter()
        .filter(|record| record.rr_type == wire::TYPE_NSEC)
        .collect();
    if !nsec_records.is_empty() {
        // Any authenticated owner at or below the closest encloser proves that
        // ancestor exists, including as an empty non-terminal. This matters for
        // wildcard answers where the denial proof is carried by the wildcard
        // owner's own NSEC RRset (for example *.wild.example).
        let has_closest = nsec_records
            .iter()
            .any(|record| dns_name_is_at_or_below(record.name.text(), &closest));
        let covers_next = nsec_records
            .iter()
            .any(|record| nsec_covers_name(packet, record, &next_closer).unwrap_or(false));
        if has_closest && covers_next {
            return Ok(true);
        }
    }

    let parsed = parsed_nsec3_records(records)?;
    for (zone, _, parameters) in &parsed {
        if !dns_name_is_at_or_below(&closest, zone) {
            continue;
        }
        let compatible = compatible_nsec3_records(&parsed, zone, parameters);
        let closest_hash = nsec3_hash(&closest, parameters)?;
        if !compatible
            .iter()
            .any(|(_, owner_hash, _)| owner_hash.as_slice() == closest_hash.as_slice())
        {
            continue;
        }
        let next_hash = nsec3_hash(&next_closer, parameters)?;
        if compatible.iter().any(|(_, owner_hash, record)| {
            record.flags == 0
                && hash_interval_covers(owner_hash, &record.next_hashed_owner, &next_hash)
        }) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn dns_name_suffix(name: &str, labels: usize) -> Option<String> {
    let normalized = normalize_dns_name(name);
    if normalized == "." {
        return (labels == 0).then(|| ".".to_owned());
    }
    let parts = normalized.split('.').collect::<Vec<_>>();
    if labels > parts.len() {
        None
    } else if labels == 0 {
        Some(".".to_owned())
    } else {
        Some(parts[parts.len() - labels..].join("."))
    }
}

pub(crate) fn authenticated_ds_denial(
    packet: &[u8],
    child: &str,
    parent_keys: &[wire::ResourceRecord],
) -> Result<bool, ResolveError> {
    let (_, _, records, end) = wire::parse_sections(packet)?;
    if end != packet.len() {
        return Err(WireError::TrailingData.into());
    }
    let header = Header::parse(packet)?;
    let authenticated_record_count =
        usize::from(header.answer_count) + usize::from(header.authority_count);
    let authenticated_records = &records[..authenticated_record_count];
    let mut saw_denial = false;
    for record in authenticated_records
        .iter()
        .filter(|record| matches!(record.rr_type, wire::TYPE_NSEC | wire::TYPE_NSEC3))
    {
        if verify_packet_rrset(packet, record.name.text(), record.rr_type, parent_keys)? {
            saw_denial = true;
        } else {
            return Ok(false);
        }
    }
    if !saw_denial {
        return Ok(false);
    }
    Ok(
        nsec_proves_ds_absence(packet, authenticated_records, child)?
            || nsec3_proves_ds_absence(authenticated_records, child)?,
    )
}

fn nsec_proves_ds_absence(
    packet: &[u8],
    records: &[wire::ResourceRecord],
    child: &str,
) -> Result<bool, ResolveError> {
    for record in records
        .iter()
        .filter(|record| record.rr_type == wire::TYPE_NSEC)
    {
        if !dns_names_equal(record.name.text(), child) {
            continue;
        }
        let nsec = wire::parse_nsec(packet, record)?;
        if !nsec.types.contains(&wire::TYPE_DS) && !nsec.types.contains(&wire::TYPE_SOA) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn nsec3_proves_ds_absence(
    records: &[wire::ResourceRecord],
    child: &str,
) -> Result<bool, ResolveError> {
    Ok(matches!(
        nsec3_denial_result(records, child, wire::TYPE_DS)?,
        DnssecDenialResult::NoData | DnssecDenialResult::NxDomain | DnssecDenialResult::OptOut
    ))
}

fn nsec3_owner(record: &wire::ResourceRecord) -> Option<(Vec<u8>, String)> {
    let wire = record.name.canonical_wire();
    let label_length = usize::from(*wire.first()?);
    if label_length == 0 || label_length + 1 >= wire.len() {
        return None;
    }
    let label = std::str::from_utf8(wire.get(1..1 + label_length)?).ok()?;
    let owner_hash = decode_base32hex(label)?;
    let zone = record
        .name
        .text()
        .split_once('.')
        .map_or(".", |(_, zone)| zone);
    Some((owner_hash, normalize_dns_name(zone)))
}

fn nsec3_hash(name: &str, parameters: &wire::Nsec3Record) -> Result<Vec<u8>, ResolveError> {
    use sha1::Digest as _;

    let canonical = wire::encode_name(&normalize_dns_name(name))?
        .into_iter()
        .map(|byte| byte.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let mut digest = sha1::Sha1::new();
    digest.update(&canonical);
    digest.update(&parameters.salt);
    let mut output = digest.finalize().to_vec();
    for _ in 0..parameters.iterations {
        let mut digest = sha1::Sha1::new();
        digest.update(&output);
        digest.update(&parameters.salt);
        output = digest.finalize().to_vec();
    }
    Ok(output)
}

fn hash_interval_covers(owner: &[u8], next: &[u8], name: &[u8]) -> bool {
    if owner < next {
        owner < name && name < next
    } else if owner > next {
        name > owner || name < next
    } else {
        name != owner
    }
}

fn decode_base32hex(value: &str) -> Option<Vec<u8>> {
    let mut accumulator = 0_u64;
    let mut bits = 0_u8;
    let mut output = Vec::with_capacity(value.len() * 5 / 8);
    for byte in value.bytes() {
        let digit = match byte.to_ascii_uppercase() {
            b'0'..=b'9' => byte.to_ascii_uppercase() - b'0',
            b'A'..=b'V' => byte.to_ascii_uppercase() - b'A' + 10,
            _ => return None,
        };
        accumulator = (accumulator << 5) | u64::from(digit);
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            output.push(u8::try_from(accumulator >> bits).expect("complete base32 octet"));
            accumulator &= (1_u64 << bits).wrapping_sub(1);
        }
    }
    if bits != 0 && accumulator != 0 {
        return None;
    }
    Some(output)
}

pub(crate) fn trust_anchor_matches_dnskey(
    anchor: &PositiveTrustAnchor,
    key: &wire::ResourceRecord,
) -> Result<bool, crate::dnssec::DnssecError> {
    match &anchor.data {
        PositiveTrustAnchorData::Ds {
            key_tag,
            algorithm,
            digest_type,
            digest,
        } => {
            let parsed = wire::parse_dnskey(key)?;
            Ok(parsed.algorithm == *algorithm
                && wire::dnskey_key_tag(key)? == *key_tag
                && crate::dnssec::dnskey_ds_digest(key, *digest_type)? == *digest)
        }
        PositiveTrustAnchorData::Dnskey(rdata) => {
            Ok(key.rr_type == wire::TYPE_DNSKEY && key.rdata == *rdata)
        }
    }
}

pub(crate) fn load_positive_trust_anchors() -> Vec<PositiveTrustAnchor> {
    let mut output = Vec::new();
    for path in trust_anchor_files("positive") {
        let Ok(contents) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in contents.lines() {
            if let Some(anchor) = parse_positive_trust_anchor_line(line) {
                output.push(anchor);
            }
        }
    }
    if !output.iter().any(|anchor| anchor.owner == ".") {
        output.extend(builtin_root_trust_anchors());
    }
    output
}

fn parse_positive_trust_anchor_line(line: &str) -> Option<PositiveTrustAnchor> {
    let line = strip_anchor_comment(line).trim();
    let fields = line.split_whitespace().collect::<Vec<_>>();
    if fields.len() < 4 || !fields[1].eq_ignore_ascii_case("IN") {
        return None;
    }
    let owner = normalize_dns_name(fields[0]);
    let data = if fields[2].eq_ignore_ascii_case("DS") {
        if fields.len() != 7 {
            if !fields
                .get(7)
                .is_some_and(|field| is_escaped_comment_trailer(field))
            {
                return None;
            }
        }
        PositiveTrustAnchorData::Ds {
            key_tag: fields[3].parse().ok()?,
            algorithm: parse_dnssec_algorithm(fields[4])?,
            digest_type: parse_dnssec_digest(fields[5])?,
            digest: decode_hex(fields[6].trim_matches('"'))?,
        }
    } else if fields[2].eq_ignore_ascii_case("DNSKEY") {
        if fields.len() != 7 {
            if !fields
                .get(7)
                .is_some_and(|field| is_escaped_comment_trailer(field))
            {
                return None;
            }
        }
        let flags = fields[3].parse::<u16>().ok()?;
        let protocol = fields[4].parse::<u8>().ok()?;
        let algorithm = parse_dnssec_algorithm(fields[5])?;
        if flags & 0x0100 == 0 || flags & 0x0080 != 0 || protocol != 3 {
            return None;
        }
        let public_key = decode_base64(fields[6].trim_matches('"'))?;
        if public_key.is_empty() {
            return None;
        }
        let mut rdata = Vec::with_capacity(4 + public_key.len());
        rdata.extend_from_slice(&flags.to_be_bytes());
        rdata.push(protocol);
        rdata.push(algorithm);
        rdata.extend_from_slice(&public_key);
        PositiveTrustAnchorData::Dnskey(rdata)
    } else {
        return None;
    };
    Some(PositiveTrustAnchor { owner, data })
}

fn is_escaped_comment_trailer(field: &str) -> bool {
    field.starts_with("\\#") || field.starts_with("\\;")
}

fn strip_anchor_comment(line: &str) -> &str {
    let mut escaped = false;
    for (index, character) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' {
            escaped = true;
            continue;
        }
        if matches!(character, '#' | ';') {
            return &line[..index];
        }
    }
    line
}

fn builtin_root_trust_anchors() -> Vec<PositiveTrustAnchor> {
    [
        (
            20326,
            "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
        ),
        (
            38696,
            "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
        ),
    ]
    .into_iter()
    .map(|(key_tag, digest)| PositiveTrustAnchor {
        owner: ".".to_owned(),
        data: PositiveTrustAnchorData::Ds {
            key_tag,
            algorithm: 8,
            digest_type: 2,
            digest: decode_hex(digest).expect("built-in root digest"),
        },
    })
    .collect()
}

fn parse_dnssec_algorithm(value: &str) -> Option<u8> {
    value
        .parse()
        .ok()
        .or_else(|| match value.to_ascii_uppercase().as_str() {
            "RSAMD5" => Some(1),
            "DH" => Some(2),
            "DSA" => Some(3),
            "ECC" => Some(4),
            "RSASHA1" => Some(5),
            "DSA-NSEC3-SHA1" => Some(6),
            "RSASHA1-NSEC3-SHA1" => Some(7),
            "RSASHA256" => Some(8),
            "RSASHA512" => Some(10),
            "ECC-GOST" => Some(12),
            "ECDSAP256SHA256" => Some(13),
            "ECDSAP384SHA384" => Some(14),
            "ED25519" => Some(15),
            "ED448" => Some(16),
            "INDIRECT" => Some(252),
            "PRIVATEDNS" => Some(253),
            "PRIVATEOID" => Some(254),
            _ => None,
        })
}

fn parse_dnssec_digest(value: &str) -> Option<u8> {
    value
        .parse()
        .ok()
        .or_else(|| match value.to_ascii_uppercase().as_str() {
            "SHA1" => Some(1),
            "SHA256" => Some(2),
            "GOST" | "GOST-R-34.11-94" => Some(3),
            "SHA384" => Some(4),
            _ => None,
        })
}

fn load_negative_trust_anchors() -> Vec<String> {
    let mut output = Vec::new();
    for path in trust_anchor_files("negative") {
        let Ok(contents) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in contents.lines() {
            let name = line.split(['#', ';']).next().unwrap_or("").trim();
            if !name.is_empty() {
                output.push(normalize_dns_name(name));
            }
        }
    }
    if output.is_empty() {
        let positive = load_positive_trust_anchors();
        output.extend(builtin_negative_trust_anchors().into_iter().filter(|name| {
            !positive
                .iter()
                .any(|anchor| dns_names_equal(&anchor.owner, name))
        }));
    }
    output
}

fn builtin_negative_trust_anchors() -> Vec<String> {
    let mut output = vec!["test".to_owned(), "10.in-addr.arpa".to_owned()];
    output.extend((16..=31).map(|octet| format!("{octet}.172.in-addr.arpa")));
    output.extend(
        [
            "168.192.in-addr.arpa",
            "d.f.ip6.arpa",
            "local",
            "home",
            "corp",
            "lan",
            "intranet",
            "internal",
            "private",
            "home.arpa",
            "resolver.arpa",
            "ipv4only.arpa",
            "170.0.0.192.in-addr.arpa",
            "171.0.0.192.in-addr.arpa",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    output
}

fn trust_anchor_files(extension: &str) -> Vec<std::path::PathBuf> {
    let mut selected = std::collections::BTreeMap::<std::ffi::OsString, std::path::PathBuf>::new();
    for directory in DNSSEC_TRUST_ANCHOR_DIRECTORIES.iter().rev() {
        let Ok(entries) = std::fs::read_dir(directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(std::ffi::OsStr::to_str) == Some(extension) {
                selected.insert(entry.file_name(), path);
            }
        }
    }
    selected.into_values().collect()
}

pub(crate) fn dns_name_ancestors(name: &str) -> Vec<String> {
    let normalized = normalize_dns_name(name);
    if normalized == "." {
        return vec![normalized];
    }
    let labels = normalized.split('.').collect::<Vec<_>>();
    let mut output = vec![".".to_owned()];
    for index in (0..labels.len()).rev() {
        output.push(labels[index..].join("."));
    }
    output
}

pub(crate) fn normalize_dns_name(name: &str) -> String {
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty() {
        ".".to_owned()
    } else {
        name
    }
}

pub(crate) fn dns_names_equal(left: &str, right: &str) -> bool {
    normalize_dns_name(left) == normalize_dns_name(right)
}

fn dns_name_is_at_or_below(name: &str, parent: &str) -> bool {
    let name = normalize_dns_name(name);
    let parent = normalize_dns_name(parent);
    parent == "."
        || name == parent
        || name
            .strip_suffix(&parent)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16)?;
            let low = (pair[1] as char).to_digit(16)?;
            Some(((high << 4) | low) as u8)
        })
        .collect()
}

fn decode_base64(input: &str) -> Option<Vec<u8>> {
    if input.len() % 4 != 0 {
        return None;
    }
    let mut output = Vec::with_capacity(input.len() / 4 * 3);
    for (index, chunk) in input.as_bytes().chunks_exact(4).enumerate() {
        let last = index + 1 == input.len() / 4;
        let first = base64_value(chunk[0])?;
        let second = base64_value(chunk[1])?;
        let third = if chunk[2] == b'=' {
            if chunk[3] != b'=' || !last || second & 0x0f != 0 {
                return None;
            }
            None
        } else {
            Some(base64_value(chunk[2])?)
        };
        let fourth = if chunk[3] == b'=' {
            if !last || third.is_some_and(|value| value & 0x03 != 0) {
                return None;
            }
            None
        } else {
            Some(base64_value(chunk[3])?)
        };
        if third.is_none() && fourth.is_some() {
            return None;
        }
        output.push((first << 2) | (second >> 4));
        if let Some(third) = third {
            output.push((second << 4) | (third >> 2));
            if let Some(fourth) = fourth {
                output.push((third << 6) | fourth);
            }
        }
    }
    Some(output)
}

const fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod dnssec_parity_tests {
    use super::*;


    #[test]
    fn authenticated_dnskey_rrset_promotes_zsk_for_test75_svcb_signature() {
        const SVCB_PACKET: &str = concat!(
            "000f85000001000200000000047376636204746573740000400001c00c00400001000151800027",
            "0001000001000403646f74000400040a00000100060010fd00deadbeefcafe0000000000000001",
            "c00c002e000100015180005800400d02000151806a8cca106a7a3ff83a16047465737400",
            "91ab5e972f2079c12bf5b0c30ac630f7dbba3b56788614ec1923cb56b9e8513185cdbd14189826276b768d6e1a0fa3b451e3eda9de8f032d816611d0d12c6c4c",
        );
        const DNSKEY_PACKET: &str = concat!(
            "00128500000100030000000004746573740000300001c00c003000010001518000440100030d",
            "c1c1e088d0aedfe6d1a17ccefa28a27b6ba70498a5db4872e1cc283dd28601ebe78d928580497528bd815ef22fc8753ad1536896bc3cc5bf965ebbf5f2d08902",
            "c00c003000010001518000440101030d",
            "4ae329e54dbeae5bd50306eebf7cce9b6f7ee086182acedca987c68e279f1153ba1f81bb58736825fdafec8e1160214935527dc2ef35844bdca42d2214831e1f",
            "c00c002e000100015180005800300d01000151806a8cca106a7a3ff83b6b047465737400",
            "3d3598b3495e2614752a1e5b4fefc332d8d173a884a2f2555536fb4afb331c18e430c164293ed0fc2ebe4aa7776015130db08a85d3d6ff6aa114741ffb34968c",
        );

        let svcb_packet = decode_hex(SVCB_PACKET).expect("captured TEST-75 SVCB packet");
        let dnskey_packet = decode_hex(DNSKEY_PACKET).expect("captured TEST-75 DNSKEY packet");
        let keys = records_of_type(&dnskey_packet, "test", wire::TYPE_DNSKEY)
            .expect("TEST-75 DNSKEY records");
        assert_eq!(keys.len(), 2);

        let ksk = keys
            .iter()
            .find(|key| wire::dnskey_key_tag(key).ok() == Some(15_211))
            .expect("TEST-75 KSK")
            .clone();
        assert!(!verify_packet_rrset(&svcb_packet, "svcb.test", 64, &[ksk])
            .expect("KSK-only verification"));

        let trusted = authenticated_zone_signing_keys(&keys).expect("authenticated zone keys");
        let mut tags = trusted
            .iter()
            .map(|key| wire::dnskey_key_tag(key).expect("DNSKEY tag"))
            .collect::<Vec<_>>();
        tags.sort_unstable();
        assert_eq!(tags, vec![14_870, 15_211]);
        assert!(verify_packet_rrset(&svcb_packet, "svcb.test", 64, &trusted)
            .expect("ZSK-backed SVCB verification"));
    }

    #[test]
    fn positive_anchor_parser_accepts_ds_and_dnskey_records() {
        let ds = parse_positive_trust_anchor_line(
            ". IN DS 20326 RSASHA256 SHA256 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
        )
        .expect("DS trust anchor");
        assert_eq!(ds.owner, ".");
        assert!(matches!(
            ds.data,
            PositiveTrustAnchorData::Ds {
                key_tag: 20326,
                algorithm: 8,
                digest_type: 2,
                ref digest,
            } if digest.len() == 32
        ));

        let dnskey =
            parse_positive_trust_anchor_line("example. IN DNSKEY 257 3 ECDSAP256SHA256 AQIDBA==")
                .expect("DNSKEY trust anchor");
        assert_eq!(dnskey.owner, "example");
        assert_eq!(
            dnskey.data,
            PositiveTrustAnchorData::Dnskey(vec![0x01, 0x01, 3, 13, 1, 2, 3, 4])
        );
    }

    #[test]
    fn positive_anchor_parser_rejects_unsafe_dnskeys_and_wrong_class() {
        assert!(parse_positive_trust_anchor_line(
            "example CH DS 1 8 2 0000000000000000000000000000000000000000000000000000000000000000"
        )
        .is_none());
        assert!(parse_positive_trust_anchor_line("example IN DNSKEY 1 3 13 AQIDBA==").is_none());
        assert!(parse_positive_trust_anchor_line("example IN DNSKEY 257 2 13 AQIDBA==").is_none());
        assert!(parse_positive_trust_anchor_line("example IN DNSKEY 385 3 13 AQIDBA==").is_none());
    }

    #[test]
    fn built_in_root_anchor_set_matches_upstream_v261() {
        let anchors = builtin_root_trust_anchors();
        assert_eq!(anchors.len(), 2);
        assert!(anchors.iter().all(|anchor| anchor.owner == "."));
        assert!(anchors.iter().any(|anchor| matches!(
            anchor.data,
            PositiveTrustAnchorData::Ds {
                key_tag: 20326,
                algorithm: 8,
                digest_type: 2,
                ..
            }
        )));
        assert!(anchors.iter().any(|anchor| matches!(
            anchor.data,
            PositiveTrustAnchorData::Ds {
                key_tag: 38696,
                algorithm: 8,
                digest_type: 2,
                ..
            }
        )));
    }

    #[test]
    fn built_in_negative_anchor_set_matches_upstream_v261() {
        let anchors = builtin_negative_trust_anchors();
        assert_eq!(anchors.len(), 32);
        for name in [
            "test",
            "10.in-addr.arpa",
            "16.172.in-addr.arpa",
            "31.172.in-addr.arpa",
            "local",
            "home.arpa",
            "resolver.arpa",
            "ipv4only.arpa",
            "171.0.0.192.in-addr.arpa",
        ] {
            assert!(anchors.iter().any(|anchor| anchor == name));
        }

        let exported = Resolver::new(Config::default()).dnssec_negative_trust_anchors();
        assert!(!exported.is_empty());
        assert!(exported.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn positive_anchor_stops_inherited_negative_anchor() {
        let negative = vec!["corp".to_owned()];
        let positive = vec![PositiveTrustAnchor {
            owner: "signed.corp".to_owned(),
            data: PositiveTrustAnchorData::Ds {
                key_tag: 1,
                algorithm: 8,
                digest_type: 2,
                digest: vec![0; 32],
            },
        }];

        assert!(negative_trust_anchor_matches(
            "unsigned.corp",
            &negative,
            &positive
        ));
        assert!(!negative_trust_anchor_matches(
            "host.signed.corp",
            &negative,
            &positive
        ));
        assert!(negative_trust_anchor_matches(
            "signed.corp",
            &["signed.corp".to_owned()],
            &positive
        ));
    }

    #[test]
    fn positive_anchor_parser_accepts_trailing_comment_syntax() {
        assert!(parse_positive_trust_anchor_line(
            ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D # comment"
        )
        .is_some());
        assert!(parse_positive_trust_anchor_line(
            ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D ; comment"
        )
        .is_some());
    }

    #[test]
    fn positive_anchor_parser_ignores_escaped_comment_prefixes() {
        assert!(parse_positive_trust_anchor_line(
            ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D \\# not-comment"
        )
        .is_some());
        assert!(parse_positive_trust_anchor_line(
            ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D \\; not-comment"
        )
        .is_some());
    }

    #[test]
    fn dnssec_verdict_statistics_are_live_and_resettable() {
        let resolver = Resolver::new(Config::default());
        resolver.record_dnssec_verdict(DnssecVerdict::Secure);
        resolver.record_dnssec_verdict(DnssecVerdict::Insecure);
        resolver.record_dnssec_verdict(DnssecVerdict::NotValidated);
        resolver.record_dnssec_error(&dnssec_validation_error("invalid signature"));
        resolver.record_dnssec_error(&ResolveError::NoTrustAnchor);

        let statistics = resolver.stats();
        assert_eq!(statistics.dnssec_secure, 1);
        assert_eq!(statistics.dnssec_insecure, 1);
        assert_eq!(statistics.dnssec_bogus, 1);
        assert_eq!(statistics.dnssec_indeterminate, 1);

        resolver.reset_statistics();
        let statistics = resolver.stats();
        assert_eq!(statistics.dnssec_secure, 0);
        assert_eq!(statistics.dnssec_insecure, 0);
        assert_eq!(statistics.dnssec_bogus, 0);
        assert_eq!(statistics.dnssec_indeterminate, 0);
    }

    #[test]
    fn nsec_ds_denial_requires_the_exact_parent_side_owner() {
        let valid = nsec_packet("child.example", "next.example", &[2, 46, 47]);
        let (_, _, records, _) = wire::parse_sections(&valid).expect("valid NSEC packet");
        assert!(nsec_proves_ds_absence(&valid, &records, "child.example").unwrap());

        let unrelated = nsec_packet("other.example", "next.example", &[2, 46, 47]);
        let (_, _, records, _) = wire::parse_sections(&unrelated).expect("unrelated NSEC packet");
        assert!(!nsec_proves_ds_absence(&unrelated, &records, "child.example").unwrap());

        let has_ds = nsec_packet("child.example", "next.example", &[2, 43, 46, 47]);
        let (_, _, records, _) = wire::parse_sections(&has_ds).expect("DS NSEC packet");
        assert!(!nsec_proves_ds_absence(&has_ds, &records, "child.example").unwrap());

        let child_side = nsec_packet("child.example", "next.example", &[2, 6, 46, 47]);
        let (_, _, records, _) = wire::parse_sections(&child_side).expect("child-side NSEC packet");
        assert!(!nsec_proves_ds_absence(&child_side, &records, "child.example").unwrap());
    }

    #[test]
    fn nsec_negative_answers_require_nodata_or_complete_nxdomain_proofs() {
        let mut nodata = denial_packet("host.example", wire::TYPE_AAAA, 1);
        append_nsec(&mut nodata, "host.example", "next.example", &[1, 46, 47]);
        let (_, _, records, _) = wire::parse_sections(&nodata).expect("NODATA packet");
        assert_eq!(
            nsec_denial_result(&nodata, &records, "host.example", wire::TYPE_AAAA).unwrap(),
            DnssecDenialResult::NoData
        );

        let mut nxdomain = denial_packet("m.example", wire::TYPE_A, 3);
        append_soa(&mut nxdomain, "example");
        append_nsec(&mut nxdomain, "example", "a.example", &[6, 46, 47]);
        append_nsec(&mut nxdomain, "a.example", "z.example", &[1, 46, 47]);
        let (_, _, records, _) = wire::parse_sections(&nxdomain).expect("NXDOMAIN packet");
        assert_eq!(
            nsec_denial_result(&nxdomain, &records, "m.example", wire::TYPE_A).unwrap(),
            DnssecDenialResult::NxDomain
        );

        let mut incomplete = denial_packet("m.example", wire::TYPE_A, 2);
        append_soa(&mut incomplete, "example");
        append_nsec(&mut incomplete, "a.example", "z.example", &[1, 46, 47]);
        let (_, _, records, _) = wire::parse_sections(&incomplete).expect("incomplete packet");
        assert_eq!(
            nsec_denial_result(&incomplete, &records, "m.example", wire::TYPE_A).unwrap(),
            DnssecDenialResult::Missing
        );

        let mut wildcard_nodata = denial_packet("m.example", wire::TYPE_AAAA, 3);
        append_soa(&mut wildcard_nodata, "example");
        append_nsec(&mut wildcard_nodata, "a.example", "z.example", &[1, 46, 47]);
        append_nsec(
            &mut wildcard_nodata,
            "*.example",
            "a.example",
            &[16, 46, 47],
        );
        let (_, _, records, _) =
            wire::parse_sections(&wildcard_nodata).expect("wildcard NODATA packet");
        assert!(records.iter().any(|record| nsec_covers_name(
            &wildcard_nodata,
            record,
            "m.example"
        )
        .unwrap_or(false)));
        assert_eq!(
            closest_existing_ancestor(&records, "m.example").as_deref(),
            Some("example")
        );
        let wildcard = records
            .iter()
            .find(|record| dns_record_name_equal(record, "*.example"))
            .expect("wildcard NSEC");
        assert_eq!(
            wire::parse_nsec(&wildcard_nodata, wildcard)
                .expect("wildcard NSEC data")
                .types,
            vec![16, 46, 47]
        );
        assert_eq!(
            nsec_denial_result(&wildcard_nodata, &records, "m.example", wire::TYPE_AAAA,).unwrap(),
            DnssecDenialResult::NoData
        );
    }

    #[test]
    fn authenticated_response_semantics_enforces_negative_and_wildcard_proofs() {
        let query = make_query_with_class("host.example", wire::TYPE_AAAA, wire::CLASS_IN, 1)
            .expect("NODATA query");
        let mut nodata = denial_packet("host.example", wire::TYPE_AAAA, 1);
        append_nsec(&mut nodata, "host.example", "next.example", &[1, 46, 47]);
        let (_, _, records, _) = wire::parse_sections(&nodata).expect("NODATA packet");
        assert_eq!(
            authenticated_response_semantics(&query, &nodata, &records).unwrap(),
            DnssecVerdict::Secure
        );

        let nx_query = make_query_with_class("m.example", wire::TYPE_A, wire::CLASS_IN, 1)
            .expect("NXDOMAIN query");
        let mut incomplete = denial_packet("m.example", wire::TYPE_A, 2);
        incomplete[3] |= 3;
        append_soa(&mut incomplete, "example");
        append_nsec(&mut incomplete, "a.example", "z.example", &[1, 46, 47]);
        let (_, _, records, _) = wire::parse_sections(&incomplete).expect("incomplete packet");
        assert!(authenticated_response_semantics(&nx_query, &incomplete, &records).is_err());

        let wildcard_query =
            make_query_with_class("m.wild.example", 16, wire::CLASS_IN, 1).expect("wildcard query");
        let wildcard = wildcard_response(true);
        let (_, _, records, _) = wire::parse_sections(&wildcard).expect("wildcard response");
        assert_eq!(
            authenticated_response_semantics(&wildcard_query, &wildcard, &records).unwrap(),
            DnssecVerdict::Secure
        );

        // TEST-75's signed wildcard zone proves the closest encloser as an
        // empty non-terminal: *.wild.example exists and its NSEC covers the
        // next-closer name. No explicit wild.example NSEC owner is required.
        let mut empty_nonterminal = wildcard_response(false);
        empty_nonterminal[8..10].copy_from_slice(&1_u16.to_be_bytes());
        append_nsec(
            &mut empty_nonterminal,
            "*.wild.example",
            "example",
            &[16, 46, 47],
        );
        let (_, _, records, _) = wire::parse_sections(&empty_nonterminal)
            .expect("empty-nonterminal wildcard response");
        assert_eq!(
            authenticated_response_semantics(
                &wildcard_query,
                &empty_nonterminal,
                &records,
            )
            .unwrap(),
            DnssecVerdict::Secure
        );

        let wildcard = wildcard_response(false);
        let (_, _, records, _) =
            wire::parse_sections(&wildcard).expect("unproved wildcard response");
        assert!(authenticated_response_semantics(&wildcard_query, &wildcard, &records).is_err());
    }

    #[test]
    fn authenticated_redirect_only_response_is_not_misclassified_as_nodata() {
        let query = make_query_with_class("alias.example", wire::TYPE_A, wire::CLASS_IN, 1)
            .expect("redirect query");
        let mut response = denial_packet("alias.example", wire::TYPE_A, 0);
        response[6..8].copy_from_slice(&1_u16.to_be_bytes());
        append_record(
            &mut response,
            "alias.example",
            wire::TYPE_CNAME,
            &wire::encode_name("target.example").expect("CNAME target"),
        );
        let (_, _, records, _) = wire::parse_sections(&response).expect("redirect response");
        assert_eq!(
            authenticated_response_semantics(&query, &response, &records).unwrap(),
            DnssecVerdict::Secure
        );
    }

    #[test]
    fn only_wire_exact_dname_synthesized_cnames_inherit_authentication() {
        let packet = dname_response("x.d.target");
        let (_, _, records, _) = wire::parse_sections(&packet).expect("DNAME response");
        let rrsets = substantive_rrsets(&packet, &records).unwrap();
        assert_eq!(rrsets.len(), 1);
        assert_eq!(rrsets[0].1, wire::TYPE_DNAME);

        let packet = dname_response("attacker.example");
        let (_, _, records, _) = wire::parse_sections(&packet).expect("mismatched DNAME response");
        let rrsets = substantive_rrsets(&packet, &records).unwrap();
        assert_eq!(rrsets.len(), 2);
        assert!(rrsets
            .iter()
            .any(|(_, rr_type, _)| *rr_type == wire::TYPE_CNAME));
    }

    #[test]
    fn trusted_dnskey_cache_is_ttl_bounded_and_flushable() {
        let packet = dnskey_response();
        assert_eq!(
            dnskey_cache_lifetime(&packet, "example").unwrap(),
            Duration::from_secs(10)
        );

        let resolver = Resolver::new(Config::default());
        let server = ServerKey::new(
            ScopeKind::Global,
            "192.0.2.53:53".parse().expect("test server"),
        );
        resolver.dnskey_cache.lock().unwrap().insert(
            DnskeyCacheKey {
                server,
                zone: "example".to_owned(),
            },
            DnskeyCacheEntry {
                keys: Vec::new(),
                expires: Instant::now() + Duration::from_secs(30),
            },
        );
        resolver.flush_cache();
        assert!(resolver.dnskey_cache.lock().unwrap().is_empty());
    }

    #[test]
    fn nsec3_ds_denial_accepts_exact_nodata_and_rejects_child_side_data() {
        let parameters = nsec3_parameters(0);
        let child_hash = nsec3_hash("child.example", &parameters).expect("child hash");
        let exact = nsec3_packet(&[nsec3_record(
            &child_hash,
            "example",
            0,
            &child_hash,
            &[2, 46, 50],
        )]);
        let (_, _, records, _) = wire::parse_sections(&exact).expect("exact NSEC3 packet");
        assert!(nsec3_proves_ds_absence(&records, "child.example").unwrap());

        let child_side = nsec3_packet(&[nsec3_record(
            &child_hash,
            "example",
            0,
            &child_hash,
            &[2, 6, 46, 50],
        )]);
        let (_, _, records, _) =
            wire::parse_sections(&child_side).expect("child-side NSEC3 packet");
        assert!(!nsec3_proves_ds_absence(&records, "child.example").unwrap());
    }

    #[test]
    fn nsec3_optout_denial_applies_to_non_ds_queries() {
        let parameters = nsec3_parameters(0);
        let child_hash = nsec3_hash("child.example", &parameters).expect("child hash");
        let mut low = child_hash.clone();
        decrement_hash(&mut low);
        let mut high = child_hash.clone();
        increment_hash(&mut high);
        let zone_hash = nsec3_hash("example", &parameters).expect("zone hash");
        let mut zone_next = zone_hash.clone();
        increment_hash(&mut zone_next);

        let coverage = nsec3_packet(&[
            nsec3_record(&zone_hash, "example", 0, &zone_next, &[6, 46, 50]),
            nsec3_record(&low, "example", 1, &high, &[6, 46, 50]),
        ]);
        let (_, _, records, _) = wire::parse_sections(&coverage).expect("coverage packet");
        assert_eq!(
            nsec3_denial_result(&records, "child.example", wire::TYPE_A).expect("optout denial"),
            DnssecDenialResult::OptOut
        );
        assert_eq!(
            nsec3_denial_result(&records, "child.example", wire::TYPE_DNSKEY)
                .expect("dnskey denial"),
            DnssecDenialResult::OptOut
        );
    }

    #[test]
    fn nsec3_optout_denial_maps_to_insecure_authenticated_verdict() {
        let parameters = nsec3_parameters(0);
        let child_hash = nsec3_hash("child.example", &parameters).expect("child hash");
        let mut low = child_hash.clone();
        decrement_hash(&mut low);
        let mut high = child_hash.clone();
        increment_hash(&mut high);
        let zone_hash = nsec3_hash("example", &parameters).expect("zone hash");
        let mut zone_next = zone_hash.clone();
        increment_hash(&mut zone_next);

        let denial = nsec3_packet(&[
            nsec3_record(&zone_hash, "example", 0, &zone_next, &[6, 46, 50]),
            nsec3_record(&low, "example", 1, &high, &[6, 46, 50]),
        ]);
        let (_, _, records, _) = wire::parse_sections(&denial).expect("coverage packet");
        let query = make_query_with_class("child.example", wire::TYPE_A, wire::CLASS_IN, 1)
            .expect("NSEC3 query");

        assert_eq!(
            authenticated_response_semantics(&query, &denial, &records).unwrap(),
            DnssecVerdict::Insecure
        );

        let mut nxdomain = denial.clone();
        nxdomain[3] = 3;
        let (_, _, nxdomain_records, _) =
            wire::parse_sections(&nxdomain).expect("NXDOMAIN coverage packet");
        assert_eq!(
            authenticated_response_semantics(&query, &nxdomain, &nxdomain_records).unwrap(),
            DnssecVerdict::Insecure
        );
    }

    #[test]
    fn nsec3_ds_denial_accepts_pinned_test_75_untrusted_delegation() {
        let packet = decode_hex(concat!(
            "004a8503000100000008000009756e74727573746564047465737400002b0001",
            "c0160006000100015180002a036e733108756e7369676e6564c01604726f6f",
            "74c0300000002d00002a300000038400093a8000015180203669757266766932",
            "3839756d356b6d71636c7366666467706937336934356e66c016003200010001",
            "5180002c0100000008b97959dcc5a2b7061483903feb8de893582b7c02fd3278",
            "696439bc08c800082200000000029018206c713361766c66687374716f373767",
            "7472687162666b6865326d3972396a6666c01600320001000151800022010000",
            "0008b97959dcc5a2b70614ea3de2956b59f93347fe6b38b2b978effe20095420",
            "3330367634736231623471676464376f6c666a6a6270376e7166727363327372",
            "c016003200010001518000250100000008b97959dcc5a2b7061434bdb7fe4242",
            "7d62d2da6578f7b61991c72216ef000120c016002e000100015180005800060d",
            "01000151806a8b34b76a78aa9f3a8f0474657374006da47a7f4ab1783976f7",
            "72370c192fe340114e56fd03490438b3ddd3c204c920ca9fe882bb7563333cc8",
            "3799759eb81914ba9a7f705162595dc2d459b865fb8dc056002e000100015180",
            "005800320d02000151806a8b34b56a78aa9d3a8f0474657374007ba228ab148",
            "677675db67ecad67777e13cfce2f29e7b28fa8d753b49d11aa33c63f7145e7",
            "1b47bb37366f493a8981c4da80ba93a33cd0f802806cc9e0ace8150c0af002e",
            "000100015180005800320d02000151806a8b34b56a78aa9d3a8f047465737400",
            "e520e4109a0b8b5b3a5df3542ced23d9333f027168b16d089eb2e685f94211d",
            "fd31626f81151e430d7b53940ace07726bc3a2cadd5a29421355578e9ad1740c",
            "6c0fe002e000100015180005800320d02000151806a8b34b56a78aa9d3a8f04",
            "74657374007e16817ec8b2b4fa87ee0f610b3fdb8767a4ae5875319837fe045b",
            "ec4243ff26f3e122246cec09d08b9f88d346ecf422ff33a57b8b93081383e9c",
            "416f69637b9"
        ))
        .expect("TEST-75 packet hex");
        let (_, _, records, end) = wire::parse_sections(&packet).expect("TEST-75 DS denial");
        assert_eq!(end, packet.len());
        assert!(nsec3_proves_ds_absence(&records, "untrusted.test").unwrap());
    }

    #[test]
    fn nsec3_optout_requires_a_closest_encloser_and_covering_range() {
        let parameters = nsec3_parameters(0);
        let zone_hash = nsec3_hash("example", &parameters).expect("zone hash");
        let child_hash = nsec3_hash("child.example", &parameters).expect("child hash");
        let mut low = child_hash.clone();
        decrement_hash(&mut low);
        let mut high = child_hash.clone();
        increment_hash(&mut high);
        let mut zone_next = zone_hash.clone();
        increment_hash(&mut zone_next);
        assert!(low.as_slice() < child_hash.as_slice() && child_hash.as_slice() < high.as_slice());

        let optout = nsec3_packet(&[
            nsec3_record(&zone_hash, "example", 0, &zone_next, &[6, 46, 50]),
            nsec3_record(&low, "example", 1, &high, &[46, 50]),
        ]);
        let (_, _, records, _) = wire::parse_sections(&optout).expect("opt-out NSEC3 packet");
        assert!(nsec3_proves_ds_absence(&records, "child.example").unwrap());

        let no_optout = nsec3_packet(&[
            nsec3_record(&zone_hash, "example", 0, &zone_next, &[6, 46, 50]),
            nsec3_record(&low, "example", 0, &high, &[46, 50]),
        ]);
        let (_, _, records, _) = wire::parse_sections(&no_optout).expect("plain NSEC3 packet");
        assert!(!nsec3_proves_ds_absence(&records, "child.example").unwrap());

        let no_encloser = nsec3_packet(&[nsec3_record(&low, "example", 1, &high, &[46, 50])]);
        let (_, _, records, _) =
            wire::parse_sections(&no_encloser).expect("incomplete NSEC3 packet");
        assert!(!nsec3_proves_ds_absence(&records, "child.example").unwrap());

        let delegated_encloser = nsec3_packet(&[
            nsec3_record(&zone_hash, "example", 0, &zone_next, &[2, 46, 50]),
            nsec3_record(&low, "example", 1, &high, &[46, 50]),
        ]);
        let (_, _, records, _) =
            wire::parse_sections(&delegated_encloser).expect("delegated encloser packet");
        assert!(!nsec3_proves_ds_absence(&records, "child.example").unwrap());
    }

    #[test]
    fn trust_anchor_filtering_uses_zone_owner_before_dnskey_matching() {
        let key = dnskey_record("example.", &[1, 1, 3, 13, 1, 1, 3, 13, 1]);
        let anchors = [
            parse_positive_trust_anchor_line("example. IN DNSKEY 257 3 ECDSAP256SHA256 AQIDBA==")
                .expect("wrong key in matching zone"),
            parse_positive_trust_anchor_line(
                "other.example. IN DNSKEY 257 3 ECDSAP256SHA256 AQEDDQE=",
            )
            .expect("matching key in different zone"),
        ];

        let trusted_zone = anchors
            .iter()
            .filter(|anchor| dns_names_equal(&anchor.owner, "example."))
            .collect::<Vec<_>>();
        assert!(
            !trusted_zone
                .iter()
                .any(|anchor| trust_anchor_matches_dnskey(anchor, &key).unwrap_or(false))
        );
        assert!(anchors
            .iter()
            .any(|anchor| trust_anchor_matches_dnskey(anchor, &key).unwrap_or(false)));
    }

    fn decrement_hash(hash: &mut [u8]) {
        for byte in hash.iter_mut().rev() {
            let (next, borrow) = byte.overflowing_sub(1);
            *byte = next;
            if !borrow {
                return;
            }
        }
        panic!("cannot decrement zero hash");
    }

    fn increment_hash(hash: &mut [u8]) {
        for byte in hash.iter_mut().rev() {
            let (next, carry) = byte.overflowing_add(1);
            *byte = next;
            if !carry {
                return;
            }
        }
        panic!("cannot increment maximum hash");
    }

    fn nsec3_parameters(flags: u8) -> wire::Nsec3Record {
        wire::Nsec3Record {
            hash_algorithm: 1,
            flags,
            iterations: 0,
            salt: Vec::new(),
            next_hashed_owner: vec![0; 20],
            types: Vec::new(),
        }
    }

    fn nsec_packet(owner: &str, next: &str, types: &[u16]) -> Vec<u8> {
        let mut packet =
            make_query_with_class(owner, wire::TYPE_DS, wire::CLASS_IN, 1).expect("NSEC query");
        packet[2] |= 0x80;
        packet[8..10].copy_from_slice(&1_u16.to_be_bytes());
        let mut rdata = wire::encode_name(next).expect("NSEC next name");
        rdata.extend_from_slice(&type_bitmap(types));
        append_record(&mut packet, owner, wire::TYPE_NSEC, &rdata);
        packet
    }

    fn denial_packet(question: &str, rr_type: u16, authority_count: u16) -> Vec<u8> {
        let mut packet =
            make_query_with_class(question, rr_type, wire::CLASS_IN, 1).expect("denial query");
        packet[2] |= 0x80;
        packet[8..10].copy_from_slice(&authority_count.to_be_bytes());
        packet
    }

    fn wildcard_response(with_proof: bool) -> Vec<u8> {
        let mut packet =
            make_query_with_class("m.wild.example", 16, wire::CLASS_IN, 1).expect("wildcard query");
        packet[2] |= 0x80;
        packet[6..8].copy_from_slice(&2_u16.to_be_bytes());
        packet[8..10].copy_from_slice(&u16::from(with_proof).to_be_bytes());
        append_record(&mut packet, "m.wild.example", 16, &[1, b'x']);

        let mut rrsig = Vec::new();
        rrsig.extend_from_slice(&16_u16.to_be_bytes());
        rrsig.push(13);
        rrsig.push(2);
        rrsig.extend_from_slice(&60_u32.to_be_bytes());
        rrsig.extend_from_slice(&u32::MAX.to_be_bytes());
        rrsig.extend_from_slice(&0_u32.to_be_bytes());
        rrsig.extend_from_slice(&1_u16.to_be_bytes());
        rrsig.extend_from_slice(&wire::encode_name("example").unwrap());
        rrsig.push(1);
        append_record(&mut packet, "m.wild.example", wire::TYPE_RRSIG, &rrsig);
        if with_proof {
            append_nsec(
                &mut packet,
                "a.wild.example",
                "z.wild.example",
                &[1, 46, 47],
            );
            // The closest encloser proof requires an NSEC for the closest encloser itself.
            // Since the source labels is 2 ("wild.example"), we need an NSEC for "wild.example".
            append_nsec(
                &mut packet,
                "wild.example",
                "a.wild.example",
                &[1, 46, 47],
            );
            // We added one more record to the Authority section. Update the count.
            let authority_count = u16::from_be_bytes(packet[8..10].try_into().unwrap());
            packet[8..10].copy_from_slice(&(authority_count + 1).to_be_bytes());
        }
        packet
    }

    fn dname_response(cname_target: &str) -> Vec<u8> {
        let mut packet = make_query_with_class("x.d.example", wire::TYPE_A, wire::CLASS_IN, 1)
            .expect("DNAME query");
        packet[2] |= 0x80;
        packet[6..8].copy_from_slice(&2_u16.to_be_bytes());
        append_record(
            &mut packet,
            "d.example",
            wire::TYPE_DNAME,
            &wire::encode_name("d.target").unwrap(),
        );
        append_record(
            &mut packet,
            "x.d.example",
            wire::TYPE_CNAME,
            &wire::encode_name(cname_target).unwrap(),
        );
        packet
    }

    fn dnskey_response() -> Vec<u8> {
        let mut packet = make_query_with_class("example", wire::TYPE_DNSKEY, wire::CLASS_IN, 1)
            .expect("DNSKEY query");
        packet[2] |= 0x80;
        packet[6..8].copy_from_slice(&2_u16.to_be_bytes());
        append_record(
            &mut packet,
            "example",
            wire::TYPE_DNSKEY,
            &[0x01, 0x01, 3, 13, 1],
        );
        let mut rrsig = Vec::new();
        rrsig.extend_from_slice(&wire::TYPE_DNSKEY.to_be_bytes());
        rrsig.push(13);
        rrsig.push(1);
        rrsig.extend_from_slice(&10_u32.to_be_bytes());
        rrsig.extend_from_slice(&u32::MAX.to_be_bytes());
        rrsig.extend_from_slice(&0_u32.to_be_bytes());
        rrsig.extend_from_slice(&1_u16.to_be_bytes());
        rrsig.extend_from_slice(&wire::encode_name("example").unwrap());
        rrsig.push(1);
        append_record(&mut packet, "example", wire::TYPE_RRSIG, &rrsig);
        packet
    }

    fn dnskey_record(name: &str, rdata: &[u8]) -> wire::ResourceRecord {
        let mut packet = make_query_with_class(name, wire::TYPE_DNSKEY, wire::CLASS_IN, 1)
            .expect("DNSKEY record query");
        packet[2] |= 0x80;
        packet[6..8].copy_from_slice(&1_u16.to_be_bytes());
        append_record(&mut packet, name, wire::TYPE_DNSKEY, rdata);
        let (_, _, records, _) = wire::parse_sections(&packet).expect("DNSKEY record sections");
        records
            .into_iter()
            .find(|record| record.rr_type == wire::TYPE_DNSKEY)
            .expect("DNSKEY test record")
    }

    fn append_nsec(packet: &mut Vec<u8>, owner: &str, next: &str, types: &[u16]) {
        let mut rdata = wire::encode_name(next).expect("NSEC next name");
        rdata.extend_from_slice(&type_bitmap(types));
        append_record(packet, owner, wire::TYPE_NSEC, &rdata);
    }

    fn append_soa(packet: &mut Vec<u8>, owner: &str) {
        let mut rdata = wire::encode_name("ns.example").expect("SOA primary name");
        rdata.extend_from_slice(
            &wire::encode_name("hostmaster.example").expect("SOA responsible name"),
        );
        rdata.extend_from_slice(&[0; 20]);
        append_record(packet, owner, wire::TYPE_SOA, &rdata);
    }

    fn nsec3_packet(records: &[Vec<u8>]) -> Vec<u8> {
        let mut packet = make_query_with_class("child.example", wire::TYPE_DS, wire::CLASS_IN, 1)
            .expect("NSEC3 query");
        packet[2] |= 0x80;
        packet[8..10].copy_from_slice(
            &u16::try_from(records.len())
                .expect("NSEC3 test record count")
                .to_be_bytes(),
        );
        for record in records {
            packet.extend_from_slice(record);
        }
        packet
    }

    fn nsec3_record(
        owner_hash: &[u8],
        zone: &str,
        flags: u8,
        next_hash: &[u8],
        types: &[u16],
    ) -> Vec<u8> {
        let owner = format!("{}.{}", encode_base32hex(owner_hash), zone);
        let mut rdata = vec![
            1,
            flags,
            0,
            0,
            0,
            u8::try_from(next_hash.len()).expect("NSEC3 test hash length"),
        ];
        rdata.extend_from_slice(next_hash);
        rdata.extend_from_slice(&type_bitmap(types));
        let mut record = Vec::new();
        append_record(&mut record, &owner, wire::TYPE_NSEC3, &rdata);
        record
    }

    fn append_record(packet: &mut Vec<u8>, owner: &str, rr_type: u16, rdata: &[u8]) {
        packet.extend_from_slice(&wire::encode_name(owner).expect("record owner"));
        packet.extend_from_slice(&rr_type.to_be_bytes());
        packet.extend_from_slice(&wire::CLASS_IN.to_be_bytes());
        packet.extend_from_slice(&60_u32.to_be_bytes());
        packet.extend_from_slice(
            &u16::try_from(rdata.len())
                .expect("test record RDATA length")
                .to_be_bytes(),
        );
        packet.extend_from_slice(rdata);
    }

    fn type_bitmap(types: &[u16]) -> Vec<u8> {
        assert!(types.iter().all(|rr_type| *rr_type < 256));
        let length = types
            .iter()
            .map(|rr_type| usize::from(*rr_type) / 8 + 1)
            .max()
            .unwrap_or(1);
        let mut output = vec![0, u8::try_from(length).expect("test bitmap length")];
        output.resize(2 + length, 0);
        for rr_type in types {
            let bit = usize::from(*rr_type);
            output[2 + bit / 8] |= 0x80 >> (bit % 8);
        }
        output
    }

    fn encode_base32hex(input: &[u8]) -> String {
        const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";
        let mut accumulator = 0_u64;
        let mut bits = 0_u8;
        let mut output = String::new();
        for byte in input {
            accumulator = (accumulator << 8) | u64::from(*byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                let index =
                    usize::try_from((accumulator >> bits) & 31).expect("base32 alphabet index");
                output.push(char::from(ALPHABET[index]));
                accumulator &= (1_u64 << bits).wrapping_sub(1);
            }
        }
        if bits != 0 {
            let index =
                usize::try_from((accumulator << (5 - bits)) & 31).expect("base32 alphabet index");
            output.push(char::from(ALPHABET[index]));
        }
        output
    }
}
