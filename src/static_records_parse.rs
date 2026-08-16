// SPDX-License-Identifier: LGPL-2.1-or-later
fn add_record_value(database: &mut HashMap<String, Vec<StaticRecord>>, value: &Value) {
    let Some((owner, resource)) = parse_record_value(value) else {
        return;
    };
    let rrset = database.entry(owner).or_default();
    if !rrset.contains(&resource) {
        rrset.push(resource);
    }
}

fn parse_record_value(value: &Value) -> Option<(String, StaticRecord)> {
    let Some(key) = value.get("key") else {
        tracing::warn!("Static record missing 'key' field");
        return None;
    };
    let Some(owner_val) = key.get("name") else {
        tracing::warn!("Static record missing 'key.name' field");
        return None;
    };
    let Some(owner) = owner_val.as_str() else {
        tracing::warn!("Static record 'key.name' is not a string");
        return None;
    };
    if wire::encode_name(owner).is_err() {
        tracing::warn!(owner, "Static record has invalid owner name");
        return None;
    }
    let Some(type_val) = key.get("type") else {
        tracing::warn!("Static record missing 'key.type' field");
        return None;
    };
    let Some(type_u64) = type_val.as_u64() else {
        tracing::warn!("Static record 'key.type' is not a number");
        return None;
    };
    let Ok(rr_type) = u16::try_from(type_u64) else {
        tracing::warn!(type_u64, "Static record 'key.type' is out of range");
        return None;
    };
    let class = match key.get("class") {
        Some(val) => {
            let Some(class_u64) = val.as_u64() else {
                tracing::warn!("Static record 'key.class' is not a number");
                return None;
            };
            let Ok(class) = u16::try_from(class_u64) else {
                tracing::warn!(class_u64, "Static record 'key.class' is out of range");
                return None;
            };
            class
        }
        None => CLASS_IN,
    };

    let rdata = match rr_type {
        TYPE_A => {
            let Some(addr_val) = value.get("address") else {
                tracing::warn!("Static record missing 'address' field for A record");
                return None;
            };
            let Some(ip) = parse_ip_address(addr_val) else {
                tracing::warn!(
                    ?addr_val,
                    "Static record has invalid IP address for A record"
                );
                return None;
            };
            match ip {
                IpAddr::V4(address) => address.octets().to_vec(),
                IpAddr::V6(_) => {
                    tracing::warn!("Static record has IPv6 address for A record");
                    return None;
                }
            }
        }
        TYPE_AAAA => {
            let Some(addr_val) = value.get("address") else {
                tracing::warn!("Static record missing 'address' field for AAAA record");
                return None;
            };
            let Some(ip) = parse_ip_address(addr_val) else {
                tracing::warn!(
                    ?addr_val,
                    "Static record has invalid IP address for AAAA record"
                );
                return None;
            };
            match ip {
                IpAddr::V4(_) => {
                    tracing::warn!("Static record has IPv4 address for AAAA record");
                    return None;
                }
                IpAddr::V6(address) => address.octets().to_vec(),
            }
        }
        TYPE_PTR | TYPE_NS | TYPE_CNAME | TYPE_DNAME => {
            let Some(target_val) = value.get("name") else {
                tracing::warn!("Static record missing 'name' field for pointer record");
                return None;
            };
            let Some(target) = target_val.as_str() else {
                tracing::warn!("Static record 'name' is not a string");
                return None;
            };
            match wire::encode_name(target) {
                Ok(encoded) => encoded,
                Err(_) => {
                    tracing::warn!(target, "Static record has invalid target name");
                    return None;
                }
            }
        }
        _ => {
            tracing::warn!(rr_type, "Static record has unsupported RR type");
            return None;
        }
    };

    Some((
        canonical_name(owner),
        StaticRecord {
            class,
            rr_type,
            rdata,
        },
    ))
}

fn parse_ip_address(value: &Value) -> Option<IpAddr> {
    if let Some(address) = value.as_str() {
        return address.parse().ok();
    }
    let bytes = value
        .as_array()?
        .iter()
        .map(|value| value.as_u64().and_then(|number| u8::try_from(number).ok()))
        .collect::<Option<Vec<_>>>()?;
    match bytes.as_slice() {
        [a, b, c, d] => Some(IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d))),
        bytes if bytes.len() == 16 => {
            let bytes: [u8; 16] = bytes.try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}
