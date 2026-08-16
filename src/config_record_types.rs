// SPDX-License-Identifier: LGPL-2.1-or-later
fn apply_refuse_record_types(destination: &mut BTreeSet<u16>, value: &str) {
    if value.is_empty() {
        destination.clear();
        return;
    }
    for token in value.split_whitespace() {
        if let Some(rr_type) = dns_record_type_from_string(token) {
            destination.insert(rr_type);
        }
    }
}

pub fn dns_record_type_from_string(value: &str) -> Option<u16> {
    if value.len() > 4 && value[..4].eq_ignore_ascii_case("TYPE") {
        return value[4..].parse::<u16>().ok();
    }

    Some(match value {
        "A" => 1,
        "NS" => 2,
        "MD" => 3,
        "MF" => 4,
        "CNAME" => 5,
        "SOA" => 6,
        "MB" => 7,
        "MG" => 8,
        "MR" => 9,
        "NULL" => 10,
        "WKS" => 11,
        "PTR" => 12,
        "HINFO" => 13,
        "MINFO" => 14,
        "MX" => 15,
        "TXT" => 16,
        "RP" => 17,
        "AFSDB" => 18,
        "X25" => 19,
        "ISDN" => 20,
        "RT" => 21,
        "NSAP" => 22,
        "NSAP-PTR" => 23,
        "SIG" => 24,
        "KEY" => 25,
        "PX" => 26,
        "GPOS" => 27,
        "AAAA" => 28,
        "LOC" => 29,
        "NXT" => 30,
        "EID" => 31,
        "NIMLOC" => 32,
        "SRV" => 33,
        "ATMA" => 34,
        "NAPTR" => 35,
        "KX" => 36,
        "CERT" => 37,
        "A6" => 38,
        "DNAME" => 39,
        "SINK" => 40,
        "OPT" => 41,
        "APL" => 42,
        "DS" => 43,
        "SSHFP" => 44,
        "IPSECKEY" => 45,
        "RRSIG" => 46,
        "NSEC" => 47,
        "DNSKEY" => 48,
        "DHCID" => 49,
        "NSEC3" => 50,
        "NSEC3PARAM" => 51,
        "TLSA" => 52,
        "SMIMEA" => 53,
        "HIP" => 55,
        "NINFO" => 56,
        "RKEY" => 57,
        "TALINK" => 58,
        "CDS" => 59,
        "CDNSKEY" => 60,
        "OPENPGPKEY" => 61,
        "CSYNC" => 62,
        "ZONEMD" => 63,
        "SVCB" => 64,
        "HTTPS" => 65,
        "SPF" => 99,
        "UINFO" => 100,
        "UID" => 101,
        "GID" => 102,
        "UNSPEC" => 103,
        "NID" => 104,
        "L32" => 105,
        "L64" => 106,
        "LP" => 107,
        "EUI48" => 108,
        "EUI64" => 109,
        "TKEY" => 249,
        "TSIG" => 250,
        "IXFR" => 251,
        "AXFR" => 252,
        "MAILB" => 253,
        "MAILA" => 254,
        "ANY" => 255,
        "URI" => 256,
        "CAA" => 257,
        "AVC" => 258,
        "DOA" => 259,
        "AMTRELAY" => 260,
        "RESINFO" => 261,
        "TA" => 32768,
        "DLV" => 32769,
        _ => return None,
    })
}

pub fn dns_record_type_name(value: u16) -> Option<&'static str> {
    Some(match value {
        1 => "A",
        2 => "NS",
        3 => "MD",
        4 => "MF",
        5 => "CNAME",
        6 => "SOA",
        7 => "MB",
        8 => "MG",
        9 => "MR",
        10 => "NULL",
        11 => "WKS",
        12 => "PTR",
        13 => "HINFO",
        14 => "MINFO",
        15 => "MX",
        16 => "TXT",
        17 => "RP",
        18 => "AFSDB",
        19 => "X25",
        20 => "ISDN",
        21 => "RT",
        22 => "NSAP",
        23 => "NSAP-PTR",
        24 => "SIG",
        25 => "KEY",
        26 => "PX",
        27 => "GPOS",
        28 => "AAAA",
        29 => "LOC",
        30 => "NXT",
        31 => "EID",
        32 => "NIMLOC",
        33 => "SRV",
        34 => "ATMA",
        35 => "NAPTR",
        36 => "KX",
        37 => "CERT",
        38 => "A6",
        39 => "DNAME",
        40 => "SINK",
        41 => "OPT",
        42 => "APL",
        43 => "DS",
        44 => "SSHFP",
        45 => "IPSECKEY",
        46 => "RRSIG",
        47 => "NSEC",
        48 => "DNSKEY",
        49 => "DHCID",
        50 => "NSEC3",
        51 => "NSEC3PARAM",
        52 => "TLSA",
        53 => "SMIMEA",
        55 => "HIP",
        56 => "NINFO",
        57 => "RKEY",
        58 => "TALINK",
        59 => "CDS",
        60 => "CDNSKEY",
        61 => "OPENPGPKEY",
        62 => "CSYNC",
        63 => "ZONEMD",
        64 => "SVCB",
        65 => "HTTPS",
        99 => "SPF",
        100 => "UINFO",
        101 => "UID",
        102 => "GID",
        103 => "UNSPEC",
        104 => "NID",
        105 => "L32",
        106 => "L64",
        107 => "LP",
        108 => "EUI48",
        109 => "EUI64",
        249 => "TKEY",
        250 => "TSIG",
        251 => "IXFR",
        252 => "AXFR",
        253 => "MAILB",
        254 => "MAILA",
        255 => "ANY",
        256 => "URI",
        257 => "CAA",
        258 => "AVC",
        259 => "DOA",
        260 => "AMTRELAY",
        261 => "RESINFO",
        32768 => "TA",
        32769 => "DLV",
        _ => return None,
    })
}

#[cfg(test)]
mod record_type_tests {
    use super::*;

    #[test]
    fn parses_named_and_rfc3597_record_types() {
        assert_eq!(dns_record_type_from_string("AAAA"), Some(28));
        assert_eq!(dns_record_type_from_string("SRV"), Some(33));
        assert_eq!(dns_record_type_from_string("TYPE65400"), Some(65400));
        assert_eq!(dns_record_type_from_string("type65400"), Some(65400));
        assert_eq!(dns_record_type_from_string("TYPE65536"), None);
        assert_eq!(dns_record_type_from_string("NOT-A-TYPE"), None);
        assert_eq!(dns_record_type_name(23), Some("NSAP-PTR"));
        assert_eq!(dns_record_type_name(261), Some("RESINFO"));
        assert_eq!(dns_record_type_name(54), None);
    }

    #[test]
    fn empty_refuse_assignment_clears_the_set() {
        let mut types = BTreeSet::from([1, 28]);
        apply_refuse_record_types(&mut types, "");
        assert!(types.is_empty());
    }

    #[test]
    fn invalid_refuse_tokens_are_ignored() {
        let mut types = BTreeSet::new();
        apply_refuse_record_types(&mut types, "A bogus TYPE65400");
        assert_eq!(types, BTreeSet::from([1, 65400]));
    }
}
