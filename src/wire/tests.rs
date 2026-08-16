// SPDX-License-Identifier: LGPL-2.1-or-later
#[cfg(test)]
mod tests {
    use super::*;

    fn append_answer(packet: &mut Vec<u8>, owner: &[u8], rr_type: u16, rdata: &[u8]) {
        packet.extend_from_slice(owner);
        packet.extend_from_slice(&rr_type.to_be_bytes());
        packet.extend_from_slice(&CLASS_IN.to_be_bytes());
        packet.extend_from_slice(&60u32.to_be_bytes());
        packet.extend_from_slice(
            &u16::try_from(rdata.len())
                .expect("test RDATA length")
                .to_be_bytes(),
        );
        packet.extend_from_slice(rdata);
    }

    fn response_with_record(
        rr_type: u16,
        class: u16,
        ttl: u32,
        rdata: &[u8],
    ) -> Vec<u8> {
        let query = make_query("example.test", TYPE_A, 0x5151).expect("query");
        let end = question_end(&query).expect("question end");
        let mut response = query[..end].to_vec();
        response[2..4].copy_from_slice(&(FLAG_QR | FLAG_RA | FLAG_RD).to_be_bytes());
        response[6..8].copy_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&rr_type.to_be_bytes());
        response.extend_from_slice(&class.to_be_bytes());
        response.extend_from_slice(&ttl.to_be_bytes());
        response.extend_from_slice(
            &u16::try_from(rdata.len())
                .expect("test RDATA length")
                .to_be_bytes(),
        );
        response.extend_from_slice(rdata);
        response
    }

    #[test]
    fn query_round_trip() {
        let packet = make_query("Example.COM.", TYPE_A, 0x1234).expect("query");
        validate(&packet, false).expect("valid query");
        assert_eq!(first_question(&packet).expect("question").name.text(), "Example.COM");
    }

    #[test]
    fn utf8_and_escaped_dns_labels_round_trip() {
        let packet = make_query(r"Caf\195\169\046Desk._demo._tcp.bücher.local", TYPE_SRV, 1)
            .expect("UTF-8 service query");
        validate(&packet, false).expect("valid UTF-8 query");
        let question = first_question(&packet).expect("question");
        assert_eq!(
            question.name.text(),
            r"Caf\195\169\046Desk._demo._tcp.b\195\188cher.local"
        );
        assert_eq!(
            String::from_utf8(decode_label(r"Caf\195\169\046Desk").expect("service label"))
                .expect("UTF-8 service label"),
            "Café.Desk"
        );
    }

    #[test]
    fn malformed_presentation_escapes_are_rejected() {
        for name in [
            "",
            "example..test",
            "example\\",
            r"example\999",
            r"example\z",
            r"example\1",
            r"example\12",
            "bad\nname.test",
            "bad\u{7f}name.test",
        ] {
            assert!(encode_name(name).is_err(), "accepted {name:?}");
        }
        assert!(encode_name(r"escaped\010label.test").is_ok());
        assert!(encode_name(r"escaped\.dot.test").is_ok());
        assert!(encode_name(r"escaped\\slash.test").is_ok());
    }

    #[test]
    fn reserved_and_pseudo_question_types_are_rejected() {
        for rr_type in [0, TYPE_OPT, TYPE_RRSIG, 249, TYPE_TSIG] {
            assert_eq!(
                make_query("example.test", rr_type, 1),
                Err(WireError::InvalidQuestionType(rr_type))
            );

            let mut query = make_query("example.test", TYPE_A, 1).expect("base query");
            let type_offset = question_end(&query).expect("question end") - 4;
            query[type_offset..type_offset + 2].copy_from_slice(&rr_type.to_be_bytes());
            assert_eq!(
                validate(&query, false),
                Err(WireError::InvalidQuestionType(rr_type))
            );

            query[2] |= 0x80;
            assert_eq!(
                validate(&query, true),
                Err(WireError::InvalidQuestionType(rr_type))
            );
        }
    }

    #[test]
    fn zone_transfer_and_any_question_types_remain_parseable() {
        for rr_type in [TYPE_IXFR, TYPE_AXFR, TYPE_ANY] {
            validate(
                &make_query("example.test", rr_type, 1).expect("valid question type"),
                false,
            )
            .expect("query packet");
        }
    }

    #[test]
    fn unicast_queries_reject_truncation_and_answer_sections() {
        let mut truncated = make_query("example.test", TYPE_A, 1).expect("query");
        truncated[2] |= 0x02;
        assert_eq!(validate(&truncated, false), Err(WireError::TruncatedQuery));

        let mut answered = make_query("example.test", TYPE_A, 1).expect("query");
        answered[6..8].copy_from_slice(&1u16.to_be_bytes());
        append_answer(&mut answered, &[0xc0, 0x0c], TYPE_A, &[192, 0, 2, 1]);
        assert_eq!(
            validate(&answered, false),
            Err(WireError::QueryContainsAnswers(1))
        );
    }

    #[test]
    fn checking_disabled_is_echoed_and_suppresses_authenticated_data() {
        let mut query = make_query("signed.test", TYPE_A, 7).expect("query");
        let query_flags = u16::from_be_bytes([query[2], query[3]]) | FLAG_CD;
        query[2..4].copy_from_slice(&query_flags.to_be_bytes());
        let mut response = local_response(
            &query,
            &[LocalRecord::A(Ipv4Addr::new(192, 0, 2, 1))],
            60,
        )
        .expect("response");
        set_authenticated_data(&mut response, true).expect("AD");

        apply_query_validation_flags(&query, &mut response).expect("validation flags");

        let header = Header::parse(&response).expect("header");
        assert!(header.checking_disabled());
        assert!(!header.authentic_data());
    }

    #[test]
    fn compression_cycle_is_rejected() {
        let mut packet = vec![0; DNS_HEADER_LEN];
        packet[4..6].copy_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
        assert_eq!(validate(&packet, false), Err(WireError::CompressionLoop));
    }

    #[test]
    fn servfail_preserves_the_question() {
        let mut query = make_query("example.com", TYPE_AAAA, 44).expect("query");
        query[3] |= 0x20;
        let response = servfail_for(&query).expect("response");
        let header = Header::parse(&response).expect("header");
        assert_eq!(header.response_code(), 2);
        assert!(!header.authentic_data());
        response_matches(&query, &response).expect("matching response");
    }

    #[test]
    fn nxdomain_preserves_the_question_and_clears_sections() {
        let query = make_query("hello.invalid", TYPE_A, 45).expect("query");
        let response = nxdomain_for(&query).expect("response");
        response_matches(&query, &response).expect("matching response");
        let header = Header::parse(&response).expect("header");
        assert_eq!(header.response_code(), 3);
        assert_eq!(header.total_records(), 0);
    }

    #[test]
    fn local_a_response_is_extractable() {
        let query = make_query("localhost", TYPE_A, 9).expect("query");
        let response = local_response(
            &query,
            &[LocalRecord::A(Ipv4Addr::LOCALHOST)],
            0,
        )
        .expect("response");
        assert_eq!(
            extract_addresses(&response, Some(2)).expect("addresses"),
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]
        );
    }

    #[test]
    fn local_alias_response_uses_the_canonical_owner() {
        let query = make_query("alias.example", TYPE_A, 10).expect("query");
        let response = local_response(
            &query,
            &[
                LocalRecord::Cname("host.example".to_owned()),
                LocalRecord::NamedA(
                    "host.example".to_owned(),
                    Ipv4Addr::new(192, 0, 2, 10),
                ),
            ],
            0,
        )
        .expect("response");
        let answers = extract_answer_records(&response).expect("answers");
        assert_eq!(answers.len(), 2);
        assert_eq!(answers[0].name.text(), "alias.example");
        assert_eq!(answers[0].rr_type, TYPE_CNAME);
        assert_eq!(answers[1].name.text(), "host.example");
        assert_eq!(answers[1].rr_type, TYPE_A);
        let addresses = extract_address_records(&response, Some(2)).expect("addresses");
        assert_eq!(addresses.canonical_name, "host.example");
        assert_eq!(
            addresses.addresses,
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]
        );
    }

    #[test]
    fn answer_export_expands_compressed_rdata_names() {
        let query = make_query("mail.example", 15, 10).expect("query");
        let end = question_end(&query).expect("question end");
        let mut response = query[..end].to_vec();
        response[2..4].copy_from_slice(&(FLAG_QR | FLAG_RA | FLAG_RD).to_be_bytes());
        response[6..8].copy_from_slice(&1u16.to_be_bytes());
        append_answer(&mut response, &[0xc0, 0x0c], 15, &[0, 10, 0xc0, 0x0c]);

        let records = extract_answer_records(&response).expect("answer records");
        let mut expected = vec![0, 10];
        expected.extend_from_slice(&encode_name("mail.example").expect("exchange"));
        assert_eq!(records[0].rdata, expected);
        assert!(!records[0].raw.windows(2).any(|window| window == [0xc0, 0x0c]));
    }

    #[test]
    fn answer_export_expands_every_compressible_rdata_name() {
        let target = encode_name("example.test").expect("target");
        let pointer = [0xc0, 0x0c];
        let mut soa = pointer.to_vec();
        soa.extend_from_slice(&pointer);
        soa.extend_from_slice(&[0; 20]);
        let mut canonical_soa = target.clone();
        canonical_soa.extend_from_slice(&target);
        canonical_soa.extend_from_slice(&[0; 20]);
        let mut mx = 10u16.to_be_bytes().to_vec();
        mx.extend_from_slice(&pointer);
        let mut canonical_mx = 10u16.to_be_bytes().to_vec();
        canonical_mx.extend_from_slice(&target);
        let mut srv = vec![0; 6];
        srv.extend_from_slice(&pointer);
        let mut canonical_srv = vec![0; 6];
        canonical_srv.extend_from_slice(&target);

        for (rr_type, rdata, expected) in [
            (TYPE_NS, pointer.to_vec(), target.clone()),
            (TYPE_CNAME, pointer.to_vec(), target.clone()),
            (TYPE_PTR, pointer.to_vec(), target.clone()),
            (TYPE_DNAME, pointer.to_vec(), target.clone()),
            (TYPE_SOA, soa, canonical_soa),
            (15, mx, canonical_mx),
            (TYPE_SRV, srv, canonical_srv),
        ] {
            let record = extract_answer_records(&response_with_record(
                rr_type,
                CLASS_IN,
                60,
                &rdata,
            ))
            .unwrap_or_else(|error| panic!("type {rr_type} extraction failed: {error}"))
            .remove(0);
            assert_eq!(record.rdata, expected, "type {rr_type}");
        }
    }

    #[test]
    fn canonical_raw_records_refuse_all_name_compression() {
        let owner = encode_name("example.test").expect("owner");
        let mut raw = owner.clone();
        raw.extend_from_slice(&TYPE_NS.to_be_bytes());
        raw.extend_from_slice(&CLASS_IN.to_be_bytes());
        raw.extend_from_slice(&60u32.to_be_bytes());
        raw.extend_from_slice(&2u16.to_be_bytes());
        raw.extend_from_slice(&[0xc0, 0]);

        parse_record(&raw, 0).expect("network record permits NS compression");
        assert_eq!(
            parse_uncompressed_record(&raw, 0),
            Err(WireError::InvalidRecord)
        );

        let mut canonical = owner.clone();
        canonical.extend_from_slice(&TYPE_NS.to_be_bytes());
        canonical.extend_from_slice(&CLASS_IN.to_be_bytes());
        canonical.extend_from_slice(&60u32.to_be_bytes());
        canonical.extend_from_slice(
            &u16::try_from(owner.len())
                .expect("owner length")
                .to_be_bytes(),
        );
        canonical.extend_from_slice(&owner);
        parse_uncompressed_record(&canonical, 0).expect("canonical raw record");
    }

    #[test]
    fn cname_chain_returns_only_the_canonical_owner_addresses() {
        let query = make_query("Alias.Example", TYPE_A, 0x1235).expect("query");
        let end = question_end(&query).expect("question end");
        let mut response = query[..end].to_vec();
        response[2..4].copy_from_slice(&(FLAG_QR | FLAG_RA | FLAG_RD).to_be_bytes());
        response[6..8].copy_from_slice(&3u16.to_be_bytes());

        let canonical = encode_name("Real.Example").expect("canonical name");
        append_answer(&mut response, &[0xc0, 0x0c], TYPE_CNAME, &canonical);
        append_answer(
            &mut response,
            &encode_name("unrelated.example").expect("unrelated owner"),
            TYPE_A,
            &[203, 0, 113, 9],
        );
        append_answer(
            &mut response,
            &canonical,
            TYPE_A,
            &[192, 0, 2, 10],
        );

        let records = extract_address_records(&response, Some(2)).expect("address records");
        assert_eq!(records.canonical_name, "Real.Example");
        assert_eq!(
            records.addresses,
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]
        );
    }

    #[test]
    fn cname_loop_is_rejected() {
        let query = make_query("alias.example", TYPE_A, 0x1236).expect("query");
        let end = question_end(&query).expect("question end");
        let mut response = query[..end].to_vec();
        response[2..4].copy_from_slice(&(FLAG_QR | FLAG_RA | FLAG_RD).to_be_bytes());
        response[6..8].copy_from_slice(&2u16.to_be_bytes());

        let second = encode_name("second.example").expect("second name");
        let first = encode_name("alias.example").expect("first name");
        append_answer(&mut response, &[0xc0, 0x0c], TYPE_CNAME, &second);
        append_answer(&mut response, &second, TYPE_CNAME, &first);

        assert_eq!(
            extract_address_records(&response, Some(2)),
            Err(WireError::InvalidRecord)
        );
    }

    #[test]
    fn cname_owner_cannot_also_hold_address_data() {
        let query = make_query("alias.example", TYPE_A, 0x1237).expect("query");
        let end = question_end(&query).expect("question end");
        let mut response = query[..end].to_vec();
        response[2..4].copy_from_slice(&(FLAG_QR | FLAG_RA | FLAG_RD).to_be_bytes());
        response[6..8].copy_from_slice(&2u16.to_be_bytes());

        let canonical = encode_name("real.example").expect("canonical name");
        append_answer(&mut response, &[0xc0, 0x0c], TYPE_CNAME, &canonical);
        append_answer(
            &mut response,
            &[0xc0, 0x0c],
            TYPE_A,
            &[192, 0, 2, 11],
        );

        assert_eq!(
            extract_address_records(&response, Some(2)),
            Err(WireError::InvalidRecord)
        );
    }

    #[test]
    fn dname_rewrites_the_most_specific_suffix() {
        let query = make_query("Api.Branch.Example", TYPE_A, 0x1238).expect("query");
        let end = question_end(&query).expect("question end");
        let mut response = query[..end].to_vec();
        response[2..4].copy_from_slice(&(FLAG_QR | FLAG_RA | FLAG_RD).to_be_bytes());
        response[6..8].copy_from_slice(&4u16.to_be_bytes());

        append_answer(
            &mut response,
            &encode_name("Example").expect("parent owner"),
            TYPE_DNAME,
            &encode_name("fallback.test").expect("parent target"),
        );
        append_answer(
            &mut response,
            &encode_name("Branch.Example").expect("specific owner"),
            TYPE_DNAME,
            &encode_name("Service.Test").expect("specific target"),
        );
        append_answer(
            &mut response,
            &encode_name("unrelated.test").expect("unrelated owner"),
            TYPE_A,
            &[203, 0, 113, 20],
        );
        append_answer(
            &mut response,
            &encode_name("api.service.test").expect("rewritten owner"),
            TYPE_A,
            &[192, 0, 2, 20],
        );

        let records = extract_address_records(&response, Some(2)).expect("address records");
        assert_eq!(records.canonical_name, "Api.Service.Test");
        assert_eq!(
            records.addresses,
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20))]
        );
    }

    #[test]
    fn explicit_cname_takes_precedence_over_covering_dname() {
        let query = make_query("host.branch.example", TYPE_A, 0x1239).expect("query");
        let end = question_end(&query).expect("question end");
        let mut response = query[..end].to_vec();
        response[2..4].copy_from_slice(&(FLAG_QR | FLAG_RA | FLAG_RD).to_be_bytes());
        response[6..8].copy_from_slice(&3u16.to_be_bytes());

        append_answer(
            &mut response,
            &encode_name("branch.example").expect("DNAME owner"),
            TYPE_DNAME,
            &encode_name("redirect.test").expect("DNAME target"),
        );
        append_answer(
            &mut response,
            &[0xc0, 0x0c],
            TYPE_CNAME,
            &encode_name("explicit.test").expect("CNAME target"),
        );
        append_answer(
            &mut response,
            &encode_name("explicit.test").expect("address owner"),
            TYPE_A,
            &[192, 0, 2, 21],
        );

        let records = extract_address_records(&response, Some(2)).expect("address records");
        assert_eq!(records.canonical_name, "explicit.test");
        assert_eq!(
            records.addresses,
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 21))]
        );
    }

    #[test]
    fn dname_loop_is_rejected() {
        let query = make_query("host.a.test", TYPE_A, 0x1240).expect("query");
        let end = question_end(&query).expect("question end");
        let mut response = query[..end].to_vec();
        response[2..4].copy_from_slice(&(FLAG_QR | FLAG_RA | FLAG_RD).to_be_bytes());
        response[6..8].copy_from_slice(&2u16.to_be_bytes());

        append_answer(
            &mut response,
            &encode_name("a.test").expect("first owner"),
            TYPE_DNAME,
            &encode_name("b.test").expect("first target"),
        );
        append_answer(
            &mut response,
            &encode_name("b.test").expect("second owner"),
            TYPE_DNAME,
            &encode_name("a.test").expect("second target"),
        );

        assert_eq!(
            extract_address_records(&response, Some(2)),
            Err(WireError::InvalidRecord)
        );
    }

    #[test]
    fn cname_and_dname_cannot_share_an_owner() {
        let query = make_query("alias.example", TYPE_A, 0x1241).expect("query");
        let end = question_end(&query).expect("question end");
        let mut response = query[..end].to_vec();
        response[2..4].copy_from_slice(&(FLAG_QR | FLAG_RA | FLAG_RD).to_be_bytes());
        response[6..8].copy_from_slice(&2u16.to_be_bytes());

        append_answer(
            &mut response,
            &[0xc0, 0x0c],
            TYPE_CNAME,
            &encode_name("real.example").expect("CNAME target"),
        );
        append_answer(
            &mut response,
            &[0xc0, 0x0c],
            TYPE_DNAME,
            &encode_name("redirect.example").expect("DNAME target"),
        );

        assert_eq!(
            extract_address_records(&response, Some(2)),
            Err(WireError::InvalidRecord)
        );
    }

    #[test]
    fn reverse_names_round_trip() {
        let addresses = [
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V6("2001:db8::1".parse().expect("IPv6")),
        ];
        for address in addresses {
            assert_eq!(parse_reverse_name(&reverse_name(address)), Some(address));
        }
    }

    #[test]
    fn service_records_are_extracted() {
        let query = make_query("_demo._tcp.example", TYPE_SRV, 0x4242).expect("query");
        let question_end = question_end(&query).expect("question end");
        let mut response = query[..question_end].to_vec();
        response[2..4].copy_from_slice(&(FLAG_QR | FLAG_RA | FLAG_RD).to_be_bytes());
        response[6..8].copy_from_slice(&2u16.to_be_bytes());

        let target = encode_name("host.example").expect("target");
        let srv_length = u16::try_from(6 + target.len()).expect("SRV length");
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&TYPE_SRV.to_be_bytes());
        response.extend_from_slice(&CLASS_IN.to_be_bytes());
        response.extend_from_slice(&120u32.to_be_bytes());
        response.extend_from_slice(&srv_length.to_be_bytes());
        response.extend_from_slice(&10u16.to_be_bytes());
        response.extend_from_slice(&20u16.to_be_bytes());
        response.extend_from_slice(&8080u16.to_be_bytes());
        response.extend_from_slice(&target);

        let txt = b"path=/";
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&TYPE_TXT.to_be_bytes());
        response.extend_from_slice(&CLASS_IN.to_be_bytes());
        response.extend_from_slice(&120u32.to_be_bytes());
        response.extend_from_slice(
            &u16::try_from(txt.len() + 1)
                .expect("TXT length")
                .to_be_bytes(),
        );
        response.push(u8::try_from(txt.len()).expect("TXT item length"));
        response.extend_from_slice(txt);

        let records = extract_service_records(&response).expect("service records");
        assert_eq!(
            records.srv,
            vec![SrvRecord {
                priority: 10,
                weight: 20,
                port: 8080,
                target: read_name(&target, 0).expect("target name").0,
            }]
        );
        assert_eq!(records.txt, vec![txt.to_vec()]);
    }

    #[test]
    fn service_records_are_limited_to_the_canonical_owner() {
        let query = make_query("_demo._tcp.example", TYPE_SRV, 0x4244).expect("query");
        let question_end = question_end(&query).expect("question end");
        let mut response = query[..question_end].to_vec();
        response[2..4].copy_from_slice(&(FLAG_QR | FLAG_RA | FLAG_RD).to_be_bytes());
        response[6..8].copy_from_slice(&4u16.to_be_bytes());

        let target = encode_name("host.example").expect("target");
        let mut srv = Vec::new();
        srv.extend_from_slice(&10u16.to_be_bytes());
        srv.extend_from_slice(&20u16.to_be_bytes());
        srv.extend_from_slice(&8080u16.to_be_bytes());
        srv.extend_from_slice(&target);
        append_answer(&mut response, &[0xc0, 0x0c], TYPE_SRV, &srv);
        append_answer(
            &mut response,
            &encode_name("_other._tcp.example").expect("unrelated owner"),
            TYPE_SRV,
            &srv,
        );

        let txt = b"path=/";
        let mut txt_rdata = vec![u8::try_from(txt.len()).expect("TXT length")];
        txt_rdata.extend_from_slice(txt);
        append_answer(&mut response, &[0xc0, 0x0c], TYPE_TXT, &txt_rdata);
        append_answer(
            &mut response,
            &encode_name("_other._tcp.example").expect("unrelated owner"),
            TYPE_TXT,
            &txt_rdata,
        );

        let records = extract_service_records_for_name(
            &response,
            "_DEMO._TCP.EXAMPLE.",
        )
        .expect("matching service records");
        assert_eq!(records.srv.len(), 1);
        assert_eq!(records.txt, vec![txt.to_vec()]);
    }

    #[test]
    fn answer_records_are_limited_to_the_canonical_question() {
        let query = make_query("canonical.example", TYPE_A, 0x4245).expect("query");
        let question_end = question_end(&query).expect("question end");
        let mut response = query[..question_end].to_vec();
        response[2..4].copy_from_slice(&(FLAG_QR | FLAG_RA | FLAG_RD).to_be_bytes());
        response[6..8].copy_from_slice(&3u16.to_be_bytes());
        append_answer(
            &mut response,
            &[0xc0, 0x0c],
            TYPE_A,
            &[192, 0, 2, 1],
        );
        append_answer(
            &mut response,
            &encode_name("unrelated.example").expect("unrelated owner"),
            TYPE_A,
            &[192, 0, 2, 2],
        );
        append_answer(&mut response, &[0xc0, 0x0c], TYPE_AAAA, &[0; 16]);

        let records = extract_matching_answer_records(
            &response,
            "CANONICAL.EXAMPLE.",
            CLASS_IN,
            TYPE_A,
        )
        .expect("matching answer records");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].rdata, vec![192, 0, 2, 1]);

        let any_records = extract_matching_answer_records(
            &response,
            "canonical.example",
            CLASS_ANY,
            TYPE_ANY,
        )
        .expect("ANY answer records");
        assert_eq!(any_records.len(), 2);
    }

    #[test]
    fn malformed_txt_record_is_rejected() {
        let query = make_query("_demo._tcp.example", TYPE_TXT, 0x4243).expect("query");
        let question_end = question_end(&query).expect("question end");
        let mut response = query[..question_end].to_vec();
        response[2..4].copy_from_slice(&(FLAG_QR | FLAG_RA | FLAG_RD).to_be_bytes());
        response[6..8].copy_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&TYPE_TXT.to_be_bytes());
        response.extend_from_slice(&CLASS_IN.to_be_bytes());
        response.extend_from_slice(&120u32.to_be_bytes());
        response.extend_from_slice(&2u16.to_be_bytes());
        response.extend_from_slice(&[5, b'x']);

        assert_eq!(
            extract_service_records(&response),
            Err(WireError::InvalidRecord)
        );
    }

    #[test]
    fn known_resource_record_shapes_are_validated() {
        let target = encode_name("target.test").expect("target");
        let malformed = [
            (TYPE_A, vec![192, 0, 2]),
            (TYPE_AAAA, vec![0; 15]),
            (TYPE_NS, vec![0, 0]),
            (TYPE_SOA, target.clone()),
            (13, vec![1, b'x']),
            (15, vec![0]),
            (TYPE_TXT, vec![2, b'x']),
            (29, vec![0; 15]),
            (TYPE_SRV, vec![0; 6]),
            (43, vec![0; 4]),
            (44, vec![0; 2]),
            (TYPE_RRSIG, vec![0; 18]),
            (47, vec![0, 0, 1, 0]),
            (48, vec![0; 4]),
            (50, vec![1, 0, 0, 0, 0, 0]),
            (52, vec![0; 3]),
            (64, vec![0, 1]),
            (257, vec![0]),
        ];

        for (rr_type, rdata) in malformed {
            let packet = response_with_record(rr_type, CLASS_IN, 60, &rdata);
            assert!(
                validate(&packet, true).is_err(),
                "malformed type {rr_type} was accepted"
            );
        }
    }

    #[test]
    fn parsed_resource_record_types_accept_pinned_valid_shapes() {
        let target = encode_name("target.test").expect("target");
        let mut soa = target.clone();
        soa.extend_from_slice(&target);
        soa.extend_from_slice(&[0; 20]);
        let mut mx = 10u16.to_be_bytes().to_vec();
        mx.extend_from_slice(&target);
        let mut srv = vec![0; 6];
        srv.extend_from_slice(&target);
        let mut rrsig = vec![0; 18];
        rrsig.extend_from_slice(&target);
        rrsig.push(1);
        let mut nsec = target.clone();
        nsec.extend_from_slice(&[0, 1, 0x40]);
        let mut svcb = 1u16.to_be_bytes().to_vec();
        svcb.extend_from_slice(&target);
        svcb.extend_from_slice(&[0, 3, 0, 2, 0x01, 0xbb]);
        let mut naptr = vec![0, 1, 0, 2, 1, b's', 0, 0];
        naptr.extend_from_slice(&target);
        let valid = [
            (TYPE_A, vec![192, 0, 2, 1]),
            (TYPE_AAAA, vec![0; 16]),
            (TYPE_NS, target.clone()),
            (TYPE_SOA, soa),
            (13, vec![1, b'x', 1, b'y']),
            (15, mx),
            (TYPE_TXT, Vec::new()),
            (29, vec![0, 0x12, 0x13, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            (TYPE_SRV, srv),
            (35, naptr),
            (43, vec![0; 5]),
            (44, vec![0; 3]),
            (TYPE_RRSIG, rrsig),
            (47, nsec),
            (48, vec![0; 5]),
            (50, vec![1, 0, 0, 0, 0, 1, 1]),
            (52, vec![0; 4]),
            (64, svcb),
            (257, vec![0, 1, b'a']),
        ];

        for (rr_type, rdata) in valid {
            let packet = response_with_record(rr_type, CLASS_IN, 60, &rdata);
            validate(&packet, true)
                .unwrap_or_else(|error| panic!("valid type {rr_type} was rejected: {error}"));
        }
    }

    #[test]
    fn forbidden_rdata_name_compression_is_rejected() {
        let pointer = [0xc0, 0x0c];
        let mut rrsig = vec![0; 18];
        rrsig.extend_from_slice(&pointer);
        rrsig.push(1);
        let mut nsec = pointer.to_vec();
        nsec.extend_from_slice(&[0, 1, 0x40]);
        let mut svcb = 1u16.to_be_bytes().to_vec();
        svcb.extend_from_slice(&pointer);
        let mut naptr = vec![0, 1, 0, 2, 0, 0, 0];
        naptr.extend_from_slice(&pointer);

        for (rr_type, rdata) in [
            (TYPE_RRSIG, rrsig),
            (47, nsec),
            (64, svcb),
            (35, naptr),
        ] {
            assert_eq!(
                validate(
                    &response_with_record(rr_type, CLASS_IN, 60, &rdata),
                    true
                ),
                Err(WireError::InvalidRecord),
                "type {rr_type} accepted forbidden compression"
            );
        }

        validate(
            &response_with_record(TYPE_NS, CLASS_IN, 60, &pointer),
            true,
        )
        .expect("NS compression remains valid");
    }

    #[test]
    fn svcb_parameter_order_and_lengths_are_validated() {
        let target = encode_name("target.test").expect("target");
        let mut duplicate = 1u16.to_be_bytes().to_vec();
        duplicate.extend_from_slice(&target);
        duplicate.extend_from_slice(&[0, 3, 0, 2, 0x01, 0xbb]);
        duplicate.extend_from_slice(&[0, 3, 0, 2, 0x01, 0xbb]);

        let mut bad_ipv4hint = 1u16.to_be_bytes().to_vec();
        bad_ipv4hint.extend_from_slice(&target);
        bad_ipv4hint.extend_from_slice(&[0, 4, 0, 3, 192, 0, 2]);

        for rdata in [duplicate, bad_ipv4hint] {
            assert_eq!(
                validate(&response_with_record(64, CLASS_IN, 60, &rdata), true),
                Err(WireError::InvalidRecord)
            );
        }
    }

    #[test]
    fn invalid_resource_record_class_and_pseudo_types_are_rejected() {
        assert_eq!(
            validate(
                &response_with_record(TYPE_A, CLASS_ANY, 60, &[192, 0, 2, 1]),
                true
            ),
            Err(WireError::InvalidRecord)
        );
        for rr_type in [TYPE_IXFR, TYPE_AXFR, TYPE_ANY] {
            assert_eq!(
                validate(
                    &response_with_record(rr_type, CLASS_IN, 60, &[1]),
                    true
                ),
                Err(WireError::InvalidRecord)
            );
        }
    }

    #[test]
    fn high_bit_ttl_is_zero_except_for_opt() {
        let packet = response_with_record(TYPE_A, CLASS_IN, 0x8000_0001, &[192, 0, 2, 1]);
        let record = extract_answer_records(&packet).expect("answer").remove(0);
        assert_eq!(record.ttl, 0);

        let packet = response_with_record(TYPE_OPT, 1232, 0x8000_0001, &[]);
        let (_, _, records, _) = parse_sections(&packet).expect("OPT packet");
        assert_eq!(records[0].ttl, 0x8000_0001);
    }

}
