// SPDX-License-Identifier: LGPL-2.1-or-later
#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{
        classify_redirect_answer, extract_address_records, make_query, RedirectAnswer,
    };
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn loads_object_and_array_record_files() {
        let directory = temporary_directory("records");
        fs::create_dir_all(&directory).expect("static record directory");
        fs::write(
            directory.join("address.rr"),
            r#"{"key":{"name":"host.example","type":1},"address":[192,0,2,80]}"#,
        )
        .expect("A record");
        fs::write(
            directory.join("aliases.rr"),
            r#"[
                {"key":{"name":"alias.example","type":5},"name":"host.example"},
                {"key":{"name":"host6.example","type":28},"address":"2001:db8::80"}
            ]"#,
        )
        .expect("record array");

        let mut database = StaticRecords::new(true, vec![directory.clone()]);
        database.force_reload().expect("static record reload");

        let query = make_query("host.example", TYPE_A, 0x1234).expect("A query");
        let response = database
            .answer(&query)
            .expect("static answer")
            .expect("known static name");
        let addresses = extract_address_records(&response, Some(2)).expect("addresses");
        assert_eq!(addresses.addresses, vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 80))]);

        let query = make_query("alias.example", TYPE_A, 0x1235).expect("alias query");
        let response = database
            .answer(&query)
            .expect("static alias answer")
            .expect("known alias");
        assert_eq!(
            classify_redirect_answer(&response),
            Ok(RedirectAnswer::Redirect {
                canonical_name: "host.example".to_owned(),
                redirects: 1,
            })
        );
        fs::remove_dir_all(directory).expect("remove static record directory");
    }

    #[test]
    fn lookup_is_exact_and_known_names_return_nodata() {
        let directory = temporary_directory("exact");
        fs::create_dir_all(&directory).expect("static record directory");
        fs::write(
            directory.join("record.rr"),
            r#"{"key":{"name":"exact.example","type":1},"address":"192.0.2.81"}"#,
        )
        .expect("static record");
        let mut database = StaticRecords::new(true, vec![directory.clone()]);
        database.force_reload().expect("static record reload");

        let child = make_query("child.exact.example", TYPE_A, 1).expect("child query");
        assert!(database.answer(&child).expect("child lookup").is_none());

        let aaaa = make_query("exact.example", TYPE_AAAA, 2).expect("AAAA query");
        let answer = database
            .answer(&aaaa)
            .expect("AAAA lookup")
            .expect("known owner");
        assert_eq!(u16::from_be_bytes([answer[6], answer[7]]), 0);
        fs::remove_dir_all(directory).expect("remove static record directory");
    }

    #[test]
    fn higher_priority_files_override_and_dev_null_masks() {
        let low = temporary_directory("low");
        let high = temporary_directory("high");
        fs::create_dir_all(&low).expect("low priority directory");
        fs::create_dir_all(&high).expect("high priority directory");
        fs::write(
            low.join("same.rr"),
            r#"{"key":{"name":"low.example","type":1},"address":"192.0.2.82"}"#,
        )
        .expect("low record");
        fs::write(
            high.join("same.rr"),
            r#"{"key":{"name":"high.example","type":1},"address":"192.0.2.83"}"#,
        )
        .expect("high record");

        let mut database = StaticRecords::new(true, vec![low.clone(), high.clone()]);
        database.force_reload().expect("override reload");
        let low_query = make_query("low.example", TYPE_A, 1).expect("low query");
        let high_query = make_query("high.example", TYPE_A, 2).expect("high query");
        assert!(database.answer(&low_query).expect("low lookup").is_none());
        assert!(database
            .answer(&high_query)
            .expect("high lookup")
            .is_some());

        fs::remove_file(high.join("same.rr")).expect("remove high record");
        std::os::unix::fs::symlink("/dev/null", high.join("same.rr")).expect("mask record");
        database.force_reload().expect("masked reload");
        assert!(database.answer(&low_query).expect("masked lookup").is_none());

        fs::remove_dir_all(low).expect("remove low directory");
        fs::remove_dir_all(high).expect("remove high directory");
    }

    #[test]
    fn malformed_and_unsupported_records_are_skipped() {
        let directory = temporary_directory("invalid");
        fs::create_dir_all(&directory).expect("static record directory");
        fs::write(directory.join("broken.rr"), "not-json").expect("broken record");
        fs::write(
            directory.join("unsupported.rr"),
            r#"{"key":{"name":"txt.example","type":16},"name":"ignored"}"#,
        )
        .expect("unsupported record");
        let mut database = StaticRecords::new(true, vec![directory.clone()]);
        database.force_reload().expect("static record reload");
        let query = make_query("txt.example", 16, 1).expect("TXT query");
        assert!(database.answer(&query).expect("unsupported lookup").is_none());
        fs::remove_dir_all(directory).expect("remove static record directory");
    }

    fn temporary_directory(label: &str) -> PathBuf {
        let serial = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "rustd-resolved-static-{label}-{}-{serial}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&directory);
        directory
    }
}
