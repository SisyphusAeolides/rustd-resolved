const QUERY_MONITOR_HISTORY_MAX: usize = 256;

impl Resolver {
    pub fn query_monitor_cursor(&self) -> u64 {
        self.query_monitor.sequence.load(Ordering::Acquire)
    }

    pub fn configuration_generation(&self) -> u64 {
        self.routing_generation.load(Ordering::Acquire)
    }

    pub fn wait_query_event(
        &self,
        after: u64,
        timeout: Duration,
    ) -> Option<ResolverQueryEvent> {
        let mut events = self
            .query_monitor
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if let Some(event) = events.iter().find(|event| event.sequence > after) {
                return Some(event.clone());
            }
            let (next, result) = self
                .query_monitor
                .changed
                .wait_timeout(events, timeout)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            events = next;
            if result.timed_out() {
                return None;
            }
        }
    }

    fn publish_query_event(
        &self,
        query: &[u8],
        ifindex: Option<i32>,
        outcome: &Result<(Vec<u8>, u64, Option<i32>), ResolveError>,
    ) {
        let Ok(question) = first_question(query) else {
            return;
        };
        let (state, result, rcode, errno, extended_code, extended_message, answer) =
            query_event_outcome(outcome, ifindex);
        let mut event = ResolverQueryEvent {
            sequence: 0,
            state,
            result,
            rcode,
            errno,
            extended_dns_error_code: extended_code,
            extended_dns_error_message: extended_message,
            question: vec![ResolverResourceKey {
                class: question.class,
                rr_type: question.rr_type,
                name: question.name.text().to_owned(),
            }],
            collected_questions: Vec::new(),
            answer,
        };
        let mut events = self
            .query_monitor
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let sequence = self
            .query_monitor
            .sequence
            .load(Ordering::Relaxed)
            .saturating_add(1);
        event.sequence = sequence;
        events.push_back(event);
        while events.len() > QUERY_MONITOR_HISTORY_MAX {
            events.pop_front();
        }
        self.query_monitor
            .sequence
            .store(sequence, Ordering::Release);
        self.query_monitor.changed.notify_all();
    }
}

#[allow(clippy::type_complexity)]
fn query_event_outcome(
    outcome: &Result<(Vec<u8>, u64, Option<i32>), ResolveError>,
    requested_ifindex: Option<i32>,
) -> (
    String,
    Option<String>,
    Option<u16>,
    Option<i32>,
    Option<u16>,
    Option<String>,
    Vec<ResolverQueryAnswer>,
) {
    match outcome {
        Ok((response, _, response_ifindex)) => {
            let ifindex = response_ifindex.or(requested_ifindex);
            let rcode_result = response_full_rcode(response);
            let (rcode, extended_dns_error_code, extended_dns_error_message) =
                if let Ok(values) = rcode_result {
                    values
                } else {
                    return query_failure("invalid-reply", None);
                };
            let answer = extract_answer_records(response)
                .unwrap_or_default()
                .into_iter()
                .map(|record| ResolverQueryAnswer {
                    raw: record.raw,
                    ifindex: ifindex.filter(|value| *value > 0),
                })
                .collect();
            if rcode == 0 {
                (
                    "success".to_owned(),
                    None,
                    None,
                    None,
                    None,
                    None,
                    answer,
                )
            } else {
                (
                    "rcode-failure".to_owned(),
                    None,
                    Some(rcode),
                    None,
                    extended_dns_error_code,
                    extended_dns_error_message,
                    answer,
                )
            }
        }
        Err(ResolveError::DnsError {
            rcode,
            extended_dns_error_code,
            extended_dns_error_message,
            ..
        }) => (
            "rcode-failure".to_owned(),
            None,
            Some(*rcode),
            None,
            *extended_dns_error_code,
            extended_dns_error_message.clone(),
            Vec::new(),
        ),
        Err(ResolveError::DnssecValidationFailed {
            result,
            extended_dns_error_code,
            extended_dns_error_message,
        }) => (
            "dnssec-failed".to_owned(),
            Some(result.clone()),
            None,
            None,
            *extended_dns_error_code,
            extended_dns_error_message.clone(),
            Vec::new(),
        ),
        Err(ResolveError::NoNameServers) => query_failure("no-servers", None),
        Err(ResolveError::QueryAborted) => query_failure("aborted", None),
        Err(ResolveError::ResourceRecordTypeUnsupported) => {
            query_failure("rr-type-unsupported", None)
        }
        Err(error) if error.is_timeout() => query_failure("timeout", None),
        Err(ResolveError::Io(error)) if error.raw_os_error().is_some() => {
            query_failure("errno", error.raw_os_error().map(i32::abs))
        }
        Err(ResolveError::NoTrustAnchor) => query_failure("no-trust-anchor", None),
        Err(ResolveError::StubLoop) => query_failure("stub-loop", None),
        Err(ResolveError::NoSuchResourceRecord) => query_failure("not-found", None),
        Err(_) => query_failure("invalid-reply", None),
    }
}

#[allow(clippy::type_complexity)]
fn query_failure(
    state: &str,
    errno: Option<i32>,
) -> (
    String,
    Option<String>,
    Option<u16>,
    Option<i32>,
    Option<u16>,
    Option<String>,
    Vec<ResolverQueryAnswer>,
) {
    (
        state.to_owned(),
        None,
        None,
        errno,
        None,
        None,
        Vec::new(),
    )
}

#[cfg(test)]
mod query_monitor_tests {
    use super::*;

    #[test]
    fn completed_query_is_published_after_the_subscription_cursor() {
        let resolver = Resolver::new(Config::default());
        let cursor = resolver.query_monitor_cursor();
        let query = make_query("localhost", TYPE_A, 42).expect("query");
        resolver
            .query(&query, QueryMode::Full)
            .expect("local answer");

        let event = resolver
            .wait_query_event(cursor, Duration::from_millis(10))
            .expect("query event");
        assert_eq!(event.state, "success");
        assert_eq!(event.question.len(), 1);
        assert_eq!(event.question[0].name, "localhost");
        assert_eq!(event.question[0].rr_type, TYPE_A);
        assert!(!event.answer.is_empty());
    }

    #[test]
    fn high_level_hostname_lookup_publishes_each_address_family() {
        let resolver = Resolver::new(Config::default());
        let cursor = resolver.query_monitor_cursor();
        resolver
            .lookup_name("localhost", 0)
            .expect("parallel local address lookup");

        let first = resolver
            .wait_query_event(cursor, Duration::from_millis(10))
            .expect("first address-family event");
        let second = resolver
            .wait_query_event(first.sequence, Duration::from_millis(10))
            .expect("second address-family event");
        let mut types = [first.question[0].rr_type, second.question[0].rr_type];
        types.sort_unstable();
        assert_eq!(types, [TYPE_A, TYPE_AAAA]);
        assert!(!first.answer.is_empty());
        assert!(!second.answer.is_empty());
    }

    #[test]
    fn query_history_does_not_replay_at_the_current_cursor() {
        let resolver = Resolver::new(Config::default());
        let query = make_query("localhost", TYPE_A, 7).expect("query");
        resolver
            .query(&query, QueryMode::Full)
            .expect("local answer");
        let cursor = resolver.query_monitor_cursor();
        assert!(resolver
            .wait_query_event(cursor, Duration::from_millis(1))
            .is_none());
    }
}
