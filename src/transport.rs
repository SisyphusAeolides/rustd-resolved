// SPDX-License-Identifier: LGPL-2.1-or-later

pub const TRANSPORT_RETRY_ATTEMPTS: u8 = 3;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TransportMode {
    #[default]
    Udp,
    Tcp,
}

#[derive(Clone, Debug)]
pub struct ServerTransportState {
    mode: TransportMode,
    failed_udp: u8,
    failed_tcp: u8,
    packet_truncated: bool,
    packet_fragmented: bool,
    received_udp_fragment_max: u32,
}

impl Default for ServerTransportState {
    fn default() -> Self {
        Self {
            mode: TransportMode::Udp,
            failed_udp: 0,
            failed_tcp: 0,
            packet_truncated: false,
            packet_fragmented: false,
            received_udp_fragment_max: 512,
        }
    }
}

impl ServerTransportState {
    pub const fn mode(&self) -> TransportMode {
        self.mode
    }

    pub const fn packet_truncated(&self) -> bool {
        self.packet_truncated
    }

    pub const fn failures(&self, mode: TransportMode) -> u8 {
        match mode {
            TransportMode::Udp => self.failed_udp,
            TransportMode::Tcp => self.failed_tcp,
        }
    }

    pub fn record_success(&mut self, mode: TransportMode) {
        match mode {
            TransportMode::Udp => self.failed_udp = 0,
            TransportMode::Tcp => self.failed_tcp = 0,
        }
    }

    pub fn record_failure(&mut self, mode: TransportMode) -> Option<TransportMode> {
        let failures = match mode {
            TransportMode::Udp => &mut self.failed_udp,
            TransportMode::Tcp => &mut self.failed_tcp,
        };
        *failures = failures.saturating_add(1);
        if *failures < TRANSPORT_RETRY_ATTEMPTS || mode != self.mode {
            return None;
        }

        self.mode = match mode {
            TransportMode::Udp => TransportMode::Tcp,
            TransportMode::Tcp => TransportMode::Udp,
        };
        self.clear_failures();
        Some(self.mode)
    }

    pub fn record_truncated(&mut self) {
        self.packet_truncated = true;
    }

    pub fn clear_failures(&mut self) {
        self.failed_udp = 0;
        self.failed_tcp = 0;
    }

    pub const fn packet_fragmented(&self) -> bool {
        self.packet_fragmented
    }

    pub const fn received_udp_fragment_max(&self) -> u32 {
        self.received_udp_fragment_max
    }

    pub fn record_udp_packet(&mut self, dns_size: usize, fragment_size: u32, ipv6: bool) {
        let header_size = if ipv6 { 48 } else { 28 };
        let unfragmented_size = if fragment_size == 0 {
            u32::try_from(dns_size).unwrap_or(u32::MAX)
        } else {
            self.packet_fragmented = true;
            fragment_size.saturating_sub(header_size)
        };
        self.received_udp_fragment_max = self.received_udp_fragment_max.max(unfragmented_size);
    }

    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_udp_loss_switches_to_tcp() {
        let mut state = ServerTransportState::default();
        assert_eq!(state.record_failure(TransportMode::Udp), None);
        assert_eq!(state.record_failure(TransportMode::Udp), None);
        assert_eq!(
            state.record_failure(TransportMode::Udp),
            Some(TransportMode::Tcp)
        );
        assert_eq!(state.mode(), TransportMode::Tcp);
    }

    #[test]
    fn repeated_tcp_loss_switches_back_to_udp() {
        let mut state = ServerTransportState::default();
        for _ in 0..TRANSPORT_RETRY_ATTEMPTS {
            let _ = state.record_failure(TransportMode::Udp);
        }
        assert_eq!(state.mode(), TransportMode::Tcp);
        assert_eq!(state.record_failure(TransportMode::Tcp), None);
        assert_eq!(state.record_failure(TransportMode::Tcp), None);
        assert_eq!(
            state.record_failure(TransportMode::Tcp),
            Some(TransportMode::Udp)
        );
        assert_eq!(state.mode(), TransportMode::Udp);
    }

    #[test]
    fn fallback_tcp_failures_do_not_replace_the_udp_mode() {
        let mut state = ServerTransportState::default();
        state.record_truncated();
        assert_eq!(state.record_failure(TransportMode::Tcp), None);
        assert_eq!(state.record_failure(TransportMode::Tcp), None);
        assert_eq!(state.record_failure(TransportMode::Tcp), None);
        assert_eq!(state.mode(), TransportMode::Udp);
        assert_eq!(state.failures(TransportMode::Tcp), TRANSPORT_RETRY_ATTEMPTS);
        assert!(state.packet_truncated());
    }

    #[test]
    fn udp_fragment_telemetry_tracks_largest_unfragmented_payload() {
        let mut state = ServerTransportState::default();
        state.record_udp_packet(900, 0, false);
        assert!(!state.packet_fragmented());
        assert_eq!(state.received_udp_fragment_max(), 900);

        state.record_udp_packet(1500, 1200, false);
        assert!(state.packet_fragmented());
        assert_eq!(state.received_udp_fragment_max(), 1172);

        state.record_udp_packet(1500, 1280, true);
        assert_eq!(state.received_udp_fragment_max(), 1232);
    }
}
