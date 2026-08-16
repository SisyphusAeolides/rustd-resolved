// SPDX-License-Identifier: LGPL-2.1-or-later
use std::cmp::Ordering;

#[derive(Clone, Copy, Debug)]
pub struct ServerMetric {
    pub round_trip_ms: f64,
    pub failures: i32,
    pub feature_level: i32,
    pub cooldown_ms: i32,
}

impl Default for ServerMetric {
    fn default() -> Self {
        Self {
            round_trip_ms: 100.0,
            failures: 0,
            feature_level: 0,
            cooldown_ms: 0,
        }
    }
}

pub fn choose_server(metrics: &[ServerMetric]) -> Option<usize> {
    metrics
        .iter()
        .enumerate()
        .min_by(|(_, left), (_, right)| {
            score(left)
                .partial_cmp(&score(right))
                .unwrap_or(Ordering::Equal)
        })
        .map(|(index, _)| index)
}

fn score(metric: &ServerMetric) -> f64 {
    f64::from(metric.cooldown_ms.max(0))
        + metric.round_trip_ms.clamp(1.0, 60_000.0)
        + f64::from(metric.failures.max(0)) * 250.0
        - f64::from(metric.feature_level.max(0)) * 5.0
}

pub fn update_rtt(previous: f64, sample: f64, succeeded: bool) -> f64 {
    let sample = sample.clamp(1.0, 60_000.0);
    if previous <= 0.0 {
        sample
    } else if succeeded {
        previous.mul_add(0.8, sample * 0.2)
    } else {
        (previous * 1.5).max(sample).min(60_000.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_lowest_effective_cost() {
        let metrics = [
            ServerMetric {
                round_trip_ms: 20.0,
                failures: 2,
                ..ServerMetric::default()
            },
            ServerMetric {
                round_trip_ms: 80.0,
                ..ServerMetric::default()
            },
        ];
        assert_eq!(choose_server(&metrics), Some(1));
    }

    #[test]
    fn success_smooths_round_trip_time() {
        assert!((update_rtt(100.0, 50.0, true) - 90.0).abs() < f64::EPSILON);
    }
}
