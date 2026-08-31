// SPDX-License-Identifier: LGPL-2.1-or-later
//! Bounded nonlinear control signals for resolver scheduling.
//!
//! The controller is deterministic, allocation-free after construction, and
//! never changes DNS protocol semantics.  It contributes only small bounded
//! offsets to upstream selection and retry cooldowns; measured RTT, failures,
//! DNSSEC policy, and transport capabilities remain dominant.

use std::net::SocketAddr;

const MANDELBROT_ITERS: u32 = 16;
const MAX_SELECTION_BIAS_MS: f64 = 12.0;

#[derive(Clone, Copy, Debug)]
pub struct ChaosSnapshot {
    pub lorenz_energy: f64,
    pub mandelbrot_complexity: f64,
    pub lyapunov_instability: f64,
    pub rossler_phase: f64,
    pub logistic_state: f64,
    pub duffing_energy: f64,
    pub composite_pressure: f64,
}

impl Default for ChaosSnapshot {
    fn default() -> Self {
        Self {
            lorenz_energy: 0.0,
            mandelbrot_complexity: 0.0,
            lyapunov_instability: 0.0,
            rossler_phase: 0.0,
            logistic_state: 0.5,
            duffing_energy: 0.0,
            composite_pressure: 0.0,
        }
    }
}

#[derive(Debug)]
pub struct ChaosOptimizer {
    lorenz: [f64; 3],
    rossler: [f64; 3],
    logistic: f64,
    duffing_x: f64,
    duffing_v: f64,
    duffing_phase: f64,
    lyapunov_ewma: f64,
    rtt_ewma_ms: f64,
    failure_ewma: f64,
    observations: u64,
    snapshot: ChaosSnapshot,
}

impl Default for ChaosOptimizer {
    fn default() -> Self {
        Self {
            lorenz: [0.1, 0.0, 0.0],
            rossler: [0.1, 0.0, 0.0],
            logistic: 0.417,
            duffing_x: 0.0,
            duffing_v: 0.0,
            duffing_phase: 0.0,
            lyapunov_ewma: 0.0,
            rtt_ewma_ms: 20.0,
            failure_ewma: 0.0,
            observations: 0,
            snapshot: ChaosSnapshot::default(),
        }
    }
}

impl ChaosOptimizer {
    /// Advance all six bounded systems from one completed upstream exchange.
    pub fn observe(&mut self, rtt_ms: f64, failed: bool) {
        let rtt_ms = finite(rtt_ms).clamp(1.0, 60_000.0);
        self.rtt_ewma_ms = ewma(self.rtt_ewma_ms, rtt_ms, 0.18);
        self.failure_ewma = ewma(self.failure_ewma, if failed { 1.0 } else { 0.0 }, 0.12);

        let latency = clamp01((self.rtt_ewma_ms / 500.0).ln_1p() / 5.0_f64.ln());
        let pressure = clamp01(0.65 * latency + 0.35 * self.failure_ewma);

        self.step_logistic(pressure);
        self.step_lorenz(pressure);
        self.step_rossler(pressure);
        self.step_duffing(pressure);

        let mandelbrot_complexity =
            mandelbrot_complexity(-0.82 + 0.32 * pressure, (self.logistic - 0.5) * 0.55);
        let lorenz_energy = clamp01(
            (self.lorenz[0] * self.lorenz[0]
                + self.lorenz[1] * self.lorenz[1]
                + self.lorenz[2] * self.lorenz[2])
                / 2_400.0,
        );
        let rossler_phase =
            clamp01((self.rossler[0].abs() + self.rossler[1].abs() + self.rossler[2].abs()) / 24.0);
        let duffing_energy = clamp01(
            (0.5 * self.duffing_v * self.duffing_v
                + 0.25 * self.duffing_x.powi(4)
                + 0.5 * self.duffing_x * self.duffing_x)
                / 4.0,
        );
        let lyapunov_instability = clamp01((self.lyapunov_ewma + 1.0) * 0.5);
        let composite_pressure = clamp01(
            0.24 * pressure
                + 0.18 * lorenz_energy
                + 0.16 * mandelbrot_complexity
                + 0.16 * lyapunov_instability
                + 0.13 * rossler_phase
                + 0.13 * duffing_energy,
        );

        self.observations = self.observations.saturating_add(1);
        self.snapshot = ChaosSnapshot {
            lorenz_energy,
            mandelbrot_complexity,
            lyapunov_instability,
            rossler_phase,
            logistic_state: self.logistic,
            duffing_energy,
            composite_pressure,
        };
    }

    #[must_use]
    pub const fn snapshot(&self) -> ChaosSnapshot {
        self.snapshot
    }

    /// Return a deterministic, bounded exploration offset in milliseconds.
    #[must_use]
    pub fn selection_bias_ms(&self, server: SocketAddr) -> f64 {
        if self.observations == 0 {
            return 0.0;
        }
        let phase = unit_hash(server, self.observations);
        let wave = 2.0 * phase - 1.0;
        let gain = 0.15 + 0.85 * self.snapshot.composite_pressure;
        (wave * gain * MAX_SELECTION_BIAS_MS).clamp(-MAX_SELECTION_BIAS_MS, MAX_SELECTION_BIAS_MS)
    }

    /// Modulate an exponential cooldown without defeating its hard bounds.
    #[must_use]
    pub fn cooldown_ms(&self, base_ms: u64) -> u64 {
        let logistic = self.snapshot.logistic_state - 0.5;
        let factor =
            (0.9 + 0.20 * self.snapshot.composite_pressure + 0.10 * logistic).clamp(0.85, 1.20);
        ((base_ms as f64 * factor).round() as u64).clamp(100, 60_000)
    }

    fn step_logistic(&mut self, pressure: f64) {
        let r = 3.72 + 0.25 * pressure;
        let derivative = (r * (1.0 - 2.0 * self.logistic)).abs().max(1.0e-9);
        self.lyapunov_ewma = ewma(self.lyapunov_ewma, derivative.ln().clamp(-4.0, 4.0), 0.08);
        self.logistic = (r * self.logistic * (1.0 - self.logistic)).clamp(1.0e-6, 1.0 - 1.0e-6);
    }

    fn step_lorenz(&mut self, pressure: f64) {
        let [x, y, z] = self.lorenz;
        let dt = 0.006;
        let dx = 10.0 * (y - x) + 0.4 * pressure;
        let dy = x * (28.0 - z) - y + 0.2 * pressure;
        let dz = x * y - (8.0 / 3.0) * z;
        self.lorenz = bounded3([x + dt * dx, y + dt * dy, z + dt * dz], 60.0);
    }

    fn step_rossler(&mut self, pressure: f64) {
        let [x, y, z] = self.rossler;
        let dt = 0.018;
        let dx = -y - z + 0.08 * pressure;
        let dy = x + 0.2 * y;
        let dz = 0.2 + z * (x - 5.7);
        self.rossler = bounded3([x + dt * dx, y + dt * dy, z + dt * dz], 18.0);
    }

    fn step_duffing(&mut self, pressure: f64) {
        self.duffing_phase = (self.duffing_phase + 0.07).rem_euclid(std::f64::consts::TAU);
        let drive = 0.30 * self.duffing_phase.cos() + 0.12 * pressure;
        let acceleration = drive - 0.20 * self.duffing_v + self.duffing_x - self.duffing_x.powi(3);
        self.duffing_v = (self.duffing_v + 0.02 * acceleration).clamp(-4.0, 4.0);
        self.duffing_x = (self.duffing_x + 0.02 * self.duffing_v).clamp(-3.0, 3.0);
    }
}

fn mandelbrot_complexity(cr: f64, ci: f64) -> f64 {
    let mut zr: f64 = 0.0;
    let mut zi: f64 = 0.0;
    for iteration in 0..MANDELBROT_ITERS {
        let zr2 = zr * zr;
        let zi2 = zi * zi;
        if zr2 + zi2 > 4.0 {
            return f64::from(iteration) / f64::from(MANDELBROT_ITERS);
        }
        zi = (2.0 * zr).mul_add(zi, ci);
        zr = zr2 - zi2 + cr;
    }
    1.0
}

fn bounded3(mut value: [f64; 3], limit: f64) -> [f64; 3] {
    for component in &mut value {
        *component = finite(*component).clamp(-limit, limit);
    }
    value
}

fn unit_hash(server: SocketAddr, epoch: u64) -> f64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64 ^ epoch.rotate_left(17);
    for byte in server.to_string().bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    (hash >> 11) as f64 / ((1u64 << 53) - 1) as f64
}

fn ewma(previous: f64, sample: f64, alpha: f64) -> f64 {
    finite(previous).mul_add(1.0 - alpha, finite(sample) * alpha)
}

fn finite(value: f64) -> f64 {
    if value.is_finite() {
        value
    } else {
        0.0
    }
}

fn clamp01(value: f64) -> f64 {
    finite(value).clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_dynamics_remain_bounded_under_failure_pressure() {
        let mut optimizer = ChaosOptimizer::default();
        for index in 0..20_000 {
            optimizer.observe(1.0 + f64::from(index % 60_000), index % 3 == 0);
        }
        let snapshot = optimizer.snapshot();
        for value in [
            snapshot.lorenz_energy,
            snapshot.mandelbrot_complexity,
            snapshot.lyapunov_instability,
            snapshot.rossler_phase,
            snapshot.logistic_state,
            snapshot.duffing_energy,
            snapshot.composite_pressure,
        ] {
            assert!(value.is_finite());
            assert!((0.0..=1.0).contains(&value));
        }
    }

    #[test]
    fn selection_and_cooldown_adjustments_are_strictly_bounded() {
        let mut optimizer = ChaosOptimizer::default();
        for _ in 0..128 {
            optimizer.observe(250.0, true);
        }
        let server: SocketAddr = "192.0.2.53:53".parse().expect("server");
        assert!(optimizer.selection_bias_ms(server).abs() <= MAX_SELECTION_BIAS_MS);
        assert!((100..=60_000).contains(&optimizer.cooldown_ms(4_000)));
    }
}
