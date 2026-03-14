/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::sync::Mutex;

use log::warn;

use crate::metric::cpu::{CpuState, CpuTimes};
use crate::utils::stats::{Counter, CounterType, CounterValue, OwnedCountable};

/// CPU metrics collector that implements RefCountable for integration
/// with the stats::Collector system. This automatically handles:
/// - Standalone mode: writing metrics to file via UniformSenderThread
/// - Managed mode: sending metrics to remote server via UniformSenderThread
///
/// The collector computes delta-based CPU usage percentages between
/// successive collection intervals, similar to how `top` or `mpstat` work.
pub struct CpuMetricCollector {
    prev_state: Mutex<Option<CpuState>>,
}

impl CpuMetricCollector {
    pub fn new() -> Self {
        Self {
            prev_state: Mutex::new(None),
        }
    }

    fn compute_pct(delta: &CpuTimes) -> Vec<(&'static str, f64)> {
        let total = delta.total() as f64;
        if total == 0.0 {
            return vec![
                ("cpu_user_pct", 0.0),
                ("cpu_nice_pct", 0.0),
                ("cpu_system_pct", 0.0),
                ("cpu_idle_pct", 0.0),
                ("cpu_iowait_pct", 0.0),
                ("cpu_irq_pct", 0.0),
                ("cpu_softirq_pct", 0.0),
                ("cpu_steal_pct", 0.0),
                ("cpu_guest_pct", 0.0),
                ("cpu_guest_nice_pct", 0.0),
            ];
        }
        let pct = |v: u64| v as f64 / total * 100.0;
        vec![
            ("cpu_user_pct", pct(delta.user)),
            ("cpu_nice_pct", pct(delta.nice)),
            ("cpu_system_pct", pct(delta.system)),
            ("cpu_idle_pct", pct(delta.idle)),
            ("cpu_iowait_pct", pct(delta.iowait)),
            ("cpu_irq_pct", pct(delta.irq)),
            ("cpu_softirq_pct", pct(delta.softirq)),
            ("cpu_steal_pct", pct(delta.steal)),
            ("cpu_guest_pct", pct(delta.guest)),
            ("cpu_guest_nice_pct", pct(delta.guest_nice)),
        ]
    }
}

impl OwnedCountable for CpuMetricCollector {
    fn closed(&self) -> bool {
        false
    }

    fn get_counters(&self) -> Vec<Counter> {
        let current = match CpuState::collect() {
            Ok(state) => state,
            Err(e) => {
                warn!("Failed to collect CPU metrics: {}", e);
                return vec![];
            }
        };

        let mut prev_guard = self.prev_state.lock().unwrap();
        let mut metrics = Vec::new();

        if let Some(ref prev) = *prev_guard {
            // Compute delta-based percentage for total CPU
            let delta_total = current.total - prev.total;
            for (name, value) in Self::compute_pct(&delta_total) {
                metrics.push((name, CounterType::Gauged, CounterValue::Float(value)));
            }

            // Compute active CPU percentage (aggregate)
            let total_jiffies = delta_total.total() as f64;
            let active_pct = if total_jiffies > 0.0 {
                delta_total.active() as f64 / total_jiffies * 100.0
            } else {
                0.0
            };
            metrics.push((
                "cpu_active_pct",
                CounterType::Gauged,
                CounterValue::Float(active_pct),
            ));

            // Per-CPU active percentage
            let cpu_count = current.cpus.len().min(prev.cpus.len());
            for i in 0..cpu_count {
                let delta = current.cpus[i] - prev.cpus[i];
                let t = delta.total() as f64;
                let active = if t > 0.0 {
                    delta.active() as f64 / t * 100.0
                } else {
                    0.0
                };
                metrics.push((
                    "per_cpu_active_pct",
                    CounterType::Gauged,
                    CounterValue::Float(active),
                ));
            }

            // Context switches delta
            let ctxt_delta = current
                .context_switches
                .saturating_sub(prev.context_switches);
            metrics.push((
                "context_switches_delta",
                CounterType::Counted,
                CounterValue::Unsigned(ctxt_delta),
            ));
        }

        // Always report absolute counters
        metrics.push((
            "context_switches",
            CounterType::Gauged,
            CounterValue::Unsigned(current.context_switches),
        ));
        metrics.push((
            "boot_time",
            CounterType::Gauged,
            CounterValue::Unsigned(current.boot_time),
        ));
        metrics.push((
            "processes",
            CounterType::Gauged,
            CounterValue::Unsigned(current.processes),
        ));
        metrics.push((
            "procs_running",
            CounterType::Gauged,
            CounterValue::Unsigned(current.procs_running),
        ));
        metrics.push((
            "procs_blocked",
            CounterType::Gauged,
            CounterValue::Unsigned(current.procs_blocked),
        ));
        metrics.push((
            "cpu_count",
            CounterType::Gauged,
            CounterValue::Unsigned(current.cpus.len() as u64),
        ));

        // Store current state for next delta computation
        *prev_guard = Some(current);

        metrics
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpu_metric_collector_first_collect() {
        let collector = CpuMetricCollector::new();
        let counters = collector.get_counters();
        // First collection: no delta metrics, only absolute counters
        assert!(!counters.is_empty());
        let names: Vec<&str> = counters.iter().map(|c| c.0).collect();
        assert!(names.contains(&"context_switches"));
        assert!(names.contains(&"boot_time"));
        assert!(names.contains(&"cpu_count"));
        // No delta metrics on first run
        assert!(!names.contains(&"cpu_user_pct"));
    }

    #[test]
    fn test_cpu_metric_collector_second_collect() {
        let collector = CpuMetricCollector::new();
        // First collect seeds the state
        let _ = collector.get_counters();
        // Second collect should produce delta metrics
        let counters = collector.get_counters();
        let names: Vec<&str> = counters.iter().map(|c| c.0).collect();
        assert!(names.contains(&"cpu_user_pct"));
        assert!(names.contains(&"cpu_active_pct"));
        assert!(names.contains(&"context_switches_delta"));
    }

    #[test]
    fn test_compute_pct_zero_total() {
        let delta = CpuTimes::default();
        let pcts = CpuMetricCollector::compute_pct(&delta);
        for (_, v) in &pcts {
            assert_eq!(*v, 0.0);
        }
    }
}
