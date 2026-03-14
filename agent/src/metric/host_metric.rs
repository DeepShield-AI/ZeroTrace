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
use crate::metric::disk;
use crate::metric::memory;
use crate::metric::network;
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

// =============================================================================
// Memory Metrics Collector
// =============================================================================

pub struct MemoryMetricCollector;

impl MemoryMetricCollector {
    pub fn new() -> Self {
        Self
    }
}

impl OwnedCountable for MemoryMetricCollector {
    fn closed(&self) -> bool {
        false
    }

    fn get_counters(&self) -> Vec<Counter> {
        let info = match memory::MemInfo::collect() {
            Ok(info) => info,
            Err(e) => {
                warn!("Failed to collect memory metrics: {}", e);
                return vec![];
            }
        };

        vec![
            ("mem_total_kb", CounterType::Gauged, CounterValue::Unsigned(info.mem_total)),
            ("mem_free_kb", CounterType::Gauged, CounterValue::Unsigned(info.mem_free)),
            ("mem_available_kb", CounterType::Gauged, CounterValue::Unsigned(info.mem_available)),
            ("mem_used_kb", CounterType::Gauged, CounterValue::Unsigned(info.used_kb())),
            ("mem_usage_pct", CounterType::Gauged, CounterValue::Float(info.usage_pct())),
            ("mem_buffers_kb", CounterType::Gauged, CounterValue::Unsigned(info.buffers)),
            ("mem_cached_kb", CounterType::Gauged, CounterValue::Unsigned(info.cached)),
            ("mem_swap_cached_kb", CounterType::Gauged, CounterValue::Unsigned(info.swap_cached)),
            ("mem_active_kb", CounterType::Gauged, CounterValue::Unsigned(info.active)),
            ("mem_inactive_kb", CounterType::Gauged, CounterValue::Unsigned(info.inactive)),
            ("mem_active_anon_kb", CounterType::Gauged, CounterValue::Unsigned(info.active_anon)),
            ("mem_inactive_anon_kb", CounterType::Gauged, CounterValue::Unsigned(info.inactive_anon)),
            ("mem_active_file_kb", CounterType::Gauged, CounterValue::Unsigned(info.active_file)),
            ("mem_inactive_file_kb", CounterType::Gauged, CounterValue::Unsigned(info.inactive_file)),
            ("mem_swap_total_kb", CounterType::Gauged, CounterValue::Unsigned(info.swap_total)),
            ("mem_swap_free_kb", CounterType::Gauged, CounterValue::Unsigned(info.swap_free)),
            ("mem_swap_used_kb", CounterType::Gauged, CounterValue::Unsigned(info.swap_used_kb())),
            ("mem_swap_usage_pct", CounterType::Gauged, CounterValue::Float(info.swap_usage_pct())),
            ("mem_dirty_kb", CounterType::Gauged, CounterValue::Unsigned(info.dirty)),
            ("mem_writeback_kb", CounterType::Gauged, CounterValue::Unsigned(info.writeback)),
            ("mem_anon_pages_kb", CounterType::Gauged, CounterValue::Unsigned(info.anon_pages)),
            ("mem_mapped_kb", CounterType::Gauged, CounterValue::Unsigned(info.mapped)),
            ("mem_shmem_kb", CounterType::Gauged, CounterValue::Unsigned(info.shmem)),
            ("mem_slab_kb", CounterType::Gauged, CounterValue::Unsigned(info.slab)),
            ("mem_sreclaimable_kb", CounterType::Gauged, CounterValue::Unsigned(info.sreclaimable)),
            ("mem_sunreclaim_kb", CounterType::Gauged, CounterValue::Unsigned(info.sunreclaim)),
            ("mem_kernel_stack_kb", CounterType::Gauged, CounterValue::Unsigned(info.kernel_stack)),
            ("mem_page_tables_kb", CounterType::Gauged, CounterValue::Unsigned(info.page_tables)),
            ("mem_commit_limit_kb", CounterType::Gauged, CounterValue::Unsigned(info.commit_limit)),
            ("mem_committed_as_kb", CounterType::Gauged, CounterValue::Unsigned(info.committed_as)),
            ("mem_vmalloc_used_kb", CounterType::Gauged, CounterValue::Unsigned(info.vmalloc_used)),
            ("mem_hugepages_total", CounterType::Gauged, CounterValue::Unsigned(info.hugepages_total)),
            ("mem_hugepages_free", CounterType::Gauged, CounterValue::Unsigned(info.hugepages_free)),
            ("mem_hugepagesize_kb", CounterType::Gauged, CounterValue::Unsigned(info.hugepagesize)),
        ]
    }
}

// =============================================================================
// Disk Metrics Collector
// =============================================================================

pub struct DiskMetricCollector {
    prev_stats: Mutex<Option<Vec<disk::DiskStat>>>,
}

impl DiskMetricCollector {
    pub fn new() -> Self {
        Self {
            prev_stats: Mutex::new(None),
        }
    }
}

impl OwnedCountable for DiskMetricCollector {
    fn closed(&self) -> bool {
        false
    }

    fn get_counters(&self) -> Vec<Counter> {
        let current = match disk::collect_diskstats() {
            Ok(stats) => stats,
            Err(e) => {
                warn!("Failed to collect disk metrics: {}", e);
                return vec![];
            }
        };

        let mut prev_guard = self.prev_stats.lock().unwrap();
        let mut metrics = Vec::new();

        // Report per-device absolute and delta metrics
        for dev in &current {
            // Skip ram/loop devices
            if dev.name.starts_with("ram") || dev.name.starts_with("loop") {
                continue;
            }

            metrics.push(("disk_read_completed", CounterType::Gauged, CounterValue::Unsigned(dev.read_completed)));
            metrics.push(("disk_read_merged", CounterType::Gauged, CounterValue::Unsigned(dev.read_merged)));
            metrics.push(("disk_sectors_read", CounterType::Gauged, CounterValue::Unsigned(dev.sectors_read)));
            metrics.push(("disk_read_time_ms", CounterType::Gauged, CounterValue::Unsigned(dev.read_time_ms)));
            metrics.push(("disk_write_completed", CounterType::Gauged, CounterValue::Unsigned(dev.write_completed)));
            metrics.push(("disk_write_merged", CounterType::Gauged, CounterValue::Unsigned(dev.write_merged)));
            metrics.push(("disk_sectors_written", CounterType::Gauged, CounterValue::Unsigned(dev.sectors_written)));
            metrics.push(("disk_write_time_ms", CounterType::Gauged, CounterValue::Unsigned(dev.write_time_ms)));
            metrics.push(("disk_ios_in_progress", CounterType::Gauged, CounterValue::Unsigned(dev.ios_in_progress)));
            metrics.push(("disk_io_time_ms", CounterType::Gauged, CounterValue::Unsigned(dev.io_time_ms)));
            metrics.push(("disk_weighted_io_time_ms", CounterType::Gauged, CounterValue::Unsigned(dev.weighted_io_time_ms)));
            // Read/Write bytes (sectors * 512)
            metrics.push(("disk_read_bytes", CounterType::Gauged, CounterValue::Unsigned(dev.sectors_read * 512)));
            metrics.push(("disk_write_bytes", CounterType::Gauged, CounterValue::Unsigned(dev.sectors_written * 512)));

            // Delta-based throughput if we have a previous snapshot
            if let Some(ref prev_list) = *prev_guard {
                if let Some(prev_dev) = prev_list.iter().find(|d| d.name == dev.name) {
                    let read_delta = dev.sectors_read.saturating_sub(prev_dev.sectors_read) * 512;
                    let write_delta = dev.sectors_written.saturating_sub(prev_dev.sectors_written) * 512;
                    let read_ops_delta = dev.read_completed.saturating_sub(prev_dev.read_completed);
                    let write_ops_delta = dev.write_completed.saturating_sub(prev_dev.write_completed);
                    metrics.push(("disk_read_bytes_delta", CounterType::Counted, CounterValue::Unsigned(read_delta)));
                    metrics.push(("disk_write_bytes_delta", CounterType::Counted, CounterValue::Unsigned(write_delta)));
                    metrics.push(("disk_read_ops_delta", CounterType::Counted, CounterValue::Unsigned(read_ops_delta)));
                    metrics.push(("disk_write_ops_delta", CounterType::Counted, CounterValue::Unsigned(write_ops_delta)));
                }
            }
        }

        *prev_guard = Some(current);
        metrics
    }
}

// =============================================================================
// Network Metrics Collector
// =============================================================================

pub struct NetworkMetricCollector {
    prev_stats: Mutex<Option<Vec<network::NetDevStat>>>,
}

impl NetworkMetricCollector {
    pub fn new() -> Self {
        Self {
            prev_stats: Mutex::new(None),
        }
    }
}

impl OwnedCountable for NetworkMetricCollector {
    fn closed(&self) -> bool {
        false
    }

    fn get_counters(&self) -> Vec<Counter> {
        let current = match network::collect_netdev() {
            Ok(stats) => stats,
            Err(e) => {
                warn!("Failed to collect network metrics: {}", e);
                return vec![];
            }
        };

        let mut prev_guard = self.prev_stats.lock().unwrap();
        let mut metrics = Vec::new();

        for iface in &current {
            // Receive metrics
            metrics.push(("net_rx_bytes", CounterType::Gauged, CounterValue::Unsigned(iface.rx_bytes)));
            metrics.push(("net_rx_packets", CounterType::Gauged, CounterValue::Unsigned(iface.rx_packets)));
            metrics.push(("net_rx_errors", CounterType::Gauged, CounterValue::Unsigned(iface.rx_errors)));
            metrics.push(("net_rx_dropped", CounterType::Gauged, CounterValue::Unsigned(iface.rx_dropped)));
            metrics.push(("net_rx_fifo", CounterType::Gauged, CounterValue::Unsigned(iface.rx_fifo)));
            metrics.push(("net_rx_frame", CounterType::Gauged, CounterValue::Unsigned(iface.rx_frame)));
            metrics.push(("net_rx_compressed", CounterType::Gauged, CounterValue::Unsigned(iface.rx_compressed)));
            metrics.push(("net_rx_multicast", CounterType::Gauged, CounterValue::Unsigned(iface.rx_multicast)));
            // Transmit metrics
            metrics.push(("net_tx_bytes", CounterType::Gauged, CounterValue::Unsigned(iface.tx_bytes)));
            metrics.push(("net_tx_packets", CounterType::Gauged, CounterValue::Unsigned(iface.tx_packets)));
            metrics.push(("net_tx_errors", CounterType::Gauged, CounterValue::Unsigned(iface.tx_errors)));
            metrics.push(("net_tx_dropped", CounterType::Gauged, CounterValue::Unsigned(iface.tx_dropped)));
            metrics.push(("net_tx_fifo", CounterType::Gauged, CounterValue::Unsigned(iface.tx_fifo)));
            metrics.push(("net_tx_colls", CounterType::Gauged, CounterValue::Unsigned(iface.tx_colls)));
            metrics.push(("net_tx_carrier", CounterType::Gauged, CounterValue::Unsigned(iface.tx_carrier)));
            metrics.push(("net_tx_compressed", CounterType::Gauged, CounterValue::Unsigned(iface.tx_compressed)));

            // Delta-based throughput
            if let Some(ref prev_list) = *prev_guard {
                if let Some(prev_iface) = prev_list.iter().find(|i| i.name == iface.name) {
                    metrics.push(("net_rx_bytes_delta", CounterType::Counted, CounterValue::Unsigned(iface.rx_bytes.saturating_sub(prev_iface.rx_bytes))));
                    metrics.push(("net_tx_bytes_delta", CounterType::Counted, CounterValue::Unsigned(iface.tx_bytes.saturating_sub(prev_iface.tx_bytes))));
                    metrics.push(("net_rx_packets_delta", CounterType::Counted, CounterValue::Unsigned(iface.rx_packets.saturating_sub(prev_iface.rx_packets))));
                    metrics.push(("net_tx_packets_delta", CounterType::Counted, CounterValue::Unsigned(iface.tx_packets.saturating_sub(prev_iface.tx_packets))));
                    metrics.push(("net_rx_errors_delta", CounterType::Counted, CounterValue::Unsigned(iface.rx_errors.saturating_sub(prev_iface.rx_errors))));
                    metrics.push(("net_tx_errors_delta", CounterType::Counted, CounterValue::Unsigned(iface.tx_errors.saturating_sub(prev_iface.tx_errors))));
                }
            }
        }

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
        assert!(!counters.is_empty());
        let names: Vec<&str> = counters.iter().map(|c| c.0).collect();
        assert!(names.contains(&"context_switches"));
        assert!(names.contains(&"boot_time"));
        assert!(names.contains(&"cpu_count"));
        assert!(!names.contains(&"cpu_user_pct"));
    }

    #[test]
    fn test_cpu_metric_collector_second_collect() {
        let collector = CpuMetricCollector::new();
        let _ = collector.get_counters();
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

    #[test]
    fn test_memory_metric_collector() {
        let collector = MemoryMetricCollector::new();
        let counters = collector.get_counters();
        assert!(!counters.is_empty());
        let names: Vec<&str> = counters.iter().map(|c| c.0).collect();
        assert!(names.contains(&"mem_total_kb"));
        assert!(names.contains(&"mem_free_kb"));
        assert!(names.contains(&"mem_usage_pct"));
        assert!(names.contains(&"mem_swap_total_kb"));
    }

    #[test]
    fn test_disk_metric_collector() {
        let collector = DiskMetricCollector::new();
        let counters = collector.get_counters();
        // Should have some disk metrics (at least on Linux)
        if !counters.is_empty() {
            let names: Vec<&str> = counters.iter().map(|c| c.0).collect();
            assert!(names.contains(&"disk_read_completed") || names.contains(&"disk_read_bytes"));
        }
    }

    #[test]
    fn test_disk_metric_collector_delta() {
        let collector = DiskMetricCollector::new();
        let _ = collector.get_counters();
        let counters = collector.get_counters();
        if !counters.is_empty() {
            let names: Vec<&str> = counters.iter().map(|c| c.0).collect();
            assert!(names.contains(&"disk_read_bytes_delta"));
        }
    }

    #[test]
    fn test_network_metric_collector() {
        let collector = NetworkMetricCollector::new();
        let counters = collector.get_counters();
        assert!(!counters.is_empty());
        let names: Vec<&str> = counters.iter().map(|c| c.0).collect();
        assert!(names.contains(&"net_rx_bytes"));
        assert!(names.contains(&"net_tx_bytes"));
    }

    #[test]
    fn test_network_metric_collector_delta() {
        let collector = NetworkMetricCollector::new();
        let _ = collector.get_counters();
        let counters = collector.get_counters();
        let names: Vec<&str> = counters.iter().map(|c| c.0).collect();
        assert!(names.contains(&"net_rx_bytes_delta"));
        assert!(names.contains(&"net_tx_bytes_delta"));
    }
}
