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

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io;

use bincode::{Decode, Encode};

/// Memory information from /proc/meminfo (values in kB)
#[derive(Debug, Default, Clone, Encode, Decode, PartialEq)]
pub struct MemInfo {
    pub mem_total: u64,
    pub mem_free: u64,
    pub mem_available: u64,
    pub buffers: u64,
    pub cached: u64,
    pub swap_cached: u64,
    pub active: u64,
    pub inactive: u64,
    pub active_anon: u64,
    pub inactive_anon: u64,
    pub active_file: u64,
    pub inactive_file: u64,
    pub swap_total: u64,
    pub swap_free: u64,
    pub dirty: u64,
    pub writeback: u64,
    pub anon_pages: u64,
    pub mapped: u64,
    pub shmem: u64,
    pub kreclaimable: u64,
    pub slab: u64,
    pub sreclaimable: u64,
    pub sunreclaim: u64,
    pub kernel_stack: u64,
    pub page_tables: u64,
    pub commit_limit: u64,
    pub committed_as: u64,
    pub vmalloc_total: u64,
    pub vmalloc_used: u64,
    pub vmalloc_chunk: u64,
    pub hugepages_total: u64,
    pub hugepages_free: u64,
    pub hugepagesize: u64,
}

impl MemInfo {
    pub fn collect() -> io::Result<Self> {
        let content = fs::read_to_string("/proc/meminfo")?;
        Self::parse(&content)
    }

    fn parse(content: &str) -> io::Result<Self> {
        let mut map = HashMap::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            // Format: "Key:     1234 kB"
            if let Some((key, rest)) = line.split_once(':') {
                let val_str = rest.trim().split_whitespace().next().unwrap_or("0");
                if let Ok(val) = val_str.parse::<u64>() {
                    map.insert(key.trim().to_string(), val);
                }
            }
        }

        let g = |k: &str| -> u64 { *map.get(k).unwrap_or(&0) };

        Ok(MemInfo {
            mem_total: g("MemTotal"),
            mem_free: g("MemFree"),
            mem_available: g("MemAvailable"),
            buffers: g("Buffers"),
            cached: g("Cached"),
            swap_cached: g("SwapCached"),
            active: g("Active"),
            inactive: g("Inactive"),
            active_anon: g("Active(anon)"),
            inactive_anon: g("Inactive(anon)"),
            active_file: g("Active(file)"),
            inactive_file: g("Inactive(file)"),
            swap_total: g("SwapTotal"),
            swap_free: g("SwapFree"),
            dirty: g("Dirty"),
            writeback: g("Writeback"),
            anon_pages: g("AnonPages"),
            mapped: g("Mapped"),
            shmem: g("Shmem"),
            kreclaimable: g("KReclaimable"),
            slab: g("Slab"),
            sreclaimable: g("SReclaimable"),
            sunreclaim: g("SUnreclaim"),
            kernel_stack: g("KernelStack"),
            page_tables: g("PageTables"),
            commit_limit: g("CommitLimit"),
            committed_as: g("Committed_AS"),
            vmalloc_total: g("VmallocTotal"),
            vmalloc_used: g("VmallocUsed"),
            vmalloc_chunk: g("VmallocChunk"),
            hugepages_total: g("HugePages_Total"),
            hugepages_free: g("HugePages_Free"),
            hugepagesize: g("Hugepagesize"),
        })
    }

    pub fn used_kb(&self) -> u64 {
        self.mem_total.saturating_sub(self.mem_available)
    }

    pub fn usage_pct(&self) -> f64 {
        if self.mem_total == 0 {
            return 0.0;
        }
        self.used_kb() as f64 / self.mem_total as f64 * 100.0
    }

    pub fn swap_used_kb(&self) -> u64 {
        self.swap_total.saturating_sub(self.swap_free)
    }

    pub fn swap_usage_pct(&self) -> f64 {
        if self.swap_total == 0 {
            return 0.0;
        }
        self.swap_used_kb() as f64 / self.swap_total as f64 * 100.0
    }
}

impl fmt::Display for MemInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "MemTotal:       {} kB", self.mem_total)?;
        writeln!(f, "MemFree:        {} kB", self.mem_free)?;
        writeln!(f, "MemAvailable:   {} kB", self.mem_available)?;
        writeln!(f, "MemUsed:        {} kB ({:.1}%)", self.used_kb(), self.usage_pct())?;
        writeln!(f, "Buffers:        {} kB", self.buffers)?;
        writeln!(f, "Cached:         {} kB", self.cached)?;
        writeln!(f, "SwapCached:     {} kB", self.swap_cached)?;
        writeln!(f, "Active:         {} kB", self.active)?;
        writeln!(f, "Inactive:       {} kB", self.inactive)?;
        writeln!(f, "SwapTotal:      {} kB", self.swap_total)?;
        writeln!(f, "SwapFree:       {} kB", self.swap_free)?;
        writeln!(f, "SwapUsed:       {} kB ({:.1}%)", self.swap_used_kb(), self.swap_usage_pct())?;
        writeln!(f, "Dirty:          {} kB", self.dirty)?;
        writeln!(f, "Slab:           {} kB", self.slab)?;
        writeln!(f, "KernelStack:    {} kB", self.kernel_stack)?;
        write!(f, "PageTables:     {} kB", self.page_tables)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROC_MEMINFO: &str = r#"MemTotal:       16384000 kB
MemFree:         8192000 kB
MemAvailable:   12288000 kB
Buffers:          512000 kB
Cached:          2048000 kB
SwapCached:            0 kB
Active:          4096000 kB
Inactive:        2048000 kB
Active(anon):    2048000 kB
Inactive(anon):   512000 kB
Active(file):    2048000 kB
Inactive(file):  1536000 kB
SwapTotal:       4096000 kB
SwapFree:        4096000 kB
Dirty:               128 kB
Writeback:             0 kB
AnonPages:       2048000 kB
Mapped:           512000 kB
Shmem:            256000 kB
KReclaimable:     256000 kB
Slab:             512000 kB
SReclaimable:     256000 kB
SUnreclaim:       256000 kB
KernelStack:       16384 kB
PageTables:        32768 kB
CommitLimit:     12288000 kB
Committed_AS:    8192000 kB
VmallocTotal:   34359738367 kB
VmallocUsed:       65536 kB
VmallocChunk:          0 kB
HugePages_Total:       0
HugePages_Free:        0
Hugepagesize:       2048 kB
"#;

    #[test]
    fn test_parse_meminfo() {
        let info = MemInfo::parse(PROC_MEMINFO).unwrap();
        assert_eq!(info.mem_total, 16384000);
        assert_eq!(info.mem_free, 8192000);
        assert_eq!(info.mem_available, 12288000);
        assert_eq!(info.buffers, 512000);
        assert_eq!(info.cached, 2048000);
        assert_eq!(info.swap_total, 4096000);
        assert_eq!(info.swap_free, 4096000);
        assert_eq!(info.slab, 512000);
        assert_eq!(info.active_anon, 2048000);
        assert_eq!(info.hugepagesize, 2048);
    }

    #[test]
    fn test_usage_pct() {
        let info = MemInfo::parse(PROC_MEMINFO).unwrap();
        assert_eq!(info.used_kb(), 16384000 - 12288000);
        let pct = info.usage_pct();
        assert!(pct > 24.0 && pct < 26.0);
    }

    #[test]
    fn test_swap_usage_zero() {
        let info = MemInfo::parse(PROC_MEMINFO).unwrap();
        assert_eq!(info.swap_used_kb(), 0);
        assert_eq!(info.swap_usage_pct(), 0.0);
    }

    #[test]
    fn test_display() {
        let info = MemInfo::parse(PROC_MEMINFO).unwrap();
        let s = format!("{}", info);
        assert!(s.contains("MemTotal:"));
        assert!(s.contains("MemUsed:"));
    }
}
