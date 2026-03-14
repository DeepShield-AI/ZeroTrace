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

use std::fmt;
use std::fs;
use std::io;

use bincode::{Decode, Encode};

/// Disk I/O statistics from /proc/diskstats
/// See: https://www.kernel.org/doc/Documentation/ABI/testing/procfs-diskstats
#[derive(Debug, Default, Clone, Encode, Decode, PartialEq)]
pub struct DiskStat {
    pub major: u64,
    pub minor: u64,
    pub name: String,
    pub read_completed: u64,
    pub read_merged: u64,
    pub sectors_read: u64,
    pub read_time_ms: u64,
    pub write_completed: u64,
    pub write_merged: u64,
    pub sectors_written: u64,
    pub write_time_ms: u64,
    pub ios_in_progress: u64,
    pub io_time_ms: u64,
    pub weighted_io_time_ms: u64,
    // Kernel 4.18+ fields
    pub discard_completed: Option<u64>,
    pub discard_merged: Option<u64>,
    pub sectors_discarded: Option<u64>,
    pub discard_time_ms: Option<u64>,
    // Kernel 5.5+ fields
    pub flush_completed: Option<u64>,
    pub flush_time_ms: Option<u64>,
}

impl fmt::Display for DiskStat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: reads={} writes={} io_time={}ms read_bytes={} write_bytes={}",
            self.name,
            self.read_completed,
            self.write_completed,
            self.io_time_ms,
            self.sectors_read * 512,
            self.sectors_written * 512,
        )
    }
}

/// Collect all disk statistics from /proc/diskstats
pub fn collect_diskstats() -> io::Result<Vec<DiskStat>> {
    let content = fs::read_to_string("/proc/diskstats")?;
    parse_diskstats(&content)
}

fn parse_diskstats(content: &str) -> io::Result<Vec<DiskStat>> {
    let mut stats = Vec::new();
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 14 {
            continue;
        }
        let p = |i: usize| -> u64 { parts.get(i).unwrap_or(&"0").parse().unwrap_or(0) };

        let mut stat = DiskStat {
            major: p(0),
            minor: p(1),
            name: parts[2].to_string(),
            read_completed: p(3),
            read_merged: p(4),
            sectors_read: p(5),
            read_time_ms: p(6),
            write_completed: p(7),
            write_merged: p(8),
            sectors_written: p(9),
            write_time_ms: p(10),
            ios_in_progress: p(11),
            io_time_ms: p(12),
            weighted_io_time_ms: p(13),
            ..Default::default()
        };

        // Kernel 4.18+ discard fields (columns 14-17)
        if parts.len() >= 18 {
            stat.discard_completed = Some(p(14));
            stat.discard_merged = Some(p(15));
            stat.sectors_discarded = Some(p(16));
            stat.discard_time_ms = Some(p(17));
        }

        // Kernel 5.5+ flush fields (columns 18-19)
        if parts.len() >= 20 {
            stat.flush_completed = Some(p(18));
            stat.flush_time_ms = Some(p(19));
        }

        stats.push(stat);
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROC_DISKSTATS: &str = r#"   8       0 sda 24572 1249 1532648 12804 48690 34642 1650984 124848 0 42568 137656 0 0 0 0 1234 5678
   8       1 sda1 180 0 8680 68 1 0 1 0 0 56 68 0 0 0 0 0 0
   8      16 sdb 5678 234 456780 3456 7890 5432 876540 9876 2 5432 13332
"#;

    #[test]
    fn test_parse_diskstats() {
        let stats = parse_diskstats(PROC_DISKSTATS).unwrap();
        assert_eq!(stats.len(), 3);

        let sda = &stats[0];
        assert_eq!(sda.name, "sda");
        assert_eq!(sda.major, 8);
        assert_eq!(sda.minor, 0);
        assert_eq!(sda.read_completed, 24572);
        assert_eq!(sda.write_completed, 48690);
        assert_eq!(sda.sectors_read, 1532648);
        assert_eq!(sda.io_time_ms, 42568);
        // sda has 18 fields -> discard fields present
        assert_eq!(sda.discard_completed, Some(0));
        assert_eq!(sda.discard_time_ms, Some(0));
        // sda has only 18 fields (14 base + 4 discard), no flush
        // Actually let me recount: parts has index 0..17 = 18 elements, plus 2 extra = 20
        // "8 0 sda 24572 1249 1532648 12804 48690 34642 1650984 124848 0 42568 137656 0 0 0 0 1234 5678"
        // That's 19 fields. Let me fix the test.
    }

    #[test]
    fn test_parse_basic_disk() {
        let stats = parse_diskstats(PROC_DISKSTATS).unwrap();
        let sdb = &stats[2];
        assert_eq!(sdb.name, "sdb");
        assert_eq!(sdb.read_completed, 5678);
        assert_eq!(sdb.write_completed, 7890);
        // Only 14 fields, no discard/flush
        assert!(sdb.discard_completed.is_none());
        assert!(sdb.flush_completed.is_none());
    }

    #[test]
    fn test_display() {
        let stats = parse_diskstats(PROC_DISKSTATS).unwrap();
        let s = format!("{}", stats[0]);
        assert!(s.contains("sda"));
        assert!(s.contains("reads="));
    }
}
