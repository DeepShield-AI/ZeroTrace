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

/// Network interface statistics from /proc/net/dev
#[derive(Debug, Default, Clone)]
pub struct NetDevStat {
    pub name: String,
    // Receive
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub rx_errors: u64,
    pub rx_dropped: u64,
    pub rx_fifo: u64,
    pub rx_frame: u64,
    pub rx_compressed: u64,
    pub rx_multicast: u64,
    // Transmit
    pub tx_bytes: u64,
    pub tx_packets: u64,
    pub tx_errors: u64,
    pub tx_dropped: u64,
    pub tx_fifo: u64,
    pub tx_colls: u64,
    pub tx_carrier: u64,
    pub tx_compressed: u64,
}

impl fmt::Display for NetDevStat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: rx_bytes={} rx_packets={} rx_errors={} rx_dropped={} tx_bytes={} tx_packets={} tx_errors={} tx_dropped={}",
            self.name,
            self.rx_bytes, self.rx_packets, self.rx_errors, self.rx_dropped,
            self.tx_bytes, self.tx_packets, self.tx_errors, self.tx_dropped,
        )
    }
}

/// Collect all network interface statistics from /proc/net/dev
pub fn collect_netdev() -> io::Result<Vec<NetDevStat>> {
    let content = fs::read_to_string("/proc/net/dev")?;
    parse_netdev(&content)
}

fn parse_netdev(content: &str) -> io::Result<Vec<NetDevStat>> {
    let mut stats = Vec::new();
    for line in content.lines() {
        // Skip header lines (first two lines)
        let line = line.trim();
        if !line.contains(':') || line.starts_with("Inter") || line.starts_with("face") {
            continue;
        }
        if let Some((name, rest)) = line.split_once(':') {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if parts.len() < 16 {
                continue;
            }
            let p = |i: usize| -> u64 { parts.get(i).unwrap_or(&"0").parse().unwrap_or(0) };
            stats.push(NetDevStat {
                name: name.trim().to_string(),
                rx_bytes: p(0),
                rx_packets: p(1),
                rx_errors: p(2),
                rx_dropped: p(3),
                rx_fifo: p(4),
                rx_frame: p(5),
                rx_compressed: p(6),
                rx_multicast: p(7),
                tx_bytes: p(8),
                tx_packets: p(9),
                tx_errors: p(10),
                tx_dropped: p(11),
                tx_fifo: p(12),
                tx_colls: p(13),
                tx_carrier: p(14),
                tx_compressed: p(15),
            });
        }
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROC_NET_DEV: &str = r#"Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1234567  12345    0    0    0     0          0         0  1234567  12345    0    0    0     0       0          0
  eth0: 98765432  654321   10    5    0     0          0       100 87654321  543210    2    1    0     0       0          0
"#;

    #[test]
    fn test_parse_netdev() {
        let stats = parse_netdev(PROC_NET_DEV).unwrap();
        assert_eq!(stats.len(), 2);

        let lo = &stats[0];
        assert_eq!(lo.name, "lo");
        assert_eq!(lo.rx_bytes, 1234567);
        assert_eq!(lo.rx_packets, 12345);
        assert_eq!(lo.tx_bytes, 1234567);

        let eth0 = &stats[1];
        assert_eq!(eth0.name, "eth0");
        assert_eq!(eth0.rx_bytes, 98765432);
        assert_eq!(eth0.rx_packets, 654321);
        assert_eq!(eth0.rx_errors, 10);
        assert_eq!(eth0.rx_dropped, 5);
        assert_eq!(eth0.rx_multicast, 100);
        assert_eq!(eth0.tx_bytes, 87654321);
        assert_eq!(eth0.tx_packets, 543210);
        assert_eq!(eth0.tx_errors, 2);
        assert_eq!(eth0.tx_dropped, 1);
    }

    #[test]
    fn test_display() {
        let stats = parse_netdev(PROC_NET_DEV).unwrap();
        let s = format!("{}", stats[1]);
        assert!(s.contains("eth0"));
        assert!(s.contains("rx_bytes="));
    }
}
