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

use std::fs;
use std::io;

use bincode::{Decode, Encode};

#[derive(Debug, Default, Clone, Copy, Encode, Decode, PartialEq)]
pub struct CpuTimes {
    pub user: u64,
    pub nice: u64,
    pub system: u64,
    pub idle: u64,
    pub iowait: u64,
    pub irq: u64,
    pub softirq: u64,
    pub steal: u64,
    pub guest: u64,
    pub guest_nice: u64,
}

#[derive(Debug, Default, Clone, Encode, Decode, PartialEq)]
pub struct CpuState {
    pub total: CpuTimes,
    pub cpus: Vec<CpuTimes>,
    pub context_switches: u64,
    pub boot_time: u64,
    pub processes: u64,
    pub procs_running: u64,
    pub procs_blocked: u64,
}

impl CpuState {
    pub fn collect() -> io::Result<Self> {
        let content = fs::read_to_string("/proc/stat")?;
        Self::parse(&content)
    }

    fn parse(content: &str) -> io::Result<Self> {
        let mut total = CpuTimes::default();
        let mut cpus = Vec::new();
        let mut context_switches = 0;
        let mut boot_time = 0;
        let mut processes = 0;
        let mut procs_running = 0;
        let mut procs_blocked = 0;

        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            if parts[0] == "cpu" {
                if parts.len() >= 11 {
                    total = parse_cpu_times(&parts[1..]);
                }
            } else if parts[0].starts_with("cpu") {
                if parts.len() >= 11 {
                    cpus.push(parse_cpu_times(&parts[1..]));
                }
            } else {
                match parts[0] {
                    "ctxt" => if let Ok(v) = parts.get(1).unwrap_or(&"0").parse() { context_switches = v; },
                    "btime" => if let Ok(v) = parts.get(1).unwrap_or(&"0").parse() { boot_time = v; },
                    "processes" => if let Ok(v) = parts.get(1).unwrap_or(&"0").parse() { processes = v; },
                    "procs_running" => if let Ok(v) = parts.get(1).unwrap_or(&"0").parse() { procs_running = v; },
                    "procs_blocked" => if let Ok(v) = parts.get(1).unwrap_or(&"0").parse() { procs_blocked = v; },
                    _ => {}
                }
            }
        }

        Ok(CpuState {
            total,
            cpus,
            context_switches,
            boot_time,
            processes,
            procs_running,
            procs_blocked,
        })
    }
}

fn parse_cpu_times(parts: &[&str]) -> CpuTimes {
    let parse = |s: &str| s.parse::<u64>().unwrap_or(0);
    CpuTimes {
        user: parse(parts.get(0).unwrap_or(&"0")),
        nice: parse(parts.get(1).unwrap_or(&"0")),
        system: parse(parts.get(2).unwrap_or(&"0")),
        idle: parse(parts.get(3).unwrap_or(&"0")),
        iowait: parse(parts.get(4).unwrap_or(&"0")),
        irq: parse(parts.get(5).unwrap_or(&"0")),
        softirq: parse(parts.get(6).unwrap_or(&"0")),
        steal: parse(parts.get(7).unwrap_or(&"0")),
        guest: parse(parts.get(8).unwrap_or(&"0")),
        guest_nice: parse(parts.get(9).unwrap_or(&"0")),
    }
}
