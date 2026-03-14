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
use std::ops::Sub;

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

impl CpuTimes {
    pub fn total(&self) -> u64 {
        self.user
            + self.nice
            + self.system
            + self.idle
            + self.iowait
            + self.irq
            + self.softirq
            + self.steal
            + self.guest
            + self.guest_nice
    }

    pub fn active(&self) -> u64 {
        self.total() - self.idle - self.iowait
    }
}

impl Sub for CpuTimes {
    type Output = CpuTimes;

    fn sub(self, rhs: Self) -> Self::Output {
        CpuTimes {
            user: self.user.saturating_sub(rhs.user),
            nice: self.nice.saturating_sub(rhs.nice),
            system: self.system.saturating_sub(rhs.system),
            idle: self.idle.saturating_sub(rhs.idle),
            iowait: self.iowait.saturating_sub(rhs.iowait),
            irq: self.irq.saturating_sub(rhs.irq),
            softirq: self.softirq.saturating_sub(rhs.softirq),
            steal: self.steal.saturating_sub(rhs.steal),
            guest: self.guest.saturating_sub(rhs.guest),
            guest_nice: self.guest_nice.saturating_sub(rhs.guest_nice),
        }
    }
}

impl fmt::Display for CpuTimes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let total = self.total() as f64;
        if total == 0.0 {
            return write!(f, "user=0.00% nice=0.00% system=0.00% idle=0.00% iowait=0.00% irq=0.00% softirq=0.00% steal=0.00% guest=0.00% guest_nice=0.00%");
        }
        let pct = |v: u64| v as f64 / total * 100.0;
        write!(
            f,
            "user={:.2}% nice={:.2}% system={:.2}% idle={:.2}% iowait={:.2}% irq={:.2}% softirq={:.2}% steal={:.2}% guest={:.2}% guest_nice={:.2}%",
            pct(self.user),
            pct(self.nice),
            pct(self.system),
            pct(self.idle),
            pct(self.iowait),
            pct(self.irq),
            pct(self.softirq),
            pct(self.steal),
            pct(self.guest),
            pct(self.guest_nice),
        )
    }
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

impl fmt::Display for CpuState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "CPU Total:  {}", self.total)?;
        for (i, cpu) in self.cpus.iter().enumerate() {
            writeln!(f, "CPU {:>5}:  {}", i, cpu)?;
        }
        writeln!(f, "Context Switches: {}", self.context_switches)?;
        writeln!(f, "Boot Time:        {}", self.boot_time)?;
        writeln!(f, "Processes:        {}", self.processes)?;
        writeln!(f, "Procs Running:    {}", self.procs_running)?;
        write!(f, "Procs Blocked:    {}", self.procs_blocked)
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

#[cfg(test)]
mod tests {
    use super::*;

    const PROC_STAT: &str = r#"cpu  10132153 290696 3084719 46828483 16683 0 25195 0 0 0
cpu0 1393280 32966 572056 13343292 6130 0 17875 0 0 0
cpu1 1335498 26113 525820 13345612 3931 0 4960 0 0 0
cpu2 1364872 21498 496116 13370498 3023 0 1313 0 0 0
cpu3 1365925 21270 496483 13372498 2702 0 1047 0 0 0
intr 199292886 44 0 0 0 0 0 0 0 0
ctxt 490315963
btime 1677292882
processes 124319
procs_running 1
procs_blocked 0
softirq 50234534 2 10780769 26 784191 1209517 0 1498 12767672 0 24690859
"#;

    #[test]
    fn test_parse_cpu_state() {
        let state = CpuState::parse(PROC_STAT).unwrap();
        assert_eq!(state.cpus.len(), 4);
        assert_eq!(state.total.user, 10132153);
        assert_eq!(state.total.nice, 290696);
        assert_eq!(state.context_switches, 490315963);
        assert_eq!(state.boot_time, 1677292882);
        assert_eq!(state.processes, 124319);
        assert_eq!(state.procs_running, 1);
        assert_eq!(state.procs_blocked, 0);
    }

    #[test]
    fn test_cpu_times_total() {
        let t = CpuTimes {
            user: 100,
            nice: 10,
            system: 50,
            idle: 800,
            iowait: 20,
            irq: 5,
            softirq: 3,
            steal: 2,
            guest: 0,
            guest_nice: 0,
        };
        assert_eq!(t.total(), 990);
        assert_eq!(t.active(), 170);
    }

    #[test]
    fn test_cpu_times_sub() {
        let a = CpuTimes { user: 200, nice: 20, system: 100, idle: 1600, iowait: 40, irq: 10, softirq: 6, steal: 4, guest: 0, guest_nice: 0 };
        let b = CpuTimes { user: 100, nice: 10, system: 50, idle: 800, iowait: 20, irq: 5, softirq: 3, steal: 2, guest: 0, guest_nice: 0 };
        let delta = a - b;
        assert_eq!(delta.user, 100);
        assert_eq!(delta.idle, 800);
    }

    #[test]
    fn test_display() {
        let state = CpuState::parse(PROC_STAT).unwrap();
        let s = format!("{}", state);
        assert!(s.contains("CPU Total:"));
        assert!(s.contains("CPU     0:"));
        assert!(s.contains("Context Switches:"));
    }
}
