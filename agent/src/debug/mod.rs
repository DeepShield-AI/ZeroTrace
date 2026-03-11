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

mod debugger;
#[cfg(all(target_os = "linux", feature = "libtrace"))]
mod ebpf;
#[cfg(target_os = "linux")]
mod platform;
mod policy;
mod rpc;
mod cpu;

use bincode::{Decode, Encode};
pub use debugger::{Client, ConstructDebugCtx, Debugger};
#[cfg(all(target_os = "linux", feature = "libtrace"))]
pub use ebpf::EbpfMessage;
#[cfg(target_os = "linux")]
pub use platform::PlatformMessage;
pub use policy::PolicyMessage;
pub use rpc::{ConfigResp, RpcMessage};
pub use cpu::CpuMessage;

use std::str;
use std::time::Duration;

use num_enum::{IntoPrimitive, TryFromPrimitive};

/// 调试操作的默认队列长度
pub const QUEUE_LEN: usize = 1024;
/// 发送 Beacon 消息的最小间隔
pub const BEACON_INTERVAL_MIN: Duration = Duration::from_secs(1);
/// 发送 Beacon 消息的默认间隔
pub const BEACON_INTERVAL: Duration = Duration::from_secs(60);
/// 调试队列空闲状态的超时时间
pub const DEBUG_QUEUE_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Beacon 消息中用于标识 zerotrace-agent 的魔术字符串
pub const ZEROTRACE_AGENT_BEACON: &str = "zerotrace-agent";

/// 调试器支持的模块枚举
#[derive(PartialEq, Eq, Debug, TryFromPrimitive, IntoPrimitive, Clone, Copy, Encode, Decode)]
#[repr(u8)]
pub enum Module {
    Unknown,
    /// RPC 模块，用于配置/状态同步
    Rpc,
    #[cfg(target_os = "linux")]
    /// 平台模块，用于 K8s/云资源
    Platform,
    /// 发现模块
    List,
    /// 内部队列监控
    Queue,
    /// 策略/流 ACL 调试
    Policy,
    #[cfg(all(target_os = "linux", feature = "libtrace"))]
    /// eBPF 探针调试
    Ebpf,
    /// CPU 指标调试
    Cpu,
}

impl Default for Module {
    fn default() -> Self {
        Module::Unknown
    }
}

/// Agent 发现使用的信标消息结构
#[derive(PartialEq, Debug, Encode, Decode)]
pub struct Beacon {
    pub agent_id: u16,
    pub hostname: String,
}

/// 调试通信的通用消息结构
#[derive(Encode, Decode, PartialEq, Debug)]
pub struct Message<T> {
    pub module: Module,
    pub msg: T,
}

impl<T> Message<T> {
    pub fn new(module: Module, msg: T) -> Self {
        Self { module, msg }
    }

    pub fn into_inner(self) -> T {
        self.msg
    }
}
