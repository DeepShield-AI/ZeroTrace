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

use std::ffi::CString;
use std::net::{SocketAddr, UdpSocket};
use std::slice;
use std::time::{Duration, Instant};

use bincode::config::Configuration;
use bincode::{Decode, Encode};
use libc::{c_char, c_int};
use log::warn;

use crate::ebpf::{cpdbg_set_config, datadump_set_config};
use public::{
    debug::send_to,
    queue::{bounded, Receiver, Sender},
};

/// eBPF 模块调试消息
#[derive(PartialEq, Debug, Encode, Decode)]
pub enum EbpfMessage {
    /// 数据抓取请求/响应: (进程ID, 进程名, 协议号, 超时时间)
    DataDump((u32, String, u8, u16)),
    /// 持续剖析调试请求: 超时时间
    Cpdbg(u16),
    /// 内容消息: (序列号, 数据)
    Context((u64, Vec<u8>)),
    Error(String), // 错误消息
    Done,          // 完成信号
}

/// eBPF 模块调试器
pub struct EbpfDebugger {
    receiver: Receiver<Vec<u8>>, // eBPF 数据接收端
}

// 全局发送端，用于 C 回调函数将数据发回 Rust
// 由于 C 回调是普通函数无法捕获环境，我们需要使用静态全局变量。
#[allow(static_mut_refs)]
static mut EBPF_DEBUG_SENDER: Option<Sender<Vec<u8>>> = None;

impl EbpfDebugger {
    // 从队列接收数据的超时时间
    const QUEUE_RECV_TIMEOUT: Duration = Duration::from_secs(1);

    /// 传递给 C 代码的回调函数
    ///
    /// 当有新的调试数据时，eBPF C 代码会调用此函数。
    extern "C" fn ebpf_debug(data: *mut c_char, len: c_int) {
        #[allow(static_mut_refs)]
        unsafe {
            // 检查全局发送端是否已初始化
            if let Some(sender) = EBPF_DEBUG_SENDER.as_ref() {
                // 将原始 C 指针和长度转换为 Rust Vec<u8>
                let datas = slice::from_raw_parts(data as *mut u8, len as usize).to_vec();
                // 通过通道发送数据
                let _ = sender.send(datas);
            }
        }
    }

    /// 创建新的 EbpfDebugger
    pub fn new() -> Self {
        // 创建一个有界通道用于传输 eBPF 数据
        let (sender, receiver, _) = bounded(1024);
        
        // 初始化全局发送端（不安全操作）
        #[allow(static_mut_refs)]
        unsafe {
            EBPF_DEBUG_SENDER = Some(sender);
        }
        Self { receiver }
    }

    /// 持续剖析调试
    ///
    /// 配置底层 eBPF 剖析器并将数据流式传回客户端。
    pub fn cpdbg(
        &self,
        sock: &UdpSocket,
        conn: SocketAddr,
        serialize_conf: Configuration,
        msg: &EbpfMessage,
    ) {
        // 从消息中提取超时时间
        let EbpfMessage::Cpdbg(timeout) = msg else {
            return;
        };
        let now = Instant::now();
        let duration = Duration::from_secs(*timeout as u64);
        
        // 配置 C 端 eBPF 剖析器
        unsafe {
            cpdbg_set_config(*timeout as c_int, Self::ebpf_debug);
        }
        
        let mut seq = 1;
        // 循环接收并发送数据直到超时
        while now.elapsed() < duration {
            // 从通道接收数据，带超时
            let s = match self.receiver.recv(Some(Self::QUEUE_RECV_TIMEOUT)) {
                Ok(s) => s,
                _ => continue, // 超时或其他错误则继续
            };

            // 将数据包装在 Context 消息中并通过 UDP 发送给客户端
            if let Err(e) = send_to(&sock, conn, EbpfMessage::Context((seq, s)), serialize_conf) {
                warn!("send ebpf item error: {}", e);
            }
            seq += 1;
        }
        // 发送完成消息
        if let Err(e) = send_to(&sock, conn, EbpfMessage::Done, serialize_conf) {
            warn!("send ebpf item error: {}", e);
        }
    }

    /// 数据抓取调试 (L7 协议数据)
    ///
    /// 配置底层 eBPF 追踪器以捕获特定协议数据。
    pub fn datadump(
        &self,
        sock: &UdpSocket,
        conn: SocketAddr,
        serialize_conf: Configuration,
        msg: &EbpfMessage,
    ) {
        // 从消息中提取参数
        let EbpfMessage::DataDump((pid, name, protocol, timeout)) = msg else {
            return;
        };
        let now = Instant::now();
        let duration = Duration::from_secs(*timeout as u64);
        let empty_cstr = CString::new("").unwrap();
        
        // 配置 C 端 eBPF 数据抓取
        unsafe {
            datadump_set_config(
                *pid as i32,
                CString::new(name.as_bytes()).unwrap().as_c_str().as_ptr(),
                *protocol as i32,
                empty_cstr.as_c_str().as_ptr(),
                0 as c_int,
                *timeout as c_int,
                Self::ebpf_debug,
            );
        }
        
        let mut seq = 1;
        // 循环接收并发送数据直到超时
        while now.elapsed() < duration {
            // 从通道接收数据，带超时
            let s = match self.receiver.recv(Some(Self::QUEUE_RECV_TIMEOUT)) {
                Ok(s) => s,
                _ => continue,
            };

            // 将数据包装在 Context 消息中并通过 UDP 发送给客户端
            if let Err(e) = send_to(&sock, conn, EbpfMessage::Context((seq, s)), serialize_conf) {
                warn!("send ebpf item error: {}", e);
            }
            seq += 1;
        }
        // 发送完成消息
        if let Err(e) = send_to(&sock, conn, EbpfMessage::Done, serialize_conf) {
            warn!("send ebpf item error: {}", e);
        }
    }
}
