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

use std::{
    net::{SocketAddr, UdpSocket},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use bincode::{config::Configuration, Decode, Encode};
use log::warn;

use crate::policy::PolicySetter;
use public::{
    debug::send_to,
    queue::{bounded, Error, Receiver, Sender},
};

/// 策略模块调试消息
#[derive(PartialEq, Debug, Encode, Decode)]
pub enum PolicyMessage {
    Unknown,
    On,              // 开启监控
    Off,             // 关闭监控
    Title(String),   // 标题消息
    Context(String), // 内容消息
    Show,            // 显示所有 ACL
    Analyzing(u32),  // 分析特定 ACL ID
    Done,            // 完成信号
    Err(String),     // 错误消息
}

/// 策略模块调试器
pub struct PolicyDebugger {
    policy_setter: PolicySetter,        // 策略设置器，用于与策略模块交互
    sender: Arc<Sender<String>>,        // 监控数据发送端
    receiver: Arc<Receiver<String>>,    // 监控数据接收端
    enabled: Arc<AtomicBool>,           // 监控开启状态标志
}

impl PolicyDebugger {
    // 监控队列接收超时时间
    const QUEUE_RECV_TIMEOUT: Duration = Duration::from_secs(1);

    /// 创建新的 PolicyDebugger
    pub fn new(mut policy_setter: PolicySetter) -> Self {
        // 创建一个有界通道用于传输监控数据
        let (sender, receiver, _) = bounded(1024);
        let sender = Arc::new(sender);
        let enabled = Arc::new(AtomicBool::new(false));

        // 将监控通道和开关注册到 PolicySetter 中
        // 这允许策略模块在启用时推送命中数据
        policy_setter.set_monitor(sender.clone(), enabled.clone());

        PolicyDebugger {
            enabled,
            sender,
            receiver: Arc::new(receiver),
            policy_setter,
        }
    }

    /// 关闭监控
    pub(super) fn turn_off(&self) {
        self.enabled.swap(false, Ordering::Relaxed);
    }

    /// 开启监控
    pub(super) fn turn_on(&self) {
        self.enabled.swap(true, Ordering::Relaxed);
    }

    /// 处理监控命令：将策略命中信息发送给客户端
    pub(super) fn send(&self, sock: &UdpSocket, conn: SocketAddr, serialize_conf: Configuration) {
        let now = Instant::now();
        // 监控持续时间限制（30秒）
        let duration = Duration::from_secs(30);

        // 在策略模块中启用监控
        self.turn_on();

        // 循环接收并转发监控数据
        while self.enabled.load(Ordering::SeqCst) && now.elapsed() < duration {
            // 从通道接收数据，带超时
            let s = match self.receiver.recv(Some(Self::QUEUE_RECV_TIMEOUT)) {
                Ok(s) => s,
                Err(Error::Terminated(..)) => {
                    // 通道关闭，停止监控并发送错误
                    self.turn_off();
                    let _ = send_to(
                        &sock,
                        conn,
                        PolicyMessage::Err("policy monitor queue terminated.".to_string()),
                        serialize_conf,
                    );
                    return;
                }
                Err(Error::Timeout) => continue, // 超时，重新检查循环条件
                Err(Error::BatchTooLarge(_)) => unreachable!(),
            };

            // 将接收到的字符串（策略命中信息）发送给客户端
            if let Err(e) = send_to(&sock, conn, PolicyMessage::Context(s), serialize_conf) {
                warn!("send policy item error: {}", e);
            }
        }
        // 禁用监控
        self.turn_off();

        // 发送完成消息
        let _ = send_to(&sock, conn, PolicyMessage::Done, serialize_conf);
    }

    /// 处理 show 命令：列出所有 ACL
    pub(super) fn show(&self, sock: &UdpSocket, conn: SocketAddr, serialize_conf: Configuration) {
        // 获取当前 ACL 列表并克隆
        let mut acls = self.policy_setter.get_acls().clone();
        // 获取命中计数
        let (first_hits, fast_hits) = self.policy_setter.get_hits();
        // 按 ID 排序 ACL
        acls.sort_by_key(|x| x.id);
        
        // 发送汇总标题
        let _ = send_to(
            &sock,
            conn,
            PolicyMessage::Title(format!(
                "FirstPath Hits: {}, FastPath Hits: {}",
                first_hits, fast_hits
            )),
            serialize_conf,
        );
        
        // 遍历并发送每个 ACL 详情
        for acl in acls {
            let _ = send_to(
                &sock,
                conn,
                PolicyMessage::Context(acl.to_string()),
                serialize_conf,
            );
        }
        // 发送完成消息
        let _ = send_to(&sock, conn, PolicyMessage::Done, serialize_conf);
    }

    /// 处理 analyzing 命令：显示指定 ACL 的详细信息
    pub(super) fn analyzing(
        &self,
        sock: &UdpSocket,
        conn: SocketAddr,
        id: u32,
        serialize_conf: Configuration,
    ) {
        // 根据 ID 查找 ACL
        let acl = self.policy_setter.get_acls().iter().find(|&x| x.id == id);
        if acl.is_none() {
            // 未找到，发送错误消息
            let _ = send_to(
                &sock,
                conn,
                PolicyMessage::Context(format!("Invalid acl id {}.", id)),
                serialize_conf,
            );
            return;
        }
        // 获取资源组信息用于解析组 ID
        let groups = self.policy_setter.get_groups();
        let acl = acl.unwrap();
        let mut src_groups = Vec::new();
        let mut dst_groups = Vec::new();

        // 解析源组 ID 为组对象
        for group_id in &acl.src_groups {
            let src_group = groups.iter().find(|x| x.id == *group_id as u16);
            if src_group.is_some() {
                src_groups.push(src_group.unwrap().clone());
            }
        }
        // 解析目标组 ID 为组对象
        for group_id in &acl.dst_groups {
            let dst_group = groups.iter().find(|x| x.id == *group_id as u16);
            if dst_group.is_some() {
                dst_groups.push(dst_group.unwrap().clone());
            }
        }

        // 格式化并发送详细的 ACL 信息
        let _ = send_to(&sock, conn, PolicyMessage::Context(format!(
            "Id: {}\nCaptureNetworkType: {}\nIP Src: \n\t{}\nIP Dst: \n\t{}\nProtocol: {}\nPort Src: {:?}\nPort Dst: {:?}\nActions: {}\n", 
            acl.id,
            acl.tap_type,
            src_groups.iter().map(|x| format!("EPC: {} IP: {:?}", x.epc_id, x.ips)).collect::<Vec<String>>().join("\t\n"),
            dst_groups.iter().map(|x| format!("EPC: {} IP: {:?}", x.epc_id, x.ips)).collect::<Vec<String>>().join("\t\n"),
            acl.proto,
            acl.src_port_ranges.iter().map(|x| x.to_string()).collect::<Vec<String>>().join(", "),
            acl.dst_port_ranges.iter().map(|x| x.to_string()).collect::<Vec<String>>().join(", "),
            acl.npb_actions.iter().map(|x| x.to_string()).collect::<Vec<String>>().join(","),
        )), serialize_conf);
    }
}
