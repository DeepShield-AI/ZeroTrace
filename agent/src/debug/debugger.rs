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
    io::{self, ErrorKind},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use arc_swap::access::Access;
use bincode::{
    config::{self, Configuration},
    decode_from_std_read, encode_to_vec, Decode, Encode,
};
use log::{error, info, warn};
use parking_lot::RwLock;
use tokio::runtime::Runtime;

#[cfg(all(target_os = "linux", feature = "libtrace"))]
use super::ebpf::{EbpfDebugger, EbpfMessage};
#[cfg(target_os = "linux")]
use super::platform::{PlatformDebugger, PlatformMessage};
use super::{
    cpu::{CpuDebugger, CpuMessage},
    policy::{PolicyDebugger, PolicyMessage},
    rpc::{RpcDebugger, RpcMessage},
    Beacon, Message, Module, BEACON_INTERVAL, BEACON_INTERVAL_MIN, ZEROTRACE_AGENT_BEACON,
};
#[cfg(target_os = "linux")]
use crate::platform::{ApiWatcher, GenericPoller};
use crate::{
    config::handler::DebugAccess,
    policy::PolicySetter,
    rpc::{Session, StaticConfig, Status},
    trident::AgentId,
    utils::command::get_hostname,
};
use public::{
    consts::DEFAULT_CONTROLLER_PORT,
    debug::{send_to, Error, QueueDebugger, QueueMessage, Result, MAX_BUF_SIZE},
};

/// 各模块的调试器集合
struct ModuleDebuggers {
    #[cfg(target_os = "linux")]
    pub platform: PlatformDebugger, 
    pub rpc: RpcDebugger,           
    pub queue: Arc<QueueDebugger>,  
    pub policy: PolicyDebugger,     
    #[cfg(all(target_os = "linux", feature = "libtrace"))]
    pub ebpf: EbpfDebugger,
    pub cpu: CpuDebugger,
}

/// 调试器主结构
pub struct Debugger {
    thread: Mutex<Option<JoinHandle<()>>>, 
    running: Arc<AtomicBool>,              
    debuggers: Arc<ModuleDebuggers>,       
    config: DebugAccess,                   
    override_os_hostname: Arc<Option<String>>, 
}

/// 构造调试器的上下文信息
pub struct ConstructDebugCtx {
    pub runtime: Arc<Runtime>,             
    pub config: DebugAccess,               
    #[cfg(target_os = "linux")]
    pub api_watcher: Arc<ApiWatcher>,      
    #[cfg(target_os = "linux")]
    pub poller: Arc<GenericPoller>,        
    pub session: Arc<Session>,             
    pub static_config: Arc<StaticConfig>,  
    pub agent_id: Arc<RwLock<AgentId>>,    
    pub status: Arc<RwLock<Status>>,       
    pub policy_setter: PolicySetter,       
}

impl Debugger {
    const TIMEOUT: Duration = Duration::from_millis(500);

    /// 启动调试器
    /// 1. 绑定 UDP 套接字以监听调试命令。
    /// 2. 启动线程处理传入请求。
    /// 3. 启动 Beacon 线程广播 Agent 存在。
    pub fn start(&self) {
        // 确保调试器未在运行
        if self.running.swap(true, Ordering::Relaxed) {
            return;
        }

        // 克隆共享资源以供线程使用
        let running = self.running.clone();
        let debuggers = self.debuggers.clone();
        let conf = self.config.clone();
        let override_os_hostname = self.override_os_hostname.clone();

        #[cfg(any(target_os = "linux", target_os = "android"))]
        let thread = thread::Builder::new()
            .name("debugger".to_owned())
            .spawn(move || {
                // 根据配置确定绑定地址（IPv6 未指定地址）
                let addr: SocketAddr =
                    (IpAddr::from(Ipv6Addr::UNSPECIFIED), conf.load().listen_port).into();
                
                // 尝试绑定 UDP 套接字
                let sock = match UdpSocket::bind(addr) {
                    Ok(s) => Arc::new(s),
                    Err(_) => {
                        // 如果 IPv6 失败，回退到 IPv4
                        let ipv4_addr: SocketAddr =
                            (IpAddr::from(Ipv4Addr::UNSPECIFIED), conf.load().listen_port).into();
                        match UdpSocket::bind(ipv4_addr) {
                            Ok(s) => Arc::new(s),
                            Err(e) => {
                                error!(
                                    "failed to create debugger socket with addr={:?} error: {}",
                                    ipv4_addr, e
                                );
                                return;
                            }
                        }
                    }
                };
                info!("debugger listening on: {:?}", sock.local_addr().unwrap());
                
                // 设置套接字的读写超时
                if let Err(e) = sock.set_read_timeout(Some(Self::TIMEOUT)) {
                    warn!("debugger set read timeout error: {:?}", e);
                }
                if let Err(e) = sock.set_write_timeout(Some(Self::TIMEOUT)) {
                    warn!("debugger set write timeout error: {:?}", e);
                }

                let sock_clone = sock.clone();
                let running_clone = running.clone();
                let serialize_conf = config::standard();
                #[cfg(target_os = "linux")]
                let agent_mode = conf.load().agent_mode;
                let beacon_port = conf.load().controller_port;

                // 启动 Beacon 线程以广播 Agent 存在
                let beacon_thread = thread::Builder::new()
                    .name("debugger-beacon".to_owned())
                    .spawn(move || {
                        // 计算 Beacon 发送间隔
                        let interval_counter_max =
                            BEACON_INTERVAL.as_secs() / BEACON_INTERVAL_MIN.as_secs();
                        let mut interval_counter = 0;
                        
                        while running_clone.load(Ordering::Relaxed) {
                            thread::sleep(BEACON_INTERVAL_MIN);
                            interval_counter += 1;
                            if interval_counter < interval_counter_max {
                                continue;
                            }
                            interval_counter = 0;

                            // 确定要在 Beacon 中包含的主机名
                            let Some(hostname) = override_os_hostname.as_ref().clone().or_else(
                                || match get_hostname() {
                                    Ok(hostname) => Some(hostname),
                                    Err(e) => {
                                        warn!("get hostname failed: {}", e);
                                        None
                                    }
                                },
                            ) else {
                                continue;
                            };

                            // 构造 Beacon 消息
                            let beacon = Beacon {
                                agent_id: conf.load().agent_id,
                                hostname,
                            };

                            // 序列化 Beacon 消息
                            let serialized_beacon = match encode_to_vec(beacon, serialize_conf) {
                                Ok(v) => v,
                                Err(_) => continue,
                            };
                            
                            // 向所有配置的控制器发送 Beacon
                            for &ip in conf.load().controller_ips.iter() {
                                if let Err(e) = sock_clone.send_to(
                                    [
                                        ZEROTRACE_AGENT_BEACON.as_bytes(),
                                        serialized_beacon.as_slice(),
                                    ]
                                    .concat()
                                    .as_slice(),
                                    (ip, beacon_port),
                                ) {
                                    warn!("write beacon to client error: {}", e);
                                }
                            }
                        }
                    })
                    .unwrap();

                // 接收和处理调试命令的主循环
                while running.load(Ordering::Relaxed) {
                    let mut buf = [0u8; MAX_BUF_SIZE];
                    let mut addr = None;
                    match sock.recv_from(&mut buf) {
                        Ok((n, a)) => {
                            if n == 0 {
                                continue;
                            }
                            if addr.is_none() {
                                addr.replace(a);
                            }
                            // 分发接收到的包到相应的模块
                            Self::dispatch(
                                (&sock, addr.unwrap()),
                                &buf,
                                &debuggers,
                                serialize_conf,
                                #[cfg(target_os = "linux")]
                                agent_mode,
                            )
                            .unwrap_or_else(|e| warn!("handle client request error: {}", e));
                        }
                        Err(e) => {
                            match e.kind() {
                                ErrorKind::WouldBlock => {}
                                _ => {
                                    warn!(
                                        "receive udp packet error: kind=({:?}) detail={}",
                                        e.kind(),
                                        e
                                    );
                                }
                            }
                            continue;
                        }
                    }
                }
                let _ = beacon_thread.join();
            })
            .unwrap();

        #[cfg(target_os = "windows")]
        let thread = thread::Builder::new()
            .name("debugger".to_owned())
            .spawn(move || {
                // 检查控制器 IP 是 IPv4 还是 IPv6
                let (mut has_ipv4, mut has_ipv6) = (false, false);
                for &ip in conf.load().controller_ips.iter() {
                    if ip.is_ipv4() {
                        has_ipv4 = true;
                    } else if ip.is_ipv6() {
                        has_ipv6 = true;
                    }
                }

                // 绑定 IPv4 Socket
                let addr_v4: SocketAddr =
                    (IpAddr::from(Ipv4Addr::UNSPECIFIED), conf.load().listen_port).into();
                let sock_v4 = match UdpSocket::bind(addr_v4) {
                    Ok(s) => Arc::new(s),
                    Err(e) => {
                        error!(
                            "failed to create debugger socket with addr_v4={:?} error: {}",
                            addr_v4, e
                        );
                        return;
                    }
                };

                // 绑定 IPv6 Socket
                let addr_v6: SocketAddr =
                    (IpAddr::from(Ipv6Addr::UNSPECIFIED), conf.load().listen_port).into();
                let sock_v6 = match UdpSocket::bind(addr_v6) {
                    Ok(s) => Arc::new(s),
                    Err(e) => {
                        error!(
                            "failed to create debugger socket with addr_v6={:?} error: {}",
                            addr_v6, e
                        );
                        return;
                    }
                };
                info!(
                    "debugger listening on: {:?} and {:?}",
                    sock_v4.local_addr().unwrap(),
                    sock_v6.local_addr().unwrap()
                );
                
                // 设置 IPv4 Socket 超时
                if let Err(e) = sock_v4.set_read_timeout(Some(Self::TIMEOUT)) {
                    warn!("debugger ipv4 set read timeout error: {:?}", e);
                }
                if let Err(e) = sock_v4.set_write_timeout(Some(Self::TIMEOUT)) {
                    warn!("debugger ipv4 set write timeout error: {:?}", e);
                }
                
                // 设置 IPv6 Socket 超时
                if let Err(e) = sock_v6.set_read_timeout(Some(Self::TIMEOUT)) {
                    warn!("debugger ipv6 set read timeout error: {:?}", e);
                }
                if let Err(e) = sock_v6.set_write_timeout(Some(Self::TIMEOUT)) {
                    warn!("debugger ipv6 set write timeout error: {:?}", e);
                }
                
                let sock_v4_clone = sock_v4.clone();
                let sock_v6_clone = sock_v6.clone();
                let running_clone = running.clone();
                let serialize_conf = config::standard();
                let beacon_port = conf.load().controller_port;
                
                // 启动 Beacon 线程
                let beacon_thread = thread::Builder::new()
                    .name("debugger-beacon".to_owned())
                    .spawn(move || {
                        let interval_counter_max =
                            BEACON_INTERVAL.as_secs() / BEACON_INTERVAL_MIN.as_secs();
                        let mut interval_counter = 0;
                        while running_clone.load(Ordering::Relaxed) {
                            thread::sleep(BEACON_INTERVAL_MIN);
                            interval_counter += 1;
                            if interval_counter < interval_counter_max {
                                continue;
                            }
                            interval_counter = 0;

                            let Some(hostname) = override_os_hostname.as_ref().clone().or_else(
                                || match get_hostname() {
                                    Ok(hostname) => Some(hostname),
                                    Err(e) => {
                                        warn!("get hostname failed: {}", e);
                                        None
                                    }
                                },
                            ) else {
                                continue;
                            };

                            let beacon = Beacon {
                                agent_id: conf.load().agent_id,
                                hostname,
                            };

                            let serialized_beacon = match encode_to_vec(beacon, serialize_conf) {
                                Ok(v) => v,
                                Err(_) => continue,
                            };
                            
                            // 根据控制器 IP 版本使用相应的 Socket 发送 Beacon
                            for &ip in conf.load().controller_ips.iter() {
                                if has_ipv4 {
                                    if let Err(e) = sock_v4_clone.send_to(
                                        [
                                            ZEROTRACE_AGENT_BEACON.as_bytes(),
                                            serialized_beacon.as_slice(),
                                        ]
                                        .concat()
                                        .as_slice(),
                                        (ip, beacon_port),
                                    ) {
                                        warn!("write beacon to client error: {}", e);
                                    }
                                } else if has_ipv6 {
                                    if let Err(e) = sock_v6_clone.send_to(
                                        [
                                            ZEROTRACE_AGENT_BEACON.as_bytes(),
                                            serialized_beacon.as_slice(),
                                        ]
                                        .concat()
                                        .as_slice(),
                                        (ip, beacon_port),
                                    ) {
                                        warn!("write beacon to client error: {}", e);
                                    }
                                }
                            }
                        }
                    })
                    .unwrap();

                // 主循环：处理 IPv4 和 IPv6 Socket 上的传入请求
                while running.load(Ordering::Relaxed) {
                    // 轮询 IPv4 Socket
                    if has_ipv4 {
                        let mut buf_v4 = [0u8; MAX_BUF_SIZE];
                        let mut addr_v4 = None;
                        match sock_v4.recv_from(&mut buf_v4) {
                            Ok((n, a)) => {
                                if n == 0 {
                                    continue;
                                }
                                if addr_v4.is_none() {
                                    addr_v4.replace(a);
                                }
                                Self::dispatch(
                                    (&sock_v4, addr_v4.unwrap()),
                                    &buf_v4,
                                    &debuggers,
                                    serialize_conf,
                                )
                                .unwrap_or_else(|e| warn!("handle client request error: {}", e));
                            }
                            Err(e) => {
                                match e.kind() {
                                    ErrorKind::ConnectionReset => {} 
                                    ErrorKind::WouldBlock => {}
                                    ErrorKind::TimedOut => {}
                                    _ => {
                                        warn!(
                                            "receive udp packet error: kind=({:?}) detail={}",
                                            e.kind(),
                                            e
                                        );
                                    }
                                }
                                continue;
                            }
                        }
                    }
                    // 轮询 IPv6 Socket
                    if has_ipv6 {
                        let mut buf_v6 = [0u8; MAX_BUF_SIZE];
                        let mut addr_v6 = None;
                        match sock_v6.recv_from(&mut buf_v6) {
                            Ok((n, a)) => {
                                if n == 0 {
                                    continue;
                                }
                                if addr_v6.is_none() {
                                    addr_v6.replace(a);
                                }
                                Self::dispatch(
                                    (&sock_v6, addr_v6.unwrap()),
                                    &buf_v6,
                                    &debuggers,
                                    serialize_conf,
                                )
                                .unwrap_or_else(|e| warn!("handle client request error: {}", e));
                            }
                            Err(e) => {
                                match e.kind() {
                                    ErrorKind::ConnectionReset => {} 
                                    ErrorKind::WouldBlock => {}
                                    ErrorKind::TimedOut => {}
                                    _ => {
                                        warn!(
                                            "receive udp packet error: kind=({:?}) detail={}",
                                            e.kind(),
                                            e
                                        );
                                    }
                                }
                                continue;
                            }
                        }
                    }
                }
                let _ = beacon_thread.join();
            })
            .unwrap();
        self.thread.lock().unwrap().replace(thread);
        info!("debugger started");
    }

    /// 分发接收到的消息到对应的模块调试器
    fn dispatch(
        conn: (&Arc<UdpSocket>, SocketAddr),
        mut payload: &[u8],
        debuggers: &ModuleDebuggers,
        serialize_conf: Configuration,
        #[cfg(target_os = "linux")] agent_mode: crate::trident::RunningMode,
    ) -> Result<()> {
        // 从 payload 的第一个字节读取模块 ID
        let m = *payload.first().unwrap();
        // 将字节转换为 Module 枚举
        let module = Module::try_from(m).unwrap_or_default();

        match module {
            #[cfg(target_os = "linux")]
            Module::Platform => {
                // 如果处于 Standalone 模式，立即发送 Fin 消息
                if matches!(agent_mode, crate::trident::RunningMode::Standalone) {
                    let msg = PlatformMessage::Fin;
                    send_to(conn.0, conn.1, msg, serialize_conf)?;
                }
                // 从 payload 解码 PlatformMessage
                let req: Message<PlatformMessage> =
                    decode_from_std_read(&mut payload, serialize_conf)?;
                let debugger = &debuggers.platform;
                
                // 处理不同的 Platform 消息
                let resp = match req.into_inner() {
                    PlatformMessage::Version(_) => debugger.api_version(),
                    PlatformMessage::Watcher(w) => debugger
                        .watcher(String::from_utf8(w).map_err(|e| Error::FromUtf8(e.to_string()))?),
                    PlatformMessage::MacMappings(_) => debugger.mac_mapping(),
                    _ => unreachable!(),
                };
                // 发送响应
                iter_send_to(conn.0, conn.1, resp.iter(), serialize_conf)?;
            }
            Module::Rpc => {
                // 解码 RpcMessage
                let req: Message<RpcMessage> = decode_from_std_read(&mut payload, serialize_conf)?;
                let debugger = &debuggers.rpc;
                
                // 分发到特定的 RPC 调试函数
                let resp_result = match req.into_inner() {
                    RpcMessage::Acls(_) => debugger.flow_acls(),
                    RpcMessage::Cidr(_) => debugger.cidrs(),
                    RpcMessage::Config(_) => debugger.basic_config(),
                    RpcMessage::Groups(_) => debugger.ip_groups(),
                    RpcMessage::Segments(_) => debugger.local_segments(),
                    RpcMessage::CaptureNetworkTypes(_) => debugger.tap_types(),
                    RpcMessage::Version(_) => debugger.current_version(),
                    RpcMessage::PlatformData(_) => debugger.platform_data(),
                    _ => unreachable!(),
                };

                // 将结果转换为响应消息，处理错误
                let resp = match resp_result {
                    Ok(m) => m,
                    Err(e) => vec![RpcMessage::Err(e.to_string())],
                };
                iter_send_to(conn.0, conn.1, resp.iter(), serialize_conf)?;
            }
            Module::Queue => {
                // 解码 QueueMessage
                let req: Message<QueueMessage> =
                    decode_from_std_read(&mut payload, serialize_conf)?;
                let debugger = &debuggers.queue;
                
                // 处理 Queue 命令
                match req.into_inner() {
                    QueueMessage::Clear => {
                        let msg = debugger.turn_off_all_queue();
                        send_to(conn.0, conn.1, msg, serialize_conf)?;
                    }
                    QueueMessage::Off(v) => {
                        let msg = debugger.turn_off_queue(v);
                        send_to(conn.0, conn.1, msg, serialize_conf)?;
                    }
                    QueueMessage::Names(_) => {
                        let msgs = debugger.queue_names();
                        iter_send_to(conn.0, conn.1, msgs.iter(), serialize_conf)?;
                    }
                    QueueMessage::On((name, duration)) => {
                        let msg = debugger.turn_on_queue(name.as_str());
                        send_to(conn.0, conn.1, msg, serialize_conf)?;
                        debugger.send(name, conn.1, serialize_conf, duration);
                    }
                    _ => unreachable!(),
                }
            }
            Module::Policy => {
                // 解码 PolicyMessage
                let req: Message<PolicyMessage> =
                    decode_from_std_read(&mut payload, serialize_conf)?;
                let debugger = &debuggers.policy;
                
                // 处理 Policy 命令
                match req.into_inner() {
                    PolicyMessage::On => debugger.send(conn.0, conn.1, serialize_conf),
                    PolicyMessage::Off => {
                        debugger.turn_off();
                    }
                    PolicyMessage::Show => {
                        debugger.show(conn.0, conn.1, serialize_conf);
                    }
                    PolicyMessage::Analyzing(id) => {
                        debugger.analyzing(conn.0, conn.1, id, serialize_conf);
                    }
                    _ => unreachable!(),
                }
            }
            #[cfg(all(target_os = "linux", feature = "libtrace"))]
            Module::Ebpf => {
                let ebpf = &debuggers.ebpf;
                // 解码 EbpfMessage
                let req: Message<EbpfMessage> = decode_from_std_read(&mut payload, serialize_conf)?;
                let req = req.into_inner();
                
                // 处理 eBPF 命令
                match req {
                    EbpfMessage::DataDump(_) => {
                        ebpf.datadump(conn.0, conn.1, serialize_conf, &req);
                    }
                    EbpfMessage::Cpdbg(_) => {
                        ebpf.cpdbg(conn.0, conn.1, serialize_conf, &req);
                    }
                    _ => unreachable!(),
                }
            }
            Module::Cpu => {
                // 解码 CpuMessage
                let req: Message<CpuMessage> =
                    decode_from_std_read(&mut payload, serialize_conf)?;
                let debugger = &debuggers.cpu;

                // 处理 Cpu 命令
                match req.into_inner() {
                    CpuMessage::Show => debugger.show(conn.0, conn.1, serialize_conf),
                    _ => return Err(Error::InvalidMessage("Invalid CpuMessage".to_string())),
                }
            }
            _ => warn!("invalid module or invalid request, skip it"),
        }

        Ok(())
    }
}

impl Debugger {
    /// 创建一个新的 Debugger 实例
    pub fn new(context: ConstructDebugCtx) -> Self {
        let override_os_hostname = Arc::new(context.static_config.override_os_hostname.clone());
        let debuggers = ModuleDebuggers {
            #[cfg(target_os = "linux")]
            platform: PlatformDebugger::new(context.api_watcher, context.poller),
            rpc: RpcDebugger::new(
                context.runtime.clone(),
                context.session,
                context.static_config,
                context.agent_id,
                context.status,
            ),
            queue: Arc::new(QueueDebugger::new()),
            policy: PolicyDebugger::new(context.policy_setter),
            #[cfg(all(target_os = "linux", feature = "libtrace"))]
            ebpf: EbpfDebugger::new(),
            cpu: CpuDebugger::new(),
        };

        Self {
            thread: Mutex::new(None),
            running: Arc::new(AtomicBool::new(false)),
            debuggers: Arc::new(debuggers),
            config: context.config,
            override_os_hostname,
        }
    }

    /// 克隆队列调试器实例
    pub fn clone_queue(&self) -> Arc<QueueDebugger> {
        self.debuggers.queue.clone()
    }

    /// 停止调试器并等待线程结束
    pub fn notify_stop(&self) -> Option<JoinHandle<()>> {
        if !self.running.swap(false, Ordering::Relaxed) {
            return None;
        }

        info!("notified debugger exit");
        self.thread.lock().unwrap().take()
    }

    /// 停止调试器
    pub fn stop(&self) {
        if !self.running.swap(false, Ordering::Relaxed) {
            return;
        }

        let _ = self.thread.lock().unwrap().take();
        info!("debugger exited");
    }
}

/// 用于与 Agent 调试器通信的客户端（供 zerotrace-agent-ctl 使用）
pub struct Client {
    sock: UdpSocket,
    conf: Configuration,
    addr: SocketAddr,
}

impl Client {
    /// Create a new Client
    /// 创建新的客户端
    pub fn new(addr: SocketAddr) -> Result<Self> {
        // 在相应的接口（IPv4/IPv6）上绑定随机端口
        let sock = if addr.is_ipv4() {
            UdpSocket::bind((IpAddr::from(Ipv4Addr::UNSPECIFIED), 0))?
        } else {
            UdpSocket::bind((IpAddr::from(Ipv6Addr::UNSPECIFIED), 0))?
        };
        Ok(Self {
            sock,
            conf: config::standard(),
            addr,
        })
    }

    /// 发送消息给调试器
    ///
    /// Message structure: msg_type (1 byte) + serialized message
    /// 消息结构：msg_type (1 字节) + 序列化消息
    ///
    /// 0          1               N (Bytes)
    /// +----------+---------------+
    /// | msg_type |   message     |
    /// +----------+---------------+
    pub fn send_to(&mut self, msg: impl Encode) -> Result<()> {
        send_to(&self.sock, self.addr, msg, self.conf)?;
        Ok(())
    }

    /// 从调试器接收响应
    pub fn recv<D: Decode>(&mut self) -> Result<D> {
        let mut buf = [0u8; MAX_BUF_SIZE];
        match self.sock.recv(&mut buf) {
            Ok(n) => {
                if n == 0 {
                    return Err(Error::IoError(io::Error::new(
                        ErrorKind::Other,
                        "receive zero byte",
                    )));
                }

                // 解码响应消息
                let d = decode_from_std_read(&mut buf.as_slice(), self.conf)?;
                Ok(d)
            }
            Err(e) => Err(Error::IoError(e)),
        }
    }
}

/// 辅助函数：迭代并发送多条消息
pub(super) fn iter_send_to<I: Iterator>(
    sock: &UdpSocket,
    addr: impl ToSocketAddrs + Clone,
    msgs: I,
    conf: Configuration,
) -> Result<()>
where
    I::Item: Encode,
{
    for msg in msgs {
        send_to(sock, addr.clone(), msg, conf)?
    }
    Ok(())
}
