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
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket},
    time::Duration,
};
#[cfg(target_os = "linux")]
use std::{fmt, io::Write};

use anyhow::{anyhow, Result};
use bincode::{config, decode_from_std_read};
use clap::{ArgEnum, Parser, Subcommand};
#[cfg(target_os = "linux")]
use flate2::write::ZlibDecoder;

#[cfg(all(target_os = "linux", feature = "libtrace"))]
use zerotrace_agent::debug::EbpfMessage;
#[cfg(target_os = "linux")]
use zerotrace_agent::debug::PlatformMessage;
use zerotrace_agent::debug::{
    Beacon, Client, CpuMessage, DiskMessage, MemoryMessage, Message, Module, NetworkMessage,
    PolicyMessage, RpcMessage, DEBUG_QUEUE_IDLE_TIMEOUT, ZEROTRACE_AGENT_BEACON,
};
use public::{consts::DEFAULT_CONTROLLER_PORT, debug::QueueMessage};

const ERR_PORT_MSG: &str = "error: The following required arguments were not provided:
    \t--port <PORT> required arguments were not provided";

#[derive(Parser)]
#[clap(name = "zerotrace-agent-ctl")]
struct Cmd {
    #[clap(subcommand)]
    command: ControllerCmd,
    /// 远程 zerotrace-agent 监听端口
    #[clap(short, long, parse(try_from_str))]
    port: Option<u16>,
    /// 远程 zerotrace-agent 主机 IP
    ///
    /// IPv6 格式为 'fe80::5054:ff:fe95:c839', IPv4 格式为 '127.0.0.1'
    #[clap(short, long, parse(try_from_str), default_value_t=IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))]
    address: IpAddr,
}

#[derive(Subcommand)]
enum ControllerCmd {
    /// 获取 RPC 同步器信息
    Rpc(RpcCmd),
    #[cfg(target_os = "linux")]
    /// 获取 K8s 平台信息
    Platform(PlatformCmd),
    /// 监控选中 zerotrace-agent 的各种队列
    Queue(QueueCmd),
    /// 获取策略信息
    Policy(PolicyCmd),
    #[cfg(all(target_os = "linux", feature = "libtrace"))]
    /// 获取 eBPF 信息
    Ebpf(EbpfCmd),
    /// 获取 zerotrace-agent 信息
    List,
    /// 获取 CPU 信息
    Cpu(CpuCmd),
    /// 获取内存信息
    Memory(MemoryCmd),
    /// 获取磁盘信息
    Disk(DiskCmd),
    /// 获取网络信息
    Network(NetworkCmd),
}

#[derive(Debug, Parser)]
struct CpuCmd {
    #[clap(subcommand)]
    subcmd: CpuSubCmd,
}

#[derive(Subcommand, Debug)]
enum CpuSubCmd {
    Show,
}

#[derive(Debug, Parser)]
struct MemoryCmd {
    #[clap(subcommand)]
    subcmd: MemorySubCmd,
}

#[derive(Subcommand, Debug)]
enum MemorySubCmd {
    Show,
}

#[derive(Debug, Parser)]
struct DiskCmd {
    #[clap(subcommand)]
    subcmd: DiskSubCmd,
}

#[derive(Subcommand, Debug)]
enum DiskSubCmd {
    Show,
}

#[derive(Debug, Parser)]
struct NetworkCmd {
    #[clap(subcommand)]
    subcmd: NetworkSubCmd,
}

#[derive(Subcommand, Debug)]
enum NetworkSubCmd {
    Show,
}

#[derive(Parser)]
struct QueueCmd {
    /// 监控模块
    ///
    /// 例如：监控 1-tagged-flow-to-quadruple-generator 队列 60 秒
    ///
    /// zerotrace-agent-ctl queue --on 1-tagged-flow-to-quadruple-generator --duration 60
    #[clap(long, requires = "monitor")]
    on: Option<String>,
    /// 监控时长（秒）
    #[clap(long, group = "monitor")]
    duration: Option<u64>,
    /// 关闭监控
    ///
    /// 例如：关闭 1-tagged-flow-to-quadruple-generator 队列监控
    ///
    /// zerotrace-agent-ctl queue --off 1-tagged-flow-to-quadruple-generator queue
    #[clap(long)]
    off: Option<String>,
    /// 显示队列列表
    ///
    /// eg: zerotrace-agent-ctl queue --show
    #[clap(long)]
    show: bool,
    /// 关闭所有队列监控
    ///
    /// eg: zerotrace-agent-ctl queue --clear
    #[clap(long)]
    clear: bool,
}

#[cfg(target_os = "linux")]
#[derive(Parser)]
struct PlatformCmd {
    /// 获取 K8s API 资源
    ///
    /// eg: zerotrace-agent-ctl platform --k8s_get node
    #[clap(short, long, arg_enum)]
    k8s_get: Option<Resource>,
    /// 显示 K8s 容器 MAC 到全局接口索引的映射
    ///
    /// eg: zerotrace-agent-ctl platform --mac_mappings
    #[clap(short, long)]
    mac_mappings: bool,
}

#[derive(Debug, Parser)]
struct PolicyCmd {
    #[clap(subcommand)]
    subcmd: PolicySubCmd,
}

#[derive(Subcommand, Debug)]
enum PolicySubCmd {
    Monitor,
    Show,
    Analyzing(AnalyzingArgs),
}

#[derive(Debug, Parser)]
struct AnalyzingArgs {
    /// 设置策略 ID
    ///
    /// eg: zerotrace-agent-ctl policy analyzing --id 10
    #[clap(long, parse(try_from_str))]
    id: Option<u32>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Parser)]
struct EbpfCmd {
    #[clap(subcommand)]
    subcmd: EbpfSubCmd,
}

#[cfg(target_os = "linux")]
#[derive(Subcommand, Debug)]
enum EbpfSubCmd {
    /// 监控数据转储
    Datadump(EbpfArgs),
    /// 监控持续剖析调试
    Cpdbg(EbpfArgs),
}

#[cfg(target_os = "linux")]
#[derive(Debug, Parser)]
struct EbpfArgs {
    /// 设置数据转储 PID
    ///
    /// eg: zerotrace-agent-ctl ebpf datadump --pid 10001
    #[clap(long, parse(try_from_str), default_value_t = 0)]
    pid: u32,
    /// 设置数据转储名称
    ///
    /// eg: zerotrace-agent-ctl ebpf datadump --name nginx
    #[clap(long, parse(try_from_str), default_value = "")]
    name: String,
    /// 设置数据转储应用协议
    ///
    /// 应用协议: All(0), Other(1),
    ///   HTTP1(20), HTTP2(21), Dubbo(40), SofaRPC(43),
    ///   MySQL(60), PostGreSQL(61), Oracle(62),
    ///   Redis(80), MongoDB(81), Memcached(82),
    ///   Kafka(100), MQTT(101), RocketMQ(107), WebSphereMQ(108),  DNS(120), TLS(121),
    ///
    /// 例如: zerotrace-agent-ctl ebpf datadump --proto 20
    #[clap(long, parse(try_from_str), default_value_t = 0)]
    proto: u8,
    /// 设置数据转储/持续剖析调试时长
    ///
    /// eg: zerotrace-agent-ctl ebpf datadump --duration 10
    #[clap(long, parse(try_from_str), default_value_t = 30)]
    duration: u16,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, ArgEnum, Debug)]
enum Resource {
    Version,
    No,
    Node,
    Nodes,
    Ns,
    Namespace,
    Namespaces,
    Ing,
    Ingress,
    Ingresses,
    Svc,
    Service,
    Services,
    Deploy,
    Deployment,
    Deployments,
    Po,
    Pod,
    Pods,
    St,
    Statefulset,
    Statefulsets,
    Ds,
    Daemonset,
    Daemonsets,
    Rc,
    Replicationcontroller,
    Replicationcontrollers,
    Rs,
    Replicaset,
    Replicasets,
}

#[cfg(target_os = "linux")]
impl fmt::Display for Resource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Resource::No | Resource::Node | Resource::Nodes => write!(f, "nodes"),
            Resource::Ns | Resource::Namespace | Resource::Namespaces => write!(f, "namespaces"),
            Resource::Svc | Resource::Service | Resource::Services => write!(f, "services"),
            Resource::Deploy | Resource::Deployment | Resource::Deployments => {
                write!(f, "deployments")
            }
            Resource::Po | Resource::Pod | Resource::Pods => write!(f, "pods"),
            Resource::St | Resource::Statefulset | Resource::Statefulsets => {
                write!(f, "statefulsets")
            }
            Resource::Ds | Resource::Daemonset | Resource::Daemonsets => write!(f, "daemonsets"),
            Resource::Rc | Resource::Replicationcontroller | Resource::Replicationcontrollers => {
                write!(f, "replicationcontrollers")
            }
            Resource::Rs | Resource::Replicaset | Resource::Replicasets => {
                write!(f, "replicasets")
            }
            Resource::Ing | Resource::Ingress | Resource::Ingresses => write!(f, "ingresses"),
            Resource::Version => write!(f, "version"),
        }
    }
}

#[derive(Parser)]
struct RpcCmd {
    /// 从 RPC 获取数据
    ///
    /// 例如：获取 rpc 配置数据
    /// zerotrace-agent-ctl rpc --get config
    #[clap(long, arg_enum)]
    get: RpcData,
}

#[derive(Clone, Copy, ArgEnum, Debug)]
enum RpcData {
    /// 基础配置
    Config,
    /// 平台数据（接口、对等端）
    Platform,
    /// 采集网络类型
    CaptureNetworkTypes,
    /// CIDR 列表
    Cidr,
    /// IP 资源组
    Groups,
    /// 流控制策略
    Acls,
    /// 本地网段
    Segments,
    /// 版本信息
    Version,
}

struct Controller {
    cmd: Option<Cmd>,
    addr: IpAddr,
    port: Option<u16>,
}

impl Controller {
    pub fn new() -> Self {
        let cmd = Cmd::parse();
        Self {
            addr: cmd.address,
            port: cmd.port,
            cmd: Some(cmd),
        }
    }

    fn dispatch(&mut self) -> Result<()> {
        match self.cmd.take().unwrap().command {
            #[cfg(target_os = "linux")]
            ControllerCmd::Platform(c) => self.platform(c),
            ControllerCmd::Rpc(c) => self.rpc(c),
            ControllerCmd::List => self.list(),
            ControllerCmd::Queue(c) => self.queue(c),
            ControllerCmd::Policy(c) => self.policy(c),
            #[cfg(all(target_os = "linux", feature = "libtrace"))]
            ControllerCmd::Ebpf(c) => self.ebpf(c),
            ControllerCmd::Cpu(c) => self.cpu(c),
            ControllerCmd::Memory(c) => self.memory(c),
            ControllerCmd::Disk(c) => self.disk(c),
            ControllerCmd::Network(c) => self.network(c),
        }
    }

    fn cpu(&self, c: CpuCmd) -> Result<()> {
        if self.port.is_none() {
            return Err(anyhow!(ERR_PORT_MSG));
        }

        let mut client = self.new_client()?;
        match c.subcmd {
            CpuSubCmd::Show => {
                client.send_to(Message {
                    module: Module::Cpu,
                    msg: CpuMessage::Show,
                })?;

                let Ok(res) = client.recv::<CpuMessage>() else {
                    return Ok(());
                };
                match res {
                    CpuMessage::Context(s) => println!("{}", s),
                    CpuMessage::Err(e) => println!("{}", e),
                    _ => unreachable!(),
                }
            }
        }
        Ok(())
    }

    fn memory(&self, c: MemoryCmd) -> Result<()> {
        if self.port.is_none() {
            return Err(anyhow!(ERR_PORT_MSG));
        }

        let mut client = self.new_client()?;
        match c.subcmd {
            MemorySubCmd::Show => {
                client.send_to(Message {
                    module: Module::Memory,
                    msg: MemoryMessage::Show,
                })?;

                let Ok(res) = client.recv::<MemoryMessage>() else {
                    return Ok(());
                };
                match res {
                    MemoryMessage::Context(s) => println!("{}", s),
                    MemoryMessage::Err(e) => println!("{}", e),
                    _ => unreachable!(),
                }
            }
        }
        Ok(())
    }

    fn disk(&self, c: DiskCmd) -> Result<()> {
        if self.port.is_none() {
            return Err(anyhow!(ERR_PORT_MSG));
        }

        let mut client = self.new_client()?;
        match c.subcmd {
            DiskSubCmd::Show => {
                client.send_to(Message {
                    module: Module::Disk,
                    msg: DiskMessage::Show,
                })?;

                let Ok(res) = client.recv::<DiskMessage>() else {
                    return Ok(());
                };
                match res {
                    DiskMessage::Context(stats) => {
                        for stat in &stats {
                            println!("{}", stat);
                        }
                    }
                    DiskMessage::Err(e) => println!("{}", e),
                    _ => unreachable!(),
                }
            }
        }
        Ok(())
    }

    fn network(&self, c: NetworkCmd) -> Result<()> {
        if self.port.is_none() {
            return Err(anyhow!(ERR_PORT_MSG));
        }

        let mut client = self.new_client()?;
        match c.subcmd {
            NetworkSubCmd::Show => {
                client.send_to(Message {
                    module: Module::Network,
                    msg: NetworkMessage::Show,
                })?;

                let Ok(res) = client.recv::<NetworkMessage>() else {
                    return Ok(());
                };
                match res {
                    NetworkMessage::Context(stats) => {
                        for stat in &stats {
                            println!("{}", stat);
                        }
                    }
                    NetworkMessage::Err(e) => println!("{}", e),
                    _ => unreachable!(),
                }
            }
        }
        Ok(())
    }

    fn new_client(&self) -> Result<Client> {
        let addr = match self.addr {
            IpAddr::V4(a) => IpAddr::V4(a),
            IpAddr::V6(a) => {
                if let Some(v4) = a.to_ipv4() {
                    IpAddr::V4(v4)
                } else {
                    IpAddr::V6(a)
                }
            }
        };

        let client = Client::new(
            (
                addr,
                self.port.expect("need input a port to connect debugger"),
            )
                .into(),
        )?;
        Ok(client)
    }

    /*
    $ zerotrace-agent-ctl list
    zerotrace-agent-ctl listening udp port 30035 to find zerotrace-agent

    -----------------------------------------------------------------------------------------------------
    VTAP ID        HOSTNAME                     IP                                            PORT
    -----------------------------------------------------------------------------------------------------
    1              ubuntu                       ::ffff:127.0.0.1                              42700
    */
    fn list(&self) -> Result<()> {
        let beacon_port = if let Some(port) = self.port {
            port
        } else {
            DEFAULT_CONTROLLER_PORT
        };

        let server = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, beacon_port))?;
        let mut vtap_map = HashSet::new();

        println!(
            "zerotrace-agent-ctl listening udp port {} to find zerotrace-agent\n",
            beacon_port
        );
        println!("{:-<100}", "");
        println!(
            "{:<14} {:<28} {:45} {}",
            "VTAP ID", "HOSTNAME", "IP", "PORT"
        );
        println!("{:-<100}", "");
        loop {
            let mut buf = [0u8; 1024];
            match server.recv_from(&mut buf) {
                Ok((n, a)) => {
                    if n == 0 {
                        continue;
                    }

                    // 过滤trident的beacon包
                    let length = ZEROTRACE_AGENT_BEACON.as_bytes().len();
                    if buf
                        .get(..length)
                        .filter(|&s| s == ZEROTRACE_AGENT_BEACON.as_bytes())
                        .is_none()
                    {
                        continue;
                    }

                    let beacon: Beacon =
                        decode_from_std_read(&mut &buf[length..n], config::standard())?;
                    if !vtap_map.contains(&beacon.agent_id) {
                        println!(
                            "{:<14} {:<28} {:<45} {}",
                            beacon.agent_id,
                            beacon.hostname,
                            a.ip(),
                            a.port()
                        );
                        vtap_map.insert(beacon.agent_id);
                    }
                }
                Err(e) => return Err(anyhow!("{}", e)),
            };
        }
    }

    fn rpc(&self, c: RpcCmd) -> Result<()> {
        if self.port.is_none() {
            return Err(anyhow!(ERR_PORT_MSG));
        }
        let mut client = self.new_client()?;

        let payload = match c.get {
            RpcData::Acls => RpcMessage::Acls(None),
            RpcData::Config => RpcMessage::Config(None),
            RpcData::Platform => RpcMessage::PlatformData(None),
            RpcData::CaptureNetworkTypes => RpcMessage::CaptureNetworkTypes(None),
            RpcData::Cidr => RpcMessage::Cidr(None),
            RpcData::Groups => RpcMessage::Groups(None),
            RpcData::Segments => RpcMessage::Segments(None),
            RpcData::Version => RpcMessage::Version(None),
        };

        let msg = Message {
            module: Module::Rpc,
            msg: payload,
        };
        client.send_to(msg)?;

        loop {
            let Ok(resp) = client.recv::<RpcMessage>() else {
                continue;
            };
            match resp {
                RpcMessage::Acls(v)
                | RpcMessage::PlatformData(v)
                | RpcMessage::CaptureNetworkTypes(v)
                | RpcMessage::Cidr(v)
                | RpcMessage::Groups(v)
                | RpcMessage::Segments(v) => match v {
                    Some(v) => println!("{}", v),
                    None => return Err(anyhow!(format!("{:?} data is empty", c.get))),
                },
                RpcMessage::Config(s) | RpcMessage::Version(s) => match s {
                    Some(s) => println!("{}", s),
                    None => return Err(anyhow!(format!("{:?} is empty", c.get))),
                },
                RpcMessage::Fin => return Ok(()),
                RpcMessage::Err(e) => return Err(anyhow!(e)),
            }
        }
    }

    fn queue(&self, c: QueueCmd) -> Result<()> {
        if self.port.is_none() {
            return Err(anyhow!(ERR_PORT_MSG));
        }
        if c.on.is_some() && c.off.is_some() {
            return Err(anyhow!("error: --on and --off cannot set at the same time"));
        }

        let mut client = self.new_client()?;
        if c.show {
            let msg = Message {
                module: Module::Queue,
                msg: QueueMessage::Names(None),
            };
            client.send_to(msg)?;

            println!("available queues: ");

            loop {
                let Ok(res) = client.recv::<QueueMessage>() else {
                    continue;
                };
                match res {
                    QueueMessage::Names(e) => match e {
                        Some(e) => {
                            for (i, (s, e)) in e.into_iter().enumerate() {
                                println!(
                                    "{:<5} {:<45} {}",
                                    i,
                                    s,
                                    if e { "enabled" } else { "disabled" }
                                );
                            }
                        }
                        None => return Err(anyhow!("cannot get queue names")),
                    },
                    QueueMessage::Fin => return Ok(()),
                    QueueMessage::Err(e) => return Err(anyhow!(e)),
                    _ => unreachable!(),
                }
            }
        }

        if c.clear {
            let msg = Message {
                module: Module::Queue,
                msg: QueueMessage::Clear,
            };
            client.send_to(msg)?;

            let Ok(res) = client.recv::<QueueMessage>() else {
                return Ok(());
            };
            match res {
                QueueMessage::Fin => {
                    println!("turn off all queues successful");
                    return Ok(());
                }
                QueueMessage::Err(e) => return Err(anyhow!(e)),
                _ => unreachable!(),
            }
        }

        if let Some(s) = c.off {
            let msg = Message {
                module: Module::Queue,
                msg: QueueMessage::Off(s.clone()),
            };
            client.send_to(msg)?;
            let Ok(res) = client.recv::<QueueMessage>() else {
                return Ok(());
            };
            match res {
                QueueMessage::Fin => {
                    println!("turn off queue={} successful", s);
                    return Ok(());
                }
                QueueMessage::Err(e) => return Err(anyhow!(e)),
                _ => unreachable!(),
            }
        }

        if let Some((s, d)) = c.on.zip(c.duration) {
            if d == 0 {
                return Err(anyhow!("zero duration isn't allowed"));
            }

            let dur = Duration::from_secs(d);

            let msg = Message {
                module: Module::Queue,
                msg: QueueMessage::On((s, dur)),
            };
            client.send_to(msg)?;

            let Ok(res) = client.recv::<QueueMessage>() else {
                return Ok(());
            };
            if let QueueMessage::Err(e) = res {
                return Err(anyhow!(e));
            }
            println!("loading queue item...");
            let mut seq = 0;
            loop {
                let Ok(res) = client.recv::<QueueMessage>() else {
                    continue;
                };
                match res {
                    QueueMessage::Send(e) => {
                        println!("MSG-{} {}", seq, e);
                        seq += 1;
                    }
                    QueueMessage::Continue => {
                        println!("nothing received for {:?}", DEBUG_QUEUE_IDLE_TIMEOUT);
                        continue;
                    }
                    QueueMessage::Fin => return Ok(()),
                    QueueMessage::Err(e) => return Err(anyhow!(e)),
                    _ => unreachable!(),
                }
            }
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn decode_entry(decoder: &mut ZlibDecoder<Vec<u8>>, entry: &[u8]) -> Result<String> {
        decoder.write_all(entry)?;
        let b = decoder.reset(vec![])?;
        let result = String::from_utf8(b)?;
        Ok(result)
    }

    #[cfg(target_os = "linux")]
    fn platform(&self, c: PlatformCmd) -> Result<()> {
        if self.port.is_none() {
            return Err(anyhow!(ERR_PORT_MSG));
        }
        let mut client = self.new_client()?;
        if c.mac_mappings {
            let msg = Message {
                module: Module::Platform,
                msg: PlatformMessage::MacMappings(None),
            };
            client.send_to(msg)?;
            println!("Interface Index \t MAC address");

            loop {
                let Ok(res) = client.recv::<PlatformMessage>() else {
                    continue;
                };
                match res {
                    PlatformMessage::MacMappings(e) => {
                        match e {
                            /*
                            $ zerotrace-agent-ctl -p 42700 platform --mac-mappings
                            Interface Index          MAC address
                            12                       01:02:03:04:05:06
                            13                       01:02:03:04:05:06
                            14                       01:02:03:04:05:06
                            */
                            Some(e) => {
                                for (idx, m) in e {
                                    println!("{:<15} \t {}", idx, m);
                                }
                            }
                            None => return Err(anyhow!("mac mappings is empty")),
                        }
                    }
                    PlatformMessage::Fin => return Ok(()),
                    _ => unreachable!(),
                }
            }
        }

        if let Some(r) = c.k8s_get {
            if let Resource::Version = r {
                let msg = Message {
                    module: Module::Platform,
                    msg: PlatformMessage::Version(None),
                };
                client.send_to(msg)?;
                loop {
                    let Ok(res) = client.recv::<PlatformMessage>() else {
                        continue;
                    };
                    match res {
                        PlatformMessage::Version(v) => {
                            /*
                            $ zerotrace-agent-ctl -p 54911 platform --k8s-get version
                            k8s-api-watcher-version xxx
                            */
                            match v {
                                Some(v) => println!("{}", v),
                                None => return Err(anyhow!("server version is empty")),
                            }
                        }
                        PlatformMessage::Fin => return Ok(()),
                        _ => unreachable!(),
                    }
                }
            }

            let msg = Message {
                module: Module::Platform,
                msg: PlatformMessage::Watcher(r.to_string().into_bytes()),
            };
            client.send_to(msg)?;
            let mut decoder = ZlibDecoder::new(vec![]);
            loop {
                let Ok(res) = client.recv::<PlatformMessage>() else {
                    continue;
                };
                match res {
                    PlatformMessage::Watcher(v) => {
                        /*
                        $ zerotrace-agent-ctl -p 54911 platform --k8s-get node
                        nodes entries...
                        */
                        match Self::decode_entry(&mut decoder, v.as_slice()) {
                            Ok(v) => println!("{}", v),
                            Err(e) => eprintln!("{}", e),
                        }
                    }
                    PlatformMessage::NotFound => return Err(anyhow!("no data")),
                    PlatformMessage::Fin => return Ok(()),
                    _ => unreachable!(),
                }
            }
        }
        Ok(())
    }

    fn policy(&self, c: PolicyCmd) -> Result<()> {
        if self.port.is_none() {
            return Err(anyhow!(ERR_PORT_MSG));
        }

        let mut client = self.new_client()?;
        match c.subcmd {
            PolicySubCmd::Monitor => {
                client.send_to(Message {
                    module: Module::Policy,
                    msg: PolicyMessage::On,
                })?;

                loop {
                    let Ok(res) = client.recv::<PolicyMessage>() else {
                        continue;
                    };
                    match res {
                        PolicyMessage::Context(c) => println!("{}", c),
                        PolicyMessage::Done => return Ok(()),
                        PolicyMessage::Err(e) => {
                            println!("{}", e);
                            return Ok(());
                        }
                        _ => unreachable!(),
                    }
                }
            }
            PolicySubCmd::Show => {
                client.send_to(Message {
                    module: Module::Policy,
                    msg: PolicyMessage::Show,
                })?;

                let mut count = 1;
                loop {
                    let Ok(res) = client.recv::<PolicyMessage>() else {
                        continue;
                    };
                    match res {
                        PolicyMessage::Title(t) => {
                            println!("{}", t);
                            continue;
                        }
                        PolicyMessage::Context(c) => println!("\t{}: {}", count, c),
                        PolicyMessage::Done => return Ok(()),
                        PolicyMessage::Err(e) => {
                            println!("{}", e);
                            return Ok(());
                        }
                        _ => unreachable!(),
                    }
                    count += 1;
                }
            }
            PolicySubCmd::Analyzing(args) => {
                client.send_to(Message {
                    module: Module::Policy,
                    msg: PolicyMessage::Analyzing(args.id.unwrap_or_default()),
                })?;

                let Ok(res) = client.recv::<PolicyMessage>() else {
                    return Ok(());
                };
                match res {
                    PolicyMessage::Context(c) => println!("{}", c),
                    _ => unreachable!(),
                }
                Ok(())
            }
        }
    }

    #[cfg(all(target_os = "linux", feature = "libtrace"))]
    fn ebpf(&self, c: EbpfCmd) -> Result<()> {
        if self.port.is_none() {
            return Err(anyhow!(ERR_PORT_MSG));
        }

        let mut client = self.new_client()?;
        match c.subcmd {
            EbpfSubCmd::Cpdbg(arg) => {
                client.send_to(Message {
                    module: Module::Ebpf,
                    msg: EbpfMessage::Cpdbg(arg.duration),
                })?;
            }
            EbpfSubCmd::Datadump(arg) => {
                client.send_to(Message {
                    module: Module::Ebpf,
                    msg: EbpfMessage::DataDump((arg.pid, arg.name, arg.proto, arg.duration)),
                })?;
            }
        }

        loop {
            let Ok(res) = client.recv::<EbpfMessage>() else {
                continue;
            };
            match res {
                EbpfMessage::Context((seq, c)) => {
                    println!("SEQ {}: {}", seq, String::from_utf8_lossy(&c))
                }
                EbpfMessage::Done => return Ok(()),
                EbpfMessage::Error(e) => {
                    println!("{}", e);
                    return Ok(());
                }
                _ => unreachable!(),
            }
        }
    }
}

fn main() {
    let mut controller = Controller::new();
    if let Err(e) = controller.dispatch() {
        eprintln!("{}", e);
    }
}
