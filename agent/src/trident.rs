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

use std::env;
use std::fmt;
use std::fs;
use std::io::Write;
use std::mem;
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::{
    atomic::{AtomicBool, AtomicI64, Ordering},
    Arc, Condvar, Mutex, RwLock, Weak,
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{anyhow, Result};
use arc_swap::access::Access;
use dns_lookup::lookup_host;
use flexi_logger::{
    colored_opt_format, writers::LogWriter, Age, Cleanup, Criterion, FileSpec, Logger, Naming,
};
use log::{debug, error, info, warn};
use num_enum::{FromPrimitive, IntoPrimitive};
use tokio::runtime::{Builder, Runtime};
use tokio::sync::broadcast;
use zstd::Encoder as ZstdEncoder;

use crate::{
    collector::{
        flow_aggr::FlowAggrThread, quadruple_generator::QuadrupleGeneratorThread, CollectorThread,
        MetricsType,
    },
    collector::{
        l7_quadruple_generator::L7QuadrupleGeneratorThread, Collector, L7Collector,
        L7CollectorThread,
    },
    common::{
        enums::CaptureNetworkType,
        flow::L7Stats,
        tagged_flow::{BoxedTaggedFlow, TaggedFlow},
        tap_types::CaptureNetworkTyper,
        FeatureFlags, DEFAULT_LOG_RETENTION, DEFAULT_LOG_UNCOMPRESSED_FILE_COUNT,
        DEFAULT_TRIDENT_CONF_FILE, FREE_SPACE_REQUIREMENT,
    },
    config::PcapStream,
    config::{
        handler::{ConfigHandler, DispatcherConfig, ModuleConfig},
        Config, ConfigError, DpdkSource, UserConfig,
    },
    debug::{ConstructDebugCtx, Debugger},
    dispatcher::{
        self, recv_engine::bpf, BpfOptions, Dispatcher, DispatcherBuilder, DispatcherListener,
    },
    exception::ExceptionHandler,
    flow_generator::{
        protocol_logs::BoxAppProtoLogsData, protocol_logs::SessionAggregator, PacketSequenceParser,
        TIME_UNIT,
    },
    handler::{NpbBuilder, PacketHandlerBuilder},
    integration_collector::{
        ApplicationLog, BoxedPrometheusExtra, Datadog, MetricServer, OpenTelemetry,
        OpenTelemetryCompressed, Profile, TelegrafMetric,
    },
    metric::document::BoxedDocument,
    monitor::Monitor,
    platform::synchronizer::Synchronizer as PlatformSynchronizer,
    policy::{Policy, PolicyGetter, PolicySetter},
    rpc::{Session, Synchronizer, DEFAULT_TIMEOUT},
    sender::{
        npb_sender::NpbArpTable,
        uniform_sender::{Connection, UniformSenderThread},
    },
    utils::{
        cgroups::{is_kernel_available_for_cgroups, Cgroups},
        command::get_hostname,
        environment::{
            check, controller_ip_check, free_memory_check, free_space_checker, get_ctrl_ip_and_mac,
            get_env, kernel_check, running_in_container, running_in_k8s, tap_interface_check,
            trident_process_check,
        },
        guard::Guard,
        logger::{LogLevelWriter, LogWriterAdapter, RemoteLogWriter},
        npb_bandwidth_watcher::NpbBandwidthWatcher,
        stats::{self, Countable, QueueStats, RefCountable},
    },
};
#[cfg(any(target_os = "linux", target_os = "android"))]
use crate::{
    platform::SocketSynchronizer,
    utils::{environment::core_file_check, lru::Lru, process::ProcessListener},
};
#[cfg(target_os = "linux")]
use crate::{
    platform::{
        kubernetes::{GenericPoller, Poller, SidecarPoller},
        ApiWatcher, LibvirtXmlExtractor,
    },
    utils::environment::{IN_CONTAINER, K8S_WATCH_POLICY},
};

#[cfg(feature = "enterprise-integration")]
use integration_skywalking::SkyWalkingExtra;
#[cfg(feature = "enterprise-integration")]
use integration_vector::vector_component::VectorComponent;
use packet_sequence_block::BoxedPacketSequenceBlock;
use pcap_assembler::{BoxedPcapBatch, PcapAssembler};

#[cfg(feature = "enterprise")]
use enterprise_utils::kernel_version::{kernel_version_check, ActionFlags};
use public::{
    buffer::BatchedBox,
    debug::QueueDebugger,
    packet::MiniPacket,
    proto::agent::{self, Exception, PacketCaptureType, SocketType},
    queue::{self, DebugSender},
    utils::net::{get_route_src_ip, IpMacPair, Link, MacAddr},
    LeakyBucket,
};
#[cfg(target_os = "linux")]
use public::{netns, packet, queue::Receiver};

const MINUTE: Duration = Duration::from_secs(60);
const COMMON_DELAY: u64 = 5; // Potential delay from other processing steps in flow_map
const QG_PROCESS_MAX_DELAY: u64 = 5; // FIXME: Potential delay from processing steps in qg, it is an estimated value and is not accurate; the data processing capability of the quadruple_generator should be optimized.

// 变更的配置项，用于通知 Agent 更新
#[derive(Debug, Default)]
pub struct ChangedConfig {
    pub user_config: UserConfig,
    pub blacklist: Vec<u64>,
    pub vm_mac_addrs: Vec<MacAddr>,
    pub gateway_vmac_addrs: Vec<MacAddr>,
    pub tap_types: Vec<agent::CaptureNetworkType>,
}

// Agent 运行模式
#[derive(Clone, Default, Copy, PartialEq, Eq, Debug)]
pub enum RunningMode {
    #[default]
    Managed,    // 托管模式 (由控制器管理)
    Standalone, // 独立模式 (仅本地配置)
}

// 内部状态，包含启用状态和熔断状态
#[derive(Copy, Clone, Debug)]
struct InnerState {
    enabled: bool,
    melted_down: bool,
}

impl Default for InnerState {
    fn default() -> Self {
        Self {
            enabled: false,
            melted_down: true,
        }
    }
}

impl From<InnerState> for State {
    fn from(state: InnerState) -> Self {
        if state.enabled && !state.melted_down {
            State::Running
        } else {
            State::Disabled
        }
    }
}

// Agent 整体状态
#[derive(Debug, PartialEq, Eq)]
pub enum State {
    Running,    // 运行中
    Terminated, // 已终止
    Disabled,   // 已禁用 (可能因配置或熔断)
}

// Agent 状态管理器，支持多线程同步
#[derive(Default)]
pub struct AgentState {
    // terminated is outside of Mutex because during termination, state will be locked in main thread,
    // and the main thread will try to stop other threads, in which may lock and update agent state,
    // causing a deadlock. Checking terminated state before locking inner state will avoid this deadlock.
    // 终止标志放在 Mutex 之外，以避免在终止过程中发生死锁
    terminated: AtomicBool,
    state: Mutex<(InnerState, Option<ChangedConfig>)>,
    notifier: Condvar,
}

impl AgentState {
    // 获取当前 Agent 状态
    pub fn get(&self) -> State {
        let sg = self.state.lock().unwrap();
        sg.0.into()
    }

    // 启用 Agent (从禁用状态恢复)
    pub fn enable(&self) {
        if self.terminated.load(Ordering::Relaxed) {
            // when state is Terminated, main thread should still be notified for exiting
            self.notifier.notify_one();
            return;
        }
        let mut sg = self.state.lock().unwrap();
        let old_state: State = sg.0.into();
        sg.0.enabled = true;
        let new_state: State = sg.0.into();
        if old_state != new_state {
            info!("Agent state changed from {old_state:?} to {new_state:?} (enabled: {} melted_down: {})", sg.0.enabled, sg.0.melted_down);
            self.notifier.notify_one();
        }
    }

    // 禁用 Agent (停止所有组件)
    pub fn disable(&self) {
        if self.terminated.load(Ordering::Relaxed) {
            // when state is Terminated, main thread should still be notified for exiting
            self.notifier.notify_one();
            return;
        }
        let mut sg = self.state.lock().unwrap();
        let old_state: State = sg.0.into();
        sg.0.enabled = false;
        let new_state: State = sg.0.into();
        if old_state != new_state {
            info!("Agent state changed from {old_state:?} to {new_state:?} (enabled: {} melted_down: {})", sg.0.enabled, sg.0.melted_down);
            self.notifier.notify_one();
        }
    }

    // 发生熔断时调用，禁用 Agent
    pub fn melt_down(&self) {
        if self.terminated.load(Ordering::Relaxed) {
            // when state is Terminated, main thread should still be notified for exiting
            self.notifier.notify_one();
            return;
        }
        let mut sg = self.state.lock().unwrap();
        let old_state: State = sg.0.into();
        sg.0.melted_down = true;
        let new_state: State = sg.0.into();
        if old_state != new_state {
            info!("Agent state changed from {old_state:?} to {new_state:?} (enabled: {} melted_down: {})", sg.0.enabled, sg.0.melted_down);
            self.notifier.notify_one();
        }
    }

    // 恢复熔断状态
    pub fn recover(&self) {
        if self.terminated.load(Ordering::Relaxed) {
            // when state is Terminated, main thread should still be notified for exiting
            self.notifier.notify_one();
            return;
        }
        let mut sg = self.state.lock().unwrap();
        let old_state: State = sg.0.into();
        sg.0.melted_down = false;
        let new_state: State = sg.0.into();
        if old_state != new_state {
            info!("Agent state changed from {old_state:?} to {new_state:?} (enabled: {} melted_down: {})", sg.0.enabled, sg.0.melted_down);
            self.notifier.notify_one();
        }
    }

    // 更新配置
    pub fn update_config(&self, config: ChangedConfig) {
        if self.terminated.load(Ordering::Relaxed) {
            // when state is Terminated, main thread should still be notified for exiting
            self.notifier.notify_one();
            return;
        }
        let mut sg = self.state.lock().unwrap();
        sg.0.enabled = config.user_config.global.common.enabled;
        sg.1.replace(config);
        self.notifier.notify_one();
    }

    // 更新部分配置 (通常是 user_config)
    pub fn update_partial_config(&self, user_config: UserConfig) {
        if self.terminated.load(Ordering::Relaxed) {
            // when state is Terminated, main thread should still be notified for exiting
            self.notifier.notify_one();
            return;
        }
        let mut sg = self.state.lock().unwrap();
        sg.0.enabled = user_config.global.common.enabled;
        if let Some(changed_config) = sg.1.as_mut() {
            changed_config.user_config = user_config;
        } else {
            sg.1.replace(ChangedConfig {
                user_config,
                ..Default::default()
            });
        }
        self.notifier.notify_one();
    }
}

// 版本信息
pub struct VersionInfo {
    pub name: &'static str,
    pub branch: &'static str,
    pub commit_id: &'static str,
    pub rev_count: &'static str,
    pub compiler: &'static str,
    pub compile_time: &'static str,

    pub revision: &'static str,
}

impl VersionInfo {
    pub fn brief_tag(&self) -> String {
        format!(
            "{}|{}|{}",
            match self.name {
                "deepflow-agent-ce" => "CE",
                "deepflow-agent-ee" => "EE",
                _ => panic!("{:?} unknown deepflow-agent edition", &self.name),
            },
            self.branch,
            self.commit_id
        )
    }
}

impl fmt::Display for VersionInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}-{}
Name: {}
Branch: {}
CommitId: {}
RevCount: {}
Compiler: {}
CompileTime: {}",
            self.rev_count,
            self.commit_id,
            match self.name {
                "deepflow-agent-ce" => "deepflow-agent community edition",
                "deepflow-agent-ee" => "deepflow-agent enterprise edition",
                _ => panic!("{:?} unknown deepflow-agent edition", &self.name),
            },
            self.branch,
            self.commit_id,
            self.rev_count,
            self.compiler,
            self.compile_time
        )
    }
}

// Agent 标识符，包含 IP/MAC 和团队/组 ID
#[derive(Clone, Debug)]
pub struct AgentId {
    pub ipmac: IpMacPair,
    pub team_id: String,
    pub group_id: String,
}

impl Default for AgentId {
    fn default() -> Self {
        Self {
            ipmac: IpMacPair::default(),
            team_id: Default::default(),
            group_id: Default::default(),
        }
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.ipmac.ip, self.ipmac.mac)?;
        if !self.team_id.is_empty() {
            write!(f, "/team={}", self.team_id)?;
        }
        if !self.group_id.is_empty() {
            write!(f, "/group={}", self.group_id)?;
        }
        Ok(())
    }
}

impl From<&AgentId> for agent::AgentId {
    fn from(id: &AgentId) -> Self {
        Self {
            ip: Some(id.ipmac.ip.to_string()),
            mac: Some(id.ipmac.mac.to_string()),
            team_id: Some(id.team_id.clone()),
            group_id: Some(id.group_id.clone()),
        }
    }
}

// 发送器编码方式
#[derive(Clone, Copy, PartialEq, Eq, Debug, FromPrimitive, IntoPrimitive, num_enum::Default)]
#[repr(u8)]
pub enum SenderEncoder {
    #[num_enum(default)]
    Raw = 0,    // 原始数据

    Zstd = 3,   // Zstd 压缩
}

impl SenderEncoder {
    pub fn encode(&self, encode_buffer: &[u8], dst_buffer: &mut Vec<u8>) -> std::io::Result<()> {
        match self {
            SenderEncoder::Zstd => {
                let mut encoder = ZstdEncoder::new(dst_buffer, 0)?;
                encoder.write_all(&encode_buffer)?;
                encoder.finish()?;
                Ok(())
            }
            _ => Ok(()),
    }
    }
}

// Agent 主体结构
pub struct Trident {
    state: Arc<AgentState>,
    handle: Option<JoinHandle<()>>, // 主线程句柄
}

impl Trident {
    // 启动 DeepFlow Agent
    //
    // 该方法负责 Agent 的初始化工作，包括：
    // 1. 保护 CPU 亲和性，防止 numad 干扰
    // 2. 加载配置 (Managed 或 Standalone 模式)
    // 3. 确定控制器 IP 和 MAC 地址
    // 4. 初始化日志系统 (本地和远程)
    // 5. 启动统计数据收集器
    // 6. 启动主事件循环线程 (Trident::run)
    pub fn start<P: AsRef<Path>>(
        config_path: P,
        version_info: &'static VersionInfo,
        agent_mode: RunningMode,
        sidecar_mode: bool,
        cgroups_disabled: bool,
    ) -> Result<Trident> {
        // 1. 保护 CPU 亲和性，防止 numad 干扰
        // To prevent 'numad' from interfering with the CPU
        // affinity settings of deepflow-agent
        #[cfg(any(target_os = "linux", target_os = "android"))]
        // 只针对linux和android系统，windows系统中不存在numad
        // CPU 亲和性: DeepFlow Agent通常会将关键线程绑定到特定的 CPU 核上，以减少上下文切换和缓存失效，从而提升抓包和处理性能。
        // numad 是 Linux 下的一个用户态守护进程，用于自动调整进程的 NUMA（非统一内存访问）策略。它会监控系统资源并尝试动态迁移进程到它认为更合适的 CPU/内存节点上。
        // 如果 numad 介入并强行移动 Agent 的线程，会破坏 Agent 精心配置的 CPU 绑定，导致严重的性能抖动或下降。
        match trace_utils::protect_cpu_affinity() {
            Ok(()) => info!("CPU affinity protected successfully"),
            Err(e) => {
                // Distinguish between "numad not found" (normal) and other errors
                if e.kind() == std::io::ErrorKind::NotFound {
                    info!("numad process not found, skipping CPU affinity protection (normal)");
                } else {
                    warn!(
                        "Failed to protect CPU affinity due to unexpected error: {}",
                        e
                    );
                }
            }
        }
        // 2. 加载配置 (Managed 或 Standalone 模式)
        // 根据agent运行模式加载对应配置
        // Managed 模式：Agent 由控制器管理，仅加载基础配置，其余配置通过 RPC 拉取
        // Standalone 模式：Agent 独立运行，加载完整的本地配置文件
        let config = match agent_mode {
            RunningMode::Managed => {
                //  简单配置，只包含连接server的基本信息，其余配置由server下发
                match Config::load_from_file(config_path.as_ref()) {
                    Ok(conf) => conf,
                    Err(e) => {
                        if let ConfigError::YamlConfigInvalid(_) = e {
                            // try to load config file from trident.yaml to support upgrading from trident
                            // 默认配置
                            if let Ok(conf) = Config::load_from_file(DEFAULT_TRIDENT_CONF_FILE) {
                                conf
                            } else {
                                // return the original error instead of loading trident conf
                                return Err(e.into());
                            }
                        } else {
                            return Err(e.into());
                        }
                    }
                }
            }
            RunningMode::Standalone => {
                // 复杂配置，包含所有配置细节
                // 在 Standalone 模式下，直接加载 UserConfig，并转换为内部 Config 结构
                let rc = UserConfig::load_from_file(config_path.as_ref())?;
                let mut conf = Config::default();
                // 控制器ip地址设置为本地回环，无远程通信
                conf.controller_ips = vec!["127.0.0.1".into()];
                // 只用到复杂配置中的日志文件配置
                conf.log_file = rc.global.self_monitoring.log.log_file;
                conf.agent_mode = agent_mode;
                conf
            }
        };
        #[cfg(target_os = "linux")]
        // 在linux系统下创建和管理agent的pid文件，防止agent重复启动
        // 仅在配置中指定时运行，确保同一配置下只有一个 Agent 实例
        if !config.pid_file.is_empty() {
            if let Err(e) = crate::utils::pid_file::open(&config.pid_file) {
                return Err(anyhow!("Create pid file {} failed: {}", config.pid_file, e));
            }
        };
        // 只取第一个控制器ip，用于初始连接和身份识别
        let controller_ip: IpAddr = config.controller_ips[0].parse()?;
        // 确定agent与server通信的ip地址和mac地址
        // 也用于 Agent 自身的身份标识 (AgentId)
        let (ctrl_ip, ctrl_mac) = match get_ctrl_ip_and_mac(&controller_ip) {
            Ok(tuple) => tuple,
            Err(e) => return Err(anyhow!("get ctrl ip and mac failed: {}", e)),
        };
        // 创建配置处理器，管理静态配置和动态配置的更新
        let mut config_handler = ConfigHandler::new(config, ctrl_ip, ctrl_mac);
        // 简单配置
        let config = &config_handler.static_config;
        let cgroups_disabled = cgroups_disabled || config.cgroups_disabled;
        let hostname = match config.override_os_hostname.as_ref() {
            Some(name) => name.to_owned(),
            None => get_hostname().unwrap_or("Unknown".to_string()),
        };
        // NTP 时间差，用于校准数据时间
        let ntp_diff = Arc::new(AtomicI64::new(0));
        // 统计数据收集器，用于收集 Agent 内部的各项指标
        let stats_collector = Arc::new(stats::Collector::new(&hostname, ntp_diff.clone()));
        // 异常处理器，用于记录和上报 Agent 运行过程中的异常
        let exception_handler = ExceptionHandler::default();
        // 发送模块的漏桶限流器，用于控制发送速率
        let sender_leaky_bucket = Arc::new(LeakyBucket::new(Some(0)));
        // 日志和统计数据的共享连接，复用连接以减少资源开销
        let log_stats_shared_connection = Arc::new(Mutex::new(Connection::new()));
        // 5. 启动统计数据收集器
        // 创建统计数据发送线程
        // 该线程负责定期收集 Agent 内部指标并发送给 Collector
        // "stats": 线程名
        // stats_collector.get_receiver(): 数据接收端
        // config_handler.sender(): 发送配置
        let mut stats_sender = UniformSenderThread::new(
            "stats",
            stats_collector.get_receiver(),
            config_handler.sender(),
            stats_collector.clone(),
            exception_handler.clone(),
            Some(log_stats_shared_connection.clone()),
            SenderEncoder::Raw,
            sender_leaky_bucket.clone(),
        );
        // 启动统计数据发送线程
        stats_sender.start();

        let base_name = Path::new(&env::args().next().unwrap())
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();

        let (log_level_writer, log_level_counter) = LogLevelWriter::new();
        // 初始化日志记录器，默认日志级别 "info"
        // 使用 flexi_logger 进行日志管理
        let logger = Logger::try_with_env_or_str("info")
            .unwrap()
            .format(colored_opt_format);
        // check log folder permission
        // 检查日志目录权限，决定是否写入文件
        // 如果目录不可写，则仅输出到终端
        let base_path = Path::new(config_handler.static_config.log_file.as_str());
        let base_path = base_path.parent().unwrap();
        let write_to_file = if base_path.exists() {
            base_path
                .metadata()
                .ok()
                .map(|meta| !meta.permissions().readonly())
                .unwrap_or(false)
        } else {
            fs::create_dir_all(base_path).is_ok()
        };
        let mut logger_writers: Vec<Box<dyn LogWriter>> = vec![Box::new(log_level_writer)];
        // 如果是托管模式，添加远程日志写入器
        // 远程日志写入器会将日志发送给控制器或数据节点
        if matches!(config.agent_mode, RunningMode::Managed) {
            let remote_log_writer = RemoteLogWriter::new(
                base_name,
                hostname.clone(),
                config_handler.log(),
                config_handler.sender(),
                stats_collector.clone(),
                exception_handler.clone(),
                ntp_diff.clone(),
                log_stats_shared_connection,
                sender_leaky_bucket.clone(),
            );
            logger_writers.push(Box::new(remote_log_writer));
        }
        // 配置日志写入目标 (文件/终端/远程)
        // 配置日志轮转策略：按天轮转，保留最近的文件
        let logger = if write_to_file {
            logger
                .log_to_file_and_writer(
                    FileSpec::try_from(&config_handler.static_config.log_file)?,
                    Box::new(LogWriterAdapter::new(logger_writers)),
                )
                .rotate(
                    Criterion::Age(Age::Day),
                    Naming::Timestamps,
                    Cleanup::KeepLogAndCompressedFiles(
                        DEFAULT_LOG_UNCOMPRESSED_FILE_COUNT,
                        DEFAULT_LOG_RETENTION,
                    ),
                )
                .create_symlink(&config_handler.static_config.log_file)
                .append()
        } else {
            eprintln!(
                "Log file path '{}' access denied, logs will not be written to file",
                &config_handler.static_config.log_file
            );
            logger.log_to_writer(Box::new(LogWriterAdapter::new(logger_writers)))
        };

        #[cfg(any(target_os = "linux", target_os = "android"))]
        // 检查父进程 ID (PPID) 是否不等于 1
        // PPID != 1: 通常表示 Agent 是由用户在 Shell 中手动启动的（非 init/systemd 启动）。
        //            在这种情况下，为了方便调试，将日志同时输出到标准错误 (stderr)。
        // PPID == 1: 表示 Agent 是由 init 进程管理的守护进程。
        //            此时通常只记录到文件，避免在生产环境中产生不必要的控制台输出。
        let logger = if nix::unistd::getppid().as_raw() != 1 {
            logger.duplicate_to_stderr(flexi_logger::Duplicate::All)
        } else {
            logger
        };
        // 启动日志记录器
        let logger_handle = logger.start()?;
        config_handler.set_logger_handle(logger_handle);

        let config = &config_handler.static_config;
        // Use controller ip to replace analyzer ip before obtaining configuration
        // 在获取配置前，使用控制器 IP 替换分析器 IP (或使用默认值)
        // 在托管模式下，Agent 启动时尚未从控制器获取完整的配置（包括分析器/数据节点 IP）。
        // 此处提前启动 StatsCollector，以便在获取配置的过程中也能收集 Agent 自身的运行指标（如 CPU/内存、日志计数等）。
        // 此时发送的目标 IP 可能尚未确定（默认为 0.0.0.0 或控制器 IP），待配置同步完成后会自动更新。
        if matches!(config.agent_mode, RunningMode::Managed) {
            stats_collector.start();
        }

        // 注册日志计数器
        // stats_collector 负责收集 Agent 内部的各种统计指标 (Self-Monitoring)。
        // 这里注册的是 "log_counter"，用于统计不同级别日志的产生数量（Error, Warn）。
        stats_collector.register_countable(
            &stats::NoTagModule("log_counter"),
            stats::Countable::Owned(Box::new(log_level_counter)),
        );

        info!("static_config {:#?}", config);
        let state = Arc::new(AgentState::default());
        let state_thread = state.clone();
        let config_path = match agent_mode {
            RunningMode::Managed => None,
            RunningMode::Standalone => Some(config_path.as_ref().to_path_buf()),
        };
        // 启动主循环线程 (Trident::run)
        // 该线程负责 Agent 的核心逻辑，包括配置同步、组件管理等
        let main_loop = thread::Builder::new()
            .name("main-loop".to_owned())
            .spawn(move || {
                if let Err(e) = Self::run(
                    state_thread,
                    ctrl_ip,
                    ctrl_mac,
                    config_handler,
                    version_info,
                    stats_collector,
                    exception_handler,
                    config_path,
                    sidecar_mode,
                    cgroups_disabled,
                    ntp_diff,
                    sender_leaky_bucket,
                ) {
                    error!(
                        "Launching deepflow-agent failed: {}, deepflow-agent restart...",
                        e
                    );
                    crate::utils::clean_and_exit(1);
                }
            });
        let handle = match main_loop {
            Ok(h) => Some(h),
            Err(e) => {
                error!("Failed to create main-loop thread: {}", e);
                crate::utils::clean_and_exit(1);
                None
            }
        };

        Ok(Trident { state, handle })
    }

    #[cfg(feature = "enterprise")]
    // 检查内核版本兼容性 (企业版功能)
    // 根据内核检查结果执行相应操作：终止 Agent、熔断、禁用 eBPF 等
    fn kernel_version_check(state: &AgentState, exception_handler: &ExceptionHandler) {
        let action = kernel_version_check();
        if action.contains(ActionFlags::TERMINATE) {
            exception_handler.set(Exception::KernelVersionCircuitBreaker);
            crate::utils::clean_and_exit(1);
        } else if action.contains(ActionFlags::MELTDOWN) {
            exception_handler.set(Exception::KernelVersionCircuitBreaker);
            state.melt_down();
            warn!("kernel check: set MELTDOWN");
        } else if action.contains(ActionFlags::EBPF_MELTDOWN) {
            exception_handler.set(Exception::KernelVersionCircuitBreaker);
            // set ebpf_meltdown
            warn!("kernel check: set EBPF_MELTDOWN");
        } else if action.contains(ActionFlags::EBPF_UPROBE_MELTDOWN) {
            exception_handler.set(Exception::KernelVersionCircuitBreaker);
            // set ebpf_uprobe_meltdown
            warn!("kernel check: set EBPF_UPROBE_MELTDOWN");
        }
    }

    fn run(
        state: Arc<AgentState>,
        ctrl_ip: IpAddr,
        ctrl_mac: MacAddr,
        mut config_handler: ConfigHandler,
        version_info: &'static VersionInfo,
        stats_collector: Arc<stats::Collector>,
        exception_handler: ExceptionHandler,
        config_path: Option<PathBuf>,
        sidecar_mode: bool,
        cgroups_disabled: bool,
        ntp_diff: Arc<AtomicI64>,
        sender_leaky_bucket: Arc<LeakyBucket>,
    ) -> Result<()> {
        info!("==================== Launching DeepFlow-Agent ====================");
        info!("Brief tag: {}", version_info.brief_tag());
        info!("Environment variables: {:?}", get_env());
        // 通过环境变量检查
        if running_in_container() {
            info!(
                "use K8S_NODE_IP_FOR_DEEPFLOW env ip as destination_ip({})",
                ctrl_ip
            );
        }

        #[cfg(target_os = "linux")]
        // 确定 Agent ID
        // Sidecar 模式：使用控制器的 IP/MAC 和配置的 Team/Group ID
        // 非 Sidecar 模式：切换到宿主机命名空间获取真实的物理网卡 IP/MAC
        let agent_id = if sidecar_mode {
            AgentId {
                ipmac: IpMacPair::from((ctrl_ip.clone(), ctrl_mac)),
                team_id: config_handler.static_config.team_id.clone(),
                group_id: config_handler.static_config.vtap_group_id_request.clone(),
            }
        } else {
            // use host ip/mac as agent id if not in sidecar mode
            // 如果不在 sidecar 模式，使用宿主机 IP/MAC 作为 agent id
            if let Err(e) = netns::NsFile::Root.open_and_setns() {
                return Err(anyhow!("agent must have CAP_SYS_ADMIN to run without 'hostNetwork: true'. setns error: {}", e));
            }
            let controller_ip: IpAddr = config_handler.static_config.controller_ips[0].parse()?;
            let (ip, mac) = match get_ctrl_ip_and_mac(&controller_ip) {
                Ok(tuple) => tuple,
                Err(e) => return Err(anyhow!("get ctrl ip and mac failed with error: {}", e)),
            };
            if let Err(e) = netns::reset_netns() {
                return Err(anyhow!("reset netns error: {}", e));
            };
            AgentId {
                ipmac: IpMacPair::from((ip, mac)),
                team_id: config_handler.static_config.team_id.clone(),
                group_id: config_handler.static_config.vtap_group_id_request.clone(),
            }
        };
        #[cfg(any(target_os = "windows", target_os = "android"))]
        let agent_id = AgentId {
            ipmac: IpMacPair::from((ctrl_ip.clone(), ctrl_mac)),
            team_id: config_handler.static_config.team_id.clone(),
            group_id: config_handler.static_config.vtap_group_id_request.clone(),
        };

        info!(
            "agent {} running in {:?} mode, ctrl_ip {} ctrl_mac {}",
            agent_id, config_handler.static_config.agent_mode, ctrl_ip, ctrl_mac
        );

        // 创建与 Controller 的 RPC 会话
        // 负责所有与控制器的 GRPC 通信
        let session = Arc::new(Session::new(
            config_handler.static_config.controller_port,
            config_handler.static_config.controller_tls_port,
            DEFAULT_TIMEOUT,
            config_handler
                .static_config
                .controller_cert_file_prefix
                .clone(),
            config_handler.static_config.controller_ips.clone(),
            exception_handler.clone(),
            &stats_collector,
        ));

        // 创建 Tokio 运行时
        // 用于驱动所有的异步任务 (如 gRPC, metrics sender 等)
        let runtime = Arc::new(
            Builder::new_multi_thread()
                .worker_threads(
                    config_handler
                        .static_config
                        .async_worker_thread_number
                        .into(),
                )
                .enable_all()
                .build()
                .unwrap(),
        );

        let mut k8s_opaque_id = None;
        // 如果 Agent 运行在 K8s 环境下的托管模式
        if matches!(
            config_handler.static_config.agent_mode,
            RunningMode::Managed
        ) && running_in_k8s()
        {
            // 尝试自动填充 K8s Cluster ID
            // 如果配置中未指定 cluster_id，Agent 会尝试调用 gRPC 接口向 Server 查询。
            // 即使 ConfigMap 没配，也能通过 CA 证书指纹自动关联到正确的集群。
            config_handler
                .static_config
                .fill_k8s_info(&runtime, &session);
            // 获取 K8s CA 证书的 MD5 值
            // 作为一个不透明的 ID (opaque_id) 发送给 Controller，用于辅助识别集群身份。
            k8s_opaque_id = Config::get_k8s_ca_md5();
        }

        let (ipmac_tx, _) = broadcast::channel::<IpMacPair>(1);
        let ipmac_tx = Arc::new(ipmac_tx);

        // 创建同步器，负责从 Controller 拉取配置和策略
        // 定期同步并触发配置更新事件
        let synchronizer = Arc::new(Synchronizer::new(
            runtime.clone(),
            session.clone(),
            state.clone(),
            version_info,
            agent_id,
            config_handler.static_config.controller_ips[0].clone(),
            config_handler.static_config.vtap_group_id_request.clone(),
            config_handler.static_config.kubernetes_cluster_id.clone(),
            config_handler.static_config.kubernetes_cluster_name.clone(),
            k8s_opaque_id,
            config_handler.static_config.override_os_hostname.clone(),
            config_handler.static_config.agent_unique_identifier,
            exception_handler.clone(),
            config_handler.static_config.agent_mode,
            config_path,
            ipmac_tx.clone(),
            ntp_diff,
        ));
        stats_collector.register_countable(
            &stats::NoTagModule("ntp"),
            stats::Countable::Owned(Box::new(synchronizer.ntp_counter())),
        );
        synchronizer.start();

        // 如果 Agent 运行在托管模式 (Managed)
        if matches!(
            config_handler.static_config.agent_mode,
            RunningMode::Managed
        ) {
            // 启动远程执行器 (Remote Executor)
            // 允许 Server 端下发诊断命令到 Agent 执行，用于远程排查问题。
            // 支持的命令包括：系统命令 (top, ps, netstat, strace 等) 和 K8s 命令 (kubectl logs, describe 等)。
            // 这是一个长连接，Agent 会持续监听来自 Server 的指令。
            #[cfg(any(target_os = "linux", target_os = "android"))]
            let remote_executor = crate::rpc::Executor::new(
                synchronizer.agent_id.clone(),
                session.clone(),
                runtime.clone(),
                exception_handler.clone(),
                config_handler.flow(),
                config_handler.log_parser(),
            );
            #[cfg(any(target_os = "linux", target_os = "android"))]
            remote_executor.start();
        }

        // 域名监听器，监听 Controller 域名变化
        let mut domain_name_listener = DomainNameListener::new(
            stats_collector.clone(),
            session.clone(),
            config_handler.static_config.controller_domain_name.clone(),
            config_handler.static_config.controller_ips.clone(),
            sidecar_mode,
            ipmac_tx.clone(),
        );
        domain_name_listener.start();

        let mut cgroup_mount_path = "".to_string();
        let mut is_cgroup_v2 = false;
        let mut cgroups_controller = None;
        // Cgroups 初始化逻辑
        // 用于限制 Agent 自身的资源使用 (CPU/内存)，防止影响业务进程。
        if running_in_container() {
            // 如果在容器中运行，通常由 K8s/Docker 限制资源，Agent 不自行操作 Cgroups。
            info!("don't initialize cgroups controller, because agent is running in container");
        } else if !is_kernel_available_for_cgroups() {
            // fixme: Linux after kernel version 2.6.24 can use cgroups
            info!("don't initialize cgroups controller, because kernel version < 3 or agent is in Windows");
        } else if cgroups_disabled {
            // 如果配置显式禁用 Cgroups，则退化为定期轮询检查资源使用情况。
            info!("don't initialize cgroups controller, disable cgroups, deepflow-agent will default to checking the CPU and memory resource usage in a loop every 10 seconds to prevent resource usage from exceeding limits");
        } else {
            // 初始化 Cgroups 控制器，用于资源限制
            match Cgroups::new(process::id() as u64, config_handler.environment()) {
                Ok(cg_controller) => {
                    cg_controller.start();
                    cgroup_mount_path = cg_controller.get_mount_path();
                    is_cgroup_v2 = cg_controller.is_v2();
                    cgroups_controller = Some(cg_controller);
                }
                Err(e) => {
                    warn!("initialize cgroups controller failed: {}, resource utilization will be checked regularly to prevent resource usage from exceeding the limit.", e);
                    exception_handler.set(Exception::CgroupsConfigError);
                }
            }
        }

        let log_dir = Path::new(config_handler.static_config.log_file.as_str());
        let log_dir = log_dir.parent().unwrap().to_str().unwrap();
        // 初始化资源守卫，负责监控资源使用并执行熔断
        let guard = match Guard::new(
            config_handler.environment(),
            state.clone(),
            log_dir.to_string(),
            exception_handler.clone(),
            cgroup_mount_path,
            is_cgroup_v2,
            cgroups_disabled,
        ) {
            Ok(g) => g,
            Err(e) => {
                warn!("guard create failed");
                return Err(anyhow!(e));
            }
        };

        // 初始化资源监控器，定期采集资源使用情况
        let monitor = Monitor::new(
            stats_collector.clone(),
            log_dir.to_string(),
            config_handler.environment(),
        )?;
        monitor.start();

        #[cfg(target_os = "linux")]
        let (libvirt_xml_extractor, platform_synchronizer, sidecar_poller, api_watcher) = {
            // Libvirt XML 提取器: 定期扫描 KVM 虚拟机的 XML 配置文件，获取虚拟机接口信息
            let ext = Arc::new(LibvirtXmlExtractor::new());
            // 平台信息同步器: 负责将本地采集的平台信息 (如虚拟机、Pod 接口) 上报给控制器
            let syn = Arc::new(PlatformSynchronizer::new(
                runtime.clone(),
                config_handler.platform(),
                config_handler.static_config.override_os_hostname.clone(),
                synchronizer.agent_id.clone(),
                session.clone(),
                ext.clone(),
                exception_handler.clone(),
            ));
            ext.start();
            let poller = if sidecar_mode {
                // Sidecar Poller: 在 Sidecar 模式下，轮询获取当前 Pod 的接口信息
                let p = match SidecarPoller::new(
                    config_handler.static_config.controller_ips[0].parse()?,
                ) {
                    Ok(p) => p,
                    Err(e) => return Err(anyhow!(e)),
                };
                let p: Arc<GenericPoller> = Arc::new(p.into());
                syn.set_kubernetes_poller(p.clone());
                Some(p)
            } else {
                None
            };
            // K8s API 监听器: 监听 K8s Apiserver，获取 Pod、Node 等资源变更 (仅在有权限时启用)
            let watcher = Arc::new(ApiWatcher::new(
                runtime.clone(),
                config_handler.platform(),
                synchronizer.agent_id.clone(),
                session.clone(),
                exception_handler.clone(),
                stats_collector.clone(),
            ));
            (ext, syn, poller, watcher)
        };
        #[cfg(any(target_os = "windows", target_os = "android"))]
        let platform_synchronizer = Arc::new(PlatformSynchronizer::new(
            runtime.clone(),
            config_handler.platform(),
            config_handler.static_config.override_os_hostname.clone(),
            synchronizer.agent_id.clone(),
            session.clone(),
            exception_handler.clone(),
        ));
        if matches!(
            config_handler.static_config.agent_mode,
            RunningMode::Managed
        ) {
            platform_synchronizer.start();
        }

        #[cfg(feature = "enterprise")]
        Trident::kernel_version_check(&state, &exception_handler);

        let mut components: Option<Components> = None;
        let mut first_run = true;
        let mut config_initialized = false;

        loop {
            let mut state_guard = state.state.lock().unwrap();
            // 检查是否收到终止信号
            if state.terminated.load(Ordering::Relaxed) {
                mem::drop(state_guard);
                if let Some(mut c) = components {
                    c.stop();
                    guard.stop();
                    monitor.stop();
                    domain_name_listener.stop();
                    platform_synchronizer.stop();
                    #[cfg(target_os = "linux")]
                    {
                        api_watcher.stop();
                        libvirt_xml_extractor.stop();
                    }
                    if let Some(cg_controller) = cgroups_controller {
                        if let Err(e) = cg_controller.stop() {
                            info!("stop cgroups controller failed, {:?}", e);
                        }
                    }
                }
                return Ok(());
            }

            // 主循环：处理 Agent 状态变更和配置更新
            // Agent 的状态由 AgentState 维护，包括 Running, Disabled, Terminated
            // 当状态发生变化或有新配置时，notifier 会唤醒此循环
            state_guard = state.notifier.wait(state_guard).unwrap();
            match State::from(state_guard.0) {
                State::Running if state_guard.1.is_none() => {
                    // 状态: 运行中 (Running)
                    // 操作: 启动或恢复所有组件
                    // 注意: 仅当没有待处理的配置更新 (state_guard.1.is_none()) 时执行
                    mem::drop(state_guard);
                    #[cfg(target_os = "linux")]
                    // 根据配置启动或停止 K8s API 监听器
                    if config_handler
                        .candidate_config
                        .platform
                        .kubernetes_api_enabled
                    {
                        api_watcher.start();
                    } else {
                        api_watcher.stop();
                    }
                    if let Some(ref mut c) = components {
                        c.start();
                    }
                    continue;
                }
                State::Disabled => {
                    // 状态: 已禁用 (Disabled)
                    // 操作: 停止所有组件，并检查是否有新的配置需要应用
                    // 原因: 可能是用户主动禁用，或者是发生熔断 (Meltdown)
                    // 处理新的配置数据
                    let new_config = state_guard.1.take();
                    mem::drop(state_guard);
                    if let Some(ref mut c) = components {
                        c.stop();
                    }
                    if let Some(cfg) = new_config {
                        let agent_id = synchronizer.agent_id.read().clone();
                        // 处理新的 UserConfig，生成回调函数列表
                        let callbacks = config_handler.on_config(
                            cfg.user_config,
                            &exception_handler,
                            &stats_collector,
                            None,
                            #[cfg(target_os = "linux")]
                            &api_watcher,
                            &runtime,
                            &session,
                            &agent_id,
                            first_run,
                        );
                        first_run = false;

                        #[cfg(target_os = "linux")]
                        // 根据配置启动或停止 K8s API 监听器
                        if config_handler
                            .candidate_config
                            .platform
                            .kubernetes_api_enabled
                        {
                            api_watcher.start();
                        } else {
                            api_watcher.stop();
                        }

                        if let Some(Components::Agent(c)) = components.as_mut() {
                            for callback in callbacks {
                                callback(&config_handler, c);
                            }

                            for d in c.dispatcher_components.iter_mut() {
                                d.dispatcher_listener
                                    .on_config_change(&config_handler.candidate_config.dispatcher);
                            }
                        } else {
                            stats_collector
                                .set_hostname(config_handler.candidate_config.stats.host.clone());
                            stats_collector
                                .set_min_interval(config_handler.candidate_config.stats.interval);
                        }

                        if !config_initialized {
                            // 启动资源守卫
                            guard.start();
                            config_initialized = true;
                        }
                    }
                    continue;
                }
                _ => (),
            }

            // 获取变更的配置数据
            // 当 state_guard.1 (ChangedConfig) 不为空时，说明有配置更新
            // 这里会取出配置并应用到各个组件
            let ChangedConfig {
                user_config,
                blacklist,
                vm_mac_addrs,
                gateway_vmac_addrs,
                tap_types,
            } = state_guard.1.take().unwrap();
            mem::drop(state_guard);

            // 处理变更的配置数据
            let agent_id = synchronizer.agent_id.read().clone();
            match components.as_mut() {
                None => {
                    // 首次收到配置，初始化所有组件
                    let callbacks = config_handler.on_config(
                        user_config,
                        &exception_handler,
                        &stats_collector,
                        None,
                        #[cfg(target_os = "linux")]
                        &api_watcher,
                        &runtime,
                        &session,
                        &agent_id,
                        first_run,
                    );
                    first_run = false;

                    #[cfg(target_os = "linux")]
                    // 根据配置启动或停止 K8s API 监听器
                    if config_handler
                        .candidate_config
                        .platform
                        .kubernetes_api_enabled
                    {
                        api_watcher.start();
                    } else {
                        api_watcher.stop();
                    }

                    // 初始化各个组件：Dispatcher, Collector, PCAP, Debugger 等
                    let mut comp = Components::new(
                        &version_info,
                        &config_handler,
                        stats_collector.clone(),
                        &session,
                        &synchronizer,
                        exception_handler.clone(),
                        #[cfg(target_os = "linux")]
                        libvirt_xml_extractor.clone(),
                        platform_synchronizer.clone(),
                        #[cfg(target_os = "linux")]
                        sidecar_poller.clone(),
                        #[cfg(target_os = "linux")]
                        api_watcher.clone(),
                        vm_mac_addrs,
                        gateway_vmac_addrs,
                        config_handler.static_config.agent_mode,
                        runtime.clone(),
                        sender_leaky_bucket.clone(),
                        ipmac_tx.clone(),
                    )?;

                    // 启动所有组件
                    comp.start();

                    if let Components::Agent(components) = &mut comp {
                        // 如果是 Analyzer 模式，解析 TAP 类型
                        if config_handler.candidate_config.dispatcher.capture_mode
                            == PacketCaptureType::Analyzer
                        {
                            parse_tap_type(components, tap_types);
                        }

                        // 执行配置更新的回调函数
                        for callback in callbacks {
                            callback(&config_handler, components);
                        }
                    }

                    components.replace(comp);
                }
                Some(Components::Agent(components)) => {
                    // 处理配置更新 (组件已存在)
                    let callbacks: Vec<fn(&ConfigHandler, &mut AgentComponents)> = config_handler
                        .on_config(
                            user_config,
                            &exception_handler,
                            &stats_collector,
                            Some(components),
                            #[cfg(target_os = "linux")]
                            &api_watcher,
                            &runtime,
                            &session,
                            &agent_id,
                            first_run,
                        );
                    first_run = false;

                    #[cfg(target_os = "linux")]
                    // 根据配置启动或停止 K8s API 监听器
                    if config_handler
                        .candidate_config
                        .platform
                        .kubernetes_api_enabled
                    {
                        api_watcher.start();
                    } else {
                        api_watcher.stop();
                    }

                    // 更新组件配置并重新启动/刷新
                    components.config = config_handler.candidate_config.clone();
                    components.start();

                    // 通知组件处理特定配置变更 (黑名单, VM MAC, TAP 类型等)
                    component_on_config_change(
                        &config_handler,
                        components,
                        blacklist,
                        vm_mac_addrs,
                        gateway_vmac_addrs,
                        tap_types,
                        &synchronizer,
                        #[cfg(target_os = "linux")]
                        libvirt_xml_extractor.clone(),
                    );
                    for callback in callbacks {
                        callback(&config_handler, components);
                    }

                    // 通知 Dispatcher 配置变更
                    for d in components.dispatcher_components.iter_mut() {
                        d.dispatcher_listener
                            .on_config_change(&config_handler.candidate_config.dispatcher);
                    }
                }
                _ => {
                    config_handler.on_config(
                        user_config,
                        &exception_handler,
                        &stats_collector,
                        None,
                        #[cfg(target_os = "linux")]
                        &api_watcher,
                        &runtime,
                        &session,
                        &agent_id,
                        first_run,
                    );
                    first_run = false;

                    #[cfg(target_os = "linux")]
                    // 根据配置启动或停止 K8s API 监听器
                    if config_handler
                        .candidate_config
                        .platform
                        .kubernetes_api_enabled
                    {
                        api_watcher.start();
                    } else {
                        api_watcher.stop();
                    }
                }
            }

            if !config_initialized {
                // 收到第一个配置后启动 guard，确保熔断阈值已由配置设置
                guard.start();
                config_initialized = true;
            }
        }
    }

    // 停止 Agent
    pub fn stop(&mut self) {
        info!("Agent stopping");
        crate::utils::clean_and_exit(0);
    }
}

// 根据配置的正则获取需要监听的网络接口
fn get_listener_links(
    conf: &DispatcherConfig,
    #[cfg(target_os = "linux")] netns: &netns::NsFile,
) -> Vec<Link> {
    if conf.tap_interface_regex.is_empty() {
        info!("tap-interface-regex is empty, skip packet dispatcher");
        return vec![];
    }
    #[cfg(target_os = "linux")]
    match netns::links_by_name_regex_in_netns(&conf.tap_interface_regex, netns) {
        Err(e) => {
            warn!("get interfaces by name regex in {:?} failed: {}", netns, e);
            vec![]
        }
        Ok(links) => {
            if links.is_empty() {
                warn!(
                    "tap-interface-regex({}) do not match any interface in {:?}",
                    conf.tap_interface_regex, netns,
                );
            }
            debug!("tap interfaces in namespace {:?}: {:?}", netns, links);
            links
        }
    }

    #[cfg(any(target_os = "windows", target_os = "android"))]
    match public::utils::net::links_by_name_regex(&conf.tap_interface_regex) {
        Err(e) => {
            warn!("get interfaces by name regex failed: {}", e);
            vec![]
        }
        Ok(links) => {
            if links.is_empty() {
                warn!(
                    "tap-interface-regex({}) do not match any interface, in local mode",
                    conf.tap_interface_regex
                );
            }
            debug!("tap interfaces: {:?}", links);
            links
        }
    }
}

// 处理组件的特定配置变更 (如黑名单, VM MAC, TAP 类型等)
//
// 该函数在配置更新时被调用，负责：
// 1. 根据捕获模式 (Local/Mirror/Analyzer) 更新分发器 (Dispatcher)
// 2. 处理网络接口的变化 (新增/移除)
// 3. 更新黑名单、VM MAC 地址等运行时配置
fn component_on_config_change(
    config_handler: &ConfigHandler,
    components: &mut AgentComponents,
    blacklist: Vec<u64>,
    vm_mac_addrs: Vec<MacAddr>,
    gateway_vmac_addrs: Vec<MacAddr>,
    tap_types: Vec<agent::CaptureNetworkType>,
    synchronizer: &Arc<Synchronizer>,
    #[cfg(target_os = "linux")] libvirt_xml_extractor: Arc<LibvirtXmlExtractor>,
) {
    let conf = &config_handler.candidate_config.dispatcher;
    match conf.capture_mode {
        PacketCaptureType::Local => {
            // 本地捕获模式：通常用于 K8s Sidecar 或宿主机网络监控
            let if_mac_source = conf.if_mac_source;
            // 1. 更新现有的分发器
            // 移除不再需要的接口对应的分发器
            components.dispatcher_components.retain_mut(|d| {
                let links = get_listener_links(
                    conf,
                    #[cfg(target_os = "linux")]
                    d.dispatcher_listener.netns(),
                );
                // 如果接口不存在且未启用内部接口捕获，则停止并移除该分发器
                if links.is_empty() && !conf.inner_interface_capture_enabled {
                    info!("No interfaces found, stopping dispatcher {}", d.id);
                    d.stop();
                    return false;
                }
                // 更新分发器的 TAP 接口配置、黑名单等
                d.dispatcher_listener.on_tap_interface_change(
                    &links,
                    if_mac_source,
                    conf.agent_type,
                    &blacklist,
                );
                // 更新虚拟机 MAC 地址表
                d.dispatcher_listener
                    .on_vm_change(&vm_mac_addrs, &gateway_vmac_addrs);
                true
            });

            // 2. 如果没有分发器 (可能被清空了)，尝试重新创建
            if components.dispatcher_components.is_empty() {
                let links = get_listener_links(
                    conf,
                    #[cfg(target_os = "linux")]
                    &netns::NsFile::Root,
                );
                if links.is_empty() && !conf.inner_interface_capture_enabled {
                    return;
                }
                match build_dispatchers(
                    components.last_dispatcher_component_id + 1,
                    links,
                    components.stats_collector.clone(),
                    config_handler,
                    components.debugger.clone_queue(),
                    components.is_ce_version,
                    synchronizer,
                    components.npb_bps_limit.clone(),
                    components.npb_arp_table.clone(),
                    components.rx_leaky_bucket.clone(),
                    components.policy_getter,
                    components.exception_handler.clone(),
                    components.bpf_options.clone(),
                    components.packet_sequence_uniform_output.clone(),
                    components.proto_log_sender.clone(),
                    components.pcap_batch_sender.clone(),
                    components.tap_typer.clone(),
                    vm_mac_addrs.clone(),
                    gateway_vmac_addrs.clone(),
                    components.toa_info_sender.clone(),
                    components.l4_flow_aggr_sender.clone(),
                    components.metrics_sender.clone(),
                    #[cfg(target_os = "linux")]
                    netns::NsFile::Root,
                    #[cfg(target_os = "linux")]
                    components.kubernetes_poller.clone(),
                    #[cfg(target_os = "linux")]
                    libvirt_xml_extractor.clone(),
                    #[cfg(target_os = "linux")]
                    None,
                    #[cfg(target_os = "linux")]
                    false,
                ) {
                    Ok(mut d) => {
                        d.start();
                        components.dispatcher_components.push(d);
                        components.last_dispatcher_component_id += 1;
                    }
                    Err(e) => {
                        warn!(
                            "build dispatcher_component failed: {}, deepflow-agent restart...",
                            e
                        );
                        crate::utils::clean_and_exit(1);
                    }
                }
            }
        }
        PacketCaptureType::Mirror | PacketCaptureType::Analyzer => {
            // 镜像模式或分析器模式
            // 更新所有分发器的配置
            for d in components.dispatcher_components.iter_mut() {
                let links = get_listener_links(
                    conf,
                    #[cfg(target_os = "linux")]
                    &netns::NsFile::Root,
                );
                d.dispatcher_listener.on_tap_interface_change(
                    &links,
                    conf.if_mac_source,
                    conf.agent_type,
                    &blacklist,
                );
                d.dispatcher_listener
                    .on_vm_change(&vm_mac_addrs, &gateway_vmac_addrs);
            }
            if conf.capture_mode == PacketCaptureType::Analyzer {
                parse_tap_type(components, tap_types);
            }

            #[cfg(target_os = "linux")]
            // 如果不是本地模式，且配置了特殊网络 (vhost-user) 或 DPDK，则跳过后续接口检查
            // 因为这些场景下接口管理方式不同
            if conf.capture_mode != PacketCaptureType::Local
                && (!config_handler
                    .candidate_config
                    .user_config
                    .inputs
                    .cbpf
                    .special_network
                    .vhost_user
                    .vhost_socket_path
                    .is_empty()
                    || conf.dpdk_source != DpdkSource::None)
            {
                return;
            }

            // 获取当前系统匹配的所有网络接口
            let mut current_interfaces = get_listener_links(
                conf,
                #[cfg(target_os = "linux")]
                &netns::NsFile::Root,
            );
            current_interfaces.sort();

            // 如果接口列表没有变化，直接返回
            if current_interfaces == components.tap_interfaces {
                return;
            }

            // 通过比较当前接口和已有的接口，确定需要新建和移除的分发器
            // By comparing current_interfaces and components.tap_interfaces, we can determine which
            // dispatcher_components should be closed and which dispatcher_components should be built
            let interfaces_to_build: Vec<_> = current_interfaces
                .iter()
                .filter(|i| !components.tap_interfaces.contains(i))
                .cloned()
                .collect();

            // 移除不再存在的接口对应的分发器
            components.dispatcher_components.retain_mut(|d| {
                let retain = current_interfaces.contains(&d.src_link);
                if !retain {
                    d.stop();
                }
                retain
            });

            // 为新增的接口创建分发器
            let mut id = components.last_dispatcher_component_id;
            components
                .policy_setter
                .reset_queue_size(id + interfaces_to_build.len() + 1);
            let debugger_queue = components.debugger.clone_queue();
            for i in interfaces_to_build {
                id += 1;
                match build_dispatchers(
                    id,
                    vec![i],
                    components.stats_collector.clone(),
                    config_handler,
                    debugger_queue.clone(),
                    components.is_ce_version,
                    synchronizer,
                    components.npb_bps_limit.clone(),
                    components.npb_arp_table.clone(),
                    components.rx_leaky_bucket.clone(),
                    components.policy_getter,
                    components.exception_handler.clone(),
                    components.bpf_options.clone(),
                    components.packet_sequence_uniform_output.clone(),
                    components.proto_log_sender.clone(),
                    components.pcap_batch_sender.clone(),
                    components.tap_typer.clone(),
                    vm_mac_addrs.clone(),
                    gateway_vmac_addrs.clone(),
                    components.toa_info_sender.clone(),
                    components.l4_flow_aggr_sender.clone(),
                    components.metrics_sender.clone(),
                    #[cfg(target_os = "linux")]
                    netns::NsFile::Root,
                    #[cfg(target_os = "linux")]
                    components.kubernetes_poller.clone(),
                    #[cfg(target_os = "linux")]
                    libvirt_xml_extractor.clone(),
                    #[cfg(target_os = "linux")]
                    None,
                    #[cfg(target_os = "linux")]
                    false,
                ) {
                    Ok(mut d) => {
                        d.start();
                        components.dispatcher_components.push(d);
                    }
                    Err(e) => {
                        warn!(
                            "build dispatcher_component failed: {}, deepflow-agent restart...",
                            e
                        );
                        crate::utils::clean_and_exit(1);
                    }
                }
            }
            components.last_dispatcher_component_id = id;
            components.tap_interfaces = current_interfaces;
        }

        _ => {}
    }
}

// 解析并更新 TAP 类型配置
// TAP 类型用于标识流量的采集位置 (如 KVM, Tor, Edge 等)
fn parse_tap_type(components: &mut AgentComponents, tap_types: Vec<agent::CaptureNetworkType>) {
    let mut updated = false;
    if components.cur_tap_types.len() != tap_types.len() {
        updated = true;
    } else {
        for i in 0..tap_types.len() {
            if components.cur_tap_types[i] != tap_types[i] {
                updated = true;
                break;
            }
        }
    }
    if updated {
        components.tap_typer.on_tap_types_change(tap_types.clone());
        components.cur_tap_types.clear();
        components.cur_tap_types.clone_from(&tap_types);
    }
}

// 域名监听器，负责解析控制器域名并更新 IP
pub struct DomainNameListener {
    stats_collector: Arc<stats::Collector>,
    session: Arc<Session>,
    ips: Vec<String>,
    domain_names: Vec<String>,

    sidecar_mode: bool,

    thread_handler: Option<JoinHandle<()>>,
    stopped: Arc<AtomicBool>,
    ipmac_tx: Arc<broadcast::Sender<IpMacPair>>,
}

impl DomainNameListener {
    const INTERVAL: Duration = Duration::from_secs(5);

    fn new(
        stats_collector: Arc<stats::Collector>,
        session: Arc<Session>,
        domain_names: Vec<String>,
        ips: Vec<String>,
        sidecar_mode: bool,
        ipmac_tx: Arc<broadcast::Sender<IpMacPair>>,
    ) -> DomainNameListener {
        Self {
            stats_collector,
            session,
            domain_names,
            ips,
            sidecar_mode,
            thread_handler: None,
            stopped: Arc::new(AtomicBool::new(false)),
            ipmac_tx,
        }
    }

    fn start(&mut self) {
        if self.thread_handler.is_some() {
            return;
        }
        self.stopped.store(false, Ordering::Relaxed);
        self.run();
    }

    fn stop(&mut self) {
        if self.thread_handler.is_none() {
            return;
        }
        self.stopped.store(true, Ordering::Relaxed);
        if let Some(handler) = self.thread_handler.take() {
            let _ = handler.join();
        }
    }

    // 监听线程主循环
    fn run(&mut self) {
        if self.domain_names.len() == 0 {
            return;
        }

        let mut ips = self.ips.clone();
        let domain_names = self.domain_names.clone();
        let stopped = self.stopped.clone();
        let ipmac_tx = self.ipmac_tx.clone();
        let session = self.session.clone();

        #[cfg(target_os = "linux")]
        let sidecar_mode = self.sidecar_mode;

        info!(
            "Resolve controller domain name {} {}",
            domain_names[0], ips[0]
        );

        self.thread_handler = Some(
            thread::Builder::new()
                .name("domain-name-listener".to_owned())
                .spawn(move || {
                    while !stopped.swap(false, Ordering::Relaxed) {
                        thread::sleep(Self::INTERVAL);

                        let mut changed = false;
                        for i in 0..domain_names.len() {
                            let current = lookup_host(domain_names[i].as_str());
                            if current.is_err() {
                                continue;
                            }
                            let current = current.unwrap();

                            changed = current.iter().find(|&&x| x.to_string() == ips[i]).is_none();
                            if changed {
                                info!(
                                    "Domain name {} ip {} change to {}",
                                    domain_names[i], ips[i], current[0]
                                );
                                ips[i] = current[0].to_string();
                            }
                        }

                        if changed {
                            let (ctrl_ip, ctrl_mac) = match get_ctrl_ip_and_mac(&ips[0].parse().unwrap()) {
                                Ok(tuple) => tuple,
                                Err(e) => {
                                    warn!("get ctrl ip and mac failed with error: {}, deepflow-agent restart...", e);
                                    crate::utils::clean_and_exit(1);
                                    continue;
                                }
                            };
                            info!(
                                "use K8S_NODE_IP_FOR_DEEPFLOW env ip as destination_ip({})",
                                ctrl_ip
                            );
                            #[cfg(target_os = "linux")]
                            let ipmac = if sidecar_mode {
                                IpMacPair::from((ctrl_ip.clone(), ctrl_mac))
                            } else {
                                // use host ip/mac as agent id if not in sidecar mode
                                if let Err(e) = netns::NsFile::Root.open_and_setns() {
                                    warn!("agent must have CAP_SYS_ADMIN to run without 'hostNetwork: true'.");
                                    warn!("setns error: {}, deepflow-agent restart...", e);
                                    crate::utils::clean_and_exit(1);
                                    continue;
                                }
                                let (ip, mac) = match get_ctrl_ip_and_mac(&ips[0].parse().unwrap()) {
                                    Ok(tuple) => tuple,
                                    Err(e) => {
                                        warn!("get ctrl ip and mac failed with error: {}, deepflow-agent restart...", e);
                                        crate::utils::clean_and_exit(1);
                                        continue;
                                    }
                                };
                                if let Err(e) = netns::reset_netns() {
                                    warn!("reset setns error: {}, deepflow-agent restart...", e);
                                    crate::utils::clean_and_exit(1);
                                    continue;
                                }
                                IpMacPair::from((ip, mac))
                            };
                            #[cfg(any(target_os = "windows", target_os = "android"))]
                            let ipmac = IpMacPair::from((ctrl_ip.clone(), ctrl_mac));

                            session.reset_server_ip(ips.clone());
                            let _ = ipmac_tx.send(ipmac);
                        }
                    }
                })
                .unwrap(),
        );
    }
}

// 组件枚举，可以是完整的 Agent 组件或仅包含 Watcher 的组件（用于 K8s 监听模式）
pub enum Components {
    Agent(AgentComponents),
    #[cfg(target_os = "linux")]
    Watcher(WatcherComponents),
    Other,
}

#[cfg(target_os = "linux")]
// Watcher 组件，仅包含 K8s 监听功能
pub struct WatcherComponents {
    pub running: AtomicBool,         // 运行状态
    capture_mode: PacketCaptureType, // 捕获模式
    agent_mode: RunningMode,         // 运行模式
    runtime: Arc<Runtime>,           // 运行时
}

#[cfg(target_os = "linux")]
impl WatcherComponents {
    // 创建新的 WatcherComponents
    fn new(
        config_handler: &ConfigHandler,
        agent_mode: RunningMode,
        runtime: Arc<Runtime>,
    ) -> Result<Self> {
        let candidate_config = &config_handler.candidate_config;
        info!("This agent will only watch K8s resource because IN_CONTAINER={} and K8S_WATCH_POLICY={}", env::var(IN_CONTAINER).unwrap_or_default(), env::var(K8S_WATCH_POLICY).unwrap_or_default());
        Ok(WatcherComponents {
            running: AtomicBool::new(false),
            capture_mode: candidate_config.capture_mode,
            agent_mode,
            runtime,
        })
    }

    // 启动 Watcher 组件
    fn start(&mut self) {
        if self.running.swap(true, Ordering::Relaxed) {
            return;
        }
        info!("Started watcher components.");
    }

    // 停止 Watcher 组件
    fn stop(&mut self) {
        if !self.running.swap(false, Ordering::Relaxed) {
            return;
        }
        info!("Stopped watcher components.")
    }
}

#[cfg(all(unix, feature = "libtrace"))]
// eBPF 分发器组件
pub struct EbpfDispatcherComponent {
    pub ebpf_collector: Box<crate::ebpf_dispatcher::EbpfCollector>, // eBPF 采集器
    pub session_aggregator: SessionAggregator,                      // 会话聚合器
    pub l7_collector: L7CollectorThread,                            // L7 指标收集线程
}

#[cfg(all(unix, feature = "libtrace"))]
impl EbpfDispatcherComponent {
    // 启动 eBPF 分发器组件
    pub fn start(&mut self) {
        self.session_aggregator.start();
        self.l7_collector.start();
        self.ebpf_collector.start();
    }

    // 停止 eBPF 分发器组件
    pub fn stop(&mut self) {
        self.session_aggregator.stop();
        self.l7_collector.stop();
        self.ebpf_collector.notify_stop();
    }
}

// 指标服务器组件，负责对外暴露指标
pub struct MetricsServerComponent {
    pub external_metrics_server: MetricServer, // 外部指标服务
    pub l7_collector: L7CollectorThread,       // L7 指标收集线程
}

impl MetricsServerComponent {
    // 启动指标服务器组件
    pub fn start(&mut self) {
        self.external_metrics_server.start();
        self.l7_collector.start();
    }

    // 停止指标服务器组件
    pub fn stop(&mut self) {
        self.external_metrics_server.stop();
        self.l7_collector.stop();
    }
}

// 分发器组件，每个组件对应一个网卡或网络命名空间
pub struct DispatcherComponent {
    pub id: usize,                                                // 组件 ID
    pub dispatcher: Dispatcher,                                   // 核心分发器，负责收包
    pub dispatcher_listener: DispatcherListener,                  // 分发器监听器，处理配置变更
    pub session_aggregator: SessionAggregator,                    // 会话聚合器
    pub collector: CollectorThread,                               // L4 指标收集线程
    pub l7_collector: L7CollectorThread,                          // L7 指标收集线程
    pub packet_sequence_parser: PacketSequenceParser,             // 包序解析器 (企业版功能)
    pub pcap_assembler: PcapAssembler,                            // PCAP 组装器
    pub handler_builders: Arc<RwLock<Vec<PacketHandlerBuilder>>>, // 包处理器构建器集合
    pub src_link: Link,                                           // 原始源接口
}

impl DispatcherComponent {
    // 启动分发器组件
    pub fn start(&mut self) {
        self.dispatcher.start();
        self.session_aggregator.start();
        self.collector.start();
        self.l7_collector.start();
        self.packet_sequence_parser.start();
        self.pcap_assembler.start();
        self.handler_builders
            .write()
            .unwrap()
            .iter_mut()
            .for_each(|y| {
                y.start();
            });
    }
    // 停止分发器组件
    pub fn stop(&mut self) {
        self.dispatcher.stop();
        self.session_aggregator.stop();
        self.collector.stop();
        self.l7_collector.stop();
        self.packet_sequence_parser.stop();
        self.pcap_assembler.stop();
        self.handler_builders
            .write()
            .unwrap()
            .iter_mut()
            .for_each(|y| {
                y.stop();
            });
    }
}

// Agent 的主要组件集合，包含所有的核心功能模块
pub struct AgentComponents {
    pub config: ModuleConfig,
    pub rx_leaky_bucket: Arc<LeakyBucket>, // 接收端漏桶限流器
    pub tap_typer: Arc<CaptureNetworkTyper>, // 网络采集类型识别器
    pub cur_tap_types: Vec<agent::CaptureNetworkType>, // 当前采集的网络类型
    pub dispatcher_components: Vec<DispatcherComponent>, // 分发器组件列表，每个网卡或网络命名空间一个
    pub l4_flow_uniform_sender: UniformSenderThread<BoxedTaggedFlow>, // L4 流日志发送线程
    pub metrics_uniform_sender: UniformSenderThread<BoxedDocument>, // 指标数据发送线程
    pub l7_flow_uniform_sender: UniformSenderThread<BoxAppProtoLogsData>, // L7 应用协议日志发送线程
    pub platform_synchronizer: Arc<PlatformSynchronizer>, // 平台信息同步器
    #[cfg(target_os = "linux")]
    pub kubernetes_poller: Arc<GenericPoller>, // Kubernetes 信息轮询器
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub socket_synchronizer: SocketSynchronizer, // Socket 信息同步器
    pub debugger: Debugger, // 调试器
    #[cfg(all(unix, feature = "libtrace"))]
    pub ebpf_dispatcher_component: Option<EbpfDispatcherComponent>, // eBPF 分发器组件
    pub running: AtomicBool, // 运行状态标志
    pub stats_collector: Arc<stats::Collector>, // 统计数据收集器
    pub metrics_server_component: MetricsServerComponent, // 外部指标服务组件
    pub otel_uniform_sender: UniformSenderThread<OpenTelemetry>, // OpenTelemetry 数据发送线程
    pub prometheus_uniform_sender: UniformSenderThread<BoxedPrometheusExtra>, // Prometheus 数据发送线程
    pub telegraf_uniform_sender: UniformSenderThread<TelegrafMetric>, // Telegraf 数据发送线程
    pub profile_uniform_sender: UniformSenderThread<Profile>, // 性能剖析数据发送线程
    pub packet_sequence_uniform_output: DebugSender<BoxedPacketSequenceBlock>, // Enterprise Edition Feature: packet-sequence // 包序列数据调试发送端
    pub packet_sequence_uniform_sender: UniformSenderThread<BoxedPacketSequenceBlock>, // Enterprise Edition Feature: packet-sequence // 包序列数据发送线程
    #[cfg(feature = "libtrace")]
    pub proc_event_uniform_sender: UniformSenderThread<crate::common::proc_event::BoxedProcEvents>, // 进程事件发送线程
    pub application_log_uniform_sender: UniformSenderThread<ApplicationLog>, // 应用日志发送线程
    #[cfg(feature = "enterprise-integration")]
    pub skywalking_uniform_sender: UniformSenderThread<SkyWalkingExtra>, // SkyWalking 数据发送线程
    pub datadog_uniform_sender: UniformSenderThread<Datadog>, // Datadog 数据发送线程
    pub exception_handler: ExceptionHandler, // 异常处理器
    pub proto_log_sender: DebugSender<BoxAppProtoLogsData>, // 协议日志调试发送端
    pub pcap_batch_sender: DebugSender<BoxedPcapBatch>, // PCAP 数据包调试发送端
    pub toa_info_sender: DebugSender<Box<(SocketAddr, SocketAddr)>>, // TOA 信息调试发送端
    pub l4_flow_aggr_sender: DebugSender<BoxedTaggedFlow>, // L4 流聚合数据调试发送端
    pub metrics_sender: DebugSender<BoxedDocument>, // 指标数据调试发送端
    pub npb_bps_limit: Arc<LeakyBucket>, // NPB (Network Packet Broker) 带宽限制漏桶
    pub compressed_otel_uniform_sender: UniformSenderThread<OpenTelemetryCompressed>, // 压缩后的 OpenTelemetry 数据发送线程
    pub pcap_batch_uniform_sender: UniformSenderThread<BoxedPcapBatch>, // PCAP 数据包发送线程
    pub policy_setter: PolicySetter, // 策略设置器
    pub policy_getter: PolicyGetter, // 策略获取器
    pub npb_bandwidth_watcher: Box<Arc<NpbBandwidthWatcher>>, // NPB 带宽监控器
    pub npb_arp_table: Arc<NpbArpTable>, // NPB ARP 表
    #[cfg(feature = "enterprise-integration")]
    pub vector_component: VectorComponent, // Vector 组件集成
    pub is_ce_version: bool, // Determine whether the current version is a ce version, CE-AGENT always set pcap-assembler disabled // 是否为社区版
    pub tap_interfaces: Vec<Link>, // 采集的网卡接口列表
    pub bpf_options: Arc<Mutex<BpfOptions>>, // BPF 选项
    pub last_dispatcher_component_id: usize, // 最后一个分发器组件 ID
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub process_listener: Arc<ProcessListener>, // 进程监听器
    max_memory: u64, // 最大内存限制
    capture_mode: PacketCaptureType, // 捕获模式 (Analyzer, Local, Mirror)
    agent_mode: RunningMode, // 运行模式 (Managed, Standalone)

    runtime: Arc<Runtime>, // Tokio 运行时
}

impl AgentComponents {
    // 计算 FlowGenerator 的容忍延迟
    //
    // 该延迟用于确定流生成器何时可以安全地处理和聚合流数据，而不会因为乱序到达的数据包而丢失信息。
    // 计算公式考虑了：
    // 1. 数据包的最大容忍延迟
    // 2. 时间窗口的额外延迟
    // 3. 连接跟踪 (Conntrack) 的刷新间隔
    // 4. 系统固有的处理延迟 (COMMON_DELAY)
    fn get_flowgen_tolerable_delay(config: &UserConfig) -> u64 {
        // FIXME: The flow_generator and dispatcher should be decoupled, and a delay function should be provided for this purpose.
        // QuadrupleGenerator 的延迟由以下部分组成：
        //   - flow_map 中流统计数据的固有延迟: second_flow_extra_delay + packet_delay
        //   - flow_map 中 inject_flush_ticker 的额外延迟: TIME_UNIT
        //   - flow_map 中刷新输出队列的延迟: flow.flush_interval
        //   - flow_map 中其他处理步骤的潜在延迟: COMMON_DELAY 5 秒
        //   - flow_map 中时间窗口被提前推送导致的延迟: flow.flush_interval
        config
            .processors
            .flow_log
            .time_window
            .max_tolerable_packet_delay
            .as_secs()
            + TIME_UNIT.as_secs()
            + config
                .processors
                .flow_log
                .conntrack
                .flow_flush_interval
                .as_secs()
            + COMMON_DELAY
            + config
            .processors
            .flow_log
            .time_window
            .extra_tolerable_flow_delay
            .as_secs()
        + config
            .processors
            .flow_log
            .conntrack
            .flow_flush_interval
            .as_secs() // The flow_map may send data to qg ahead of time due to the output_buffer exceeding its limit. This can result in the time_window of qg being advanced prematurely, with the maximum advancement time being the flush_interval.
}

// 创建新的 Collector 线程，负责 L4 流日志的聚合和指标生成
//
// 该方法初始化 Collector 线程及其子组件：
// 1. L4 流聚合器 (FlowAggrThread): 将秒级流聚合为分钟级流 (可选)
// 2. 四元组生成器 (QuadrupleGeneratorThread): 核心组件，负责从原始流中生成四元组指标
// 3. 秒级/分钟级 Collector: 负责收集和导出最终指标
//
// 队列设置：
// - L4 流聚合器 (FlowAggrThread) -> 秒级 Collector
// - 四元组生成器 (QuadrupleGeneratorThread) -> 秒级/分钟级 Collector
fn new_collector(
    id: usize,
    stats_collector: Arc<stats::Collector>,
    flow_receiver: queue::Receiver<Arc<BatchedBox<TaggedFlow>>>,
    toa_info_sender: DebugSender<Box<(SocketAddr, SocketAddr)>>,
    l4_flow_aggr_sender: Option<DebugSender<BoxedTaggedFlow>>,
    metrics_sender: DebugSender<BoxedDocument>,
    metrics_type: MetricsType,
    config_handler: &ConfigHandler,
    queue_debugger: &QueueDebugger,
    synchronizer: &Arc<Synchronizer>,
    agent_mode: RunningMode,
) -> CollectorThread {
    let config = &config_handler.candidate_config.user_config;

    let flowgen_tolerable_delay = Self::get_flowgen_tolerable_delay(config);
    // 分钟级 QG 窗口也会因流统计时间而被向前推送，
    // 因此其延迟应为 60 + 秒级延迟 (包括额外的流延迟)
    let minute_quadruple_tolerable_delay = 60 + flowgen_tolerable_delay;

    let mut l4_flow_aggr_outer = None;
    let mut l4_log_sender_outer = None;
    if l4_flow_aggr_sender.is_some() {
        // 创建 L4 流聚合队列
        // 用于将秒级流发送给 FlowAggrThread 进行聚合
        let (l4_log_sender, l4_log_receiver, counter) = queue::bounded_with_debug(
            config
                .processors
                .flow_log
                .tunning
                .flow_aggregator_queue_size,
            "2-second-flow-to-minute-aggrer",
            queue_debugger,
        );
        l4_log_sender_outer = Some(l4_log_sender);
        stats_collector.register_countable(
            &QueueStats {
                id,
                module: "2-second-flow-to-minute-aggrer",
            },
            Countable::Owned(Box::new(counter)),
        );
        // 启动 FlowAggrThread (流聚合线程)
        let (l4_flow_aggr, flow_aggr_counter) = FlowAggrThread::new(
            id,                                   // id
            l4_log_receiver,                      // input
            l4_flow_aggr_sender.unwrap().clone(), // output
            config_handler.collector(),
            Duration::from_secs(flowgen_tolerable_delay),
            synchronizer.ntp_diff(),
        );
        l4_flow_aggr_outer = Some(l4_flow_aggr);
        stats_collector.register_countable(
            &stats::SingleTagModule("flow_aggr", "index", id),
            Countable::Ref(Arc::downgrade(&flow_aggr_counter) as Weak<dyn RefCountable>),
        );
        }

        // 创建秒级 Flow -> Collector 队列
        let (second_sender, second_receiver, counter) = queue::bounded_with_debug(
            config
                .processors
                .flow_log
                .tunning
                .quadruple_generator_queue_size,
            "2-flow-with-meter-to-second-collector",
            queue_debugger,
        );
        stats_collector.register_countable(
            &QueueStats {
                id,
                module: "2-flow-with-meter-to-second-collector",
            },
            Countable::Owned(Box::new(counter)),
        );
        // 创建分钟级 Flow -> Collector 队列
        let (minute_sender, minute_receiver, counter) = queue::bounded_with_debug(
            config
                .processors
                .flow_log
                .tunning
                .quadruple_generator_queue_size,
            "2-flow-with-meter-to-minute-collector",
            queue_debugger,
        );
        stats_collector.register_countable(
            &QueueStats {
                id,
                module: "2-flow-with-meter-to-minute-collector",
            },
            Countable::Owned(Box::new(counter)),
        );

        // 启动 QuadrupleGeneratorThread (四元组生成器线程)
        let quadruple_generator = QuadrupleGeneratorThread::new(
            id,
            flow_receiver,
            second_sender,
            minute_sender,
            toa_info_sender,
            l4_log_sender_outer,
            (config.processors.flow_log.tunning.flow_map_hash_slots as usize) << 3, // connection_lru_capacity
            metrics_type,
            flowgen_tolerable_delay,
            minute_quadruple_tolerable_delay,
            1 << 18, // possible_host_size
            config_handler.collector(),
            synchronizer.ntp_diff(),
            stats_collector.clone(),
        );

        let (mut second_collector, mut minute_collector) = (None, None);
        if metrics_type.contains(MetricsType::SECOND) {
            // 启动秒级 Collector
            second_collector = Some(Collector::new(
                id as u32,
                second_receiver,
                metrics_sender.clone(),
                MetricsType::SECOND,
                flowgen_tolerable_delay + QG_PROCESS_MAX_DELAY,
                &stats_collector,
                config_handler.collector(),
                synchronizer.ntp_diff(),
                agent_mode,
            ));
        }
        if metrics_type.contains(MetricsType::MINUTE) {
            // 启动分钟级 Collector
            minute_collector = Some(Collector::new(
                id as u32,
                minute_receiver,
                metrics_sender,
                MetricsType::MINUTE,
                minute_quadruple_tolerable_delay + QG_PROCESS_MAX_DELAY,
                &stats_collector,
                config_handler.collector(),
                synchronizer.ntp_diff(),
                agent_mode,
            ));
        }

        CollectorThread::new(
            quadruple_generator,
            l4_flow_aggr_outer,
            second_collector,
            minute_collector,
        )
    }

    // 创建新的 L7 Collector 线程，负责 L7 协议日志的指标生成
    fn new_l7_collector(
        id: usize,
        stats_collector: Arc<stats::Collector>,
        l7_stats_receiver: queue::Receiver<BatchedBox<L7Stats>>,
        metrics_sender: DebugSender<BoxedDocument>,
        metrics_type: MetricsType,
        config_handler: &ConfigHandler,
        queue_debugger: &QueueDebugger,
        synchronizer: &Arc<Synchronizer>,
        agent_mode: RunningMode,
    ) -> L7CollectorThread {
        let user_config = &config_handler.candidate_config.user_config;

        // 创建 L7 秒级 Stats -> Collector 队列
        let (l7_second_sender, l7_second_receiver, counter) = queue::bounded_with_debug(
            user_config
                .processors
                .flow_log
                .tunning
                .quadruple_generator_queue_size,
            "2-flow-with-meter-to-l7-second-collector",
            queue_debugger,
        );
        stats_collector.register_countable(
            &QueueStats {
                id,
                module: "2-flow-with-meter-to-l7-second-collector",
            },
            Countable::Owned(Box::new(counter)),
        );
        // 创建 L7 分钟级 Stats -> Collector 队列
        let (l7_minute_sender, l7_minute_receiver, counter) = queue::bounded_with_debug(
            user_config
                .processors
                .flow_log
                .tunning
                .quadruple_generator_queue_size,
            "2-flow-with-meter-to-l7-minute-collector",
            queue_debugger,
        );
        stats_collector.register_countable(
            &QueueStats {
                id,
                module: "2-flow-with-meter-to-l7-minute-collector",
            },
            Countable::Owned(Box::new(counter)),
        );

        let second_quadruple_tolerable_delay = Self::get_flowgen_tolerable_delay(user_config);
        // minute QG window is also pushed forward by flow stat time,
        // therefore its delay should be 60 + second delay (including extra flow delay)
        // 分钟级 QG 窗口也会因流统计时间而被向前推送，
        // 因此其延迟应为 60 + 秒级延迟 (包括额外的流延迟)
        let minute_quadruple_tolerable_delay = 60 + second_quadruple_tolerable_delay;

        // 启动 L7 QuadrupleGeneratorThread
        // 负责处理从 EbpfCollector 或 Dispatcher 接收的 L7Stats
        let quadruple_generator = L7QuadrupleGeneratorThread::new(
            id,
            l7_stats_receiver,
            l7_second_sender,
            l7_minute_sender,
            metrics_type,
            second_quadruple_tolerable_delay,
            minute_quadruple_tolerable_delay,
            1 << 18, // possible_host_size
            config_handler.collector(),
            synchronizer.ntp_diff(),
            stats_collector.clone(),
        );

        let (mut second_collector, mut minute_collector) = (None, None);
        if metrics_type.contains(MetricsType::SECOND) {
            // 启动 L7 秒级 Collector
            second_collector = Some(L7Collector::new(
                id as u32,
                l7_second_receiver,
                metrics_sender.clone(),
                MetricsType::SECOND,
                second_quadruple_tolerable_delay + QG_PROCESS_MAX_DELAY,
                &stats_collector,
                config_handler.collector(),
                synchronizer.ntp_diff(),
                agent_mode,
            ));
        }
        if metrics_type.contains(MetricsType::MINUTE) {
            // 启动 L7 分钟级 Collector
            minute_collector = Some(L7Collector::new(
                id as u32,
                l7_minute_receiver,
                metrics_sender,
                MetricsType::MINUTE,
                minute_quadruple_tolerable_delay + QG_PROCESS_MAX_DELAY,
                &stats_collector,
                config_handler.collector(),
                synchronizer.ntp_diff(),
                agent_mode,
            ));
        }

        L7CollectorThread::new(quadruple_generator, second_collector, minute_collector)
    }

    // 创建 AgentComponents 实例
    //
    // 该方法负责初始化 Agent 的所有核心组件，包括：
    // 1. 系统环境检查 (进程数, core文件, 控制器连接, 磁盘空间)
    // 2. 网络接口探测和监听配置 (支持 fanout, 多命名空间)
    // 3. 策略模块初始化 (FastPath)
    // 4. 调试器和状态同步模块初始化
    // 5. 各类数据发送器 (Sender) 和收集器 (Collector) 的初始化
    // 6. 构造 Dispatcher 组件 (核心流量处理模块)
    fn new(
        version_info: &VersionInfo,
        config_handler: &ConfigHandler,
        stats_collector: Arc<stats::Collector>,
        session: &Arc<Session>,
        synchronizer: &Arc<Synchronizer>,
        exception_handler: ExceptionHandler,
        #[cfg(target_os = "linux")] libvirt_xml_extractor: Arc<LibvirtXmlExtractor>,
        platform_synchronizer: Arc<PlatformSynchronizer>,
        #[cfg(target_os = "linux")] sidecar_poller: Option<Arc<GenericPoller>>,
        #[cfg(target_os = "linux")] api_watcher: Arc<ApiWatcher>,
        vm_mac_addrs: Vec<MacAddr>,
        gateway_vmac_addrs: Vec<MacAddr>,
        agent_mode: RunningMode,
        runtime: Arc<Runtime>,
        sender_leaky_bucket: Arc<LeakyBucket>,
        // only used in vector component
        #[allow(unused)] ipmac_tx: Arc<broadcast::Sender<IpMacPair>>,
    ) -> Result<Self> {
        let static_config = &config_handler.static_config;
        let candidate_config = &config_handler.candidate_config;
        let user_config = &candidate_config.user_config;
        let ctrl_ip = config_handler.ctrl_ip;
        let max_memory = config_handler.candidate_config.environment.max_memory;
        let process_threshold = config_handler
            .candidate_config
            .environment
            .process_threshold;
        let feature_flags = FeatureFlags::from(&user_config.dev.feature_flags);

        // 如果配置了 tap_interface_regex，则不应再使用 src_interfaces (已废弃)
        if !user_config.inputs.cbpf.af_packet.src_interfaces.is_empty()
            && user_config.inputs.cbpf.special_network.dpdk.source == DpdkSource::None
        {
            warn!("src_interfaces is not empty, but this has already been deprecated, instead, the tap_interface_regex should be set");
        }

        info!("Start check process...");
        // 检查当前系统进程数是否超过阈值
        trident_process_check(process_threshold);
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if !user_config.global.alerts.check_core_file_disabled {
            info!("Start check core file...");
            // 检查是否存在 core dump 文件
            core_file_check();
        }
        info!("Start check controller ip...");
        // 检查控制器 IP 连接是否正常
        controller_ip_check(&static_config.controller_ips);
        info!("Start check free space...");
        // 检查磁盘剩余空间是否满足要求
        check(free_space_checker(
            &static_config.log_file,
            FREE_SPACE_REQUIREMENT,
            exception_handler.clone(),
        ));

        #[cfg(target_os = "linux")]
        // 准备存储接口和网络命名空间的列表
        // 格式: (接口列表, 命名空间文件)
        let mut interfaces_and_ns: Vec<(Vec<Link>, netns::NsFile)> = vec![];
        #[cfg(any(target_os = "windows", target_os = "android"))]
        let mut interfaces_and_ns: Vec<Vec<Link>> = vec![];

        #[cfg(target_os = "linux")]
        // 如果配置了额外的网络命名空间正则表达式 (extra_netns_regex)
        // 该功能允许 Agent 自动发现并监控匹配特定命名规则的网络命名空间 (Network Namespace)。
        // 典型场景：监控特定 CNI 插件创建的、不在标准位置或有特定命名规律的容器网络栈。
        if candidate_config.dispatcher.extra_netns_regex != "" {
            // 限制：仅支持 Local 捕获模式
            // 因为 Mirror/Analyzer 模式通常针对物理口或特定镜像口，不涉及跨命名空间扫描。
            if candidate_config.capture_mode == PacketCaptureType::Local {
                let re = regex::Regex::new(&candidate_config.dispatcher.extra_netns_regex).unwrap();
                // 扫描系统中的网络命名空间 (通常位于 /var/run/netns 等路径)，找出名称匹配的 NS
                let mut nss = netns::find_ns_files_by_regex(&re);
                nss.sort_unstable();
                for ns in nss.into_iter() {
                    // 进入该命名空间，查找符合过滤条件（如黑白名单）的网卡接口
                    let links = get_listener_links(&candidate_config.dispatcher, &ns);
                    if !links.is_empty() {
                        interfaces_and_ns.push((links, ns));
                    }
                }
            } else {
                log::error!("When the PacketCaptureType is not Local, it does not support extra_netns_regex, other modes only support interfaces under the root network namespace");
            }
        }

        #[cfg(target_os = "linux")]
        // 计算 AF_PACKET Fanout 数量
        // Fanout 允许将同一个网卡的流量分发给多个 socket (多个线程) 并行处理，提高吞吐量。
        // 策略：
        // 1. 如果没有开启 extra_netns_regex，则使用配置文件中的设置 (通常根据内存和配置决定，例如 1, 2, 4...)。
        // 2. 如果开启了 extra_netns_regex (跨命名空间采集)，则强制将 fanout 设置为 1 (单线程)。
        //    原因：跨多个动态命名空间管理多队列捕获极其复杂，且可能导致资源通过量过大，因此此处做简化处理。
        let mut packet_fanout_count = if candidate_config.dispatcher.extra_netns_regex == "" {
            user_config
                .inputs
                .cbpf
                .af_packet
                .tunning
                .packet_fanout_count
        } else {
            1
        };
        #[cfg(any(target_os = "windows", target_os = "android"))]
        let packet_fanout_count = 1;

        // 获取根命名空间下的监听接口
        // 这是最常用的场景，监听宿主机网络接口
        let links = get_listener_links(
            &candidate_config.dispatcher,
            #[cfg(target_os = "linux")]
            &netns::NsFile::Root,
        );
        // 如果没有找到接口，且允许捕获内部接口（lo），或者找到了接口
        if interfaces_and_ns.is_empty()
            && (!links.is_empty() || candidate_config.dispatcher.inner_interface_capture_enabled)
        {
            if packet_fanout_count > 1 || candidate_config.capture_mode == PacketCaptureType::Local
            {
                // 如果开启 fanout 或本地模式，为每个 fanout 实例创建配置
                for _ in 0..packet_fanout_count {
                    #[cfg(target_os = "linux")]
                    interfaces_and_ns.push((links.clone(), netns::NsFile::Root));
                    #[cfg(any(target_os = "windows", target_os = "android"))]
                    interfaces_and_ns.push(links.clone());
                }
            } else {
                // 否则为每个接口单独创建配置
                for l in links {
                    #[cfg(target_os = "linux")]
                    interfaces_and_ns.push((vec![l], netns::NsFile::Root));
                    #[cfg(any(target_os = "windows", target_os = "android"))]
                    interfaces_and_ns.push(vec![l]);
                }
            }
        }
        #[cfg(target_os = "linux")]
        if candidate_config.capture_mode != PacketCaptureType::Local {
            // 特殊网络环境处理 (vhost-user, DPDK PDump, DPDK eBPF)
            // 这些模式下，不需要常规的接口监听逻辑
            if !user_config
                .inputs
                .cbpf
                .special_network
                .vhost_user
                .vhost_socket_path
                .is_empty()
                || candidate_config.dispatcher.dpdk_source == DpdkSource::PDump
            {
                packet_fanout_count = 1;
                interfaces_and_ns = vec![(vec![], netns::NsFile::Root)];
            } else if candidate_config.dispatcher.dpdk_source == DpdkSource::Ebpf {
                // DPDK eBPF 源
                interfaces_and_ns = vec![];
                for _ in 0..packet_fanout_count {
                    interfaces_and_ns.push((vec![], netns::NsFile::Root));
                }
            }
        }

        match candidate_config.capture_mode {
            PacketCaptureType::Analyzer => {
                info!("Start check kernel...");
                // 分析器模式：作为专用流量分析节点，需要检查内核和网络接口
                // 检查内核版本是否满足要求
                kernel_check();
                if candidate_config
                    .user_config
                    .inputs
                    .cbpf
                    .special_network
                    .dpdk
                    .source
                    == DpdkSource::None
                {
                    info!("Start check tap interface...");
                    // 检查 TAP 接口
                    #[cfg(target_os = "linux")]
                    let tap_interfaces: Vec<_> = interfaces_and_ns
                        .iter()
                        .filter_map(|i| i.0.get(0).map(|l| l.name.clone()))
                        .collect();
                    #[cfg(any(target_os = "windows", target_os = "android"))]
                    let tap_interfaces: Vec<_> = interfaces_and_ns
                        .iter()
                        .filter_map(|i| i.get(0).map(|l| l.name.clone()))
                        .collect();

                    tap_interface_check(&tap_interfaces);
                }
            }
            _ => {
                // NPF服务检查 (Windows) 或 镜像模式检查
                // TODO: npf (only on windows)
                if candidate_config.capture_mode == PacketCaptureType::Mirror {
                    info!("Start check kernel...");
                    kernel_check();
                }
            }
        }

        info!("Agent run with feature-flags: {:?}.", feature_flags);
        // Currently, only loca-mode + ebpf collector is supported, and ebpf collector is not
        // applicable to fastpath, so the number of queues is 1
        // =================================================================================
        // 目前仅支持local-mode + ebpf-collector，ebpf-collector不适用fastpath, 所以队列数为1
        // 初始化策略模块 (Policy)，用于 FastPath 包处理和 ACL 匹配
        // FastPath 可以加速特定流量的处理，绕过部分复杂的处理逻辑
        let (policy_setter, policy_getter) = Policy::new(
            1.max(
                if candidate_config.capture_mode != PacketCaptureType::Local {
                    interfaces_and_ns.len()
                } else {
                    1
                },
            ),
            user_config.processors.packet.policy.max_first_path_level,
            user_config.get_fast_path_map_size(candidate_config.dispatcher.max_memory),
            user_config.processors.packet.policy.forward_table_capacity,
            user_config.processors.packet.policy.fast_path_disabled,
            candidate_config.capture_mode == PacketCaptureType::Analyzer,
        );
        // 注册 ACL 监听器
        synchronizer.add_flow_acl_listener(Box::new(policy_setter));
        policy_setter.set_memory_limit(max_memory);

        // TODO: collector enabled
        // TODO: packet handler builders

        #[cfg(target_os = "linux")]
        // sidecar poller is created before agent start to provide pod interface info for server
        // 初始化 Kubernetes Poller，用于获取 Pod 接口信息
        let kubernetes_poller = sidecar_poller.unwrap_or_else(|| {
            let poller = Arc::new(GenericPoller::new(
                config_handler.platform(),
                config_handler
                    .candidate_config
                    .dispatcher
                    .extra_netns_regex
                    .clone(),
            ));
            platform_synchronizer.set_kubernetes_poller(poller.clone());
            poller
        });

        // 初始化调试器上下文
        // 调试器提供 HTTP 接口或其他方式来查看 Agent 内部状态
        let context = ConstructDebugCtx {
            runtime: runtime.clone(),
            #[cfg(target_os = "linux")]
            api_watcher: api_watcher.clone(),
            #[cfg(target_os = "linux")]
            poller: kubernetes_poller.clone(),
            session: session.clone(),
            static_config: synchronizer.static_config.clone(),
            agent_id: synchronizer.agent_id.clone(),
            status: synchronizer.status.clone(),
            config: config_handler.debug(),
            policy_setter,
        };
        let debugger = Debugger::new(context);
        let queue_debugger = debugger.clone_queue();
        #[cfg(any(target_os = "linux", target_os = "android"))]
        // 初始化进程监听器，用于关联流量与进程
        let process_listener = Arc::new(ProcessListener::new(
            &candidate_config.user_config.inputs.proc.process_blacklist,
            &candidate_config.user_config.inputs.proc.process_matcher,
            candidate_config
                .user_config
                .inputs
                .proc
                .proc_dir_path
                .clone(),
            candidate_config
                .user_config
                .inputs
                .proc
                .tag_extraction
                .exec_username
                .clone(),
            candidate_config
                .user_config
                .inputs
                .proc
                .tag_extraction
                .script_command
                .clone(),
        ));
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if candidate_config.user_config.inputs.proc.enabled {
            platform_synchronizer.set_process_listener(&process_listener);
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        // 创建 TOA (TCP Option Address) 信息队列
        // 用于 Socket 同步器将 TOA 信息发送给 Dispatcher
        let (toa_sender, toa_recv, _) = queue::bounded_with_debug(
            user_config.processors.packet.toa.sender_queue_size,
            "1-socket-sync-toa-info-queue",
            &queue_debugger,
        );
        #[cfg(target_os = "windows")]
        let (toa_sender, _, _) = queue::bounded_with_debug(
            user_config.processors.packet.toa.sender_queue_size,
            "1-socket-sync-toa-info-queue",
            &queue_debugger,
        );
        #[cfg(any(target_os = "linux", target_os = "android"))]
        // 初始化 Socket 同步器
        // 负责维护 Socket 到进程的映射关系，用于丰富流量数据的上下文信息
        let socket_synchronizer = SocketSynchronizer::new(
            runtime.clone(),
            config_handler.platform(),
            synchronizer.agent_id.clone(),
            Arc::new(Mutex::new(policy_getter)),
            policy_setter,
            session.clone(),
            toa_recv,
            Arc::new(Mutex::new(Lru::with_capacity(
                user_config.processors.packet.toa.cache_size >> 5,
                user_config.processors.packet.toa.cache_size,
            ))),
            process_listener.clone(),
        );

        // 初始化接收端漏桶，用于全局 PPS (Packet Per Second) 限制
        // 防止流量突发导致 CPU 或内存过载
        let rx_leaky_bucket = Arc::new(LeakyBucket::new(match candidate_config.capture_mode {
            PacketCaptureType::Analyzer => None,
            _ => Some(
                config_handler
                    .candidate_config
                    .dispatcher
                    .global_pps_threshold,
            ),
        }));

        let tap_typer = Arc::new(CaptureNetworkTyper::new());

        // TODO: collector enabled
        let mut dispatcher_components = vec![];

        // Sender/Collector
        info!(
            "static analyzer ip: '{}' actual analyzer ip '{}'",
            user_config.global.communication.ingester_ip, candidate_config.sender.dest_ip
        );
        // 初始化 L4 流日志发送队列和线程
        // 负责将聚合后的流日志发送给 DeepFlow Server 或数据节点
        let l4_flow_aggr_queue_name = "3-flowlog-to-collector-sender";
        let (l4_flow_aggr_sender, l4_flow_aggr_receiver, counter) = queue::bounded_with_debug(
            user_config
                .processors
                .flow_log
                .tunning
                .flow_generator_queue_size,
            l4_flow_aggr_queue_name,
            &queue_debugger,
        );
        stats_collector.register_countable(
            &QueueStats {
                module: l4_flow_aggr_queue_name,
                ..Default::default()
            },
            Countable::Owned(Box::new(counter)),
        );
        let l4_flow_uniform_sender = UniformSenderThread::new(
            l4_flow_aggr_queue_name,
            Arc::new(l4_flow_aggr_receiver),
            config_handler.sender(),
            stats_collector.clone(),
            exception_handler.clone(),
            None,
            if candidate_config.metric_server.l4_flow_log_compressed {
                SenderEncoder::Zstd
            } else {
                SenderEncoder::Raw
            },
            sender_leaky_bucket.clone(),
        );

        // 初始化指标数据发送队列和线程
        // 负责发送 DeepFlow Agent 自身的监控指标以及采集到的网络指标
        let metrics_queue_name = "3-doc-to-collector-sender";
        let (metrics_sender, metrics_receiver, counter) = queue::bounded_with_debug(
            user_config.outputs.flow_metrics.tunning.sender_queue_size,
            metrics_queue_name,
            &queue_debugger,
        );
        stats_collector.register_countable(
            &QueueStats {
                module: metrics_queue_name,
                ..Default::default()
            },
            Countable::Owned(Box::new(counter)),
        );
        let metrics_uniform_sender = UniformSenderThread::new(
            metrics_queue_name,
            Arc::new(metrics_receiver),
            config_handler.sender(),
            stats_collector.clone(),
            exception_handler.clone(),
            None,
            SenderEncoder::Raw,
            sender_leaky_bucket.clone(),
        );

        // 初始化 L7 协议日志发送队列和线程
        // 负责发送应用层协议分析产生的日志
        let proto_log_queue_name = "2-protolog-to-collector-sender";
        let (proto_log_sender, proto_log_receiver, counter) = queue::bounded_with_debug(
            user_config.outputs.flow_log.tunning.collector_queue_size,
            proto_log_queue_name,
            &queue_debugger,
        );
        stats_collector.register_countable(
            &QueueStats {
                module: proto_log_queue_name,
                ..Default::default()
            },
            Countable::Owned(Box::new(counter)),
        );
        let l7_flow_uniform_sender = UniformSenderThread::new(
            proto_log_queue_name,
            Arc::new(proto_log_receiver),
            config_handler.sender(),
            stats_collector.clone(),
            exception_handler.clone(),
            None,
            if candidate_config.metric_server.l7_flow_log_compressed {
                SenderEncoder::Zstd
            } else {
                SenderEncoder::Raw
            },
            sender_leaky_bucket.clone(),
        );

        // 解析分析器 IP (Analyzer IP / Ingester IP)
        // 确定数据发送的目标地址
        let analyzer_ip = if candidate_config
            .dispatcher
            .analyzer_ip
            .parse::<IpAddr>()
            .is_ok()
        {
            candidate_config
                .dispatcher
                .analyzer_ip
                .parse::<IpAddr>()
                .unwrap()
        } else {
            let ips = lookup_host(&candidate_config.dispatcher.analyzer_ip)?;
            ips[0]
        };

        // Dispatcher
        // 获取路由源 IP
        // 用于确定发送数据包时使用的源 IP 地址 (用于 GRE/VXLAN 封装等)
        let source_ip = match get_route_src_ip(&analyzer_ip) {
            Ok(ip) => ip,
            Err(e) => {
                warn!("get route to '{}' failed: {:?}", &analyzer_ip, e);
                if ctrl_ip.is_ipv6() {
                    Ipv6Addr::UNSPECIFIED.into()
                } else {
                    Ipv4Addr::UNSPECIFIED.into()
                }
            }
        };

        // NPB (Network Packet Broker) 相关配置
        // 用于配置网络包分发服务的带宽限制和 ARP 表
        let npb_bps_limit = Arc::new(LeakyBucket::new(Some(
            config_handler.candidate_config.sender.npb_bps_threshold,
        )));
        let npb_arp_table = Arc::new(NpbArpTable::new(
            config_handler.candidate_config.npb.socket_type == SocketType::RawUdp,
            exception_handler.clone(),
        ));

        // 初始化 PCAP 包发送队列和线程
        // 用于处理 PCAP 下载请求，将捕获的原始数据包发送给请求方
        let pcap_batch_queue = "2-pcap-batch-to-sender";
        let (pcap_batch_sender, pcap_batch_receiver, pcap_batch_counter) =
            queue::bounded_with_debug(
                user_config.processors.packet.pcap_stream.sender_queue_size,
                pcap_batch_queue,
                &queue_debugger,
            );
        stats_collector.register_countable(
            &QueueStats {
                module: pcap_batch_queue,
                ..Default::default()
            },
            Countable::Owned(Box::new(pcap_batch_counter)),
        );

        let pcap_packet_shared_connection = Arc::new(Mutex::new(Connection::new()));

        let pcap_batch_uniform_sender = UniformSenderThread::new(
            pcap_batch_queue,
            Arc::new(pcap_batch_receiver),
            config_handler.sender(),
            stats_collector.clone(),
            exception_handler.clone(),
            Some(pcap_packet_shared_connection.clone()),
            if user_config.outputs.compression.pcap {
                SenderEncoder::Zstd
            } else {
                SenderEncoder::Raw
            },
            sender_leaky_bucket.clone(),
        );
        // Enterprise Edition Feature: packet-sequence
        // 初始化包序列发送队列和线程 (企业版功能)
        let packet_sequence_queue_name = "2-packet-sequence-block-to-sender";
        let (packet_sequence_uniform_output, packet_sequence_uniform_input, counter) =
            queue::bounded_with_debug(
                user_config.processors.packet.tcp_header.sender_queue_size,
                packet_sequence_queue_name,
                &queue_debugger,
            );

        stats_collector.register_countable(
            &QueueStats {
                module: packet_sequence_queue_name,
                ..Default::default()
            },
            Countable::Owned(Box::new(counter)),
        );

        let packet_sequence_uniform_sender = UniformSenderThread::new(
            packet_sequence_queue_name,
            Arc::new(packet_sequence_uniform_input),
            config_handler.sender(),
            stats_collector.clone(),
            exception_handler.clone(),
            Some(pcap_packet_shared_connection),
            SenderEncoder::Raw,
            sender_leaky_bucket.clone(),
        );

        // 初始化 BPF (Berkeley Packet Filter) 构建器
        // 用于生成过滤数据包的 BPF 指令
        let bpf_builder = bpf::Builder {
            is_ipv6: ctrl_ip.is_ipv6(),
            vxlan_flags: user_config.outputs.npb.custom_vxlan_flags,
            npb_port: user_config.outputs.npb.target_port,
            controller_port: static_config.controller_port,
            controller_tls_port: static_config.controller_tls_port,
            proxy_controller_port: candidate_config.dispatcher.proxy_controller_port,
            analyzer_source_ip: source_ip,
            analyzer_port: candidate_config.dispatcher.analyzer_port,
            skip_npb_bpf: candidate_config.dispatcher.skip_npb_bpf,
        };
        // 生成 BPF 语法字符串
        let bpf_syntax_str = bpf_builder.build_pcap_syntax_to_str();
        #[cfg(any(target_os = "linux", target_os = "android"))]
        // 编译 BPF 指令
        let bpf_syntax = bpf_builder.build_pcap_syntax();

        let bpf_options = Arc::new(Mutex::new(BpfOptions {
            capture_bpf: candidate_config.dispatcher.capture_bpf.clone(),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            bpf_syntax,
            bpf_syntax_str,
        }));

        #[cfg(all(unix, feature = "libtrace"))]
        let queue_size = config_handler.ebpf().load().queue_size;
        #[cfg(all(unix, feature = "libtrace"))]
        let mut dpdk_ebpf_senders = vec![];

        let mut tap_interfaces = vec![];
        // 遍历所有网络接口/命名空间，为每个接口创建 Dispatcher
        for (i, entry) in interfaces_and_ns.into_iter().enumerate() {
            #[cfg(target_os = "linux")]
            let links = entry.0;
            #[cfg(any(target_os = "windows", target_os = "android"))]
            let links = entry;
            tap_interfaces.extend(links.clone());
            #[cfg(target_os = "linux")]
            let netns = entry.1;

            #[cfg(all(unix, feature = "libtrace"))]
            // 如果启用了 eBPF 且支持 DPDK，创建 DPDK eBPF 接收队列
            let dpdk_ebpf_receiver = {
                let queue_name = "0-ebpf-dpdk-to-dispatcher";
                let (dpdk_ebpf_sender, dpdk_ebpf_receiver, counter) =
                    queue::bounded_with_debug(queue_size, queue_name, &queue_debugger);
                stats_collector.register_countable(
                    &stats::QueueStats {
                        id: i,
                        module: queue_name,
                    },
                    Countable::Owned(Box::new(counter)),
                );
                dpdk_ebpf_senders.push(dpdk_ebpf_sender);
                Some(dpdk_ebpf_receiver)
            };
            #[cfg(all(unix, not(feature = "libtrace")))]
            let dpdk_ebpf_receiver = None;

            // 创建 Dispatcher 组件
            let dispatcher_component = build_dispatchers(
                i,
                links,
                stats_collector.clone(),
                config_handler,
                queue_debugger.clone(),
                version_info.name != env!("AGENT_NAME"),
                synchronizer,
                npb_bps_limit.clone(),
                npb_arp_table.clone(),
                rx_leaky_bucket.clone(),
                policy_getter,
                exception_handler.clone(),
                bpf_options.clone(),
                packet_sequence_uniform_output.clone(),
                proto_log_sender.clone(),
                pcap_batch_sender.clone(),
                tap_typer.clone(),
                vm_mac_addrs.clone(),
                gateway_vmac_addrs.clone(),
                toa_sender.clone(),
                l4_flow_aggr_sender.clone(),
                metrics_sender.clone(),
                #[cfg(target_os = "linux")]
                netns,
                #[cfg(target_os = "linux")]
                kubernetes_poller.clone(),
                #[cfg(target_os = "linux")]
                libvirt_xml_extractor.clone(),
                #[cfg(target_os = "linux")]
                dpdk_ebpf_receiver,
                #[cfg(target_os = "linux")]
                {
                    packet_fanout_count > 1
                },
            )?;
            dispatcher_components.push(dispatcher_component);
        }
        tap_interfaces.sort();
        #[cfg(feature = "libtrace")]
        // 初始化进程事件发送队列和线程
        // 用于发送 eBPF 捕获的进程启动/退出事件
        let (proc_event_sender, proc_event_uniform_sender) = {
            let proc_event_queue_name = "1-proc-event-to-sender";
            let (proc_event_sender, proc_event_receiver, counter) = queue::bounded_with_debug(
                user_config.inputs.ebpf.tunning.collector_queue_size,
                proc_event_queue_name,
                &queue_debugger,
            );
            stats_collector.register_countable(
                &QueueStats {
                    module: proc_event_queue_name,
                    ..Default::default()
                },
                Countable::Owned(Box::new(counter)),
            );
            let proc_event_uniform_sender = UniformSenderThread::new(
                proc_event_queue_name,
                Arc::new(proc_event_receiver),
                config_handler.sender(),
                stats_collector.clone(),
                exception_handler.clone(),
                None,
                SenderEncoder::Raw,
                sender_leaky_bucket.clone(),
            );
            (proc_event_sender, proc_event_uniform_sender)
        };

        // 初始化性能剖析 (Profile) 数据发送队列和线程
        // 用于发送 eBPF On-CPU/Off-CPU Profile 数据
        let profile_queue_name = "1-profile-to-sender";
        let (profile_sender, profile_receiver, counter) = queue::bounded_with_debug(
            user_config.inputs.ebpf.tunning.collector_queue_size,
            profile_queue_name,
            &queue_debugger,
        );
        stats_collector.register_countable(
            &QueueStats {
                module: profile_queue_name,
                ..Default::default()
            },
            Countable::Owned(Box::new(counter)),
        );
        let profile_uniform_sender = UniformSenderThread::new(
            profile_queue_name,
            Arc::new(profile_receiver),
            config_handler.sender(),
            stats_collector.clone(),
            exception_handler.clone(),
            None,
            // profiler compress is a special one, it requires compressed and directly write into db
            // so we compress profile data inside and not compress secondly
            SenderEncoder::Raw,
            sender_leaky_bucket.clone(),
        );
        // 初始化应用日志发送队列和线程
        // 用于发送从流量中提取的应用日志 (如 HTTP, MySQL 等)
        let application_log_queue_name = "1-application-log-to-sender";
        let (application_log_sender, application_log_receiver, counter) = queue::bounded_with_debug(
            user_config
                .processors
                .flow_log
                .tunning
                .flow_aggregator_queue_size,
            application_log_queue_name,
            &queue_debugger,
        );
        stats_collector.register_countable(
            &QueueStats {
                module: application_log_queue_name,
                ..Default::default()
            },
            Countable::Owned(Box::new(counter)),
        );
        let application_log_uniform_sender = UniformSenderThread::new(
            application_log_queue_name,
            Arc::new(application_log_receiver),
            config_handler.sender(),
            stats_collector.clone(),
            exception_handler.clone(),
            None,
            if candidate_config.metric_server.application_log_compressed {
                SenderEncoder::Zstd
            } else {
                SenderEncoder::Raw
            },
            sender_leaky_bucket.clone(),
        );

        #[cfg(feature = "enterprise-integration")]
        // 初始化 SkyWalking 数据集成
        let (skywalking_sender, skywalking_uniform_sender) = {
            let skywalking_queue_name = "1-skywalking-to-sender";
            let (skywalking_sender, skywalking_receiver, counter) = queue::bounded_with_debug(
                user_config
                    .processors
                    .flow_log
                    .tunning
                    .flow_aggregator_queue_size,
                skywalking_queue_name,
                &queue_debugger,
            );
            stats_collector.register_countable(
                &QueueStats {
                    module: skywalking_queue_name,
                    ..Default::default()
                },
                Countable::Owned(Box::new(counter)),
            );
            let skywalking_uniform_sender = UniformSenderThread::new(
                skywalking_queue_name,
                Arc::new(skywalking_receiver),
                config_handler.sender(),
                stats_collector.clone(),
                exception_handler.clone(),
                None,
                if candidate_config.metric_server.compressed {
                    SenderEncoder::Zstd
                } else {
                    SenderEncoder::Raw
                },
                sender_leaky_bucket.clone(),
            );
            (skywalking_sender, skywalking_uniform_sender)
        };

        // 初始化 Datadog 数据集成
        let datadog_queue_name = "1-datadog-to-sender";
        let (datadog_sender, datadog_receiver, counter) = queue::bounded_with_debug(
            user_config
                .processors
                .flow_log
                .tunning
                .flow_aggregator_queue_size,
            datadog_queue_name,
            &queue_debugger,
        );
        stats_collector.register_countable(
            &QueueStats {
                module: datadog_queue_name,
                ..Default::default()
            },
            Countable::Owned(Box::new(counter)),
        );
        let datadog_uniform_sender = UniformSenderThread::new(
            datadog_queue_name,
            Arc::new(datadog_receiver),
            config_handler.sender(),
            stats_collector.clone(),
            exception_handler.clone(),
            None,
            if candidate_config.metric_server.compressed {
                SenderEncoder::Zstd
            } else {
                SenderEncoder::Raw
            },
            sender_leaky_bucket.clone(),
        );

        let ebpf_dispatcher_id = dispatcher_components.len();
        #[cfg(all(unix, feature = "libtrace"))]
        let mut ebpf_dispatcher_component = None;
        #[cfg(all(unix, feature = "libtrace"))]
        // 初始化 eBPF Dispatcher 组件
        // 负责处理 eBPF 采集到的流量数据
        if !config_handler.ebpf().load().ebpf.disabled
            && !crate::utils::guard::is_kernel_ebpf_meltdown()
            && (candidate_config.capture_mode != PacketCaptureType::Analyzer
                || candidate_config
                    .user_config
                    .inputs
                    .cbpf
                    .special_network
                    .dpdk
                    .source
                    == DpdkSource::Ebpf)
        {
            let (l7_stats_sender, l7_stats_receiver, counter) = queue::bounded_with_debug(
                user_config
                    .processors
                    .flow_log
                    .tunning
                    .flow_generator_queue_size,
                "1-l7-stats-to-quadruple-generator",
                &queue_debugger,
            );
            stats_collector.register_countable(
                &QueueStats {
                    id: ebpf_dispatcher_id,
                    module: "1-l7-stats-to-quadruple-generator",
                },
                Countable::Owned(Box::new(counter)),
            );
            let (log_sender, log_receiver, counter) = queue::bounded_with_debug(
                user_config
                    .processors
                    .flow_log
                    .tunning
                    .flow_generator_queue_size,
                "1-tagged-flow-to-app-protocol-logs",
                &queue_debugger,
            );
            stats_collector.register_countable(
                &QueueStats {
                    id: ebpf_dispatcher_id,
                    module: "1-tagged-flow-to-app-protocol-logs",
                },
                Countable::Owned(Box::new(counter)),
            );
            let (session_aggregator, counter) = SessionAggregator::new(
                log_receiver,
                proto_log_sender.clone(),
                ebpf_dispatcher_id as u32,
                config_handler.log_parser(),
                synchronizer.ntp_diff(),
            );
            stats_collector.register_countable(
                &stats::SingleTagModule("l7_session_aggr", "index", ebpf_dispatcher_id),
                Countable::Ref(Arc::downgrade(&counter) as Weak<dyn RefCountable>),
            );
            let l7_collector = Self::new_l7_collector(
                ebpf_dispatcher_id,
                stats_collector.clone(),
                l7_stats_receiver,
                metrics_sender.clone(),
                MetricsType::SECOND | MetricsType::MINUTE,
                config_handler,
                &queue_debugger,
                &synchronizer,
                agent_mode,
            );
            match crate::ebpf_dispatcher::EbpfCollector::new(
                ebpf_dispatcher_id,
                synchronizer.ntp_diff(),
                config_handler.ebpf(),
                config_handler.log_parser(),
                config_handler.flow(),
                config_handler.collector(),
                policy_getter,
                dpdk_ebpf_senders,
                log_sender,
                l7_stats_sender,
                proc_event_sender,
                profile_sender.clone(),
                &queue_debugger,
                stats_collector.clone(),
                exception_handler.clone(),
                &process_listener,
            ) {
                Ok(ebpf_collector) => {
                    synchronizer
                        .add_flow_acl_listener(Box::new(ebpf_collector.get_sync_dispatcher()));
                    stats_collector.register_countable(
                        &stats::NoTagModule("ebpf-collector"),
                        Countable::Owned(Box::new(ebpf_collector.get_sync_counter())),
                    );
                    ebpf_dispatcher_component = Some(EbpfDispatcherComponent {
                        ebpf_collector,
                        session_aggregator,
                        l7_collector,
                    });
                }
                Err(e) => {
                    log::error!("ebpf collector error: {:?}", e);
                }
            };
        }

        // 初始化 OTel (OpenTelemetry) 数据发送队列和线程
        let otel_queue_name = "1-otel-to-sender";
        let (otel_sender, otel_receiver, counter) = queue::bounded_with_debug(
            user_config
                .processors
                .flow_log
                .tunning
                .flow_aggregator_queue_size,
            otel_queue_name,
            &queue_debugger,
        );
        stats_collector.register_countable(
            &QueueStats {
                module: otel_queue_name,
                ..Default::default()
            },
            Countable::Owned(Box::new(counter)),
        );
        let otel_uniform_sender = UniformSenderThread::new(
            otel_queue_name,
            Arc::new(otel_receiver),
            config_handler.sender(),
            stats_collector.clone(),
            exception_handler.clone(),
            None,
            if candidate_config.metric_server.compressed {
                SenderEncoder::Zstd
            } else {
                SenderEncoder::Raw
            },
            sender_leaky_bucket.clone(),
        );

        let otel_dispatcher_id = ebpf_dispatcher_id + 1;

        // 初始化 L7 统计数据发送队列（用于 OTel）
        let (l7_stats_sender, l7_stats_receiver, counter) = queue::bounded_with_debug(
            user_config
                .processors
                .flow_log
                .tunning
                .flow_generator_queue_size,
            "1-l7-stats-to-quadruple-generator",
            &queue_debugger,
        );
        stats_collector.register_countable(
            &QueueStats {
                id: otel_dispatcher_id,
                module: "1-l7-stats-to-quadruple-generator",
            },
            Countable::Owned(Box::new(counter)),
        );
        let l7_collector = Self::new_l7_collector(
            otel_dispatcher_id,
            stats_collector.clone(),
            l7_stats_receiver,
            metrics_sender.clone(),
            MetricsType::SECOND | MetricsType::MINUTE,
            config_handler,
            &queue_debugger,
            &synchronizer,
            agent_mode,
        );

        // 初始化 Prometheus 数据发送队列和线程
        let prometheus_queue_name = "1-prometheus-to-sender";
        let (prometheus_sender, prometheus_receiver, counter) = queue::bounded_with_debug(
            user_config
                .processors
                .flow_log
                .tunning
                .flow_aggregator_queue_size,
            prometheus_queue_name,
            &queue_debugger,
        );
        stats_collector.register_countable(
            &QueueStats {
                module: prometheus_queue_name,
                ..Default::default()
            },
            Countable::Owned(Box::new(counter)),
        );

        let prometheus_telegraf_shared_connection = Arc::new(Mutex::new(Connection::new()));
        let prometheus_uniform_sender = UniformSenderThread::new(
            prometheus_queue_name,
            Arc::new(prometheus_receiver),
            config_handler.sender(),
            stats_collector.clone(),
            exception_handler.clone(),
            Some(prometheus_telegraf_shared_connection.clone()),
            SenderEncoder::Raw,
            sender_leaky_bucket.clone(),
        );

        // 初始化 Telegraf 数据发送队列和线程
        let telegraf_queue_name = "1-telegraf-to-sender";
        let (telegraf_sender, telegraf_receiver, counter) = queue::bounded_with_debug(
            user_config
                .processors
                .flow_log
                .tunning
                .flow_aggregator_queue_size,
            telegraf_queue_name,
            &queue_debugger,
        );
        stats_collector.register_countable(
            &QueueStats {
                module: telegraf_queue_name,
                ..Default::default()
            },
            Countable::Owned(Box::new(counter)),
        );
        let telegraf_uniform_sender = UniformSenderThread::new(
            telegraf_queue_name,
            Arc::new(telegraf_receiver),
            config_handler.sender(),
            stats_collector.clone(),
            exception_handler.clone(),
            Some(prometheus_telegraf_shared_connection),
            SenderEncoder::Raw,
            sender_leaky_bucket.clone(),
        );

        // 初始化压缩后的 OTel 数据发送队列和线程
        let compressed_otel_queue_name = "1-compressed-otel-to-sender";
        let (compressed_otel_sender, compressed_otel_receiver, counter) = queue::bounded_with_debug(
            user_config
                .processors
                .flow_log
                .tunning
                .flow_aggregator_queue_size,
            compressed_otel_queue_name,
            &queue_debugger,
        );
        stats_collector.register_countable(
            &QueueStats {
                module: compressed_otel_queue_name,
                ..Default::default()
            },
            Countable::Owned(Box::new(counter)),
        );
        let compressed_otel_uniform_sender = UniformSenderThread::new(
            compressed_otel_queue_name,
            Arc::new(compressed_otel_receiver),
            config_handler.sender(),
            stats_collector.clone(),
            exception_handler.clone(),
            None,
            SenderEncoder::Raw,
            sender_leaky_bucket.clone(),
        );

        // 初始化外部指标服务组件 (MetricServer)
        // 负责接收和处理来自外部 (OTel, Prometheus, Telegraf 等) 的指标数据
        let (external_metrics_server, external_metrics_counter) = MetricServer::new(
            runtime.clone(),
            otel_sender,
            compressed_otel_sender,
            l7_stats_sender,
            prometheus_sender,
            telegraf_sender,
            profile_sender,
            application_log_sender,
            #[cfg(feature = "enterprise-integration")]
            skywalking_sender,
            datadog_sender,
            candidate_config.metric_server.port,
            exception_handler.clone(),
            candidate_config.metric_server.compressed,
            candidate_config.metric_server.profile_compressed,
            candidate_config.platform.epc_id,
            policy_getter,
            synchronizer.ntp_diff(),
            user_config
                .inputs
                .integration
                .prometheus_extra_labels
                .clone(),
            candidate_config.log_parser.clone(),
            user_config
                .inputs
                .integration
                .feature_control
                .profile_integration_disabled,
            user_config
                .inputs
                .integration
                .feature_control
                .trace_integration_disabled,
            user_config
                .inputs
                .integration
                .feature_control
                .metric_integration_disabled,
            user_config
                .inputs
                .integration
                .feature_control
                .log_integration_disabled,
        );

        stats_collector.register_countable(
            &stats::NoTagModule("integration_collector"),
            Countable::Owned(Box::new(external_metrics_counter)),
        );

        // 初始化 NPB (Network Packet Broker) 带宽监控器
        // 监控网络包分发流量，防止超限
        let sender_config = config_handler.sender().load();
        let (npb_bandwidth_watcher, npb_bandwidth_watcher_counter) = NpbBandwidthWatcher::new(
            sender_config.bandwidth_probe_interval.as_secs(),
            sender_config.npb_bps_threshold,
            sender_config.server_tx_bandwidth_threshold,
            npb_bps_limit.clone(),
            exception_handler.clone(),
        );
        synchronizer.add_flow_acl_listener(npb_bandwidth_watcher.clone());
        stats_collector.register_countable(
            &stats::NoTagModule("npb_bandwidth_watcher"),
            Countable::Ref(Arc::downgrade(&npb_bandwidth_watcher_counter) as Weak<dyn RefCountable>),
        );
        #[cfg(feature = "enterprise-integration")]
        // 初始化 Vector 组件 (企业版功能)
        let vector_component = VectorComponent::new(
            user_config.inputs.vector.enabled,
            user_config.inputs.vector.config.clone(),
            runtime.clone(),
            synchronizer.agent_id.read().clone().ipmac.ip.to_string(),
            ipmac_tx,
        );

        Ok(AgentComponents {
            config: candidate_config.clone(),
            rx_leaky_bucket,
            tap_typer,
            cur_tap_types: vec![],
            l4_flow_uniform_sender,
            metrics_uniform_sender,
            l7_flow_uniform_sender,
            platform_synchronizer,
            #[cfg(target_os = "linux")]
            kubernetes_poller,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            socket_synchronizer,
            debugger,
            #[cfg(all(unix, feature = "libtrace"))]
            ebpf_dispatcher_component,
            stats_collector,
            running: AtomicBool::new(false),
            metrics_server_component: MetricsServerComponent {
                external_metrics_server,
                l7_collector,
            },
            exception_handler,
            max_memory,
            otel_uniform_sender,
            prometheus_uniform_sender,
            telegraf_uniform_sender,
            profile_uniform_sender,
            #[cfg(feature = "libtrace")]
            proc_event_uniform_sender,
            application_log_uniform_sender,
            #[cfg(feature = "enterprise-integration")]
            skywalking_uniform_sender,
            datadog_uniform_sender,
            capture_mode: candidate_config.capture_mode,
            packet_sequence_uniform_output, // Enterprise Edition Feature: packet-sequence
            packet_sequence_uniform_sender, // Enterprise Edition Feature: packet-sequence
            npb_bps_limit,
            compressed_otel_uniform_sender,
            pcap_batch_uniform_sender,
            proto_log_sender,
            pcap_batch_sender,
            toa_info_sender: toa_sender,
            l4_flow_aggr_sender,
            metrics_sender,
            agent_mode,
            policy_setter,
            policy_getter,
            npb_bandwidth_watcher,
            npb_arp_table,
            #[cfg(feature = "enterprise-integration")]
            vector_component,
            runtime,
            dispatcher_components,
            is_ce_version: version_info.name != env!("AGENT_NAME"),
            tap_interfaces,
            last_dispatcher_component_id: otel_dispatcher_id,
            bpf_options,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            process_listener,
        })
    }

    // 清除所有分发器组件
    //
    // 该方法会先停止所有正在运行的分发器，然后清空列表。
    // 通常在重新加载配置或检测到网络接口发生重大变化时调用。
    pub fn clear_dispatcher_components(&mut self) {
        self.dispatcher_components.iter_mut().for_each(|d| d.stop());
        self.dispatcher_components.clear();
        self.tap_interfaces.clear();
    }

    // 启动 Agent 的所有组件
    //
    // 该方法按顺序启动：
    // 1. 基础服务 (Stats, SocketSync, K8s Poller, Debugger)
    // 2. 数据发送线程 (Metrics, L4/L7 Logs)
    // 3. 核心分发器 (Dispatcher) - 负责抓包和处理
    // 4. 平台相关组件 (eBPF, NPB, ProcessListener)
    // 5. 托管模式下的额外组件 (OTel, Prometheus, Telegraf 等)
    fn start(&mut self) {
        // 如果 Agent 已经在运行，则直接返回
        if self.running.swap(true, Ordering::Relaxed) {
            return;
        }
        info!("Starting agent components.");
        // 启动统计数据收集器
        self.stats_collector.start();

        #[cfg(any(target_os = "linux", target_os = "android"))]
        // 启动 Socket 同步器，用于建立 Socket 与进程的关联
        self.socket_synchronizer.start();
        #[cfg(target_os = "linux")]
        if crate::utils::environment::is_tt_pod(self.config.agent_type) {
            // 如果是在 TT Pod 环境中，启动 Kubernetes 轮询器
            self.kubernetes_poller.start();
        }
        // 启动调试器，提供内部状态查询接口
        self.debugger.start();
        // 启动各类型数据发送线程 (Metrics, L7 Flow, L4 Flow)
        self.metrics_uniform_sender.start();
        self.l7_flow_uniform_sender.start();
        self.l4_flow_uniform_sender.start();

        // Enterprise Edition Feature: packet-sequence
        self.packet_sequence_uniform_sender.start();

        // When capture_mode is Analyzer mode and agent is not running in container and agent
        // in the environment where cgroup is not supported, we need to check free memory
        // 当捕获模式不是分析器模式，且 Agent 不在容器中运行，且环境不支持 cgroup 时，需要检查可用内存
        // 避免在资源受限环境(如虚拟机)中耗尽内存
        if self.capture_mode != PacketCaptureType::Analyzer
            && !running_in_container()
            && !is_kernel_available_for_cgroups()
        {
            match free_memory_check(self.max_memory, &self.exception_handler) {
                Ok(()) => {
                    for d in self.dispatcher_components.iter_mut() {
                        d.start();
                    }
                }
                Err(e) => {
                    warn!("{}", e);
                }
            }
        } else {
            // 启动分发器组件
            for d in self.dispatcher_components.iter_mut() {
                d.start();
            }
        }

        #[cfg(all(unix, feature = "libtrace"))]
        // 启动 eBPF 分发器组件
        if let Some(ebpf_dispatcher_component) = self.ebpf_dispatcher_component.as_mut() {
            ebpf_dispatcher_component.start();
        }
        // 如果是托管模式，启动更多的发送线程和服务
        if matches!(self.agent_mode, RunningMode::Managed) {
            self.otel_uniform_sender.start();
            self.compressed_otel_uniform_sender.start();
            self.prometheus_uniform_sender.start();
            self.telegraf_uniform_sender.start();
            self.profile_uniform_sender.start();
            #[cfg(feature = "libtrace")]
            self.proc_event_uniform_sender.start();
            self.application_log_uniform_sender.start();
            #[cfg(feature = "enterprise-integration")]
            self.skywalking_uniform_sender.start();
            self.datadog_uniform_sender.start();
            if self.config.metric_server.enabled {
                self.metrics_server_component.start();
            }
            self.pcap_batch_uniform_sender.start();
        }

        self.npb_bandwidth_watcher.start();
        self.npb_arp_table.start();
        #[cfg(feature = "enterprise-integration")]
        self.vector_component.start();
        #[cfg(any(target_os = "linux", target_os = "android"))]
        self.process_listener.start();
        info!("Started agent components.");
    }

    // 停止 Agent 的所有组件
    //
    // 该方法负责优雅地停止所有运行中的线程和组件，并清理资源。
    // 包括：分发器、同步器、各类发送线程、调试器等。
    fn stop(&mut self) {
        // 如果 Agent 已经停止，则直接返回
        if !self.running.swap(false, Ordering::Relaxed) {
            return;
        }

        let mut join_handles = vec![];

        // 重置策略设置器的队列大小
        self.policy_setter.reset_queue_size(0);
        // 停止所有的分发器组件
        for d in self.dispatcher_components.iter_mut() {
            d.stop();
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        self.socket_synchronizer.stop();
        #[cfg(target_os = "linux")]
        self.kubernetes_poller.stop();

        // 停止各个发送线程，并收集 join handle
        if let Some(h) = self.l4_flow_uniform_sender.notify_stop() {
            join_handles.push(h);
        }
        if let Some(h) = self.metrics_uniform_sender.notify_stop() {
            join_handles.push(h);
        }
        if let Some(h) = self.l7_flow_uniform_sender.notify_stop() {
            join_handles.push(h);
        }

        // 停止调试器
        self.debugger.stop();

        #[cfg(all(unix, feature = "libtrace"))]
        // 停止 eBPF 分发器组件
        if let Some(d) = self.ebpf_dispatcher_component.as_mut() {
            d.stop();
        }

        // 停止其他服务和发送线程
        self.metrics_server_component.stop();
        if let Some(h) = self.otel_uniform_sender.notify_stop() {
            join_handles.push(h);
        }
        if let Some(h) = self.compressed_otel_uniform_sender.notify_stop() {
            join_handles.push(h);
        }
        if let Some(h) = self.prometheus_uniform_sender.notify_stop() {
            join_handles.push(h);
        }
        if let Some(h) = self.telegraf_uniform_sender.notify_stop() {
            join_handles.push(h);
        }
        if let Some(h) = self.profile_uniform_sender.notify_stop() {
            join_handles.push(h);
        }
        #[cfg(feature = "libtrace")]
        if let Some(h) = self.proc_event_uniform_sender.notify_stop() {
            join_handles.push(h);
        }
        if let Some(h) = self.pcap_batch_uniform_sender.notify_stop() {
            join_handles.push(h);
        }
        if let Some(h) = self.application_log_uniform_sender.notify_stop() {
            join_handles.push(h);
        }
        #[cfg(feature = "enterprise-integration")]
        if let Some(h) = self.skywalking_uniform_sender.notify_stop() {
            join_handles.push(h);
        }
        if let Some(h) = self.datadog_uniform_sender.notify_stop() {
            join_handles.push(h);
        }
        // Enterprise Edition Feature: packet-sequence
        if let Some(h) = self.packet_sequence_uniform_sender.notify_stop() {
            join_handles.push(h);
        }

        if let Some(h) = self.npb_bandwidth_watcher.notify_stop() {
            join_handles.push(h);
        }

        if let Some(h) = self.npb_arp_table.notify_stop() {
            join_handles.push(h);
        }
        if let Some(h) = self.stats_collector.notify_stop() {
            join_handles.push(h);
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(h) = self.process_listener.notify_stop() {
            join_handles.push(h);
        }
        #[cfg(feature = "enterprise-integration")]
        if let Some(h) = self.vector_component.notify_stop() {
            join_handles.push(h);
        }

        // 等待所有线程结束
        for handle in join_handles {
            if !handle.is_finished() {
                info!(
                    "wait for {} to fully stop",
                    handle.thread().name().unwrap_or("unnamed thread")
                );
            }
            let _ = handle.join();
        }

        info!("Stopped agent components.")
    }
}

impl Components {
    // 启动组件
    // 根据组件类型 (Agent 或 Watcher) 调用相应的启动方法
    fn start(&mut self) {
        match self {
            Self::Agent(a) => a.start(),
            #[cfg(target_os = "linux")]
            Self::Watcher(w) => w.start(),
            _ => {}
        }
    }

    // 创建新的组件实例
    //
    // 根据运行模式和环境配置，决定创建完整的 Agent 组件还是仅包含 K8s 监听功能的 Watcher 组件。
    // K8s 监听模式通常用于 sidecar 容器中，仅负责监听 K8s 资源变化。
    fn new(
        version_info: &VersionInfo,
        config_handler: &ConfigHandler,
        stats_collector: Arc<stats::Collector>,
        session: &Arc<Session>,
        synchronizer: &Arc<Synchronizer>,
        exception_handler: ExceptionHandler,
        #[cfg(target_os = "linux")] libvirt_xml_extractor: Arc<LibvirtXmlExtractor>,
        platform_synchronizer: Arc<PlatformSynchronizer>,
        #[cfg(target_os = "linux")] sidecar_poller: Option<Arc<GenericPoller>>,
        #[cfg(target_os = "linux")] api_watcher: Arc<ApiWatcher>,
        vm_mac_addrs: Vec<MacAddr>,
        gateway_vmac_addrs: Vec<MacAddr>,
        agent_mode: RunningMode,
        runtime: Arc<Runtime>,
        sender_leaky_bucket: Arc<LeakyBucket>,
        ipmac_tx: Arc<broadcast::Sender<IpMacPair>>,
    ) -> Result<Self> {
        #[cfg(target_os = "linux")]
        if crate::utils::environment::running_in_only_watch_k8s_mode() {
            // 如果仅在 K8s 监听模式下运行，初始化 Watcher 组件
            let components = WatcherComponents::new(config_handler, agent_mode, runtime)?;
            return Ok(Components::Watcher(components));
        }
        // 初始化 Agent 完整组件
        let components = AgentComponents::new(
            version_info,
            config_handler,
            stats_collector,
            session,
            synchronizer,
            exception_handler,
            #[cfg(target_os = "linux")]
            libvirt_xml_extractor,
            platform_synchronizer,
            #[cfg(target_os = "linux")]
            sidecar_poller,
            #[cfg(target_os = "linux")]
            api_watcher,
            vm_mac_addrs,
            gateway_vmac_addrs,
            agent_mode,
            runtime,
            sender_leaky_bucket,
            ipmac_tx,
        )?;
        return Ok(Components::Agent(components));
    }

    // 停止组件
    // 根据组件类型调用相应的停止方法
    fn stop(&mut self) {
        match self {
            Self::Agent(a) => a.stop(),
            #[cfg(target_os = "linux")]
            Self::Watcher(w) => w.stop(),
            _ => {}
        }
    }
}

// 构建 PcapAssembler，用于组装 PCAP 包
//
// 该函数初始化 PcapAssembler 及其输入队列。
// PcapAssembler 负责接收 MiniPacket (元数据)，从 buffer 中提取完整包数据，
// 组装成 PCAP 文件批次，最终用于 PCAP 下载功能。
fn build_pcap_assembler(
    enabled: bool,
    config: &PcapStream,
    stats_collector: &stats::Collector,
    pcap_batch_sender: DebugSender<BoxedPcapBatch>,
    queue_debugger: &QueueDebugger,
    ntp_diff: Arc<AtomicI64>,
    id: usize,
) -> (PcapAssembler, DebugSender<MiniPacket>) {
    // 创建 MiniPacket 队列：PacketHandler -> PcapAssembler
    // 用于传输从原始数据包中提取的元数据
    let mini_packet_queue = "1-mini-meta-packet-to-pcap-handler";
    let (mini_packet_sender, mini_packet_receiver, mini_packet_counter) = queue::bounded_with_debug(
        config.receiver_queue_size,
        mini_packet_queue,
        &queue_debugger,
    );
    let pcap_assembler = PcapAssembler::new(
        id as u32,
        enabled,
        config.total_buffer_size, // 总缓存大小
        config.buffer_size_per_flow, // 单流缓存大小
        config.flush_interval, // 刷新间隔
        pcap_batch_sender, // PCAP 批次发送端
        mini_packet_receiver, // MiniPacket 接收端
        ntp_diff,
    );
    stats_collector.register_countable(
        &stats::SingleTagModule("pcap_assembler", "id", id),
        Countable::Ref(Arc::downgrade(&pcap_assembler.counter) as Weak<dyn RefCountable>),
    );
    stats_collector.register_countable(
        &QueueStats {
            id,
            module: mini_packet_queue,
        },
        Countable::Owned(Box::new(mini_packet_counter)),
    );
    (pcap_assembler, mini_packet_sender)
}
    
// 构建分发器组件 (DispatcherComponent)
//
// Dispatcher 是 Agent 的核心流量处理单元，负责：
// 1. 从网卡或网络命名空间接收数据包 (AF_PACKET, DPDK, PCAP)
// 2. 执行 BPF 过滤
// 3. 分发数据包给各个处理模块 (FlowGenerator, ProtocolLogs, NPB, PCAP Assembler)
// 4. 管理 Flow 和 L7 Stats 的生成与发送
fn build_dispatchers(
    id: usize,
    links: Vec<Link>,
    stats_collector: Arc<stats::Collector>,
    config_handler: &ConfigHandler,
    queue_debugger: Arc<QueueDebugger>,
    is_ce_version: bool,
    synchronizer: &Arc<Synchronizer>,
    npb_bps_limit: Arc<LeakyBucket>,
    npb_arp_table: Arc<NpbArpTable>,
    rx_leaky_bucket: Arc<LeakyBucket>,
    policy_getter: PolicyGetter,
    exception_handler: ExceptionHandler,
    bpf_options: Arc<Mutex<BpfOptions>>,
    packet_sequence_uniform_output: DebugSender<BoxedPacketSequenceBlock>,
    proto_log_sender: DebugSender<BoxAppProtoLogsData>,
    pcap_batch_sender: DebugSender<BoxedPcapBatch>,
    tap_typer: Arc<CaptureNetworkTyper>,
    vm_mac_addrs: Vec<MacAddr>,
    gateway_vmac_addrs: Vec<MacAddr>,
    toa_info_sender: DebugSender<Box<(SocketAddr, SocketAddr)>>,
    l4_flow_aggr_sender: DebugSender<BoxedTaggedFlow>,
    metrics_sender: DebugSender<BoxedDocument>,
    #[cfg(target_os = "linux")] netns: netns::NsFile,
    #[cfg(target_os = "linux")] kubernetes_poller: Arc<GenericPoller>,
    #[cfg(target_os = "linux")] libvirt_xml_extractor: Arc<LibvirtXmlExtractor>,
    #[cfg(target_os = "linux")] dpdk_ebpf_receiver: Option<Receiver<Box<packet::Packet<'static>>>>,
    #[cfg(target_os = "linux")] fanout_enabled: bool,
) -> Result<DispatcherComponent> {
    let candidate_config = &config_handler.candidate_config;
    let user_config = &candidate_config.user_config;
    let dispatcher_config = &candidate_config.dispatcher;
    let static_config = &config_handler.static_config;
    let agent_mode = static_config.agent_mode;
    let ctrl_ip = config_handler.ctrl_ip;
    let ctrl_mac = config_handler.ctrl_mac;
    let src_link = links.get(0).map(|l| l.to_owned()).unwrap_or_default();

    // 创建 Flow (L4 流日志) 队列：Dispatcher -> QuadrupleGenerator
    let (flow_sender, flow_receiver, counter) = queue::bounded_with_debug(
        user_config
            .processors
            .flow_log
            .tunning
            .flow_generator_queue_size,
        "1-tagged-flow-to-quadruple-generator",
        &queue_debugger,
    );
    stats_collector.register_countable(
        &QueueStats {
            id,
            module: "1-tagged-flow-to-quadruple-generator",
        },
        Countable::Owned(Box::new(counter)),
    );

    // 创建 L7 Stats (应用性能指标) 队列：Dispatcher -> QuadrupleGenerator
    let (l7_stats_sender, l7_stats_receiver, counter) = queue::bounded_with_debug(
        user_config
            .processors
            .flow_log
            .tunning
            .flow_generator_queue_size,
        "1-l7-stats-to-quadruple-generator",
        &queue_debugger,
    );
    stats_collector.register_countable(
        &QueueStats {
            id,
            module: "1-l7-stats-to-quadruple-generator",
        },
        Countable::Owned(Box::new(counter)),
    );

    // 创建应用协议日志队列：Dispatcher -> AppProtoLogs
    let (log_sender, log_receiver, counter) = queue::bounded_with_debug(
        user_config
            .processors
            .flow_log
            .tunning
            .flow_generator_queue_size,
        "1-tagged-flow-to-app-protocol-logs",
        &queue_debugger,
    );
    stats_collector.register_countable(
        &QueueStats {
            id,
            module: "1-tagged-flow-to-app-protocol-logs",
        },
        Countable::Owned(Box::new(counter)),
    );

    // 初始化会话聚合器 (将请求和响应聚合为一条日志)
    let (session_aggr, counter) = SessionAggregator::new(
        log_receiver,
        proto_log_sender.clone(),
        id as u32,
        config_handler.log_parser(),
        synchronizer.ntp_diff(),
    );
    stats_collector.register_countable(
        &stats::SingleTagModule("l7_session_aggr", "index", id),
        Countable::Ref(Arc::downgrade(&counter) as Weak<dyn RefCountable>),
    );

    // 创建包序数据队列 (企业版功能)
    let (packet_sequence_sender, packet_sequence_receiver, counter) = queue::bounded_with_debug(
        user_config.processors.packet.tcp_header.sender_queue_size,
        "1-packet-sequence-block-to-parser",
        &queue_debugger,
    );
    stats_collector.register_countable(
        &QueueStats {
            id,
            module: "1-packet-sequence-block-to-parser",
        },
        Countable::Owned(Box::new(counter)),
    );

    // 初始化包序解析器
    let packet_sequence_parser = PacketSequenceParser::new(
        packet_sequence_receiver,
        packet_sequence_uniform_output,
        id as u32,
    );
    // 构建 PCAP 组装器 (用于 PCAP 下载功能)
    let (pcap_assembler, mini_packet_sender) = build_pcap_assembler(
        is_ce_version,
        &user_config.processors.packet.pcap_stream,
        &stats_collector,
        pcap_batch_sender.clone(),
        &queue_debugger,
        synchronizer.ntp_diff(),
        id,
    );

    // 配置包处理 pipeline：PCAP -> NPB
    let handler_builders = Arc::new(RwLock::new(vec![
        PacketHandlerBuilder::Pcap(mini_packet_sender),
        PacketHandlerBuilder::Npb(NpbBuilder::new(
            id,
            &candidate_config.npb,
            &queue_debugger,
            npb_bps_limit.clone(),
            npb_arp_table.clone(),
            stats_collector.clone(),
        )),
    ]));

    // 根据配置决定是否使用 AF_PACKET 捕获接口
    let pcap_interfaces = if candidate_config.capture_mode != PacketCaptureType::Local
        && candidate_config
            .user_config
            .inputs
            .cbpf
            .special_network
            .dpdk
            .source
            != DpdkSource::None
    {
        vec![]
    } else {
        links.clone()
    };

    // 配置 Dispatcher 构建器
    // Dispatcher 是流量处理的核心，负责从底层接口收包并分发
    let dispatcher_builder = DispatcherBuilder::new()
        .id(id)
        .pause(agent_mode == RunningMode::Managed) // 托管模式下启动时暂停，等待配置下发
        .handler_builders(handler_builders.clone()) // 注册包处理流水线 (PCAP, NPB)
        .ctrl_mac(ctrl_mac)
        .leaky_bucket(rx_leaky_bucket.clone()) // 全局接收限流
        .options(Arc::new(Mutex::new(dispatcher::Options {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            af_packet_version: dispatcher_config.af_packet_version, // AF_PACKET 版本 (v1/v2/v3)
            packet_blocks: dispatcher_config.af_packet_blocks, // 环形缓冲区大小配置
            capture_mode: candidate_config.capture_mode, // 捕获模式
            tap_mac_script: user_config
                .inputs
                .resources
                .private_cloud
                .vm_mac_mapping_script
                .clone(), // 虚拟机 MAC 地址解析脚本
            is_ipv6: ctrl_ip.is_ipv6(),
            npb_port: user_config.outputs.npb.target_port, // NPB 目的端口
            vxlan_flags: user_config.outputs.npb.custom_vxlan_flags, // VXLAN 标志
            controller_port: static_config.controller_port,
            controller_tls_port: static_config.controller_tls_port,
            libpcap_enabled: user_config.inputs.cbpf.special_network.libpcap.enabled, // 是否启用 libpcap
            snap_len: dispatcher_config.capture_packet_size as usize, // 抓包截断长度
            dpdk_source: dispatcher_config.dpdk_source, // DPDK 源配置
            dispatcher_queue: dispatcher_config.dispatcher_queue, // 分发队列配置
            packet_fanout_mode: user_config.inputs.cbpf.af_packet.tunning.packet_fanout_mode, // Fanout 模式 (Hash/Lb/Cpu/Rollover/Rnd/Qm)
            vhost_socket_path: user_config
                .inputs
                .cbpf
                .special_network
                .vhost_user
                .vhost_socket_path
                .clone(), // vhost-user socket 路径
            #[cfg(any(target_os = "linux", target_os = "android"))]
            cpu_set: dispatcher_config.cpu_set, // 绑核设置
            #[cfg(target_os = "linux")]
            dpdk_ebpf_receiver, // DPDK eBPF 接收端
            #[cfg(target_os = "linux")]
            dpdk_ebpf_windows: user_config
                .inputs
                .cbpf
                .special_network
                .dpdk
                .reorder_cache_window_size, // DPDK eBPF 乱序重排窗口
            #[cfg(target_os = "linux")]
            fanout_enabled, // 是否启用 Fanout
            #[cfg(any(target_os = "linux", target_os = "android"))]
            promisc: user_config.inputs.cbpf.af_packet.tunning.promisc, // 是否启用混杂模式
            skip_npb_bpf: user_config.inputs.cbpf.af_packet.skip_npb_bpf, // 是否跳过 NPB 的 BPF 过滤
            ..Default::default()
        })))
        .bpf_options(bpf_options)
            // 默认 TAP 类型 (云流量)
        .default_tap_type(
            (user_config
                .inputs
                .cbpf
                .physical_mirror
                .default_capture_network_type)
                .try_into()
                .unwrap_or(CaptureNetworkType::Cloud),
        )
        // 镜像流量 PCP (VLAN Priority Code Point)
        .mirror_traffic_pcp(
            user_config
                .inputs
                .cbpf
                .af_packet
                .vlan_pcp_in_physical_mirror_traffic,
        )
        .tap_typer(tap_typer.clone())
        .analyzer_dedup_disabled(user_config.inputs.cbpf.tunning.dispatcher_queue_enabled) // 是否禁用去重
        .flow_output_queue(flow_sender.clone()) // Flow 输出队列
        .l7_stats_output_queue(l7_stats_sender.clone()) // L7 Stats 输出队列
        .log_output_queue(log_sender.clone()) // 协议日志输出队列
        .packet_sequence_output_queue(packet_sequence_sender) // Enterprise Edition Feature: packet-sequence // 包序输出队列
        .stats_collector(stats_collector.clone())
        .flow_map_config(config_handler.flow())
        .log_parser_config(config_handler.log_parser())
        .collector_config(config_handler.collector())
        .dispatcher_config(config_handler.dispatcher())
        .policy_getter(policy_getter)
        .exception_handler(exception_handler.clone())
        .ntp_diff(synchronizer.ntp_diff())
        // 设置源接口名称 (仅在非 Fanout 模式下)
        .src_interface(
            if candidate_config.capture_mode != PacketCaptureType::Local {
                #[cfg(target_os = "linux")]
                if !fanout_enabled {
                    src_link.name.clone()
                } else {
                    "".into()
                }
                #[cfg(target_os = "windows")]
                "".into()
            } else {
                "".into()
            },
        )
        .agent_type(dispatcher_config.agent_type)
        .queue_debugger(queue_debugger.clone())
        .analyzer_queue_size(user_config.inputs.cbpf.tunning.raw_packet_queue_size)
        .pcap_interfaces(pcap_interfaces.clone()) // PCAP 捕获接口列表
        .tunnel_type_trim_bitmap(dispatcher_config.tunnel_type_trim_bitmap) // 隧道类型裁剪位图
        .bond_group(dispatcher_config.bond_group.clone()) // Bond 组配置
        .analyzer_raw_packet_block_size(
            user_config.inputs.cbpf.tunning.raw_packet_buffer_block_size,
        );
    #[cfg(target_os = "linux")]
    let dispatcher_builder = dispatcher_builder
        .netns(netns)
        .libvirt_xml_extractor(libvirt_xml_extractor.clone())
        .platform_poller(kubernetes_poller.clone());
    // 构建 Dispatcher
    let dispatcher = match dispatcher_builder.build() {
        Ok(d) => d,
        Err(e) => {
            warn!(
                "dispatcher creation failed: {}, deepflow-agent restart...",
                e
            );
            thread::sleep(Duration::from_secs(1));
            return Err(e.into());
        }
    };
    // 获取 Dispatcher 监听器并注册回调
    let mut dispatcher_listener = dispatcher.listener();
    dispatcher_listener.on_config_change(dispatcher_config);
    dispatcher_listener.on_tap_interface_change(
        &links,
        dispatcher_config.if_mac_source,
        dispatcher_config.agent_type,
        &vec![],
    );
    dispatcher_listener.on_vm_change(&vm_mac_addrs, &gateway_vmac_addrs);
    synchronizer.add_flow_acl_listener(Box::new(dispatcher_listener.clone()));

    // 创建并启动 Collector (负责聚合 L4/L7 指标)
    let collector = AgentComponents::new_collector(
        id,
        stats_collector.clone(),
        flow_receiver,
        toa_info_sender.clone(),
        Some(l4_flow_aggr_sender.clone()),
        metrics_sender.clone(),
        MetricsType::SECOND | MetricsType::MINUTE,
        config_handler,
        &queue_debugger,
        &synchronizer,
        agent_mode,
    );

    // 创建并启动 L7 Collector
    let l7_collector = AgentComponents::new_l7_collector(
        id,
        stats_collector.clone(),
        l7_stats_receiver,
        metrics_sender.clone(),
        MetricsType::SECOND | MetricsType::MINUTE,
        config_handler,
        &queue_debugger,
        &synchronizer,
        agent_mode,
    );
    Ok(DispatcherComponent {
        id,
        dispatcher,
        dispatcher_listener,
        session_aggregator: session_aggr,
        collector,
        l7_collector,
        packet_sequence_parser,
        pcap_assembler,
        handler_builders,
        src_link,
    })
}
