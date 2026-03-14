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
	Managed, // 托管模式 (由控制器管理)
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
		Self { enabled: false, melted_down: true }
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
			sg.1.replace(ChangedConfig { user_config, ..Default::default() });
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
				"zerotrace-agent-ce" => "CE",
				"zerotrace-agent-ee" => "EE",
				_ => panic!("{:?} unknown zerotrace-agent edition", &self.name),
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
				"zerotrace-agent-ce" => "zerotrace-agent community edition",
				"zerotrace-agent-ee" => "zerotrace-agent enterprise edition",
				_ => panic!("{:?} unknown zerotrace-agent edition", &self.name),
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
	Raw = 0, // 原始数据

	Zstd = 3, // Zstd 压缩
}

impl SenderEncoder {
	pub fn encode(&self, encode_buffer: &[u8], dst_buffer: &mut Vec<u8>) -> std::io::Result<()> {
		match self {
			SenderEncoder::Zstd => {
				let mut encoder = ZstdEncoder::new(dst_buffer, 0)?;
				encoder.write_all(&encode_buffer)?;
				encoder.finish()?;
				Ok(())
			},
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
	// 启动 ZeroTrace Agent
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
		// affinity settings of zerotrace-agent
		#[cfg(any(target_os = "linux", target_os = "android"))]
		// 只针对linux和android系统，windows系统中不存在numad
		// CPU 亲和性: ZeroTrace Agent通常会将关键线程绑定到特定的 CPU 核上，以减少上下文切换和缓存失效，从而提升抓包和处理性能。
		// numad 是 Linux 下的一个用户态守护进程，用于自动调整进程的 NUMA（非统一内存访问）策略。它会监控系统资源并尝试动态迁移进程到它认为更合适的 CPU/内存节点上。
		// 如果 numad 介入并强行移动 Agent 的线程，会破坏 Agent 精心配置的 CPU 绑定，导致严重的性能抖动或下降。
		match trace_utils::protect_cpu_affinity() {
			Ok(()) => info!("CPU affinity protected successfully"),
			Err(e) => {
				// Distinguish between "numad not found" (normal) and other errors
				if e.kind() == std::io::ErrorKind::NotFound {
					info!("numad process not found, skipping CPU affinity protection (normal)");
				} else {
					warn!("Failed to protect CPU affinity due to unexpected error: {}", e);
				}
			},
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
					},
				}
			},
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
			},
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
		let logger = Logger::try_with_env_or_str("info").unwrap().format(colored_opt_format);
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
		// Standalone 模式也需要启动 stats_collector，用于采集主机指标并写入本地文件
		stats_collector.start();

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
		let main_loop = thread::Builder::new().name("main-loop".to_owned()).spawn(move || {
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
				error!("Launching zerotrace-agent failed: {}, zerotrace-agent restart...", e);
				crate::utils::clean_and_exit(1);
			}
		});
		let handle = match main_loop {
			Ok(h) => Some(h),
			Err(e) => {
				error!("Failed to create main-loop thread: {}", e);
				crate::utils::clean_and_exit(1);
				None
			},
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
		info!("==================== Launching ZeroTrace-Agent ====================");
		info!("Brief tag: {}", version_info.brief_tag());
		info!("Environment variables: {:?}", get_env());
		// 通过环境变量检查
		if running_in_container() {
			info!("use K8S_NODE_IP_FOR_ZEROTRACE env ip as destination_ip({})", ctrl_ip);
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
			config_handler.static_config.controller_cert_file_prefix.clone(),
			config_handler.static_config.controller_ips.clone(),
			exception_handler.clone(),
			&stats_collector,
		));

		// 创建 Tokio 运行时
		// 用于驱动所有的异步任务 (如 gRPC, metrics sender 等)
		let runtime = Arc::new(
			Builder::new_multi_thread()
				.worker_threads(config_handler.static_config.async_worker_thread_number.into())
				.enable_all()
				.build()
				.unwrap(),
		);

		let mut k8s_opaque_id = None;
		// 如果 Agent 运行在 K8s 环境下的托管模式
		if matches!(config_handler.static_config.agent_mode, RunningMode::Managed)
			&& running_in_k8s()
		{
			// 尝试自动填充 K8s Cluster ID
			// 如果配置中未指定 cluster_id，Agent 会尝试调用 gRPC 接口向 Server 查询。
			// 即使 ConfigMap 没配，也能通过 CA 证书指纹自动关联到正确的集群。
			config_handler.static_config.fill_k8s_info(&runtime, &session);
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
		if matches!(config_handler.static_config.agent_mode, RunningMode::Managed) {
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
			info!("don't initialize cgroups controller, disable cgroups, zerotrace-agent will default to checking the CPU and memory resource usage in a loop every 10 seconds to prevent resource usage from exceeding limits");
		} else {
			// 初始化 Cgroups 控制器，用于资源限制
			match Cgroups::new(process::id() as u64, config_handler.environment()) {
				Ok(cg_controller) => {
					cg_controller.start();
					cgroup_mount_path = cg_controller.get_mount_path();
					is_cgroup_v2 = cg_controller.is_v2();
					cgroups_controller = Some(cg_controller);
				},
				Err(e) => {
					warn!("initialize cgroups controller failed: {}, resource utilization will be checked regularly to prevent resource usage from exceeding the limit.", e);
					exception_handler.set(Exception::CgroupsConfigError);
				},
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
			},
		};

		// 初始化资源监控器，定期采集资源使用情况
		let monitor = Monitor::new(
			stats_collector.clone(),
			log_dir.to_string(),
			config_handler.environment(),
		)?;
		monitor.start();

		// 注册主机指标采集器
		// 通过 stats_collector 统一管理，自动适配:
		// - Standalone 模式: 写入本地文件
		// - Managed 模式: 发送至远端服务器
		{
			use crate::metric::host_metric::*;
			stats_collector.register_countable(
				&stats::NoTagModule("host_cpu"),
				stats::Countable::Owned(Box::new(CpuMetricCollector::new())),
			);
			stats_collector.register_countable(
				&stats::NoTagModule("host_memory"),
				stats::Countable::Owned(Box::new(MemoryMetricCollector::new())),
			);
			stats_collector.register_countable(
				&stats::NoTagModule("host_disk"),
				stats::Countable::Owned(Box::new(DiskMetricCollector::new())),
			);
			stats_collector.register_countable(
				&stats::NoTagModule("host_network"),
				stats::Countable::Owned(Box::new(NetworkMetricCollector::new())),
			);
		}

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
		if matches!(config_handler.static_config.agent_mode, RunningMode::Managed) {
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
			// Agent 的状态机制：
			// 1. 状态由 AgentState 维护 (Running, Disabled, Terminated)。
			// 2. 使用 Condvar (notifier) 挂起线程，等待状态变更或配置更新通知。
			state_guard = state.notifier.wait(state_guard).unwrap();
			match State::from(state_guard.0) {
				// CASE 1: 状态为 Running 且 无新配置
				// 场景：Agent 从 Disabled 恢复为 Running，或收到无需更新配置的信号。
				State::Running if state_guard.1.is_none() => {
					// 操作：启动/恢复所有组件运行
					mem::drop(state_guard);
					#[cfg(target_os = "linux")]
					// 根据配置启动或停止 K8s API 监听器
					if config_handler.candidate_config.platform.kubernetes_api_enabled {
						api_watcher.start();
					} else {
						api_watcher.stop();
					}
					if let Some(ref mut c) = components {
						c.start();
					}
					continue;
				},
				// CASE 2: 状态为 Disabled
				// 场景：用户主动禁用 Agent，或触发熔断机制 (Circuit Breaker)。
				State::Disabled => {
					// 操作：停止所有组件运行
					// 即使是 Disabled 状态，也需要检查是否有新的配置下发（例如用户更新配置以解除熔断）。
					let new_config = state_guard.1.take();
					mem::drop(state_guard);
					if let Some(ref mut c) = components {
						c.stop();
					}
					// 如果有新配置，即使在 Disabled 状态下也要处理（更新 ConfigHandler，但不启动组件）
					if let Some(cfg) = new_config {
						let agent_id = synchronizer.agent_id.read().clone();
						// 生成配置回调
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
						if config_handler.candidate_config.platform.kubernetes_api_enabled {
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
							// 启动资源守卫 (Guard)，确保即使 Disabled 也能监控资源
							guard.start();
							config_initialized = true;
						}
					}
					continue;
				},
				_ => (),
			}

			// 流程到达此处意味着：状态为 Running 且 有新配置 (state_guard.1 is Some)
			// 获取变更的配置数据 (UserConfig, Blacklist, VM MACs, etc.)
			let ChangedConfig {
				user_config,
				blacklist,
				vm_mac_addrs,
				gateway_vmac_addrs,
				tap_types,
			} = state_guard.1.take().unwrap();
			mem::drop(state_guard);

			// 处理配置更新
			let agent_id = synchronizer.agent_id.read().clone();
			match components.as_mut() {
				// CASE 3: 首次初始化 (Initial Run)
				// components 为 None，说明是首次启动或完全重置
				None => {
					// 1. 处理配置并获取回调
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
					if config_handler.candidate_config.platform.kubernetes_api_enabled {
						api_watcher.start();
					} else {
						api_watcher.stop();
					}

					// 2. 构造全新的 AgentComponents
					// 这里会初始化 Dispatcher (抓包), Collector (统计), PlatformSynchronizer 等核心组件
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

					// 3. 启动组件
					comp.start();

					if let Components::Agent(components) = &mut comp {
						// 如果是 Analyzer 模式，解析 TAP 类型
						if config_handler.candidate_config.dispatcher.capture_mode
							== PacketCaptureType::Analyzer
						{
							parse_tap_type(components, tap_types);
						}

						// 4. 执行配置回调
						for callback in callbacks {
							callback(&config_handler, components);
						}
					}

					components.replace(comp);
				},
				// CASE 4: 热更新 (Hot Update)
				// components 已存在，根据新配置进行更新
				Some(Components::Agent(components)) => {
					// 1. 处理配置更新 (组件已存在)
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
					if config_handler.candidate_config.platform.kubernetes_api_enabled {
						api_watcher.start();
					} else {
						api_watcher.stop();
					}

					// 2. 更新组件配置并重启/刷新
					components.config = config_handler.candidate_config.clone();
					components.start();

					// 3. 处理特定的运行时变更 (黑名单, VM MAC, TAP 类型等)
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

					// 4. 执行回调
					for callback in callbacks {
						callback(&config_handler, components);
					}

					// 5. 通知 Dispatcher 监听器
					for d in components.dispatcher_components.iter_mut() {
						d.dispatcher_listener
							.on_config_change(&config_handler.candidate_config.dispatcher);
					}
				},
				_ => {
					// 处理其他情况
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
					if config_handler.candidate_config.platform.kubernetes_api_enabled {
						api_watcher.start();
					} else {
						api_watcher.stop();
					}
				},
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
		},
		Ok(links) => {
			if links.is_empty() {
				warn!(
					"tap-interface-regex({}) do not match any interface in {:?}",
					conf.tap_interface_regex, netns,
				);
			}
			debug!("tap interfaces in namespace {:?}: {:?}", netns, links);
			links
		},
	}

	#[cfg(any(target_os = "windows", target_os = "android"))]
	match public::utils::net::links_by_name_regex(&conf.tap_interface_regex) {
		Err(e) => {
			warn!("get interfaces by name regex failed: {}", e);
			vec![]
		},
		Ok(links) => {
			if links.is_empty() {
				warn!(
					"tap-interface-regex({}) do not match any interface, in local mode",
					conf.tap_interface_regex
				);
			}
			debug!("tap interfaces: {:?}", links);
			links
		},
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
				d.dispatcher_listener.on_vm_change(&vm_mac_addrs, &gateway_vmac_addrs);
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
					},
					Err(e) => {
						warn!(
							"build dispatcher_component failed: {}, zerotrace-agent restart...",
							e
						);
						crate::utils::clean_and_exit(1);
					},
				}
			}
		},
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
				d.dispatcher_listener.on_vm_change(&vm_mac_addrs, &gateway_vmac_addrs);
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
					.is_empty() || conf.dpdk_source != DpdkSource::None)
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
			components.policy_setter.reset_queue_size(id + interfaces_to_build.len() + 1);
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
					},
					Err(e) => {
						warn!(
							"build dispatcher_component failed: {}, zerotrace-agent restart...",
							e
						);
						crate::utils::clean_and_exit(1);
					},
				}
			}
			components.last_dispatcher_component_id = id;
			components.tap_interfaces = current_interfaces;
		},

		_ => {},
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

		info!("Resolve controller domain name {} {}", domain_names[0], ips[0]);

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
							let (ctrl_ip, ctrl_mac) =
								match get_ctrl_ip_and_mac(&ips[0].parse().unwrap()) {
									Ok(tuple) => tuple,
									Err(e) => {
										warn!("get ctrl ip and mac failed with error: {}, zerotrace-agent restart...", e);
										crate::utils::clean_and_exit(1);
										continue;
									},
								};
							info!(
								"use K8S_NODE_IP_FOR_ZEROTRACE env ip as destination_ip({})",
								ctrl_ip
							);
							#[cfg(target_os = "linux")]
							let ipmac = if sidecar_mode {
								IpMacPair::from((ctrl_ip.clone(), ctrl_mac))
							} else {
								// use host ip/mac as agent id if not in sidecar mode
								if let Err(e) = netns::NsFile::Root.open_and_setns() {
									warn!("agent must have CAP_SYS_ADMIN to run without 'hostNetwork: true'.");
									warn!("setns error: {}, zerotrace-agent restart...", e);
									crate::utils::clean_and_exit(1);
									continue;
								}
								let (ip, mac) = match get_ctrl_ip_and_mac(&ips[0].parse().unwrap())
								{
									Ok(tuple) => tuple,
									Err(e) => {
										warn!("get ctrl ip and mac failed with error: {}, zerotrace-agent restart...", e);
										crate::utils::clean_and_exit(1);
										continue;
									},
								};
								if let Err(e) = netns::reset_netns() {
									warn!("reset setns error: {}, zerotrace-agent restart...", e);
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
		self.handler_builders.write().unwrap().iter_mut().for_each(|y| {
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
		self.handler_builders.write().unwrap().iter_mut().for_each(|y| {
			y.stop();
		});
	}
}

// Agent 的主要组件集合，包含所有的核心功能模块
pub struct AgentComponents {
	pub config: ModuleConfig,
	pub rx_leaky_bucket: Arc<LeakyBucket>,   // 接收端漏桶限流器
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
	pub debugger: Debugger,                  // 调试器
	#[cfg(all(unix, feature = "libtrace"))]
	pub ebpf_dispatcher_component: Option<EbpfDispatcherComponent>, // eBPF 分发器组件
	pub running: AtomicBool,                 // 运行状态标志
	pub stats_collector: Arc<stats::Collector>, // 统计数据收集器
	pub metrics_server_component: MetricsServerComponent, // 外部指标服务组件
	pub otel_uniform_sender: UniformSenderThread<OpenTelemetry>, // OpenTelemetry 数据发送线程
	pub prometheus_uniform_sender: UniformSenderThread<BoxedPrometheusExtra>, // Prometheus 数据发送线程
	pub telegraf_uniform_sender: UniformSenderThread<TelegrafMetric>,         // Telegraf 数据发送线程
	pub profile_uniform_sender: UniformSenderThread<Profile>,                 // 性能剖析数据发送线程
	pub packet_sequence_uniform_output: DebugSender<BoxedPacketSequenceBlock>, // Enterprise Edition Feature: packet-sequence // 包序列数据调试发送端
	pub packet_sequence_uniform_sender: UniformSenderThread<BoxedPacketSequenceBlock>, // Enterprise Edition Feature: packet-sequence // 包序列数据发送线程
	#[cfg(feature = "libtrace")]
	pub proc_event_uniform_sender: UniformSenderThread<crate::common::proc_event::BoxedProcEvents>, // 进程事件发送线程
	pub application_log_uniform_sender: UniformSenderThread<ApplicationLog>, // 应用日志发送线程
	#[cfg(feature = "enterprise-integration")]
	pub skywalking_uniform_sender: UniformSenderThread<SkyWalkingExtra>, // SkyWalking 数据发送线程
	pub datadog_uniform_sender: UniformSenderThread<Datadog>,                // Datadog 数据发送线程
	pub exception_handler: ExceptionHandler,                                 // 异常处理器
	pub proto_log_sender: DebugSender<BoxAppProtoLogsData>,                  // 协议日志调试发送端
	pub pcap_batch_sender: DebugSender<BoxedPcapBatch>,                      // PCAP 数据包调试发送端
	pub toa_info_sender: DebugSender<Box<(SocketAddr, SocketAddr)>>,         // TOA 信息调试发送端
	pub l4_flow_aggr_sender: DebugSender<BoxedTaggedFlow>,                   // L4 流聚合数据调试发送端
	pub metrics_sender: DebugSender<BoxedDocument>,                          // 指标数据调试发送端
	pub npb_bps_limit: Arc<LeakyBucket>, // NPB (Network Packet Broker) 带宽限制漏桶
	pub compressed_otel_uniform_sender: UniformSenderThread<OpenTelemetryCompressed>, // 压缩后的 OpenTelemetry 数据发送线程
	pub pcap_batch_uniform_sender: UniformSenderThread<BoxedPcapBatch>, // PCAP 数据包发送线程
	pub policy_setter: PolicySetter,                                    // 策略设置器
	pub policy_getter: PolicyGetter,                                    // 策略获取器
	pub npb_bandwidth_watcher: Box<Arc<NpbBandwidthWatcher>>,           // NPB 带宽监控器
	pub npb_arp_table: Arc<NpbArpTable>,                                // NPB ARP 表
	#[cfg(feature = "enterprise-integration")]
	pub vector_component: VectorComponent, // Vector 组件集成
	pub is_ce_version: bool, // Determine whether the current version is a ce version, CE-AGENT always set pcap-assembler disabled // 是否为社区版
	pub tap_interfaces: Vec<Link>, // 采集的网卡接口列表
	pub bpf_options: Arc<Mutex<BpfOptions>>, // BPF 选项
	pub last_dispatcher_component_id: usize, // 最后一个分发器组件 ID
	#[cfg(any(target_os = "linux", target_os = "android"))]
	pub process_listener: Arc<ProcessListener>, // 进程监听器
	max_memory: u64,         // 最大内存限制
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
		config.processors.flow_log.time_window.max_tolerable_packet_delay.as_secs()
			+ TIME_UNIT.as_secs()
			+ config.processors.flow_log.conntrack.flow_flush_interval.as_secs()
			+ COMMON_DELAY
			+ config.processors.flow_log.time_window.extra_tolerable_flow_delay.as_secs()
			+ config.processors.flow_log.conntrack.flow_flush_interval.as_secs() // The flow_map may send data to qg ahead of time due to the output_buffer exceeding its limit. This can result in the time_window of qg being advanced prematurely, with the maximum advancement time being the flush_interval.
	}

	// 创建新的 Collector 线程，负责 L4 流日志的聚合和指标生成
	//
	// Collector 是 ZeroTrace Agent 的数据汇聚中心。
	// 它接收来自各个 Dispatcher 的原始流 (TaggedFlow)，进行二次聚合、指标计算和格式化，最终生成 Document 发送给 Server。
	//
	// 组件流程:
	// 1. FlowAggrThread (可选): "秒级转分级"。将高频的秒级流日志聚合成低频的分钟级流日志，大幅降低长期存储成本。
	// 2. QuadrupleGeneratorThread**: 核心引擎。维护流表 (Flow Map)，计算吞吐、延迟、异常等指标。
	//    它基于 "Event Time" (事件时间) 而非 "Processing Time" (处理时间) 工作，因此需要复杂的乱序处理机制。
	// 3. Collector (Second/Minute): 最终的指标导出器。将计算好的指标打包成 Document (Protobuf/Json) 发送。
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

		// 容忍延迟 (Tolerable Delay):
		// 分布式系统中，数据到达往往是乱序的。QuadrupleGenerator 使用 "Watermark" (水位) 机制来关闭时间窗口。
		// `flowgen_tolerable_delay` 定义了愿意等待多久之前的“迟到数据”。
		// 超过这个延迟的数据将被丢弃或统计到当前窗口 (取决于策略)，以保证指标的实时性。
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
				config.processors.flow_log.tunning.flow_aggregator_queue_size,
				"2-second-flow-to-minute-aggrer",
				queue_debugger,
			);
			l4_log_sender_outer = Some(l4_log_sender);
			stats_collector.register_countable(
				&QueueStats { id, module: "2-second-flow-to-minute-aggrer" },
				Countable::Owned(Box::new(counter)),
			);
			// 启动 FlowAggrThread (流聚合线程)
			// 负责将 60 个 1秒的流记录合并成 1 个 60秒的流记录
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
			config.processors.flow_log.tunning.quadruple_generator_queue_size,
			"2-flow-with-meter-to-second-collector",
			queue_debugger,
		);
		stats_collector.register_countable(
			&QueueStats { id, module: "2-flow-with-meter-to-second-collector" },
			Countable::Owned(Box::new(counter)),
		);
		// 创建分钟级 Flow -> Collector 队列
		let (minute_sender, minute_receiver, counter) = queue::bounded_with_debug(
			config.processors.flow_log.tunning.quadruple_generator_queue_size,
			"2-flow-with-meter-to-minute-collector",
			queue_debugger,
		);
		stats_collector.register_countable(
			&QueueStats { id, module: "2-flow-with-meter-to-minute-collector" },
			Countable::Owned(Box::new(counter)),
		);

		// 启动 QuadrupleGeneratorThread (四元组生成器线程)
		// Quadruple: 指 (FlowID, Metrics, Tag, Timestamp) 的组合。
		// 这个组件维护了活跃流的状态机，并在时间窗口关闭时产出统计数据。
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
			// 负责收集高精度的秒级监控指标 (通常用于实时大屏和告警)
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
			// 负责收集分钟级监控指标 (通常用于长期趋势分析和报表)
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
	//
	// 处理应用层 (Layer 7) 的性能指标数据 (L7Stats)。
	// 不同于 L4 流日志，L7 指标关注的是具体的应用请求 (Request/Response) 质量，如 HTTP 响应时间、DNS 解析延迟、SQL 错误率等。
	//
	// 1. Producer: Dispatcher 或 EbpfCollector 解析出应用协议，生成 `L7Stats` 对象。
	// 2. L7QuadrupleGenerator: 为 L7Stats 匹配或生成 FlowID (四元组标识)，使其能与 L4 流关联。
	// 3. L7Collector: 将处理好的指标聚合为 Document，发送给 Server。
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
		// 传输高精度的秒级应用性能指标。
		let (l7_second_sender, l7_second_receiver, counter) = queue::bounded_with_debug(
			user_config.processors.flow_log.tunning.quadruple_generator_queue_size,
			"2-flow-with-meter-to-l7-second-collector",
			queue_debugger,
		);
		stats_collector.register_countable(
			&QueueStats { id, module: "2-flow-with-meter-to-l7-second-collector" },
			Countable::Owned(Box::new(counter)),
		);
		// 创建 L7 分钟级 Stats -> Collector 队列
		// 传输分钟级聚合指标，用于长期趋势展示。
		let (l7_minute_sender, l7_minute_receiver, counter) = queue::bounded_with_debug(
			user_config.processors.flow_log.tunning.quadruple_generator_queue_size,
			"2-flow-with-meter-to-l7-minute-collector",
			queue_debugger,
		);
		stats_collector.register_countable(
			&QueueStats { id, module: "2-flow-with-meter-to-l7-minute-collector" },
			Countable::Owned(Box::new(counter)),
		);

		// 延迟容忍:
		// L7 数据的聚合同样受乱序影响。特别是 TCP 重传或分片可能导致 Response 晚于预期到达。
		// 这里沿用 FlowGenerator 的延迟配置，确保 L7 指标的窗口关闭时间与 L4 保持一致，方便对齐分析。
		let second_quadruple_tolerable_delay = Self::get_flowgen_tolerable_delay(user_config);
		// minute QG window is also pushed forward by flow stat time,
		// therefore its delay should be 60 + second delay (including extra flow delay)
		// 分钟级 QG 窗口也会因流统计时间而被向前推送，
		// 因此其延迟应为 60 + 秒级延迟 (包括额外的流延迟)
		let minute_quadruple_tolerable_delay = 60 + second_quadruple_tolerable_delay;

		// 启动 L7 QuadrupleGeneratorThread
		// L7 指标生成器。
		// 不仅转发指标，更重要的是维护 `L7Stats <-> Flow` 的映射。
		// 这样 Server 端在展示 HTTP 请求慢时，可以联动展示底层的 TCP 传输质量 (如 RTT、Retrans)，实现跨层关联分析。
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
	// 该方法负责初始化 Agent 的所有核心组件。涉及环境自检、网络探测、策略加载、各子模块初始化以及数据管道的搭建。
	//
	// 设计:
	// 1. Fail-Fast: 在启动早期检查关键依赖 (如控制器连接、磁盘空间)，有问题立即报错，避免僵尸状态。
	// 2. 自适应: 自动探测运行环境 (K8s, Linux, Windows, Android) 和网络拓扑 (CNI, 网卡, 命名空间)。
	// 3. 资源保护: 通过 LeakyBucket 和内存限制，防止 Agent 抢占业务进程资源。
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
		let process_threshold = config_handler.candidate_config.environment.process_threshold;
		let feature_flags = FeatureFlags::from(&user_config.dev.feature_flags);

		// 如果配置了 tap_interface_regex，则不应再使用 src_interfaces (已废弃)
		if !user_config.inputs.cbpf.af_packet.src_interfaces.is_empty()
			&& user_config.inputs.cbpf.special_network.dpdk.source == DpdkSource::None
		{
			warn!("src_interfaces is not empty, but this has already been deprecated, instead, the tap_interface_regex should be set");
		}

		info!("Start check process...");
		// 1. 环境自检：系统进程数检查
		// Linux 系统对全局 PID 数量和文件描述符有限制。
		// 如果当前系统负载过高 (进程数超标)，Agent 启动可能会失败或加剧系统不稳定性。
		// 这里进行检查可以提前预警或拒绝启动。
		trident_process_check(process_threshold);
		#[cfg(any(target_os = "linux", target_os = "android"))]
		if !user_config.global.alerts.check_core_file_disabled {
			info!("Start check core file...");
			// 2. 环境自检：Core Dump 文件检查
			// Agent 是 C/Rust 编写的系统级程序，可能会因内存错误等发生崩溃。
			// 检查是否有遗留的 core 文件，如果有，通常意味着之前发生过严重崩溃。
			// 此时可以触发报警，提示管理员进行排查。
			core_file_check();
		}
		info!("Start check controller ip...");
		// 3. 环境自检：控制器IP协议一致性检查
		// 验证配置的控制器IP是否统一为 IPv4 或 IPv6 (不支持混合模式)
		controller_ip_check(&static_config.controller_ips);
		info!("Start check free space...");
		// 4. 环境自检：磁盘空间检查
		// 防止 Agent 填满磁盘导致系统故障 (No space left on device)。
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
		// 5. 网络接口探测：额外命名空间扫描
		// 在 Kubernetes 环境中，不同的 CNI 插件 (如 Calico, Flannel, Cilium) 管理网络的方式不同。
		// 有些 CNI 会将网卡创建在特定的 Network Namespace 中，而不是宿主机的 Root Namespace。
		// `extra_netns_regex` 允许 Agent 主动扫描 `/var/run/netns` 下匹配特定正则的命名空间。
		// 这样 Agent 就能“进入”这些隔离的网络环境，抓取其中的流量，实现对容器网络的无死角监控。
		if candidate_config.dispatcher.extra_netns_regex != "" {
			// 限制：仅支持 Local 捕获模式。因为 Mirror/Analyzer 模式通常是物理层面的端口镜像，不涉及主机内的命名空间切换。
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
		// 6. 网络接口探测：计算 Fanout 数量
		// AF_PACKET 是 Linux 提供的原始抓包套接字。Fanout 机制允许将同一个网口的流量负载均衡到多个 Socket (即多个 Agent 线程) 上。
		let mut packet_fanout_count = if candidate_config.dispatcher.extra_netns_regex == "" {
			// 情况 A: 普通模式 (Host Network)
			// 未启用额外命名空间扫描，说明只监听宿主机的网络接口。
			// 此时使用用户配置文件中设定的 `packet_fanout_count` (例如 4 或 8)，启用多队列并行抓包以提升吞吐量。
			user_config.inputs.cbpf.af_packet.tunning.packet_fanout_count
		} else {
			// 情况 B: 跨命名空间模式 (Container Network)
			// 需扫描其他命名空间 (如 Pod 网卡)。强制将 Fanout 设置为 1 (单线程)。
			// 目的: 避免在成百上千个容器接口上创建多倍的 Socket，防止文件描述符 (FD) 和内存耗尽。
			1
		};
		#[cfg(any(target_os = "windows", target_os = "android"))]
		// Windows/Android 不支持 Linux 的 AF_PACKET Fanout 机制，固定使用单线程。
		let packet_fanout_count = 1;

		// 7. 网络接口探测：获取根命名空间接口
		// 这是最常用的场景，监听宿主机 (Host Network) 的物理网卡或虚拟网卡 (如 eth0, bond0)。
		let links = get_listener_links(
			&candidate_config.dispatcher,
			#[cfg(target_os = "linux")]
			&netns::NsFile::Root,
		);
		// 逻辑：如果没有在其他 Namespace 找到接口，且允许捕获内部接口（lo），或者找到了接口
		if interfaces_and_ns.is_empty()
			&& (!links.is_empty() || candidate_config.dispatcher.inner_interface_capture_enabled)
		{
			if packet_fanout_count > 1 || candidate_config.capture_mode == PacketCaptureType::Local
			{
				// 如果开启 fanout 或本地模式，为每个 fanout 实例创建配置
				// 这意味着同一个接口会被推入 vector 多次，后续会启动多个 Dispatcher 线程来处理它
				for _ in 0..packet_fanout_count {
					#[cfg(target_os = "linux")]
					interfaces_and_ns.push((links.clone(), netns::NsFile::Root));
					#[cfg(any(target_os = "windows", target_os = "android"))]
					interfaces_and_ns.push(links.clone());
				}
			} else {
				// 否则为每个接口单独创建配置 (通常用于 Analyzer 模式，避免重复处理)
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
			// 在 NFV (网络功能虚拟化) 或高性能网关场景，流量可能不经过内核协议栈，而是通过 DPDK 或共享内存传输。
			// 适配这些特殊的数据源，它们不需要常规的 AF_PACKET 抓包。
			if !user_config.inputs.cbpf.special_network.vhost_user.vhost_socket_path.is_empty()
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
				// 分析器模式: Agent 作为专用的流量分析探针部署。
				// 这种模式下，Agent 通常接收来自交换机镜像的流量。
				// 需要确保内核版本支持所需的 BPF 特性，并且配置的 TAP 接口真实存在。
				kernel_check();
				if candidate_config.user_config.inputs.cbpf.special_network.dpdk.source
					== DpdkSource::None
				{
					info!("Start check tap interface...");
					// 检查 TAP 接口 (Traffic Access Point，即接收镜像流量的物理网卡)
					//
					// 1. 确认网卡存在。
					// 2. 检查网卡特性 (Offload Features)。
					//    特别是 `rx-vlan-offload`。如果网卡硬件自动剥离了 VLAN Tag，
					//    Agent 通过 AF_PACKET 抓到的包就会丢失 VLAN 信息，导致网络隔离识别错误。
					//    此检查会发出警告，提示管理员关闭网卡的 VLAN 卸载功能。
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
			},
			_ => {
				// NPF服务检查 (Windows) 或 镜像模式检查
				// TODO: npf (only on windows)
				if candidate_config.capture_mode == PacketCaptureType::Mirror {
					info!("Start check kernel...");
					kernel_check();
				}
			},
		}

		info!("Agent run with feature-flags: {:?}.", feature_flags);
		// Currently, only loca-mode + ebpf collector is supported, and ebpf collector is not
		// applicable to fastpath, so the number of queues is 1
		// =================================================================================
		// 目前仅支持local-mode + ebpf-collector，ebpf-collector不适用fastpath, 所以队列数为1
		// 8. 策略模块 (Policy) 初始化
		// Agent 需要判断每条流 (Flow) 是否应该被采集、是否命中 ACL (访问控制列表)、以及如何打标签 (Tagging)。
		// FastPath: 为了性能，Policy 模块维护了一个“快表”。
		// 当首个包经过慢速查找 (First Path) 确定策略后，会建立快表项。后续该流的数据包直接查快表，极大降低 CPU 开销。
		let (policy_setter, policy_getter) = Policy::new(
			1.max(if candidate_config.capture_mode != PacketCaptureType::Local {
				interfaces_and_ns.len()
			} else {
				1
			}),
			user_config.processors.packet.policy.max_first_path_level,
			user_config.get_fast_path_map_size(candidate_config.dispatcher.max_memory),
			user_config.processors.packet.policy.forward_table_capacity,
			user_config.processors.packet.policy.fast_path_disabled,
			candidate_config.capture_mode == PacketCaptureType::Analyzer,
		);
		// 注册 ACL 监听器，当 ACL 配置更新时通知 Policy 模块
		synchronizer.add_flow_acl_listener(Box::new(policy_setter));
		policy_setter.set_memory_limit(max_memory);

		// TODO: collector enabled
		// TODO: packet handler builders

		#[cfg(target_os = "linux")]
		// sidecar poller is created before agent start to provide pod interface info for server
		// 9. 平台同步模块 (Platform Synchronizer) 初始化
		// Agent 需要知道“我现在的 IP 对应 K8s 里的哪个 Pod”。
		// 通过调用 Kubernetes API (或轮询)，获取 Pod 的 IP、MAC 和接口信息。
		// 这对于将网络层的 IP/MAC 地址还原为应用层的 Pod Name/Service Name 至关重要 (即“云原生上下文增强”)。
		let kubernetes_poller = sidecar_poller.unwrap_or_else(|| {
			let poller = Arc::new(GenericPoller::new(
				config_handler.platform(),
				config_handler.candidate_config.dispatcher.extra_netns_regex.clone(),
			));
			platform_synchronizer.set_kubernetes_poller(poller.clone());
			poller
		});

		// 初始化调试器上下文
		// 提供一个轻量级的内部状态观测接口 (通常是 UDP 端口)。
		// 允许开发和运维人员实时查看队列深度、内存使用、策略命中情况等，而无需 attach gdb 或重启。
		//
		// ConstructDebugCtx: 调试上下文结构体
		// 它的作用是将 Agent 核心组件的句柄 (Handle) 注入到 Debugger 模块中。
		// 这样 Debugger 就能在运行时读取这些组件的状态 (例如：当前的 K8s 资源、与 Server 的连接状态、策略表内容等)。
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
			policy_setter, // 允许 Debugger 动态查看或调整策略
		};
		// 启动 Debugger 服务 (默认监听 UDP 30033)
		// 响应 zerotrace-ctl 的调试命令
		let debugger = Debugger::new(context);

		// 创建 QueueDebugger
		// 这是一个专门用于监控内部队列健康状况的组件。
		// 它会被传递给所有的 bounded_with_debug 队列，用于统计队列的 长度、丢包数 等关键指标。
		let queue_debugger = debugger.clone_queue();

		#[cfg(any(target_os = "linux", target_os = "android"))]
		// 10. 进程监听器 (Process Listener) 初始化
		// 网络流量本身只有 IP 和端口信息。运维人员更关心是“哪个进程”或“哪个容器”在通信。
		// 监听操作系统 (Netlink/Procfs) 的进程启动和退出事件。
		// 维护 `(IP, Port) <-> PID/ProcessName/ContainerID` 的动态映射表。
		// 这是 ZeroTrace "应用感知" 能力的核心。
		let process_listener = Arc::new(ProcessListener::new(
			// 进程黑名单: 忽略不需要监控的进程 (减少噪音和资源消耗)
			&candidate_config.user_config.inputs.proc.process_blacklist,
			// 进程匹配器: 定义哪些进程是"感兴趣"的 (只有匹配的进程才会上报详细信息)
			&candidate_config.user_config.inputs.proc.process_matcher,
			// Procfs 路径:
			// 在容器环境下，Agent 需要读取宿主机的 /proc 信息。
			// 通常会将宿主机的 /proc 挂载到容器内的 /host/proc (或其他路径)，通过配置指定。
			candidate_config.user_config.inputs.proc.proc_dir_path.clone(),
			// 标签提取配置 (Tag Extraction):
			// 允许配置外部脚本或命令，Agent 在发现新进程时执行该脚本，
			// 提取自定义的业务标签 (如 env=prod, app=payment) 并附加到流日志中。
			candidate_config.user_config.inputs.proc.tag_extraction.exec_username.clone(),
			candidate_config.user_config.inputs.proc.tag_extraction.script_command.clone(),
		));
		#[cfg(any(target_os = "linux", target_os = "android"))]
		if candidate_config.user_config.inputs.proc.enabled {
			platform_synchronizer.set_process_listener(&process_listener);
		}

		#[cfg(any(target_os = "linux", target_os = "android"))]
		// 创建 TOA (TCP Option Address) 信息队列
		// 在 L4 负载均衡 (LB) 场景下，服务端看到的源 IP 往往是 LB 的 VIP 或 SNAT IP，而非真实客户端 IP。
		// TOA 是一种利用 TCP Option 字段携带真实源 IP 的技术。
		// SocketSynchronizer 读取这些信息，还原真实的访问来源。
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
		// 11. Socket 同步器 (Socket Synchronizer) 初始化
		// 结合 ProcessListener 采集的进程信息和 TOA 信息。
		// 为每条 Socket 连接补充丰富的上下文 (Context)，使得后续生成的流日志 (Flow Log) 能够包含
		// 准确的客户端 IP 和服务端进程信息。
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

		// 初始化全局接收端漏桶 (RX Leaky Bucket)
		// 全局流控。
		// 即使有多个网卡和多个 Dispatcher，Agent 总体处理的数据包速率 (PPS) 不应超过此阈值，
		// 以防止在流量洪峰时耗尽 CPU，影响宿主机上的其他业务。
		let rx_leaky_bucket = Arc::new(LeakyBucket::new(match candidate_config.capture_mode {
			PacketCaptureType::Analyzer => None,
			_ => Some(config_handler.candidate_config.dispatcher.global_pps_threshold),
		}));

		let tap_typer = Arc::new(CaptureNetworkTyper::new());

		// TODO: collector enabled
		let mut dispatcher_components = vec![];

		// 12. 数据发送模块 (Senders) 初始化
		// Agent 产生多种类型的数据，它们的特征截然不同：
		// - L4 Flow Log: 数据量大，对延迟敏感，允许少量丢弃。
		// - Metrics: 数据量小，精度要求高，不能丢弃。
		// - L7 Logs: 数据量极大 (取决于采样率)，突发性强。
		// 因此，为每种数据类型创建独立的 `Queue` (缓冲) 和 `UniformSenderThread` (发送线程)，
		// 避免海量日志阻塞了关键指标的发送。
		info!(
			"static analyzer ip: '{}' actual analyzer ip '{}'",
			user_config.global.communication.ingester_ip, candidate_config.sender.dest_ip
		);
		// (1) L4 流日志 (Flow Log) 发送器
		// 负责发送聚合后的 TCP/UDP 会话摘要 (5-tuple, packet count, byte count, duration)。
		let l4_flow_aggr_queue_name = "3-flowlog-to-collector-sender";
		let (l4_flow_aggr_sender, l4_flow_aggr_receiver, counter) = queue::bounded_with_debug(
			user_config.processors.flow_log.tunning.flow_generator_queue_size,
			l4_flow_aggr_queue_name,
			&queue_debugger,
		);
		stats_collector.register_countable(
			&QueueStats { module: l4_flow_aggr_queue_name, ..Default::default() },
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

		// (2) 监控指标 (Metrics) 发送器
		// 负责发送高精度的时序数据，包括 Agent 自身监控 (Self-monitoring) 和 业务网络指标 (FPS, RTT, Retrans, ZeroWindow)。
		let metrics_queue_name = "3-doc-to-collector-sender";
		let (metrics_sender, metrics_receiver, counter) = queue::bounded_with_debug(
			user_config.outputs.flow_metrics.tunning.sender_queue_size,
			metrics_queue_name,
			&queue_debugger,
		);
		stats_collector.register_countable(
			&QueueStats { module: metrics_queue_name, ..Default::default() },
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

		// (3) L7 协议日志 (Proto Log) 发送器
		// 负责发送应用层协议的请求/响应详情 (如 HTTP Method, URL, Status Code, DNS Query, SQL Query)。
		// 这一层的数据量通常最大。
		let proto_log_queue_name = "2-protolog-to-collector-sender";
		let (proto_log_sender, proto_log_receiver, counter) = queue::bounded_with_debug(
			user_config.outputs.flow_log.tunning.collector_queue_size,
			proto_log_queue_name,
			&queue_debugger,
		);
		stats_collector.register_countable(
			&QueueStats { module: proto_log_queue_name, ..Default::default() },
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

		// 解析 Analyzer IP (Ingester IP)
		// Agent 采集的数据发给专门的数据节点 (Ingester)。
		// Controller 负责下发 Ingester 的地址列表。
		let analyzer_ip = if candidate_config.dispatcher.analyzer_ip.parse::<IpAddr>().is_ok() {
			candidate_config.dispatcher.analyzer_ip.parse::<IpAddr>().unwrap()
		} else {
			let ips = lookup_host(&candidate_config.dispatcher.analyzer_ip)?;
			ips[0]
		};

		// 获取路由源 IP (Source IP)
		// 当 Agent 需要封装发送数据包 (如发送到 VXLAN 隧道) 时，需要知道使用本机哪个网口的 IP 作为外层源 IP。
		// 这里通过查询路由表来自动确定。
		let source_ip = match get_route_src_ip(&analyzer_ip) {
			Ok(ip) => ip,
			Err(e) => {
				warn!("get route to '{}' failed: {:?}", &analyzer_ip, e);
				if ctrl_ip.is_ipv6() {
					Ipv6Addr::UNSPECIFIED.into()
				} else {
					Ipv4Addr::UNSPECIFIED.into()
				}
			},
		};

		// NPB (Network Packet Broker) 配置
		// NPB 功能允许 ZeroTrace 将采集到的流量分发给第三方安全或分析工具。
		// 限制分发流量的带宽，防止 Agent 占满网络出口带宽。
		let npb_bps_limit = Arc::new(LeakyBucket::new(Some(
			config_handler.candidate_config.sender.npb_bps_threshold,
		)));
		let npb_arp_table = Arc::new(NpbArpTable::new(
			config_handler.candidate_config.npb.socket_type == SocketType::RawUdp,
			exception_handler.clone(),
		));

		// (4) PCAP 数据包发送器
		// **背景**: ZeroTrace 支持“按需留存” (On-Demand Capture)。
		// 当发生特定事件或通过策略配置时，Agent 会将原始数据包 (PCAP) 捕获并上传。
		let pcap_batch_queue = "2-pcap-batch-to-sender";
		let (pcap_batch_sender, pcap_batch_receiver, pcap_batch_counter) =
			queue::bounded_with_debug(
				user_config.processors.packet.pcap_stream.sender_queue_size,
				pcap_batch_queue,
				&queue_debugger,
			);
		// 注册队列监控指标
		// 允许通过 ZeroTrace 自身的监控面板查看该队列的积压情况和丢包率
		stats_collector.register_countable(
			&QueueStats { module: pcap_batch_queue, ..Default::default() },
			Countable::Owned(Box::new(pcap_batch_counter)),
		);

		// 创建共享连接对象
		// PCAP 数据通常体量较大，可能会使用独立的 TCP 连接或复用现有连接
		let pcap_packet_shared_connection = Arc::new(Mutex::new(Connection::new()));

		let pcap_batch_uniform_sender = UniformSenderThread::new(
			pcap_batch_queue,
			Arc::new(pcap_batch_receiver),
			config_handler.sender(),
			stats_collector.clone(),
			exception_handler.clone(),
			Some(pcap_packet_shared_connection.clone()),
			// 根据配置决定是否启用 Zstd 压缩
			// 压缩虽然消耗 CPU，但能显著减少带宽占用，对于传输大量 PCAP 包非常有价值
			if user_config.outputs.compression.pcap {
				SenderEncoder::Zstd
			} else {
				SenderEncoder::Raw
			},
			sender_leaky_bucket.clone(),
		);
		// Enterprise Edition Feature: packet-sequence
		// (5) TCP 时序数据发送器 (企业版功能)
		// 用于精细化分析 TCP 握手、重传、拥塞窗口等详细过程。
		let packet_sequence_queue_name = "2-packet-sequence-block-to-sender";
		let (packet_sequence_uniform_output, packet_sequence_uniform_input, counter) =
			queue::bounded_with_debug(
				user_config.processors.packet.tcp_header.sender_queue_size,
				packet_sequence_queue_name,
				&queue_debugger,
			);

		stats_collector.register_countable(
			&QueueStats { module: packet_sequence_queue_name, ..Default::default() },
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

		// 13. Dispatcher 构建准备
		// 1. 防止环路: Agent 自身上传数据也会产生网络流量。如果不加过滤，Agent 会抓到自己发的包，
		//    导致数据量指数级爆炸，最终撑爆 CPU 和带宽。因此必须过滤掉与 Controller、Analyzer 通信的端口。
		// 2. 性能优化: 过滤掉用户明确不关心的流量 (如 SSH, 监控端口)，减少内核到用户态的数据拷贝。
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
		// 生成 BPF 语法字符串 (类似 tcpdump 的过滤表达式)
		// 例如: "not (tcp port 30035 or tcp port 20035)"
		let bpf_syntax_str = bpf_builder.build_pcap_syntax_to_str();
		#[cfg(any(target_os = "linux", target_os = "android"))]
		// 编译 BPF 指令
		// 1. 构建: `bpf_builder` 生成一系列 `BpfSyntax` (ZeroTrace 定义的 BPF 指令枚举)。
		// 2. 转换: 这些指令随后会被转换成 `RawInstruction` (对应 Linux 内核的 `struct sock_filter`)。
		//    即: OpCode (操作码), JT (跳真偏移), JF (跳假偏移), K (立即数)。
		// 3. 应用: 最终在 Dispatcher 线程中，通过 `setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog)` 系统调用，
		//    将这段字节码注入到内核。内核会在网卡收包的早期阶段执行这段代码，决定丢弃还是保留数据包。
		let bpf_syntax = bpf_builder.build_pcap_syntax();

		// BpfOptions: 封装最终的过滤规则
		// 包含了系统自动生成的规则 (bpf_syntax) 和用户在配置文件中填写的自定义规则 (capture_bpf)。
		// 这个对象会被传递给所有的 Dispatcher，在 Socket 初始化时通过 SO_ATTACH_FILTER 下发给内核。
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
		// 14. 创建 Dispatcher 组件 (核心循环)
		// ZeroTrace 采用 "Per-Queue Dispatcher" 模型。
		// 每一个 (网口, Namespace, QueueID) 组合对应一个 Dispatcher 实例。
		// Dispatcher 内部是一个死循环，不断从内核 Recv 包，经过 Pipeline 处理，最后 Send 到上述的队列中
		// - 无锁设计: 尽量让一个流的处理都在同一个线程内完成，减少锁竞争。
		// - 亲和性: 配合网卡 RSS (Receive Side Scaling)，实现 CPU 亲和性，提升缓存命中率。
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
					&stats::QueueStats { id: i, module: queue_name },
					Countable::Owned(Box::new(counter)),
				);
				dpdk_ebpf_senders.push(dpdk_ebpf_sender);
				Some(dpdk_ebpf_receiver)
			};
			#[cfg(all(unix, not(feature = "libtrace")))]
			let dpdk_ebpf_receiver = None;

			// 调用 build_dispatchers 创建具体的 Dispatcher 对象
			// 在循环中被调用，为每一个 (接口, 队列) 组合创建一个独立的 Dispatcher 实例。
			let dispatcher_component = build_dispatchers(
				i,     // Dispatcher ID (唯一标识)
				links, // 需要监听的网卡接口列表
				stats_collector.clone(),
				config_handler,
				queue_debugger.clone(),
				version_info.name != env!("AGENT_NAME"),
				synchronizer,
				npb_bps_limit.clone(),
				npb_arp_table.clone(),
				rx_leaky_bucket.clone(), // 全局接收限速器 (Leaky Bucket)
				policy_getter,
				exception_handler.clone(),
				bpf_options.clone(), // BPF 过滤规则 (SO_ATTACH_FILTER)
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
				netns, // 网络命名空间 (Namespace) 句柄
				#[cfg(target_os = "linux")]
				kubernetes_poller.clone(),
				#[cfg(target_os = "linux")]
				libvirt_xml_extractor.clone(),
				#[cfg(target_os = "linux")]
				dpdk_ebpf_receiver,
				#[cfg(target_os = "linux")]
				{
					// 决定是否启用 AF_PACKET Fanout
					// 如果配置的 Dispatcher 数量 > 1，则开启 Fanout (HASH 模式)，
					// 让内核根据五元组 Hash 将流量均衡分发给不同的 Dispatcher 线程。
					packet_fanout_count > 1
				},
			)?;
			dispatcher_components.push(dispatcher_component);
		}
		tap_interfaces.sort();

		#[cfg(feature = "libtrace")]
		// 初始化进程事件发送队列和线程
		// 传统的监控往往只关注资源使用率，而忽略了进程的生命周期。
		// 通过 eBPF 捕获 `execve` 和 `exit` 系统调用，精确记录进程的启动和退出时间、命令行参数、父子关系。
		// 这使得 ZeroTrace 能够构建动态的进程拓扑图，并关联短生命周期进程的性能数据。
		let (proc_event_sender, proc_event_uniform_sender) = {
			let proc_event_queue_name = "1-proc-event-to-sender";
			let (proc_event_sender, proc_event_receiver, counter) = queue::bounded_with_debug(
				user_config.inputs.ebpf.tunning.collector_queue_size,
				proc_event_queue_name,
				&queue_debugger,
			);
			stats_collector.register_countable(
				&QueueStats { module: proc_event_queue_name, ..Default::default() },
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
		// 应用性能瓶颈往往难以定位（是 CPU 密集还是锁等待？）。
		// 利用 eBPF 定期采样 CPU 堆栈 (On-CPU) 和 调度切换 (Off-CPU)。
		// 生成“持续剖析”数据，最终绘制成火焰图，帮助开发者快速定位代码级瓶颈。
		let profile_queue_name = "1-profile-to-sender";
		let (profile_sender, profile_receiver, counter) = queue::bounded_with_debug(
			user_config.inputs.ebpf.tunning.collector_queue_size,
			profile_queue_name,
			&queue_debugger,
		);
		stats_collector.register_countable(
			&QueueStats { module: profile_queue_name, ..Default::default() },
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
		// 业务日志 (Application Log) 是排查问题的核心依据，但传统采集方式侵入性强。
		// 从网络流量中无侵入地提取应用协议 (HTTP, MySQL, Redis) 的关键信息（如 SQL 语句、HTTP Header、响应码）。
		let application_log_queue_name = "1-application-log-to-sender";
		let (application_log_sender, application_log_receiver, counter) = queue::bounded_with_debug(
			user_config.processors.flow_log.tunning.flow_aggregator_queue_size,
			application_log_queue_name,
			&queue_debugger,
		);
		stats_collector.register_countable(
			&QueueStats { module: application_log_queue_name, ..Default::default() },
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
		// 初始化 SkyWalking 数据集成 (企业版功能)
		// 许多企业已经部署了 SkyWalking 进行 APM 监控。
		// 接收 SkyWalking Agent 上报的 Trace 数据，与 ZeroTrace 自身的 eBPF/BPF 数据进行融合。
		// 消除数据孤岛，提供统一的观测视角。
		let (skywalking_sender, skywalking_uniform_sender) = {
			let skywalking_queue_name = "1-skywalking-to-sender";
			let (skywalking_sender, skywalking_receiver, counter) = queue::bounded_with_debug(
				user_config.processors.flow_log.tunning.flow_aggregator_queue_size,
				skywalking_queue_name,
				&queue_debugger,
			);
			stats_collector.register_countable(
				&QueueStats { module: skywalking_queue_name, ..Default::default() },
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
		// 兼容 Datadog 生态。
		// 允许 ZeroTrace Agent 接收 Datadog 格式的 Trace/Metric 数据。
		let datadog_queue_name = "1-datadog-to-sender";
		let (datadog_sender, datadog_receiver, counter) = queue::bounded_with_debug(
			user_config.processors.flow_log.tunning.flow_aggregator_queue_size,
			datadog_queue_name,
			&queue_debugger,
		);
		stats_collector.register_countable(
			&QueueStats { module: datadog_queue_name, ..Default::default() },
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
		// 15. 初始化 eBPF Dispatcher 组件
		// eBPF 采集模块 (EbpfCollector) 与基于 AF_PACKET/DPDK 的流量采集模块 (Dispatcher) 是解耦的。
		// eBPF 运行在内核态，通过 perf_buffer/ring_buffer 传递数据；而流量采集通过 socket/PMD 接收数据。
		// 两者的数据源、处理逻辑和性能特征不同，因此使用独立的组件进行管理。
		if !config_handler.ebpf().load().ebpf.disabled
			&& !crate::utils::guard::is_kernel_ebpf_meltdown()
			&& (candidate_config.capture_mode != PacketCaptureType::Analyzer
				|| candidate_config.user_config.inputs.cbpf.special_network.dpdk.source
					== DpdkSource::Ebpf)
		{
			// L7 统计数据队列
			// 用于传输从 eBPF 采集到的应用层 RED 指标数据，发送给 L7Collector 进行聚合。
			let (l7_stats_sender, l7_stats_receiver, counter) = queue::bounded_with_debug(
				user_config.processors.flow_log.tunning.flow_generator_queue_size,
				"1-l7-stats-to-quadruple-generator",
				&queue_debugger,
			);
			stats_collector.register_countable(
				&QueueStats { id: ebpf_dispatcher_id, module: "1-l7-stats-to-quadruple-generator" },
				Countable::Owned(Box::new(counter)),
			);
			// L7 原始日志队列
			// 用于传输 eBPF 捕获的原始请求/响应数据，发送给 SessionAggregator 进行会话聚合。
			let (log_sender, log_receiver, counter) = queue::bounded_with_debug(
				user_config.processors.flow_log.tunning.flow_generator_queue_size,
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
			// Session Aggregator: L7 会话聚合器
			// 将一段时间内 (如 1s) 的重复请求聚合为一个会话记录，或者将 Request 和 Response 关联起来。
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
			// L7 Collector: L7 指标收集器
			// 从 L7 日志中计算 RED 指标 (Rate, Errors, Duration)。
			// 生成 HTTP RPS、响应延迟、SQL 查询耗时等关键应用性能指标。
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
			// 创建 eBPF Collector 核心对象
			// 管理 eBPF 程序的加载、Map 的读取和事件的处理。
			// 它是用户态 Agent 与内核态 eBPF 程序之间的桥梁。
			match crate::ebpf_dispatcher::EbpfCollector::new(
				ebpf_dispatcher_id,
				synchronizer.ntp_diff(),
				config_handler.ebpf(),       // eBPF 相关配置 (如探针类型、环形缓冲区大小)
				config_handler.log_parser(), // L7 协议解析配置
				config_handler.flow(),       // 流聚合配置
				config_handler.collector(),  // 数据上传配置
				policy_getter,               // 策略获取器 (用于获取当前的容器/服务列表，决定挂载点)
				dpdk_ebpf_senders,
				log_sender,             // 输出队列: 原始 L7 请求/响应日志
				l7_stats_sender,        // 输出队列: L7 RED 性能指标
				proc_event_sender,      // 输出队列: 进程启动/退出事件
				profile_sender.clone(), // 输出队列: CPU Profile 数据
				&queue_debugger,
				stats_collector.clone(),
				exception_handler.clone(),
				&process_listener, // 进程监听器 (用于动态发现新进程并触发 Uprobe 挂载)
			) {
				Ok(ebpf_collector) => {
					// 注册策略监听器
					// 当从 Controller 收到新的 ACL 或容器变动通知时，EbpfCollector 需要感知
					// (例如: 用户配置了只采集特定 Pod 的 HTTP 数据)
					synchronizer
						.add_flow_acl_listener(Box::new(ebpf_collector.get_sync_dispatcher()));

					// 用于监控 eBPF 自身的运行状态 (如 Map 容量、丢失事件数、探针触发次数)
					stats_collector.register_countable(
						&stats::NoTagModule("ebpf-collector"),
						Countable::Owned(Box::new(ebpf_collector.get_sync_counter())),
					);
					ebpf_dispatcher_component = Some(EbpfDispatcherComponent {
						ebpf_collector,
						session_aggregator,
						l7_collector,
					});
				},
				Err(e) => {
					log::error!("ebpf collector error: {:?}", e);
				},
			};
		}

		// 初始化 OTel数据发送队列和线程
		// 兼容 OTel 协议，允许 ZeroTrace Agent 接收或转发 OTel Trace/Metrics 数据。
		let otel_queue_name = "1-otel-to-sender";
		let (otel_sender, otel_receiver, counter) = queue::bounded_with_debug(
			user_config.processors.flow_log.tunning.flow_aggregator_queue_size,
			otel_queue_name,
			&queue_debugger,
		);
		stats_collector.register_countable(
			&QueueStats { module: otel_queue_name, ..Default::default() },
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

		// 初始化 L7 统计数据发送队列（用于 OTel 集成）
		// OTel 数据中可能包含需要进一步聚合的 L7 指标
		let (l7_stats_sender, l7_stats_receiver, counter) = queue::bounded_with_debug(
			user_config.processors.flow_log.tunning.flow_generator_queue_size,
			"1-l7-stats-to-quadruple-generator",
			&queue_debugger,
		);
		stats_collector.register_countable(
			&QueueStats { id: otel_dispatcher_id, module: "1-l7-stats-to-quadruple-generator" },
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
		// 支持接收 Prometheus Remote Write 数据，或作为 Scraper 抓取本地 Exporter。
		let prometheus_queue_name = "1-prometheus-to-sender";
		let (prometheus_sender, prometheus_receiver, counter) = queue::bounded_with_debug(
			user_config.processors.flow_log.tunning.flow_aggregator_queue_size,
			prometheus_queue_name,
			&queue_debugger,
		);
		stats_collector.register_countable(
			&QueueStats { module: prometheus_queue_name, ..Default::default() },
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
		// 兼容 Telegraf Line Protocol，复用 Telegraf 强大的采集生态。
		let telegraf_queue_name = "1-telegraf-to-sender";
		let (telegraf_sender, telegraf_receiver, counter) = queue::bounded_with_debug(
			user_config.processors.flow_log.tunning.flow_aggregator_queue_size,
			telegraf_queue_name,
			&queue_debugger,
		);
		stats_collector.register_countable(
			&QueueStats { module: telegraf_queue_name, ..Default::default() },
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
		// 针对已压缩数据流的优化路径
		let compressed_otel_queue_name = "1-compressed-otel-to-sender";
		let (compressed_otel_sender, compressed_otel_receiver, counter) = queue::bounded_with_debug(
			user_config.processors.flow_log.tunning.flow_aggregator_queue_size,
			compressed_otel_queue_name,
			&queue_debugger,
		);
		stats_collector.register_countable(
			&QueueStats { module: compressed_otel_queue_name, ..Default::default() },
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

		// 16. 初始化外部指标服务组件 (MetricServer)
		// 统一采集器，接收来自外部系统的 **Push** 数据。
		// 支持多种主流的可观测性协议，将它们转换为 ZeroTrace 的内部格式并统一上报。
		let (external_metrics_server, external_metrics_counter) = MetricServer::new(
			runtime.clone(),
			otel_sender,            // 处理 OpenTelemetry Trace/Metrics
			compressed_otel_sender, // 处理已压缩的 OTel 数据
			l7_stats_sender,        // 处理从 OTel/SkyWalking 中提取的应用性能指标
			prometheus_sender,      // 处理 Prometheus Remote Write
			telegraf_sender,        // 处理 Telegraf Line Protocol
			profile_sender,         // 处理 Continuous Profiling 数据
			application_log_sender, // 处理普通应用日志
			#[cfg(feature = "enterprise-integration")]
			skywalking_sender, // 处理 SkyWalking Trace (企业版)
			datadog_sender,         // 处理 Datadog Trace/Metrics
			candidate_config.metric_server.port,
			exception_handler.clone(),
			candidate_config.metric_server.compressed,
			candidate_config.metric_server.profile_compressed,
			candidate_config.platform.epc_id,
			policy_getter,
			synchronizer.ntp_diff(),
			user_config.inputs.integration.prometheus_extra_labels.clone(), // 为 Prometheus 数据自动注入额外的 Label (如 K8s 标签)
			candidate_config.log_parser.clone(),
			// 特性开关控制 (Feature Control)
			// 允许用户在配置中精细控制开启或关闭某些类型的集成，节省资源。
			user_config.inputs.integration.feature_control.profile_integration_disabled,
			user_config.inputs.integration.feature_control.trace_integration_disabled,
			user_config.inputs.integration.feature_control.metric_integration_disabled,
			user_config.inputs.integration.feature_control.log_integration_disabled,
		);

		stats_collector.register_countable(
			&stats::NoTagModule("integration_collector"),
			Countable::Owned(Box::new(external_metrics_counter)),
		);

		// 17. 初始化 NPB (Network Packet Broker) 带宽监控器
		// 实时监控 NPB 出向流量。一旦超过阈值 (bps)，立即触发熔断或限流，
		// 确保监控流量绝不会影响业务流量的带宽。
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
		// Vector 是一个高性能的可观测性数据管道，用于复杂的日志处理和转发场景。
		let vector_component = VectorComponent::new(
			user_config.inputs.vector.enabled,
			user_config.inputs.vector.config.clone(),
			runtime.clone(),
			synchronizer.agent_id.read().clone().ipmac.ip.to_string(),
			ipmac_tx,
		);

		// 18. 构造并返回 AgentComponents 结构体
		// 将所有初始化的组件组装在一起。
		// AgentComponents 就像一个容器，持有所有核心对象的生命周期。
		Ok(AgentComponents {
			config: candidate_config.clone(),
			// 全局接收速率限制器 (Leaky Bucket)，防止 CPU 过载
			rx_leaky_bucket,
			tap_typer,
			cur_tap_types: vec![],
			// 核心数据发送器 (L4流日志, 统计指标, L7调用日志)
			l4_flow_uniform_sender,
			metrics_uniform_sender,
			l7_flow_uniform_sender,
			// 平台同步器: 负责与 Controller 同步配置、标签、容器信息等
			platform_synchronizer,
			#[cfg(target_os = "linux")]
			kubernetes_poller, // K8s 资源轮询器
			#[cfg(any(target_os = "linux", target_os = "android"))]
			socket_synchronizer, // Socket 同步器: 建立 Socket 与进程的映射关系
			debugger, // 调试接口服务
			#[cfg(all(unix, feature = "libtrace"))]
			ebpf_dispatcher_component, // eBPF 核心组件 (包含 EbpfCollector, SessionAggregator 等)
			stats_collector, // 自监控指标收集器
			running: AtomicBool::new(false),
			// MetricServer 组件: 负责接收外部 Push 的数据 (OTel, Prometheus 等)
			metrics_server_component: MetricsServerComponent {
				external_metrics_server,
				l7_collector,
			},
			exception_handler,
			max_memory,
			// 统一发送器 (Unified Senders): 负责将各类集成数据发送给 Server
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
			npb_bps_limit,                  // NPB 带宽限制
			compressed_otel_uniform_sender,
			pcap_batch_uniform_sender, // PCAP 抓包数据发送器
			proto_log_sender,
			pcap_batch_sender,
			toa_info_sender: toa_sender, // TOA (TCP Option Address) 信息发送器，用于获取真实客户端 IP
			l4_flow_aggr_sender,         // L4 流聚合数据发送器
			metrics_sender,
			agent_mode,
			// 策略管理: 处理 ACL, CIDR, 黑白名单等
			policy_setter,
			policy_getter,
			npb_bandwidth_watcher, // NPB 带宽监控
			npb_arp_table,
			#[cfg(feature = "enterprise-integration")]
			vector_component,
			runtime,
			dispatcher_components, // 核心 Dispatcher 列表 (负责收包、处理)
			is_ce_version: version_info.name != env!("AGENT_NAME"),
			tap_interfaces,
			last_dispatcher_component_id: otel_dispatcher_id,
			bpf_options, // BPF 过滤配置
			#[cfg(any(target_os = "linux", target_os = "android"))]
			process_listener, // 进程监听器 (监听进程启动/退出事件)
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
				},
				Err(e) => {
					warn!("{}", e);
				},
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
			_ => {},
		}
	}

	// 创建新的组件实例 (Components Factory)
	//
	// 该函数充当工厂方法，根据当前运行环境和配置，实例化具体的工作组件。
	// ZeroTrace Agent 有两种主要的工作模式：
	// 1. Watcher 模式：轻量级模式，仅负责监听 Kubernetes API 资源变化，不进行流量采集。
	//    通常用于某些特殊的 Sidecar 容器或任务中。
	// 2. Agent 模式：全功能模式，包含流量采集 (Dispatcher)、统计 (Collector)、
	//    平台同步 (PlatformSynchronizer) 等所有核心功能。
	//
	// 参数说明：
	// - config_handler: 配置管理器，提供静态和动态配置。
	// - stats_collector: 统计收集器，用于上报 Agent 自身指标。
	// - session: 与 Controller 的 RPC 会话。
	// - synchronizer: 策略同步器。
	// - platform_synchronizer: 平台信息同步器。
	// - vm_mac_addrs/gateway_vmac_addrs: 预加载的 MAC 地址表。
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
		// 逻辑分支 1: 检查是否为 "仅监听 K8s" 模式 (Watcher 模式)
		// 触发条件:
		//   1. 运行在容器中 (IN_CONTAINER=true)
		//   2. 环境变量 K8S_WATCH_POLICY 设置为 "watch-only"
		// 场景:
		//   通常用于 Sidecar 部署，或者在只需同步 K8s 信息而无需抓包的场景。
		//   这种模式下资源占用极低，因为不启动 BPF/AF_PACKET 抓包模块。
		if crate::utils::environment::running_in_only_watch_k8s_mode() {
			info!("Running in K8s Watcher-only mode");
			// 初始化 WatcherComponents
			// 仅包含: Session (RPC), PlatformSynchronizer (资源同步), ApiWatcher (K8s API 监听)
			let components = WatcherComponents::new(config_handler, agent_mode, runtime)?;
			return Ok(Components::Watcher(components));
		}

		// 逻辑分支 2: 默认模式 (Agent 模式)
		// 场景: 标准部署，执行完整的流量采集和监控功能。
		// 初始化 AgentComponents，这会启动以下核心子模块:
		//   - Dispatcher: 负责 BPF/AF_PACKET 抓包和分发
		//   - Collector: 负责聚合 Flow 和指标数据
		//   - Debugger/PcapAssembler: 调试和 PCAP 包处理
		//   - PlatformSynchronizer/ApiWatcher: 平台信息同步
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
			_ => {},
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
	let (mini_packet_sender, mini_packet_receiver, mini_packet_counter) =
		queue::bounded_with_debug(config.receiver_queue_size, mini_packet_queue, &queue_debugger);
	let pcap_assembler = PcapAssembler::new(
		id as u32,
		enabled,
		config.total_buffer_size,    // 总缓存大小
		config.buffer_size_per_flow, // 单流缓存大小
		config.flush_interval,       // 刷新间隔
		pcap_batch_sender,           // PCAP 批次发送端
		mini_packet_receiver,        // MiniPacket 接收端
		ntp_diff,
	);
	stats_collector.register_countable(
		&stats::SingleTagModule("pcap_assembler", "id", id),
		Countable::Ref(Arc::downgrade(&pcap_assembler.counter) as Weak<dyn RefCountable>),
	);
	stats_collector.register_countable(
		&QueueStats { id, module: mini_packet_queue },
		Countable::Owned(Box::new(mini_packet_counter)),
	);
	(pcap_assembler, mini_packet_sender)
}

// 构建分发器组件 (DispatcherComponent)
//
// Dispatcher 是 ZeroTrace Agent 的数据面 (Data Plane) 引擎。
// 每个 Dispatcher 对应一个独立的采集线程 (通常绑定到一个 CPU 核心)，负责处理特定的流量输入源。
//
// Pipeline:
// 1. Input (收包): 从 AF_PACKET (Linux), DPDK, 或 WinPcap (Windows) 读取原始数据包。
// 2. Filter (过滤): 应用 BPF 规则过滤掉不需要的流量。
// 3. Process (处理):
//    - FastPath: 快速查表，处理已建立连接的流量。
//    - SlowPath: 首次包处理，进行流表建立、策略匹配、应用识别。
//    - Handlers: 执行附加处理，如 PCAP 存储、NPB 转发。
// 4. Output (输出): 将生成的 Flow, Metrics, Logs 分发到下游队列。
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
	// 用于传递 L4 流统计数据 (TagggedFlow)，供 Collector 聚合
	let (flow_sender, flow_receiver, counter) = queue::bounded_with_debug(
		user_config.processors.flow_log.tunning.flow_generator_queue_size,
		"1-tagged-flow-to-quadruple-generator",
		&queue_debugger,
	);
	stats_collector.register_countable(
		&QueueStats { id, module: "1-tagged-flow-to-quadruple-generator" },
		Countable::Owned(Box::new(counter)),
	);

	// 创建 L7 Stats (应用性能指标) 队列：Dispatcher -> QuadrupleGenerator
	// 用于传递 L7 协议的统计指标 (如 HTTP RPS, Latency)，供 Collector 聚合
	let (l7_stats_sender, l7_stats_receiver, counter) = queue::bounded_with_debug(
		user_config.processors.flow_log.tunning.flow_generator_queue_size,
		"1-l7-stats-to-quadruple-generator",
		&queue_debugger,
	);
	stats_collector.register_countable(
		&QueueStats { id, module: "1-l7-stats-to-quadruple-generator" },
		Countable::Owned(Box::new(counter)),
	);

	// 创建应用协议日志队列：Dispatcher -> AppProtoLogs
	// 用于传递完整的应用层请求/响应日志
	let (log_sender, log_receiver, counter) = queue::bounded_with_debug(
		user_config.processors.flow_log.tunning.flow_generator_queue_size,
		"1-tagged-flow-to-app-protocol-logs",
		&queue_debugger,
	);
	stats_collector.register_countable(
		&QueueStats { id, module: "1-tagged-flow-to-app-protocol-logs" },
		Countable::Owned(Box::new(counter)),
	);

	// 初始化会话聚合器 (SessionAggregator)
	// 将 Request 和 Response 数据包关联起来，形成完整的会话。
	// 还负责去重和压缩，减少发送到后端的数据量。
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
	// 用于传递 TCP Header 序列信息，分析乱序、重传等深层 TCP 行为
	let (packet_sequence_sender, packet_sequence_receiver, counter) = queue::bounded_with_debug(
		user_config.processors.packet.tcp_header.sender_queue_size,
		"1-packet-sequence-block-to-parser",
		&queue_debugger,
	);
	stats_collector.register_countable(
		&QueueStats { id, module: "1-packet-sequence-block-to-parser" },
		Countable::Owned(Box::new(counter)),
	);

	// 初始化包序解析器
	let packet_sequence_parser = PacketSequenceParser::new(
		packet_sequence_receiver,
		packet_sequence_uniform_output,
		id as u32,
	);
	// 构建 PCAP 组装器 (PcapAssembler)
	// 用于处理 PCAP 下载请求，将原始 Packet 数据写入文件或流
	let (pcap_assembler, mini_packet_sender) = build_pcap_assembler(
		is_ce_version,
		&user_config.processors.packet.pcap_stream,
		&stats_collector,
		pcap_batch_sender.clone(),
		&queue_debugger,
		synchronizer.ntp_diff(),
		id,
	);

	// 配置包处理流水线 (Handlers)
	// 这里的顺序很重要：先 PCAP 后 NPB
	// PacketHandlerBuilder::Pcap -> 提取元数据给 PcapAssembler
	// PacketHandlerBuilder::Npb -> 执行网络包分发 (Network Packet Broker)
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
	// 如果是 Analyzer 模式且使用了专用 DPDK 采集卡，则不需要通过 AF_PACKET 监听常规网卡
	let pcap_interfaces = if candidate_config.capture_mode != PacketCaptureType::Local
		&& candidate_config.user_config.inputs.cbpf.special_network.dpdk.source != DpdkSource::None
	{
		vec![]
	} else {
		links.clone()
	};

	// 配置 Dispatcher 构建器
	// 这里集中配置了底层收包引擎的参数 (Ring Buffer 大小, 协议版本, BPF 等)
	let dispatcher_builder = DispatcherBuilder::new()
		.id(id)
		.pause(agent_mode == RunningMode::Managed) // 托管模式下启动时先暂停，等待配置同步完成
		.handler_builders(handler_builders.clone()) // 注册包处理流水线
		.ctrl_mac(ctrl_mac)
		.leaky_bucket(rx_leaky_bucket.clone()) // 全局接收限流
		.options(Arc::new(Mutex::new(dispatcher::Options {
			#[cfg(any(target_os = "linux", target_os = "android"))]
			af_packet_version: dispatcher_config.af_packet_version, // AF_PACKET 版本 (v1/v2/v3)，v3 性能通常更好
			packet_blocks: dispatcher_config.af_packet_blocks, // 环形缓冲区 (Ring Buffer) 块大小，影响内存占用和丢包率
			capture_mode: candidate_config.capture_mode,       // 捕获模式 (Local/Mirror/Analyzer)
			tap_mac_script: user_config
				.inputs
				.resources
				.private_cloud
				.vm_mac_mapping_script
				.clone(), // 虚拟机 MAC 地址解析脚本 (私有云场景)
			is_ipv6: ctrl_ip.is_ipv6(),
			npb_port: user_config.outputs.npb.target_port, // NPB 目的端口 (VXLAN/GRE)
			vxlan_flags: user_config.outputs.npb.custom_vxlan_flags, // 自定义 VXLAN Flags
			controller_port: static_config.controller_port,
			controller_tls_port: static_config.controller_tls_port,
			libpcap_enabled: user_config.inputs.cbpf.special_network.libpcap.enabled, // 是否回退到 libpcap (兼容性模式)
			snap_len: dispatcher_config.capture_packet_size as usize, // 抓包截断长度 (Snap Length)，通常只抓包头以节省带宽
			dpdk_source: dispatcher_config.dpdk_source,               // DPDK 源配置
			dispatcher_queue: dispatcher_config.dispatcher_queue,     // 分发队列配置
			packet_fanout_mode: user_config.inputs.cbpf.af_packet.tunning.packet_fanout_mode, // Fanout 模式 (Hash/Lb/Cpu/Rollover/Rnd/Qm)
			vhost_socket_path: user_config
				.inputs
				.cbpf
				.special_network
				.vhost_user
				.vhost_socket_path
				.clone(), // vhost-user socket 路径 (VM 场景)
			#[cfg(any(target_os = "linux", target_os = "android"))]
			cpu_set: dispatcher_config.cpu_set, // 绑核设置，将 Dispatcher 线程绑定到特定 CPU
			#[cfg(target_os = "linux")]
			dpdk_ebpf_receiver,                                 // DPDK eBPF 接收端
			#[cfg(target_os = "linux")]
			dpdk_ebpf_windows: user_config
				.inputs
				.cbpf
				.special_network
				.dpdk
				.reorder_cache_window_size, // DPDK eBPF 乱序重排窗口
			#[cfg(target_os = "linux")]
			fanout_enabled,                                     // 是否启用 Fanout
			#[cfg(any(target_os = "linux", target_os = "android"))]
			promisc: user_config.inputs.cbpf.af_packet.tunning.promisc, // 是否启用混杂模式 (Promiscuous Mode)
			skip_npb_bpf: user_config.inputs.cbpf.af_packet.skip_npb_bpf, // 是否跳过 NPB 的 BPF 过滤
			..Default::default()
		})))
		.bpf_options(bpf_options)
		// 默认 TAP 类型 (云流量)
		.default_tap_type(
			(user_config.inputs.cbpf.physical_mirror.default_capture_network_type)
				.try_into()
				.unwrap_or(CaptureNetworkType::Cloud),
		)
		// 镜像流量 PCP (VLAN Priority Code Point)
		.mirror_traffic_pcp(user_config.inputs.cbpf.af_packet.vlan_pcp_in_physical_mirror_traffic)
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
		// Fanout 模式下，多个接口可能共用同一个 Dispatcher 逻辑，或者同一个接口有多个 Dispatcher
		.src_interface(if candidate_config.capture_mode != PacketCaptureType::Local {
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
		})
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
			warn!("dispatcher creation failed: {}, zerotrace-agent restart...", e);
			thread::sleep(Duration::from_secs(1));
			return Err(e.into());
		},
	};
	// 获取 Dispatcher 监听器并注册回调
	// 监听器用于在运行时动态更新 Dispatcher 配置 (如 TAP 接口变更、VM MAC 变更)
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

	// 创建并启动 Collector (负责聚合 L4 指标)
	// Collector 从 FlowReceiver 接收 TaggedFlow，聚合为分钟级/秒级指标 (Document)
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
	// 专门处理 L7 统计数据
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
