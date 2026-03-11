# ZeroTrace Agent 架构分析与微内核演进路线

## 一、现有架构深度分析

### 1.1 当前架构总览

```
main.rs → Trident::start() → Trident::run() [main-loop thread]
                                    │
                                    ▼
                            AgentComponents::new()  ← 4101 行 God Object
                                    │
                    ┌───────────────┼───────────────────┐
                    ▼               ▼                   ▼
              Dispatcher(s)    EbpfCollector      MetricServer
              (AF_PACKET/      (kprobe/uprobe)    (OTel/Prom/DD)
               DPDK/libpcap)        │                   │
                    │               │                   │
                    ▼               ▼                   ▼
              ┌─────────────────────────────────────────┐
              │         ~15 个 UniformSenderThread       │
              │   (L4Flow, Metrics, L7Log, OTel, ...)   │
              └─────────────────────────────────────────┘
                                    │
                                    ▼
                          Controller / Ingester (Server)
```

### 1.2 关键文件量化

| 文件 | 行数 | 职责 |
|------|------|------|
| `trident.rs` | **4101** | God Object：初始化、状态机、组件生命周期、数据管道布线 |
| `config/handler.rs` | **6057** | 配置处理、回调分发、热更新逻辑 |
| `config/config.rs` | **116K bytes** | 配置结构定义 |
| `flow_generator/flow_map.rs` | **147K bytes** | 流表核心逻辑 |
| `flow_generator/flow_state.rs` | **78K bytes** | 流状态机 |
| `ebpf_dispatcher.rs` | **61K bytes** | eBPF 采集器 |
| `dispatcher/mod.rs` | **52K bytes** | Dispatcher 核心 |
| `collector/collector.rs` | **57K bytes** | 指标聚合 |
| `integration_collector.rs` | **54K bytes** | 外部集成 |
| `rpc/synchronizer.rs` | **82K bytes** | RPC 同步 |

### 1.3 `AgentComponents` 结构体 — 问题核心

`AgentComponents` 包含 **50+ 个字段**，涵盖：
- 15 个 `UniformSenderThread` (各类数据发送)
- Dispatcher 组件列表
- eBPF 组件
- Platform/K8s 同步器
- Policy 引擎
- Debugger
- 各种 LeakyBucket / BPF Options / Stats Collector
- 运行时配置和状态

**这是一个典型的 God Object 反模式。**

---

## 二、核心问题诊断

### 问题 1：God Object — `trident.rs` 承担了所有职责

**症状**：
- `AgentComponents::new()` 函数超过 1200 行，手动创建 30+ 个队列、15+ 个发送线程
- `Trident::run()` 同时管理状态机、配置更新、组件生命周期
- `build_dispatchers()` 函数有 25+ 个参数

**对比 Datadog Agent**：
Datadog 采用 `comp` (component) 框架，每个组件实现统一的 `Component` trait，通过依赖注入 (fx) 自动组装。组件之间通过 channel 通信，生命周期由框架管理。

**对比 Vector**：
Vector 使用 `topology` 模式，Source → Transform → Sink 通过声明式配置连接，每个组件实现标准 trait，独立编译测试。

### 问题 2：配置耦合 — 255K 的 handler.rs

**症状**：
- `ConfigHandler` 知道所有组件的存在，`on_config()` 方法直接操作 `AgentComponents`
- 配置更新回调是 `Vec<fn(&ConfigHandler, &mut AgentComponents)>` — 直接耦合到具体类型
- 每新增一个功能模块，都要修改 `ConfigHandler`、`AgentComponents`、`trident.rs` 三处

**对比 Cilium**：
Cilium 使用 `hive` 框架，每个 cell（模块）声明自己需要的配置片段，框架自动注入。配置变更通过 watch 机制广播，模块自行处理。

### 问题 3：队列/管道手动布线

**症状**：
- 每条数据管道需要手动创建 `(sender, receiver, counter)` → 注册 stats → 创建 `UniformSenderThread`
- 相同模式重复 15+ 次，代码行数巨大但逻辑高度相似
- 新增数据类型（如新的集成协议）需要修改 `trident.rs` 100+ 行

**对比 Vector**：
Vector 的 topology 将管道连接声明化：
```toml
[sources.input] type = "socket"
[transforms.parse] type = "remap", inputs = ["input"]
[sinks.output] type = "http", inputs = ["parse"]
```

### 问题 4：平台耦合 — `#[cfg]` 散布全局

**症状**：
- `#[cfg(target_os = "linux")]` 在 `trident.rs` 中出现 50+ 次
- 不同平台的初始化逻辑交织在同一函数中
- Windows/Android/Linux 的差异逻辑通过条件编译内联，而非抽象到平台层

**对比 Datadog Agent**：
Datadog 将平台差异封装到 `pkg/util/system` 等模块中，上层逻辑面向接口编程。

### 问题 5：可测试性差

**症状**：
- `AgentComponents::new()` 依赖真实的网络接口、内核版本、K8s 环境
- 无法在 CI 中对单个子系统（如 Collector 或 SessionAggregator）进行集成测试
- 测试代码集中在少数 bench 和 flow_map 测试中
- `config/handler.rs` 引用了 `AgentComponents`，形成循环依赖逻辑

### 问题 6：组件生命周期管理原始

**症状**：
- 每个组件自行实现 `start()/stop()`，没有统一的生命周期 trait
- 停止时手动收集 `JoinHandle` 并逐个 join
- 没有健康检查、重启策略、优雅降级机制
- `crate::utils::clean_and_exit(1)` 出现 10+ 次 — 出错就直接退出进程

---

## 三、目标架构：微内核 + Pipeline

### 3.1 设计哲学（参考业界最佳实践）

| 项目 | 核心理念 | 可借鉴点 |
|------|---------|---------|
| **Datadog Agent** | Component Framework + fx DI | 统一组件 trait、依赖注入、生命周期管理 |
| **Vector** | Source → Transform → Sink DAG | 声明式管道、类型安全的消息传递、热重载 |
| **Cilium** | Hive Cell Architecture | 模块化 cell、配置 watch、按需启停 |
| **Pixie** | Stirling (data source) + Carnot (query engine) | 数据源抽象、独立的采集与处理层 |

### 3.2 目标架构

```
┌─────────────────────────────────────────────────────┐
│                    Agent Core (微内核)                │
│  ┌─────────┐  ┌──────────┐  ┌───────────────────┐   │
│  │ Runtime │  │ Registry │  │ Config Distributor│   │
│  │ Manager │  │(Component│  │ (watch + notify)  │   │
│  │         │  │  Store)  │  │                   │   │
│  └────┬────┘  └────┬─────┘  └────────┬──────────┘   │
│       │            │                 │               │
│  ┌────┴────────────┴─────────────────┴────────────┐  │
│  │            Message Bus (typed channels)         │  │
│  └────┬────────┬──────────┬──────────┬────────────┘  │
│       │        │          │          │                │
├───────┼────────┼──────────┼──────────┼────────────────┤
│ ┌─────┴──┐ ┌───┴───┐ ┌───┴────┐ ┌───┴────┐          │
│ │Source  │ │Process│ │Collect │ │  Sink  │  Components│
│ │Layer   │ │Layer  │ │Layer   │ │ Layer  │          │
│ ├────────┤ ├───────┤ ├────────┤ ├────────┤          │
│ │AF_PCKT │ │FlowMap│ │L4 Aggr │ │Ingester│          │
│ │eBPF    │ │L7Parse│ │L7 Aggr │ │NPB     │          │
│ │DPDK    │ │Policy │ │Metrics │ │Debug   │          │
│ │OTel RX │ │Session│ │Profile │ │StatsOut│          │
│ │Prom RX │ │  Aggr │ │        │ │        │          │
│ │DD RX   │ │       │ │        │ │        │          │
│ └────────┘ └───────┘ └────────┘ └────────┘          │
└─────────────────────────────────────────────────────┘
```

### 3.3 核心抽象

```rust
/// 组件生命周期 trait — 所有模块必须实现
pub trait Component: Send + Sync + 'static {
    /// 组件唯一标识
    fn name(&self) -> &'static str;

    /// 声明依赖的配置片段类型
    type Config: DeserializeOwned + Clone + PartialEq;

    /// 启动组件
    fn start(&mut self, ctx: &ComponentContext) -> Result<()>;

    /// 优雅停止
    fn stop(&mut self) -> Result<()>;

    /// 健康检查
    fn health_check(&self) -> HealthStatus { HealthStatus::Healthy }

    /// 配置热更新
    fn on_config_change(&mut self, config: &Self::Config) -> Result<()>;
}

/// 数据源组件
pub trait Source: Component {
    type Output: Send + 'static;
    fn output_channel(&self) -> &Sender<Self::Output>;
}

/// 处理组件
pub trait Transform: Component {
    type Input: Send + 'static;
    type Output: Send + 'static;
}

/// 输出组件
pub trait Sink: Component {
    type Input: Send + 'static;
}

/// 组件上下文 — 由微内核注入
pub struct ComponentContext {
    pub runtime: Arc<Runtime>,
    pub stats: Arc<StatsCollector>,
    pub exception_handler: ExceptionHandler,
    pub bus: MessageBus,
}
```

---

## 四、分阶段演进路线

### Phase 0：准备阶段（2-3 周）

**目标**：不改架构，建立可测试基础和抽象边界。

#### 0.1 提取 Component trait
```rust
// crates/agent-core/src/component.rs
pub trait Lifecycle {
    fn start(&mut self) -> Result<()>;
    fn stop(&mut self) -> Result<()>;
    fn is_running(&self) -> bool;
}
```
让现有的 `DispatcherComponent`、`EbpfDispatcherComponent`、`MetricsServerComponent`
实现该 trait，统一 `AgentComponents::start()/stop()` 中的重复代码。

#### 0.2 提取 SenderPipeline 工厂
将 `trident.rs` 中重复 15 次的 queue+sender 创建模式提取为：
```rust
pub struct SenderPipeline<T: Sendable> {
    pub sender: DebugSender<T>,
    pub thread: UniformSenderThread<T>,
}

impl<T: Sendable> SenderPipeline<T> {
    pub fn new(name: &str, config: SenderConfig, ...) -> Self { ... }
}
```

#### 0.3 将 AgentComponents 拆为子聚合
```
AgentComponents {
    sources: SourceComponents,      // dispatchers + ebpf
    processors: ProcessorComponents, // collector + session_aggr
    sinks: SinkComponents,          // all UniformSenderThreads
    platform: PlatformComponents,   // k8s, process_listener, socket_sync
    infra: InfraComponents,         // debugger, stats, policy, bpf_options
}
```

### Phase 1：配置解耦（3-4 周）

**目标**：打破 `ConfigHandler ↔ AgentComponents` 的循环依赖。

#### 1.1 配置分片
将 `handler.rs` 的 255K 拆分为独立的配置模块：
```
config/
├── mod.rs
├── types.rs              # 纯数据结构 (UserConfig, StaticConfig)
├── dispatcher_config.rs  # Dispatcher 相关的配置处理
├── collector_config.rs   # Collector 相关
├── ebpf_config.rs        # eBPF 相关
├── sender_config.rs      # Sender 相关
├── platform_config.rs    # 平台相关
└── watcher.rs            # 配置 watch 机制
```

#### 1.2 引入配置广播机制
```rust
pub struct ConfigDistributor {
    watchers: Vec<Box<dyn ConfigWatcher>>,
}

pub trait ConfigWatcher: Send + Sync {
    fn on_config_update(&mut self, config: &UserConfig);
}
```
每个组件实现 `ConfigWatcher`，`ConfigDistributor` 广播配置变更。
**取代** 现有的 `Vec<fn(&ConfigHandler, &mut AgentComponents)>` 回调。

### Phase 2：Source 层抽象（4-6 周）

**目标**：统一数据采集入口，解耦 Dispatcher/eBPF/Integration。

#### 2.1 定义 Source trait
```rust
pub trait PacketSource: Lifecycle + ConfigWatcher {
    fn subscribe_flow(&self) -> Receiver<Arc<BatchedBox<TaggedFlow>>>;
    fn subscribe_l7_stats(&self) -> Receiver<BatchedBox<L7Stats>>;
    fn subscribe_proto_log(&self) -> Receiver<BoxAppProtoLogsData>;
}
```

#### 2.2 拆分 Source 为独立 crate
```
crates/
├── source-af-packet/     # AF_PACKET 抓包
├── source-ebpf/          # eBPF 采集
├── source-dpdk/          # DPDK 采集
├── source-integration/   # OTel/Prometheus/Datadog/SkyWalking 接收
└── source-pcap/          # libpcap 兼容模式
```

每个 source crate 可独立编译测试，不依赖 `trident.rs`。

#### 2.3 Dispatcher 内部重构
当前 `dispatcher/` 有 6 种 mode dispatcher（analyzer/local/mirror/...），通过大量重复代码实现。
重构为 Strategy 模式：
```rust
pub struct Dispatcher {
    engine: Box<dyn RecvEngine>,       // AF_PACKET / DPDK / libpcap
    mode: Box<dyn DispatcherMode>,     // Local / Mirror / Analyzer
    pipeline: Vec<Box<dyn Handler>>,   // Pcap / NPB / ...
}
```

### Phase 3：处理层模块化（4-6 周）

**目标**：FlowMap、Collector、SessionAggregator 独立为可测试模块。

#### 3.1 FlowMap 提取
`flow_map.rs` (147K) 是最复杂的模块。拆分为：
```
crates/flow-engine/
├── flow_map.rs        # 核心流表 HashMap + 时间轮
├── flow_node.rs       # 流节点状态
├── flow_state.rs      # TCP/UDP 状态机
├── flow_config.rs     # 流配置
├── conntrack.rs       # 连接跟踪
├── time_window.rs     # 时间窗口管理
└── tests/             # 独立单元测试和集成测试
```

**关键**：FlowMap 的输入是 `MetaPacket`，输出是 `TaggedFlow` + `L7Stats`。
定义清晰的接口后，可以用 pcap 文件驱动测试，无需真实网卡。

#### 3.2 Collector Pipeline 重构
```
crates/collector/
├── quadruple_generator.rs   # 四元组生成
├── flow_aggr.rs             # 秒→分 聚合
├── l7_collector.rs          # L7 指标聚合
├── time_window.rs           # 通用时间窗口
└── pipeline.rs              # 串联编排
```

#### 3.3 L7 协议解析独立化
当前 `flow_generator/protocol_logs/` 已有 50 个文件。
将其提取为独立 crate `crates/l7-protocols/`，与 `plugins/l7` 合并，
使得新增协议解析器只需要：
1. 实现 `L7ProtocolParser` trait
2. 在 registry 注册
3. 不需要修改 `trident.rs` 或 `flow_map.rs`

### Phase 4：Sink 层统一（2-3 周）

**目标**：消除 15 个几乎相同的 UniformSenderThread 创建代码。

#### 4.1 Sink Registry
```rust
pub struct SinkRegistry {
    sinks: HashMap<&'static str, Box<dyn Sink>>,
}

impl SinkRegistry {
    pub fn register<T: Sendable>(&mut self, name: &str, config: SenderConfig) { ... }
    pub fn start_all(&mut self) { ... }
    pub fn stop_all(&mut self) { ... }
}
```

#### 4.2 声明式管道配置
```rust
// 替代 trident.rs 中 1000+ 行的手动布线
let pipeline = PipelineBuilder::new()
    .source("af-packet", af_packet_source)
    .source("ebpf", ebpf_source)
    .transform("flow-engine", flow_engine)
    .transform("collector", collector)
    .sink("l4-flow", l4_flow_sink)
    .sink("metrics", metrics_sink)
    .sink("l7-log", l7_log_sink)
    .connect("af-packet.flow", "flow-engine.input")
    .connect("flow-engine.tagged_flow", "collector.input")
    .connect("collector.document", "metrics.input")
    .build()?;
```

### Phase 5：微内核组装（3-4 周）

**目标**：`trident.rs` 缩减到 < 500 行，仅负责组件发现和编排。

#### 5.1 Agent Core
```rust
pub struct AgentCore {
    registry: ComponentRegistry,
    config: ConfigDistributor,
    runtime: Arc<Runtime>,
    state: Arc<AgentState>,
}

impl AgentCore {
    pub fn new(config_path: &Path) -> Result<Self> { ... }

    pub fn register<C: Component>(&mut self, component: C) { ... }

    pub fn run(&mut self) -> Result<()> {
        // 按依赖顺序启动所有组件
        self.registry.start_all()?;
        // 进入状态机循环（仅处理 enable/disable/config_update）
        self.state_loop()
    }
}
```

#### 5.2 main.rs 变为声明式
```rust
fn main() -> Result<()> {
    let opts = Opts::parse();
    let mut core = AgentCore::new(&opts.config_file)?;

    // 注册 Sources
    core.register(AfPacketSource::new());
    #[cfg(feature = "libtrace")]
    core.register(EbpfSource::new());
    core.register(IntegrationSource::new());  // OTel/Prom/DD

    // 注册 Processors
    core.register(FlowEngine::new());
    core.register(L4Collector::new());
    core.register(L7Collector::new());
    core.register(SessionAggregator::new());

    // 注册 Sinks
    core.register(IngesterSink::new("l4-flow"));
    core.register(IngesterSink::new("metrics"));
    core.register(IngesterSink::new("l7-log"));
    // ... 其他 sinks 按需注册

    // 注册 Platform Services
    core.register(PlatformSynchronizer::new());
    core.register(PolicyEngine::new());
    core.register(Debugger::new());

    core.run()?;
    wait_on_signals();
    core.stop()
}
```

---

## 五、Crate 拆分规划

### 最终目标 crate 结构

```
agent/
├── crates/
│   ├── agent-core/           # 微内核：Component trait, Registry, MessageBus, Config
│   ├── agent-config/         # 配置解析和分发（从 config/ 拆出）
│   ├── flow-engine/          # FlowMap + 状态机（从 flow_generator/ 拆出）
│   ├── l7-protocols/         # L7 协议解析（合并 flow_generator/protocol_logs + plugins/l7）
│   ├── collector/            # 指标聚合（从 collector/ 拆出）
│   ├── source-af-packet/     # AF_PACKET 数据源
│   ├── source-ebpf/          # eBPF 数据源（从 ebpf/ + ebpf_dispatcher 拆出）
│   ├── source-integration/   # 外部集成接收（从 integration_collector 拆出）
│   ├── sink-ingester/        # Ingester 发送（从 sender/ 拆出）
│   ├── sink-npb/             # NPB 转发
│   ├── platform-k8s/         # K8s 平台集成（从 platform/ 拆出）
│   ├── platform-process/     # 进程监听（从 utils/process 拆出）
│   ├── policy/               # 策略引擎（从 policy/ 拆出）
│   ├── debug/                # 调试接口（从 debug/ 拆出）
│   ├── public/               # (已有) 公共类型
│   ├── public-derive/        # (已有) 派生宏
│   └── trace-utils/          # (已有) 跟踪工具
├── plugins/                  # (已有，部分合并到 crates)
├── src/
│   ├── main.rs               # 入口：解析参数，声明式注册组件，启动
│   └── lib.rs                # re-export
└── Cargo.toml
```

### 每个 crate 的独立测试能力

| Crate | 测试方式 |
|-------|---------|
| `flow-engine` | pcap 文件驱动，对比预期的 TaggedFlow 输出 |
| `l7-protocols` | 构造字节流，验证协议解析结果 |
| `collector` | 注入 TaggedFlow 序列，验证聚合指标 |
| `source-af-packet` | mock 网络接口，或使用 veth pair |
| `source-ebpf` | BPF skeleton 单元测试 + 虚拟机集成测试 |
| `source-integration` | HTTP mock server 发送 OTel/Prom 数据 |
| `sink-ingester` | mock gRPC server 验证发送内容 |
| `policy` | 纯内存策略树测试 |
| `agent-core` | 使用 mock Component 测试生命周期管理 |

---

## 六、风险与应对

### 6.1 二进制兼容
- **风险**：拆分 crate 可能导致 protobuf/gRPC 接口不兼容
- **应对**：`message/` 目录的 proto 定义保持不变，只在 `crates/public` 中统一生成

### 6.2 性能回归
- **风险**：抽象层引入额外开销（虚函数调用、channel hop）
- **应对**：关键路径（FlowMap 内循环）保持静态分发（泛型/enum_dispatch），只在组件边界使用 channel

### 6.3 渐进式迁移
- **原则**：每个 Phase 结束后代码必须可编译运行，不做大爆炸重写
- **方法**：Strangler Fig Pattern — 新代码包裹旧代码，逐步替换

### 6.4 平台 cfg 管理
- **当前**：50+ 个 `#[cfg(target_os = "linux")]` 散布在 `trident.rs`
- **目标**：每个 platform crate 内部处理平台差异，对外暴露统一接口
- **过渡**：先将 cfg 块提取为 platform 模块的函数，再逐步迁移到独立 crate

---

## 七、优先级排序与预期收益

| Phase | 工作量 | 风险 | 收益 |
|-------|--------|------|------|
| **Phase 0** (Trait + 工厂) | 低 | 极低 | 消除重复代码 30%，建立抽象基础 |
| **Phase 1** (配置解耦) | 中 | 低 | 打破循环依赖，handler.rs 拆分为 6 个文件 |
| **Phase 2** (Source 层) | 高 | 中 | 数据源独立测试，新增源不改 trident.rs |
| **Phase 3** (处理层) | 高 | 中 | flow_map 可用 pcap 驱动测试，覆盖率提升 |
| **Phase 4** (Sink 层) | 低 | 低 | trident.rs 减少 1000+ 行 |
| **Phase 5** (微内核) | 中 | 中 | trident.rs < 500 行，新模块即插即用 |

**推荐路线**：Phase 0 → 1 → 4 → 2 → 3 → 5

理由：Phase 0/1/4 是低风险高收益的重构，可以快速改善代码质量；
Phase 2/3 涉及核心数据面，需要充分测试；Phase 5 是最终目标。

---

## 八、与开源项目的具体对标

### 8.1 Datadog Agent 的 Component 模型

Datadog 的 `comp-def` 框架：
```go
type Component struct {
    Requires // 声明依赖
    Provides // 声明输出
}
func NewComponent(deps Requires) (Provides, error) { ... }
```

**ZeroTrace 可借鉴**：
- 每个组件声明输入/输出类型
- 框架自动解析依赖图并按序启动
- 消除 `AgentComponents::new()` 中的手动布线

### 8.2 Vector 的 Topology

Vector 的核心抽象：
```rust
#[async_trait]
pub trait SourceConfig {
    async fn build(&self, cx: SourceContext) -> Result<Source>;
}
```

**ZeroTrace 可借鉴**：
- 将 Dispatcher/EbpfCollector/IntegrationCollector 统一为 `SourceConfig`
- 管道连接通过配置声明而非硬编码
- 支持运行时动态添加/移除 Source

### 8.3 Cilium 的 Hive

Cilium 的 cell 模型：
```go
cell.Module(
    cell.Provide(NewPolicyEngine),
    cell.Config(PolicyConfig{}),
)
```

**ZeroTrace 可借鉴**：
- 模块声明自己的配置类型和构造函数
- 框架自动进行依赖注入
- 健康检查和 metrics 自动注册

---

## 九、即刻可执行的第一步

在不做大规模重构的前提下，以下改动可以**立即开始**，为后续演进奠基：

### 9.1 提取 `Lifecycle` trait (1-2 天)

在 `crates/public/src/` 中添加：
```rust
pub trait Lifecycle: Send {
    fn start(&mut self);
    fn stop(&mut self);
    fn notify_stop(&mut self) -> Option<JoinHandle<()>> { self.stop(); None }
    fn is_running(&self) -> bool;
}
```

### 9.2 提取 `SenderPipeline` (2-3 天)

将 `trident.rs` 中 15 次重复的 queue+sender 创建提取为工厂函数，
放入 `sender/pipeline.rs`。预计减少 trident.rs **600+ 行**。

### 9.3 拆分 `AgentComponents` (3-5 天)

将 50+ 字段分组为 5 个子结构体，每个子结构体实现 `Lifecycle`。
`AgentComponents::start()/stop()` 变为委托调用。

这三步完成后，`trident.rs` 将从 4100 行降至约 2500 行，
并为后续的 crate 拆分提供清晰的模块边界。
