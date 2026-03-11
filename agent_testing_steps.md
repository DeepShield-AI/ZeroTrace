# ZeroTrace Agent Ctl 测试指南

本文档整合了 `zerotrace-agent-ctl` 的命令详解与实际测试步骤，用于指导对 Agent 进行功能验证。

## 1. 概述

`zerotrace-agent-ctl` 是 ZeroTrace Agent 的命令行调试工具，通过 UDP 协议与 Agent 通信。

**工作原理**:
- Agent 启动时会随机监听一个 UDP 端口（日志中显示为 `debugger listening on`）。
- `ctl` 工具需要通过 `-p` 参数指定该端口进行连接。
- 只有 `list` 命令使用固定的 UDP 30035 端口监听广播。

**基本使用方式**:
```bash
zerotrace-agent-ctl -p <AGENT_DEBUGGER_PORT> <SUBCOMMAND> [ARGS]
```

## 2. 环境准备与启动

### 2.1 安装 Docker

如果系统尚未安装 Docker，请按以下步骤安装。

#### Ubuntu / Debian

```bash
# 更新包索引
sudo apt-get update

# 安装依赖包
sudo apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release

# 添加 Docker 官方 GPG 密钥
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# 添加 Docker APT 源
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# 安装 Docker Engine
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

#### CentOS / RHEL / Fedora

```bash
# 安装 yum-utils
sudo yum install -y yum-utils

# 添加 Docker 仓库
sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo

# 安装 Docker Engine
sudo yum install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

#### 国内镜像源（可选，网络不通时使用）

如果无法访问 Docker 官方源，可替换为阿里云镜像：

```bash
# Ubuntu
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://mirrors.aliyun.com/docker-ce/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# CentOS
sudo yum-config-manager --add-repo https://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo
```

#### 启动 Docker 并设置开机自启

```bash
sudo systemctl start docker
sudo systemctl enable docker
```

#### 验证安装

```bash
# 查看版本
docker --version

# 运行测试容器
sudo docker run --rm hello-world
```

#### （可选）免 sudo 使用 Docker

```bash
# 将当前用户加入 docker 组
sudo usermod -aG docker $USER

# 重新登录后生效，或执行：
newgrp docker
```

### 2.2 配置 Docker (支持私有镜像仓库)

由于编译镜像位于私有仓库（HTTP 协议），需要修改 Docker 配置以允许不安全的镜像库。

修改 `/etc/docker/daemon.json`:
```json
{
  "insecure-registries": ["47.97.67.233:5000"]
}
```

重启 Docker 服务以生效：
```bash
sudo systemctl daemon-reload
sudo systemctl restart docker
```

### 2.3 获取代码

拉取代码时需要包含子模块：
```bash
git clone --recurse-submodules https://github.com/DeepShield-AI/zerotrace.git
cd zerotrace
```

### 2.4 编译代码 (使用 Docker)

在开始测试之前，需要先编译 `zerotrace-agent` 和 `zerotrace-agent-ctl`。推荐使用 Docker 进行编译，无需配置本地 Rust 环境。

确保当前位于项目根目录 `zerotrace/`。

```bash
docker run --privileged --rm -it -v \
    $(pwd):/zerotrace 47.97.67.233:5000/deepshield/rust-build:cached bash -c \
    "cd /zerotrace/agent && cargo build"
```

编译产物位于 `agent/target/debug/`：
- Agent: `agent/target/debug/zerotrace-agent`
- Ctl: `agent/target/debug/zerotrace-agent-ctl`

### 2.5 启动 Agent (Standalone 模式)
在后台启动 Agent，并开启 INFO 级别日志以便查看调试端口。

```bash
# 杀死可能存在的旧进程
sudo pkill zerotrace-agent

# 启动 Agent
sudo RUST_LOG=info ./agent/target/debug/zerotrace-agent --standalone -f ./agent/config/zerotrace-agent.yaml > agent.log 2>&1 &
```

### 2.6 获取调试端口
Agent 启动后会随机监听一个 UDP 端口用于调试。需要从日志中获取该端口号。

```bash
# 等待几秒钟让 Agent 初始化
sleep 15

# 查找监听端口
grep "debugger listening on" agent.log
# 输出示例: [INFO] debugger listening on: [::]:48522
```
*记下这个端口号（例如 48522），后续命令中将用 `<PORT>` 代替。*

### 2.7 生成测试流量 (可选)
为了测试 `ebpf` 和 `policy monitor` 功能，建议在本地生成一些网络流量。

```bash
# 启动一个简单的 HTTP Server (监听 8080 端口)
python3 -m http.server 8080 > /dev/null 2>&1 &

# 启动一个循环 Curl 脚本产生流量
nohup bash -c "while true; do curl -s http://127.0.0.1:8080 > /dev/null; sleep 0.1; done" > /dev/null 2>&1 &
```

## 3. 命令详解与测试执行

以下测试基于 **Standalone (独立模式)** 运行的 Agent。在此模式下，Agent 未连接控制器，部分依赖云端同步的命令（如 `rpc`, `platform`）将无数据返回，这是正常现象。

### 3.1 基础用法与帮助

```bash
./agent/target/debug/zerotrace-agent-ctl --help
```
```text
USAGE:
    zerotrace-agent-ctl [OPTIONS] <SUBCOMMAND>

OPTIONS:
    -a, --address <ADDRESS>    remote zerotrace-agent host ip [default: 127.0.0.1]
    -p, --port <PORT>          remote zerotrace-agent listening port
    -h, --help                 Print help information

SUBCOMMANDS:
    list        get information about the zerotrace-agent
    rpc         get information about the rpc synchronizer
    queue       monitor various queues of the selected zerotrace-agent
    platform    get information about the k8s platform
    policy      get information about the policy
    ebpf        get information about the ebpf
```

### 3.2 `list` 命令
**功能**: 发现当前机器上运行的 Agent。
**原理**: 监听 UDP 30035 端口，接收 Agent 发送的心跳广播 (Beacon)。

**帮助信息**:
```text
USAGE:
    zerotrace-agent-ctl list

OPTIONS:
    -h, --help    Print help information
```

**测试命令**:
```bash
./agent/target/debug/zerotrace-agent-ctl list
```

**预期结果**:
```text
zerotrace-agent-ctl listening udp port 30035 to find zerotrace-agent
...
```
*(注：在 Standalone 模式或本地回环环境下，广播包可能无法被正确接收，导致列表为空，但这不代表程序错误)*

### 3.3 `rpc` 命令
**功能**: 查询 Agent 与控制器同步的各类配置和策略数据。
**子命令**: `--get <TYPE>`

**参数详解**:
- `--get <TYPE>`: 指定获取的数据类型。
  - `version`: 数据版本号。
  - `config`: Agent 配置信息。
  - `acls`: 流控制策略 (ACLs)。
  - `groups`: IP 资源组信息。
  - `platform`: 平台数据 (Platform Data)。
  - `cidr`: CIDR 列表。
  - `segments`: 本地网段信息。
  - `capture-network-types`: 采集网络类型。

**帮助信息**:
```text
USAGE:
    zerotrace-agent-ctl rpc --get <GET>

OPTIONS:
    --get <GET>    Get data from RPC
                   [possible values: config, platform, capture-network-types, 
                    cidr, groups, acls, segments, version]
```

**测试命令 (Version)**:
```bash
./agent/target/debug/zerotrace-agent-ctl -p <PORT> rpc --get version
```

**预期结果**:
```text
platformData version: 0
groups version: 0
flowAcls version: 0
```
**分析**: `version: 0` 表示数据未同步，符合 Standalone 模式预期。

**测试命令 (Config)**:
```bash
./agent/target/debug/zerotrace-agent-ctl -p <PORT> rpc --get config
```
**预期结果**:
可能返回 `grpc client not connected` 错误。
**分析**: Agent 运行在 Standalone 模式，未配置控制器 IP，因此 gRPC 连接未建立，无法获取数据。

**测试命令 (其他类型)**:
可以尝试获取其他类型数据，但在 Standalone 模式下通常为空或报错。
```bash
./agent/target/debug/zerotrace-agent-ctl -p <PORT> rpc --get acls
```

### 3.4 `queue` 命令
**功能**: 监控 Agent 内部各模块间的消息队列，用于排查丢包或性能瓶颈。

**参数详解**:
- `--show`: 列出所有可用队列及其当前状态（enabled/disabled）。
- `--on <NAME>`: 开启指定名称队列的监控。
- `--duration <SECONDS>`: 指定监控持续时间（秒），配合 `--on` 使用。
- `--off <NAME>`: 关闭指定名称队列的监控。
- `--clear`: 关闭所有队列的监控。

**帮助信息**:
```text
USAGE:
    zerotrace-agent-ctl queue [OPTIONS]

OPTIONS:
    --show                   show queue list
    --on <ON>                monitor module
    --duration <DURATION>    monitoring duration in seconds
    --off <OFF>              turn off monitor
    --clear                  turn off all queue
```

**测试命令 (Show)**:
列出所有队列及其状态。
```bash
./agent/target/debug/zerotrace-agent-ctl -p <PORT> queue --show
```

**测试命令 (Monitor)**:
开启指定队列监控（例如 `1-tagged-flow-to-quadruple-generator`）。
```bash
./agent/target/debug/zerotrace-agent-ctl -p <PORT> queue --on 1-tagged-flow-to-quadruple-generator --duration 5
```

**预期结果**:
```text
MSG-177 TaggedFlow { flow: Flow { ... } }
```
**分析**: 如果有流量经过，将打印出具体的流信息（TaggedFlow），包含五元组、TCP 标志位等。

**测试命令 (Off)**:
手动关闭指定队列的监控。
```bash
./agent/target/debug/zerotrace-agent-ctl -p <PORT> queue --off 1-tagged-flow-to-quadruple-generator
```

**测试命令 (Clear)**:
如果监控非正常中断，可能会遗留开启状态，可以使用 clear 命令重置。
```bash
./agent/target/debug/zerotrace-agent-ctl -p <PORT> queue --clear
```

### 3.5 `platform` 命令
**功能**: 调试平台集成信息 (Kubernetes/Cloud 资源)。

**参数详解**:
- `--mac-mappings`: 显示 K8s 容器 MAC 地址到全局接口索引 (Global Interface Index) 的映射表。
- `--k8s-get <RESOURCE>`: 查询 Agent 内部缓存的 K8s 资源信息。支持的资源缩写如下：
  - `node` (no), `namespace` (ns), `service` (svc)
  - `deployment` (deploy), `pod` (po), `ingress` (ing)
  - `statefulset` (st), `daemonset` (ds)
  - `replicationcontroller` (rc), `replicaset` (rs)
  - `version`: 查看 Watcher 版本

**帮助信息**:
```text
USAGE:
    zerotrace-agent-ctl platform [OPTIONS]

OPTIONS:
    -m, --mac-mappings       show k8s container mac to global interface index mappings
    -k, --k8s-get <K8S_GET>  get resources with k8s api
                             [possible values: node, pod, service, deployment, ingress, 
                              namespace, statefulset, daemonset, replicaset, ...]
```

**测试命令**:
```bash
./agent/target/debug/zerotrace-agent-ctl -p <PORT> platform --mac-mappings
./agent/target/debug/zerotrace-agent-ctl -p <PORT> platform --k8s-get node
./agent/target/debug/zerotrace-agent-ctl -p <PORT> platform --k8s-get version
```

**预期结果**:
结果通常为空。
**分析**: Standalone 模式下未开启 K8s 监听或云平台同步，没有维护 MAC 地址映射表或 K8s 资源缓存。

### 3.6 `policy` 命令
**功能**: 调试策略执行和流标签 (Flow Labeling)。

**帮助信息**:
```text
USAGE:
    zerotrace-agent-ctl policy <SUBCOMMAND>

SUBCOMMANDS:
    monitor      
    show         
    analyzing    
```

**测试命令 (Monitor)**:
实时监控流的查表结果。
```bash
# 该命令会阻塞输出流日志，按 Ctrl+C 停止，或等待超时
./agent/target/debug/zerotrace-agent-ctl -p <PORT> policy monitor
```

**预期结果**:
```text
1772867438.328367451s ... PolicyData { acl_id: 0, action_flags: NONE }
```
**分析**:
- `acl_id: 0`: 表示未匹配到特定策略（默认策略）。
- `l3_epc_id: -2`: 表示未匹配到云资源 VPC。
这验证了策略模块正在工作，即使没有下发具体的 ACL。

### 3.7 `ebpf` 命令
**功能**: 调试 eBPF 探针采集的数据。

**子命令详解**:
- `datadump`: 抓取 eBPF 原始数据。
  - `--pid <PID>`: 过滤进程 ID (默认 0 表示所有)。
  - `--name <NAME>`: 过滤进程名称。
  - `--proto <PROTO>`: 过滤应用层协议号。
    - **0**: All, **1**: Other
    - **20**: HTTP1, **21**: HTTP2
    - **40**: Dubbo, **43**: SofaRPC
    - **60**: MySQL, **61**: PostgreSQL, **62**: Oracle
    - **80**: Redis, **81**: MongoDB, **82**: Memcached
    - **100**: Kafka, **101**: MQTT, **107**: RocketMQ
    - **120**: DNS, **121**: TLS
  - `--duration <SEC>`: 抓取持续时间（默认 30s）。
- `cpdbg`: 调试持续剖析器 (Continuous Profiler)。
  - `--duration <SEC>`: 调试持续时间。

**帮助信息**:
```text
USAGE:
    zerotrace-agent-ctl ebpf <SUBCOMMAND>

SUBCOMMANDS:
    cpdbg       monitor cpdbg
    datadump    monitor datadump
```

**测试命令 (Datadump)**:
抓取 HTTP 流量数据的 eBPF 日志。
```bash
# --proto 20 代表 HTTP1
./agent/target/debug/zerotrace-agent-ctl -p <PORT> ebpf datadump --pid 0 --name "" --proto 20 --duration 5
```

**预期结果**:
```text
SEQ 849: ... HTTP/1.1 200 OK ...
```
**分析**: 应能清晰看到 HTTP 请求头和响应内容，证明 eBPF 模块正常 Hook 到了系统调用并解析了应用层协议。

**测试命令 (Profiler)**:
调试持续剖析器 (Continuous Profiler)。
```bash
./agent/target/debug/zerotrace-agent-ctl -p <PORT> ebpf cpdbg --duration 5
```

## 4. 清理环境

测试完成后，请清理后台进程。

```bash
# 停止 Agent
sudo pkill zerotrace-agent

# 停止流量生成进程
pkill -f "python3 -m http.server"
pkill -f "curl -s http://127.0.0.1:8080"
```
