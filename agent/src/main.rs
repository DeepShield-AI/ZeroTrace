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

use std::panic;
use std::path::Path;

use anyhow::Result;
use clap::{ArgAction, Parser};
use log::error;
#[cfg(any(target_os = "linux", target_os = "android"))]
use signal_hook::{consts::TERM_SIGNALS, iterator::Signals};

use ::zerotrace_agent::*;

#[derive(Parser)]
struct Opts {
    /// Specify config file location
    #[clap(
        short = 'f',
        visible_short_alias = 'c',
        long,
        default_value = "/etc/zerotrace-agent.yaml"
    )]
    config_file: String,

    /// Enable standalone mode, default config path is /etc/zerotrace-agent-standalone.yaml
    #[clap(long)]
    standalone: bool,

    /// Display the version
    #[clap(short, long, action = ArgAction::SetTrue)]
    version: bool,

    /// Dump interface info
    #[clap(long = "dump-ifs")]
    dump_interfaces: bool,

    // TODO: use enum type
    /// Interface mac source type, used with '--dump-ifs'
    #[clap(long, default_value = "mac")]
    if_mac_source: String,

    /// Libvirt XML path, used with '--dump-ifs' and '--if-mac-source xml'
    #[clap(long, default_value = "/etc/libvirt/qemu")]
    xml_path: String,

    /// Check privileges under kubernetes
    #[clap(long)]
    check_privileges: bool,

    /// Grant capabilities including cap_net_admin, cap_net_raw,cap_net_bind_service
    #[clap(long)]
    add_cap: bool,

    /// Run agent in sidecar mode.
    /// Environment variable `CTRL_NETWORK_INTERFACE` must be specified and
    /// optionally `K8S_POD_IP_FOR_ZEROTRACE` can be set to override ip address.
    #[clap(long)]
    sidecar: bool,

    /// Disable cgroups, zerotrace-agent will default to checking the CPU and memory resource usage in a loop every 10 seconds to prevent resource usage from exceeding limits.
    #[clap(long)]
    cgroups_disabled: bool,
}

// unix系统
#[cfg(unix)]
fn wait_on_signals() {
    // 信号监听，接收终止信号
    let mut signals = Signals::new(TERM_SIGNALS).unwrap();
    // 日志打印，输出接收到的终止信号
    log::info!(
        "The Process exits due to signal {:?}.",
        // 主线程阻塞，直到接收到终止信号
        signals.forever().next()
    );
    // 关闭信号监听
    signals.handle().close();
}

// windows系统
#[cfg(windows)]
fn wait_on_signals() {}

// 版本信息
const VERSION_INFO: &'static trident::VersionInfo = &trident::VersionInfo {
    // agent发行版名称。通常用于区分社区版或企业版。如：zerotrace-agent-ce (社区版), zerotrace-agent-ee (企业版)。
    name: env!("AGENT_NAME"),
    // git分支名。指示当前代码构建自哪个分支。
    branch: env!("BRANCH"),
    // git提交ID。指示当前代码构建自哪个提交。
    commit_id: env!("COMMIT_ID"),
    // 修订计数。表示当前分支上的提交总数。用于生成递增的版本号。
    rev_count: env!("REV_COUNT"),
    // agent的编译器版本。如：rustc 1.60.0 (5550385e5 2021-10-11)。
    compiler: env!("RUSTC_VERSION"),
    // agent的编译时间。
    compile_time: env!("COMPILE_TIME"),

    revision: concat!(
        env!("BRANCH"),
        " ",
        env!("REV_COUNT"),
        "-",
        env!("COMMIT_ID")
    ),
};

// 入口
// 执行agent的启动逻辑，监听终止信号
fn main() -> Result<()> {
    // 设置panic的处理函数
    panic::set_hook(Box::new(|panic_info| {
        // 打印panic信息
        error!("{panic_info}");
        // 打印backtrace
        error!("{}", std::backtrace::Backtrace::force_capture());
    }));
    // 解析命令行参数，包括--version, --config-file, --standalone, --sidecar, --cgroups-disabled,
    // --dump-ifs, --if-mac-source, --xml-path, --check-privileges, --add-cap
    // version: 打印版本信息
    // config-file: 配置文件路径
    // standalone：控制是否单机模式。单机模式agent独立运行，不连接server，适用于离线环境或本地直接管理场景。
    // sidecar：控制是否sidecar模式。sidecar模式agent运行在k8s pod中，通过sidecar容器与agent容器共享网络命名空间，适用于k8s环境。
    // cgroups-disabled：控制是否禁用cgroups。禁用cgroups后，agent将默认检查CPU和内存资源使用情况，每10秒检查一次，以防止资源使用超过限制。（CPU，内存，磁盘，线程数等）
    
    // 实际未实现的功能
    // dump-ifs：控制是否dump接口信息。dump接口信息后，agent将输出所有接口的MAC地址和IP地址，之后退出。用于调试，帮助用户确认agent识别到了哪些网卡、MAC地址以及它们与虚拟机/容器的对应关系。
    // if-mac-source：指定获取接口MAC地址的数据来源。mac直接读取网络接口的真实MAC地址，xml从Libvirt XML配置文件中提取。
    // 普通物理机，容器使用默认mac即可，KVM/OpenStack计算节点使用xml（虚拟机环境中，用于建立宿主机网卡与虚拟机之间的对应关系，将流量数据正确标记到对应的虚拟机）
    // xml-path：控制XML文件的路径。XML文件的路径可以是XML文件的路径或XML文件的目录。
    // check-privileges：控制是否检查权限。检查权限后，agent将检查当前用户是否具有足够的权限。
    // 访问 /proc 文件系统、加载 eBPF 程序、使用原始套接字抓包等，这些操作通常需要 root 权限或特定的 Linux Capabilities（如 SYS_ADMIN）。
    // add-cap：控制是否添加能力。添加能力后，agent将添加cap_net_admin、cap_net_raw和cap_net_bind_service能力。
    // 在非 Root 运行但支持 Capability 的环境中，agent可以通过此选项尝试提升自身的网络权限，以满足最小权限原则，而不是直接以root运行。
    let opts = Opts::parse();
    // 打印版本信息并退出
    if opts.version {
        println!("{}", VERSION_INFO);
        return Ok(());
    }
    // 启动agent
    let mut t = trident::Trident::start(
        &Path::new(&opts.config_file),
        VERSION_INFO,
        if opts.standalone {
            trident::RunningMode::Standalone
        } else {
            trident::RunningMode::Managed
        },
        opts.sidecar,
        opts.cgroups_disabled,
    )?;
    // 等待信号
    wait_on_signals();
    // 停止agent
    t.stop();

    Ok(())
}
// main() 函数启动
//   ↓
// Trident::start()  ----> [启动后台工作线程: 采集器, 发送器, 监控器...]
//   ↓
// wait_on_signals() <---- [主线程在此阻塞睡眠，等待信号]
//   ↓
// (接收到 SIGTERM 信号)
//   ↓
// wait_on_signals() 返回
//   ↓
// t.stop()          ----> [通知后台线程停止，保存状态，释放资源]
//   ↓
// 进程退出 (Ok)
