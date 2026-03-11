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

use std::sync::Arc;

use bincode::{Decode, Encode};
use parking_lot::RwLock;
use tokio::runtime::Runtime;

use crate::{
    exception::ExceptionHandler,
    rpc::{Session, StaticConfig, Status, Synchronizer},
    trident::AgentId,
};
use public::debug::{Error, Result};
use public::proto::agent;

/// RPC 模块调试器，用于获取 Agent 与 Controller 同步的数据
pub struct RpcDebugger {
    session: Arc<Session>,            // gRPC 会话接口
    status: Arc<RwLock<Status>>,      // Agent 状态信息
    config: Arc<StaticConfig>,        // 静态配置
    agent_id: Arc<RwLock<AgentId>>,   // Agent ID 包装器
    runtime: Arc<Runtime>,            // Tokio 运行时
}

/// 基础配置命令的响应结构
#[derive(PartialEq, Debug)]
pub struct ConfigResp {
    status: i32,                      // 响应状态
    version_platform_data: u64,       // 平台数据版本
    version_acls: u64,                // ACL 版本
    version_groups: u64,              // 组数据版本
    revision: String,                 // 配置修订版本
    config: String,                   // 用户配置内容
    self_update_url: String,          // 自更新 URL
}

/// RPC 调试消息枚举
#[derive(PartialEq, Debug, Encode, Decode)]
pub enum RpcMessage {
    Config(Option<String>),               // 配置消息
    PlatformData(Option<String>),         // 平台数据消息
    CaptureNetworkTypes(Option<String>),  // 采集网络类型消息
    Cidr(Option<String>),                 // CIDR 消息
    Groups(Option<String>),               // IP 组消息
    Acls(Option<String>),                 // ACL 消息
    Segments(Option<String>),             // 本地网段消息
    Version(Option<String>),              // 版本消息
    Err(String),                          // 错误消息
    Fin,                                  // 结束消息
}

impl RpcDebugger {
    /// 创建一个新的 RpcDebugger 实例
    pub(super) fn new(
        runtime: Arc<Runtime>,
        session: Arc<Session>,
        config: Arc<StaticConfig>,
        agent_id: Arc<RwLock<AgentId>>,
        status: Arc<RwLock<Status>>,
    ) -> Self {
        Self {
            runtime,
            session,
            status,
            config,
            agent_id,
        }
    }

    /// 通过 gRPC 从控制器获取同步响应
    async fn get_rpc_response(
        &self,
    ) -> Result<tonic::Response<agent::SyncResponse>, tonic::Status> {
        // 创建默认的异常处理器
        let exception_handler = ExceptionHandler::default();
        // 根据当前 Agent 状态生成同步请求
        let req = Synchronizer::generate_sync_request(
            &self.agent_id,
            &self.config,
            &self.status,
            0, // 初始时间差
            &exception_handler,
            1 << 20, // 异常容量
        );
        // 执行 gRPC 同步调用
        let resp = self.session.grpc_sync(req).await?;
        Ok(resp)
    }

    /// 获取基础配置信息
    pub(super) fn basic_config(&self) -> Result<Vec<RpcMessage>> {
        // 阻塞等待获取 RPC 响应
        let mut resp = self
            .runtime
            .block_on(self.get_rpc_response())
            .map_err(|e| Error::Tonic(e))?
            .into_inner();

        // 检查响应中是否存在用户配置
        if resp.user_config.is_none() {
            return Err(Error::NotFound(String::from(
                "sync response's config is empty",
            )));
        }

        // 从响应数据构造 ConfigResp 对象
        let config = ConfigResp {
            status: resp.status() as i32,
            version_platform_data: resp.version_platform_data(),
            version_groups: resp.version_groups(),
            revision: resp.revision.take().unwrap_or_default(),
            config: resp.user_config.take().unwrap(),
            version_acls: resp.version_acls(),
            self_update_url: resp.self_update_url.take().unwrap_or_default(),
        };

        // 将配置结构格式化为调试字符串
        let c = format!("{:?}", config);

        // 返回 Config 消息和 Fin 结束消息
        Ok(vec![RpcMessage::Config(Some(c)), RpcMessage::Fin])
    }

    /// 获取采集网络类型
    pub(super) fn tap_types(&self) -> Result<Vec<RpcMessage>> {
        // 获取 RPC 响应
        let resp = self
            .runtime
            .block_on(self.get_rpc_response())
            .map_err(|e| Error::Tonic(e))?
            .into_inner();

        // 检查采集网络类型是否为空
        if resp.capture_network_types.is_empty() {
            return Err(Error::NotFound(String::from(
                "sync response's capture_network_types is empty",
            )));
        }

        // 将类型转换为 RpcMessage::CaptureNetworkTypes
        let mut res = resp
            .capture_network_types
            .into_iter()
            .map(|t| RpcMessage::CaptureNetworkTypes(Some(format!("{:?}", t))))
            .collect::<Vec<_>>();

        // 追加 Fin 结束消息
        res.push(RpcMessage::Fin);
        Ok(res)
    }

    /// 获取 CIDR 列表
    pub(super) fn cidrs(&self) -> Result<Vec<RpcMessage>> {
        // 获取 RPC 响应
        let resp = self
            .runtime
            .block_on(self.get_rpc_response())
            .map_err(|e| Error::Tonic(e))?
            .into_inner();

        // 检查平台数据版本，0 表示未准备好
        if resp.version_platform_data() == 0 {
            return Err(Error::NotFound(String::from("cidrs data in preparation")));
        }

        // 获取 status 写锁以更新平台数据
        let mut sg = self.status.write();
        sg.get_platform_data(&resp, false);
        
        // 收集 CIDR 到 RpcMessage::Cidr
        let mut res = sg
            .cidrs
            .iter()
            .map(|c| RpcMessage::Cidr(Some(format!("{:?}", c))))
            .collect::<Vec<_>>();

        // 追加 Fin 结束消息
        res.push(RpcMessage::Fin);
        Ok(res)
    }

    /// 获取平台数据（接口和对等端）
    pub(super) fn platform_data(&self) -> Result<Vec<RpcMessage>> {
        // 获取 RPC 响应
        let resp = self
            .runtime
            .block_on(self.get_rpc_response())
            .map_err(|e| Error::Tonic(e))?
            .into_inner();

        // 检查平台数据版本
        if resp.version_platform_data() == 0 {
            return Err(Error::NotFound(String::from(
                "platform data in preparation",
            )));
        }

        // 获取 status 写锁以更新平台数据
        let mut sg = self.status.write();
        sg.get_platform_data(&resp, false);
        
        // 收集接口和对等端信息到 RpcMessage::PlatformData
        let mut res = sg
            .interfaces
            .iter()
            .map(|p| RpcMessage::PlatformData(Some(format!("{:?}", p))))
            .chain(
                sg.peers
                    .iter()
                    .map(|p| RpcMessage::PlatformData(Some(format!("{:?}", p)))),
            )
            .collect::<Vec<_>>();

        // 追加 Fin 结束消息
        res.push(RpcMessage::Fin);
        Ok(res)
    }

    /// 获取 IP 资源组
    pub(super) fn ip_groups(&self) -> Result<Vec<RpcMessage>> {
        // 获取 RPC 响应
        let resp = self
            .runtime
            .block_on(self.get_rpc_response())
            .map_err(|e| Error::Tonic(e))?
            .into_inner();

        // 检查组版本
        if resp.version_groups() == 0 {
            return Err(Error::NotFound(String::from(
                "ip groups data in preparation",
            )));
        }

        // 获取 status 写锁以更新 IP 组
        let mut sg = self.status.write();
        sg.get_ip_groups(&resp, false);
        
        // 收集 IP 组信息到 RpcMessage::Groups
        let mut res = sg
            .ip_groups
            .iter()
            .map(|g| RpcMessage::Groups(Some(format!("{:?}", g))))
            .collect::<Vec<_>>();

        // 追加 Fin 结束消息
        res.push(RpcMessage::Fin);
        Ok(res)
    }

    /// 获取流控制策略 (ACLs)
    pub(super) fn flow_acls(&self) -> Result<Vec<RpcMessage>> {
        // 获取 RPC 响应
        let resp = self
            .runtime
            .block_on(self.get_rpc_response())
            .map_err(|e| Error::Tonic(e))?
            .into_inner();

        // 检查 ACL 版本
        if resp.version_acls() == 0 {
            return Err(Error::NotFound(String::from(
                "flow acls data in preparation",
            )));
        }

        // 获取 status 写锁以更新 Flow ACL
        let mut sg = self.status.write();
        sg.get_flow_acls(&resp, false);
        
        // 收集 ACL 信息到 RpcMessage::Acls
        let mut res = sg
            .acls
            .iter()
            .map(|a| RpcMessage::Acls(Some(format!("{:?}", a))))
            .collect::<Vec<_>>();

        // 追加 Fin 结束消息
        res.push(RpcMessage::Fin);
        Ok(res)
    }

    /// 获取本地网段
    pub(super) fn local_segments(&self) -> Result<Vec<RpcMessage>> {
        // 获取 RPC 响应
        let resp = self
            .runtime
            .block_on(self.get_rpc_response())
            .map_err(|e| Error::Tonic(e))?
            .into_inner();

        // 检查本地网段列表是否为空
        if resp.local_segments.is_empty() {
            return Err(Error::NotFound(
                "local segments data is empty, maybe zerotrace-agent is not properly configured"
                    .into(),
            ));
        };

        // 收集网段信息到 RpcMessage::Segments
        let mut segments = resp
            .local_segments
            .into_iter()
            .map(|s| RpcMessage::Segments(Some(format!("{:?}", s))))
            .collect::<Vec<_>>();

        // 追加 Fin 结束消息
        segments.push(RpcMessage::Fin);

        Ok(segments)
    }

    /// 获取当前版本信息
    pub(super) fn current_version(&self) -> Result<Vec<RpcMessage>> {
        // 获取 status 读锁
        let status = self.status.read();
        
        // 格式化包含不同数据类型版本的版本字符串
        let version = format!(
            "platformData version: {}\n groups version: {}\nflowAcls version: {}",
            status.version_platform_data, status.version_groups, status.version_acls
        );

        // 返回 Version 消息和 Fin 结束消息
        Ok(vec![RpcMessage::Version(Some(version)), RpcMessage::Fin])
    }
}
