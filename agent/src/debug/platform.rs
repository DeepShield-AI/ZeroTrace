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

use crate::platform::{ApiWatcher, GenericPoller, Poller};

/// 平台模块调试消息
#[derive(PartialEq, Eq, Debug, Encode, Decode)]
pub enum PlatformMessage {
    Version(Option<String>),              // API 版本
    Watcher(Vec<u8>),                     // K8s Watcher 资源数据
    MacMappings(Option<Vec<(u32, String)>>), // 容器 MAC 到接口索引映射
    Fin,                                  // 消息流结束
    NotFound,                             // 资源未找到
}

/// 平台模块调试器
pub struct PlatformDebugger {
    api: Arc<ApiWatcher>,       // K8s API 监听器访问
    poller: Arc<GenericPoller>, // 平台轮询器访问
}

impl PlatformDebugger {
    /// 创建一个新的 PlatformDebugger
    pub(super) fn new(api: Arc<ApiWatcher>, poller: Arc<GenericPoller>) -> Self {
        Self { api, poller }
    }

    /// 获取指定资源的 Watcher 条目
    pub(super) fn watcher(&self, resource: impl AsRef<str>) -> Vec<PlatformMessage> {
        // entries 字节可能会大于MAX_MESSAGE_SIZE,要分开发送
        // 从 API watcher 获取条目
        let entries = self.api.get_watcher_entries(resource);
        match entries {
            Some(es) => {
                // 将条目映射为 Watcher 消息
                let mut res = es
                    .into_iter()
                    .map(|s| PlatformMessage::Watcher(s))
                    .collect::<Vec<_>>();
                // 追加 Fin 结束消息
                res.push(PlatformMessage::Fin);
                res
            }
            // 如果条目为 None，返回 NotFound
            None => vec![PlatformMessage::NotFound],
        }
    }

    /// 获取 API Server 版本
    pub(super) fn api_version(&self) -> Vec<PlatformMessage> {
        // 从 API watcher 获取版本
        let v = self.api.get_server_version();
        // 返回 Version 消息和 Fin
        vec![PlatformMessage::Version(v), PlatformMessage::Fin]
    }

    /// 获取 MAC 地址到接口索引的映射
    pub(super) fn mac_mapping(&self) -> Vec<PlatformMessage> {
        // 从 poller 获取接口信息并映射为 (tap_idx, mac) 元组
        let mut mappings = self
            .poller
            .get_interface_info()
            .into_iter()
            .map(|i| (i.tap_idx, i.mac.to_string()))
            .collect::<Vec<_>>();
        // 对映射进行排序
        mappings.sort();
        // 返回 MacMappings 消息和 Fin
        vec![
            PlatformMessage::MacMappings(Some(mappings)),
            PlatformMessage::Fin,
        ]
    }
}
