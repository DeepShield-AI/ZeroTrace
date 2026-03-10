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

package ingesterctl

import "github.com/deepflowio/deepflow/server/libs/debug"

const (
	DEBUG_LISTEN_IP   = "::"
	DEBUG_LISTEN_PORT = 39527
)

// 这些常量是 DeepFlow Ingester 组件的调试模块标识符，用于构建统一的调试和监控系统。
// 每个模块ID对应一个特定的功能组件：
// 核心基础设施模块 (0-5): 包括适配器、队列、标签器、RPC、日志级别和配置管理
// 数据处理队列模块 (6-13): 涵盖了所有主要的数据处理管道，包括流量指标、流量日志、外部指标、PCAP、事件、Prometheus、性能分析和应用日志
const (
	INGESTERCTL_ADAPTER               debug.ModuleId = iota // 适配器模块，用于数据适配和转换
	INGESTERCTL_QUEUE                                       // 队列管理模块，用于调试和监控队列状态
	INGESTERCTL_LABELER                                     // 标签处理模块，用于数据标签的添加和管理
	INGESTERCTL_RPC                                         // RPC通信模块，用于远程过程调用调试
	INGESTERCTL_LOGLEVEL                                    // 日志级别控制模块，用于动态调整日志级别
	INGESTERCTL_CONFIG                                      // 配置管理模块，用于配置信息的调试和管理
	INGESTERCTL_FLOW_METRICS_QUEUE                          // 流量指标队列模块，用于网络流量指标数据的处理
	INGESTERCTL_FLOW_LOG_QUEUE                              // 流量日志队列模块，用于网络流日志数据的处理
	INGESTERCTL_EXTMETRICS_QUEUE                            // 外部指标队列模块，用于Prometheus等外部指标数据的处理
	INGESTERCTL_PCAP_QUEUE                                  // 数据包捕获队列模块，用于PCAP数据包的处理
	INGESTERCTL_EVENT_QUEUE                                 // 事件队列模块，用于各类事件数据的处理
	INGESTERCTL_PROMETHEUS_QUEUE                            // Prometheus队列模块，专门用于Prometheus指标数据处理
	INGESTERCTL_PROFILE_QUEUE                               // 性能分析队列模块，用于连续性能分析数据的处理
	INGESTERCTL_APPLICATION_LOG_QUEUE                       // 应用日志队列模块，用于应用日志数据的处理

	INGESTERCTL_MAX // 模块总数，用于边界检查和数组大小定义
)

// simple cmds
const (
	CMD_PLATFORMDATA_FLOW_METRIC debug.ModuleId = 33 + iota
	CMD_PLATFORMDATA_FLOW_LOG
	CMD_PLATFORMDATA_EXT_METRICS
	CMD_PLATFORMDATA_PROMETHEUS
	CMD_PROMETHEUS_LABEL
	CMD_L7_FLOW_LOG
	CMD_OTLP_EXPORTER
	TRIDENT_ADAPTER_STATUS_CMD // 40
	CMD_PLATFORMDATA_PROFILE
	CMD_KAFKA_EXPORTER
	CMD_PROMETHEUS_EXPORTER
	CMD_EXPORTER_PLATFORMDATA
	CMD_CONTINUOUS_PROFILER
	CMD_ORG_SWITCH
	CMD_FREE_OS_MEMORY
)

const (
	DEBUG_MESSAGE_LEN = 4096
)

var ConfigPath string
