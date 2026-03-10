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

package config

import (
	"os"

	logging "github.com/op/go-logging"
	yaml "gopkg.in/yaml.v2"

	"github.com/deepflowio/deepflow/server/ingester/config"
	"github.com/deepflowio/deepflow/server/ingester/config/configdefaults"
)

var log = logging.MustGetLogger("flow_log.config")

const (
	DefaultThrottle          = 50000
	DefaultThrottleBucket    = 3
	DefaultDecoderQueueCount = 2
	DefaultDecoderQueueSize  = 4096
	DefaultBrokerQueueSize   = 1 << 14
	DefaultFlowLogTTL        = 72 // hour
)

type FlowLogTTL struct {
	L4FlowLog int `yaml:"l4-flow-log"`
	L7FlowLog int `yaml:"l7-flow-log"`
	L4Packet  int `yaml:"l4-packet"`
}

// 流日志处理模块的核心配置结构，用于控制流日志数据的接收、解码、限流和存储行为
type Config struct {
	Base              *config.Config        // 基础配置，包含数据库连接、认证等通用配置
	CKWriterConfig    config.CKWriterConfig `yaml:"flowlog-ck-writer"`            // ClickHouse写入器配置，控制队列、批次等写入参数
	Throttle          int                   `yaml:"throttle"`                     // 全局流日志限流阈值，每秒处理的最大记录数
	ThrottleBucket    int                   `yaml:"throttle-bucket"`              // 限流桶大小，用于采样算法的精度控制
	L4Throttle        int                   `yaml:"l4-throttle"`                  // 四层流日志专用限流阈值，为0时使用全局限流
	L7Throttle        int                   `yaml:"l7-throttle"`                  // 七层流日志专用限流阈值，为0时使用全局限流
	FlowLogTTL        FlowLogTTL            `yaml:"flow-log-ttl-hour"`            // 流日志数据保留时间配置，单位为小时
	DecoderQueueCount int                   `yaml:"flow-log-decoder-queue-count"` // 解码器队列数量，控制并行处理度
	DecoderQueueSize  int                   `yaml:"flow-log-decoder-queue-size"`  // 解码器队列大小，控制缓冲容量
	TraceTreeEnabled  *bool                 `yaml:"flow-log-trace-tree-enabled"`  // 是否启用调用链树功能，用于分布式追踪
}

type FlowLogConfig struct {
	FlowLog Config `yaml:"ingester"`
}

func (c *Config) Validate() error {
	// Begin validation.
	if c.DecoderQueueCount == 0 {
		c.DecoderQueueCount = DefaultDecoderQueueCount
	}

	if c.FlowLogTTL.L4FlowLog == 0 {
		c.FlowLogTTL.L4FlowLog = DefaultFlowLogTTL
	}

	if c.FlowLogTTL.L7FlowLog == 0 {
		c.FlowLogTTL.L7FlowLog = DefaultFlowLogTTL
	}

	if c.FlowLogTTL.L4Packet == 0 {
		c.FlowLogTTL.L4Packet = DefaultFlowLogTTL
	}

	if c.TraceTreeEnabled == nil {
		value := configdefaults.FLOG_LOG_TRACE_TREE_ENABLED_DEFAULT
		c.TraceTreeEnabled = &value
	}

	return nil
}

func Load(base *config.Config, path string) *Config {
	config := &FlowLogConfig{
		FlowLog: Config{
			Base:              base,
			Throttle:          DefaultThrottle,
			ThrottleBucket:    DefaultThrottleBucket,
			DecoderQueueCount: DefaultDecoderQueueCount,
			DecoderQueueSize:  DefaultDecoderQueueSize,
			CKWriterConfig:    config.CKWriterConfig{QueueCount: 1, QueueSize: 256000, BatchSize: 128000, FlushTimeout: 10},
			FlowLogTTL:        FlowLogTTL{DefaultFlowLogTTL, DefaultFlowLogTTL, DefaultFlowLogTTL},
		},
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Info("no config file, use defaults")
		return &config.FlowLog
	}
	configBytes, err := os.ReadFile(path)
	if err != nil {
		log.Warning("Read config file error:", err)
		config.FlowLog.Validate()
		return &config.FlowLog
	}
	if err = yaml.Unmarshal(configBytes, &config); err != nil {
		log.Error("Unmarshal yaml error:", err)
		os.Exit(1)
	}

	if err = config.FlowLog.Validate(); err != nil {
		log.Error(err)
		os.Exit(1)
	}
	return &config.FlowLog
}
