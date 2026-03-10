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

package ext_metrics

import (
	"strconv"
	"time"

	_ "golang.org/x/net/context"
	_ "google.golang.org/grpc"

	dropletqueue "github.com/deepflowio/deepflow/server/ingester/droplet/queue"
	"github.com/deepflowio/deepflow/server/ingester/ext_metrics/config"
	"github.com/deepflowio/deepflow/server/ingester/ext_metrics/dbwriter"
	"github.com/deepflowio/deepflow/server/ingester/ext_metrics/decoder"
	"github.com/deepflowio/deepflow/server/ingester/ingesterctl"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/debug"
	"github.com/deepflowio/deepflow/server/libs/grpc"
	"github.com/deepflowio/deepflow/server/libs/queue"
	libqueue "github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/receiver"
)

const (
	CMD_PLATFORMDATA_EXT_METRICS = 35
)

// ExtMetrics 外部指标处理组件
// 该组件负责处理来自不同来源的外部指标数据，包括Telegraf指标、DeepFlow代理统计和服务器统计
// 它是DeepFlow Ingester组件中专门处理外部指标数据的模块
type ExtMetrics struct {
	// Config 全局配置对象，包含数据库连接、队列配置等参数
	Config *config.Config
	// Telegraf Telegraf指标处理器，处理来自Telegraf的influxdb格式指标数据
	Telegraf *Metricsor
	// DeepflowAgentStats DeepFlow代理统计处理器，处理来自DeepFlow代理的性能指标
	DeepflowAgentStats *Metricsor
	// DeepflowStats DeepFlow服务器统计处理器，处理来自DeepFlow服务器的性能指标
	DeepflowStats *Metricsor
}

// Metricsor 指标处理器
// 该结构体是处理特定类型指标数据的核心组件，包含解码器、平台数据和写入器
type Metricsor struct {
	// Config 配置对象，包含解码器队列大小、写入器配置等参数
	Config *config.Config
	// Decoders 解码器数组，每个解码器在独立的goroutine中处理指标数据
	Decoders []*decoder.Decoder
	// PlatformDataEnabled 是否启用平台数据功能，用于数据富化和上下文补充
	PlatformDataEnabled bool
	// PlatformDatas 平台数据表数组，每个解码器对应一个平台数据表实例
	PlatformDatas []*grpc.PlatformInfoTable
	// Writers 写入器数组，支持将数据写入不同的数据库（如管理库、租户库等）
	Writers [dbwriter.MAX_DB_ID]*dbwriter.ExtMetricsWriter
}

// NewExtMetrics 创建外部指标处理组件实例
// 该函数初始化三种不同类型的指标处理器，构建完整的外部指标处理流水线
// 参数:
//   - config: 全局配置对象
//   - recv: 接收器实例，用于接收来自代理的指标数据
//   - platformDataManager: 平台数据管理器，提供数据富化功能
//
// 返回:
//   - *ExtMetrics: 外部指标处理组件实例
//   - error: 创建过程中的错误
func NewExtMetrics(config *config.Config, recv *receiver.Receiver, platformDataManager *grpc.PlatformDataManager) (*ExtMetrics, error) {
	// 创建队列管理器，用于管理接收器到解码器的数据队列
	// INGESTERCTL_EXTMETRICS_QUEUE 定义了外部指标的队列配置
	manager := dropletqueue.NewManager(ingesterctl.INGESTERCTL_EXTMETRICS_QUEUE)

	// 创建Telegraf指标处理器
	// MESSAGE_TYPE_TELEGRAF: 处理Telegraf发送的influxdb格式指标
	// EXT_METRICS_DB_ID: 数据写入外部指标数据库
	// true: 启用平台数据功能，用于数据富化
	telegraf, err := NewMetricsor(datatype.MESSAGE_TYPE_TELEGRAF, []dbwriter.WriterDBID{dbwriter.EXT_METRICS_DB_ID}, config, platformDataManager, manager, recv, true)
	if err != nil {
		return nil, err
	}

	// 创建DeepFlow代理统计处理器
	// MESSAGE_TYPE_DFSTATS: 处理来自DeepFlow代理的性能指标
	// DEEPFLOW_ADMIN_DB_ID, DEEPFLOW_TENANT_DB_ID: 根据组织ID写入管理库或租户库
	// false: 不启用平台数据功能，因为代理统计数据不需要富化
	deepflowAgentStats, err := NewMetricsor(datatype.MESSAGE_TYPE_DFSTATS, []dbwriter.WriterDBID{dbwriter.DEEPFLOW_ADMIN_DB_ID, dbwriter.DEEPFLOW_TENANT_DB_ID}, config, platformDataManager, manager, recv, false)
	if err != nil {
		return nil, err
	}

	// 创建DeepFlow服务器统计处理器
	// MESSAGE_TYPE_SERVER_DFSTATS: 处理来自DeepFlow服务器的性能指标
	// DEEPFLOW_ADMIN_DB_ID, DEEPFLOW_TENANT_DB_ID: 根据组织ID写入管理库或租户库
	// false: 不启用平台数据功能，因为服务器统计数据不需要富化
	deepflowStats, err := NewMetricsor(datatype.MESSAGE_TYPE_SERVER_DFSTATS, []dbwriter.WriterDBID{dbwriter.DEEPFLOW_ADMIN_DB_ID, dbwriter.DEEPFLOW_TENANT_DB_ID}, config, platformDataManager, manager, recv, false)
	if err != nil {
		return nil, err
	}

	// 返回组装完成的外部指标处理组件
	return &ExtMetrics{
		Config:             config,
		Telegraf:           telegraf,
		DeepflowAgentStats: deepflowAgentStats,
		DeepflowStats:      deepflowStats,
	}, nil
}

// NewMetricsor 创建指标处理器实例
// 该函数构建完整的指标数据处理流水线，包括队列管理、解码器、平台数据和写入器
// 参数:
//   - msgType: 消息类型，标识要处理的指标数据类型（如Telegraf、DeepFlow统计等）
//   - flowTagTablePrefixs: 流标签表前缀数组，指定数据写入的目标数据库
//   - config: 配置对象，包含队列大小、解码器数量等参数
//   - platformDataManager: 平台数据管理器，提供数据富化功能
//   - manager: 队列管理器，用于管理数据队列
//   - recv: 接收器，用于接收来自代理的指标数据
//   - platformDataEnabled: 是否启用平台数据功能
//
// 返回:
//   - *Metricsor: 配置完成的指标处理器实例
//   - error: 创建过程中的错误
func NewMetricsor(msgType datatype.MessageType, flowTagTablePrefixs []dbwriter.WriterDBID, config *config.Config, platformDataManager *grpc.PlatformDataManager, manager *dropletqueue.Manager, recv *receiver.Receiver, platformDataEnabled bool) (*Metricsor, error) {
	// 获取解码器队列数量，用于并行处理
	queueCount := config.DecoderQueueCount

	// 创建解码队列，用于从接收器到解码器的数据传输
	// 队列名称格式: "1-receive-to-decode-{消息类型}"
	decodeQueues := manager.NewQueues(
		"1-receive-to-decode-"+msgType.String(),
		config.DecoderQueueSize,
		queueCount,
		1,
		libqueue.OptionFlushIndicator(3*time.Second),
		libqueue.OptionRelease(func(p interface{}) { receiver.ReleaseRecvBuffer(p.(*receiver.RecvBuffer)) }))
	// 注册消息处理器，将指定类型的消息路由到解码队列
	recv.RegistHandler(msgType, decodeQueues, queueCount)

	// 初始化解码器数组和平台数据数组
	decoders := make([]*decoder.Decoder, queueCount)
	platformDatas := make([]*grpc.PlatformInfoTable, queueCount)

	// 为每个队列创建对应的解码器和相关组件
	for i := 0; i < queueCount; i++ {
		// 如果启用平台数据功能，创建平台数据表
		if platformDataEnabled {
			var err error
			// 创建平台数据表，用于数据富化和上下文补充
			// 表名格式: "ext-metrics-{消息类型}-{索引}"
			platformDatas[i], err = platformDataManager.NewPlatformInfoTable("ext-metrics-" + msgType.String() + "-" + strconv.Itoa(i))
			if i == 0 {
				// 为第一个平台数据表注册调试接口
				debug.ServerRegisterSimple(CMD_PLATFORMDATA_EXT_METRICS, platformDatas[i])
			}
			if err != nil {
				return nil, err
			}
		}

		// 创建指标写入器数组，支持写入多个数据库
		var metricsWriters [dbwriter.MAX_DB_ID]*dbwriter.ExtMetricsWriter
		for _, tableId := range flowTagTablePrefixs {
			// 为每个目标数据库创建写入器
			metricsWriter, err := dbwriter.NewExtMetricsWriter(i, msgType, tableId.String(), config)
			if err != nil {
				return nil, err
			}
			metricsWriters[tableId] = metricsWriter
		}

		// 创建解码器实例
		decoders[i] = decoder.NewDecoder(
			i,                // 解码器索引
			msgType,          // 消息类型
			platformDatas[i], // 平台数据表
			queue.QueueReader(decodeQueues.FixedMultiQueue[i]), // 队列读取器
			metricsWriters, // 指标写入器数组
			config,         // 配置对象
		)
	}

	// 返回配置完成的Metricsor实例
	return &Metricsor{
		Config:              config,              // 配置对象
		Decoders:            decoders,            // 解码器数组
		PlatformDataEnabled: platformDataEnabled, // 平台数据启用标志
		PlatformDatas:       platformDatas,       // 平台数据表数组
	}, nil
}

func (m *Metricsor) Start() {
	if m.PlatformDataEnabled {
		for _, platformData := range m.PlatformDatas {
			platformData.Start()
		}
	}

	for _, decoder := range m.Decoders {
		go decoder.Run()
	}
}

func (m *Metricsor) Close() {
	for _, platformData := range m.PlatformDatas {
		if m.PlatformDataEnabled {
			platformData.ClosePlatformInfoTable()
		}
	}
}

func (s *ExtMetrics) Start() {
	s.Telegraf.Start()
	s.DeepflowAgentStats.Start()
	s.DeepflowStats.Start()
}

func (s *ExtMetrics) Close() error {
	s.Telegraf.Close()
	s.DeepflowAgentStats.Close()
	s.DeepflowStats.Close()
	return nil
}
