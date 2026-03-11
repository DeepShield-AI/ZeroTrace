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

package flow_log

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	logging "github.com/op/go-logging"
	_ "golang.org/x/net/context"
	_ "google.golang.org/grpc"

	dropletqueue "github.com/zerotraceio/zerotrace/server/ingester/droplet/queue"
	"github.com/zerotraceio/zerotrace/server/ingester/exporters"
	"github.com/zerotraceio/zerotrace/server/ingester/flow_log/common"
	"github.com/zerotraceio/zerotrace/server/ingester/flow_log/config"
	"github.com/zerotraceio/zerotrace/server/ingester/flow_log/dbwriter"
	"github.com/zerotraceio/zerotrace/server/ingester/flow_log/decoder"
	"github.com/zerotraceio/zerotrace/server/ingester/flow_log/geo"
	"github.com/zerotraceio/zerotrace/server/ingester/flow_log/throttler"
	"github.com/zerotraceio/zerotrace/server/ingester/flow_tag"
	"github.com/zerotraceio/zerotrace/server/ingester/ingesterctl"
	"github.com/zerotraceio/zerotrace/server/libs/ckdb"
	"github.com/zerotraceio/zerotrace/server/libs/datatype"
	"github.com/zerotraceio/zerotrace/server/libs/debug"
	"github.com/zerotraceio/zerotrace/server/libs/grpc"
	"github.com/zerotraceio/zerotrace/server/libs/queue"
	libqueue "github.com/zerotraceio/zerotrace/server/libs/queue"
	"github.com/zerotraceio/zerotrace/server/libs/receiver"
)

var log = logging.MustGetLogger("flow_log")

// 负责协调多种类型的数据处理管道
type FlowLog struct {
	FlowLogConfig        *config.Config            // 流日志配置，包含所有流日志相关的配置参数
	L4FlowLogger         *Logger                   // 四层流日志处理器，处理网络层和传输层的流数据
	L7FlowLogger         *Logger                   // 七层流日志处理器，处理应用层协议的流数据
	OtelLogger           *Logger                   // OpenTelemetry日志处理器，处理OTLP格式的遥测数据
	OtelCompressedLogger *Logger                   // 压缩的OpenTelemetry日志处理器，处理压缩的OTLP数据
	L4PacketLogger       *Logger                   // 四层数据包日志处理器，处理原始数据包序列数据
	SkyWalkingLogger     *Logger                   // SkyWalking日志处理器，处理SkyWalking格式的链路追踪数据
	DdogLogger           *Logger                   // DataDog日志处理器，处理DataDog格式的监控数据
	Exporters            *exporters.Exporters      // 数据导出器集合，将数据导出到外部系统
	SpanWriter           *dbwriter.SpanWriter      // Span数据写入器，将链路追踪Span写入数据库
	TraceTreeWriter      *dbwriter.TraceTreeWriter // 链路树写入器，构建和写入完整的调用链树结构
}

type Logger struct {
	Config        *config.Config            //存储流日志处理相关的配置参数，如队列大小、限流设置等
	Decoders      []*decoder.Decoder        //并行解码器数组，每个解码器处理一个队列的数据，支持多线程解码
	PlatformDatas []*grpc.PlatformInfoTable //平台信息表数组，用于存储从 Controller 获取的资源元数据（如 VPC、子网、Pod 信息）
	FlowLogWriter *dbwriter.FlowLogWriter   //流日志写入器，负责将解码后的数据批量写入 ClickHouse 数据库
}

func NewFlowLog(config *config.Config, traceTreeQueue *queue.OverwriteQueue, recv *receiver.Receiver, platformDataManager *grpc.PlatformDataManager, exporters *exporters.Exporters) (*FlowLog, error) {
	manager := dropletqueue.NewManager(ingesterctl.INGESTERCTL_FLOW_LOG_QUEUE)

	if config.Base.StorageDisabled {
		// 如果关闭存储，则只创建L7FlowLogger，其他组件不创建
		l7FlowLogger, err := NewL7FlowLogger(config, platformDataManager, manager, recv, nil, exporters, nil)
		if err != nil {
			return nil, err
		}
		return &FlowLog{
			L7FlowLogger: l7FlowLogger,
			Exporters:    exporters,
		}, nil
	}

	geo.NewGeoTree()
	//flowLogWriter 是流日志管道的 ClickHouse 写入器，负责将 L4/L7 流日志数据批量写入 ClickHouse，并管理多组织数据库初始化
	flowLogWriter, err := dbwriter.NewFlowLogWriter(
		*config.Base.CKDB.ActualAddrs, config.Base.CKDBAuth.Username, config.Base.CKDBAuth.Password,
		config.Base.CKDB.ClusterName, config.Base.CKDB.StoragePolicy, config.Base.CKDB.TimeZone, config.Base.CKDB.Type,
		config.CKWriterConfig, config.FlowLogTTL, config.Base.GetCKDBColdStorages(), config.Base.CKDB.Watcher)
	if err != nil {
		return nil, err
	}
	//spanWriter：将符合条件的 Span（含 TraceID）编码后写入 span_with_trace_id 表，供调用链查询
	spanWriter, err := dbwriter.NewSpanWriter(config)
	if err != nil {
		return nil, err
	}
	//traceTreeWriter：消费来自 Querier 的 TraceTree 队列，持久化追踪树数据
	traceTreeWriter, err := dbwriter.NewTraceTreeWriter(config, traceTreeQueue)
	if err != nil {
		return nil, err
	}

	// L4FlowLogger：处理 MESSAGE_TYPE_TAGGEDFLOW，解码为 L4FlowLog，写入 l4_flow_log 表 flow_log.go:203-254 。
	//7FlowLogger：处理 MESSAGE_TYPE_PROTOCOLLOG，解码为 L7FlowLog，写入 l7_flow_log 表，并生成 Span 与应用服务标签
	l4FlowLogger := NewL4FlowLogger(config, platformDataManager, manager, recv, flowLogWriter, exporters)

	l7FlowLogger, err := NewL7FlowLogger(config, platformDataManager, manager, recv, flowLogWriter, exporters, spanWriter)
	if err != nil {
		return nil, err
	}
	//otelLogger：处理未压缩的 OTLP Traces，转换为 L7FlowLog，写入流日志并生成 Span
	otelLogger, err := NewLogger(datatype.MESSAGE_TYPE_OPENTELEMETRY, config, platformDataManager, manager, recv, flowLogWriter, common.L7_FLOW_ID, nil, spanWriter)
	if err != nil {
		return nil, err
	}
	//otelCompressedLogger：处理压缩的 OTLP 数据，逻辑同上，只是先解压
	otelCompressedLogger, err := NewLogger(datatype.MESSAGE_TYPE_OPENTELEMETRY_COMPRESSED, config, platformDataManager, manager, recv, flowLogWriter, common.L7_FLOW_ID, nil, spanWriter)
	if err != nil {
		return nil, err
	}
	//l4PacketLogger：处理 MESSAGE_TYPE_PACKETSEQUENCE，用于原始包捕获与 PCAP 策略，写入 l4_packet 表
	l4PacketLogger, err := NewLogger(datatype.MESSAGE_TYPE_PACKETSEQUENCE, config, nil, manager, recv, flowLogWriter, common.L4_PACKET_ID, nil, nil)
	if err != nil {
		return nil, err
	}
	//skywalkingLogger：处理 SkyWalking Segment，转换为 L7FlowLog 并生成 Span
	skywalkingLogger, err := NewLogger(datatype.MESSAGE_TYPE_SKYWALKING, config, platformDataManager, manager, recv, flowLogWriter, common.L7_FLOW_ID, nil, spanWriter)
	if err != nil {
		return nil, err
	}
	//ddogLogger：处理 DataDog Trace，逻辑同 SkyWalking
	ddogLogger, err := NewLogger(datatype.MESSAGE_TYPE_DATADOG, config, platformDataManager, manager, recv, flowLogWriter, common.L7_FLOW_ID, nil, spanWriter)
	if err != nil {
		return nil, err
	}
	return &FlowLog{
		FlowLogConfig:        config,
		L4FlowLogger:         l4FlowLogger,
		L7FlowLogger:         l7FlowLogger,
		OtelLogger:           otelLogger,
		OtelCompressedLogger: otelCompressedLogger,
		L4PacketLogger:       l4PacketLogger,
		SkyWalkingLogger:     skywalkingLogger,
		DdogLogger:           ddogLogger,
		Exporters:            exporters,
		SpanWriter:           spanWriter,
		TraceTreeWriter:      traceTreeWriter,
	}, nil
}

func NewLogger(msgType datatype.MessageType, config *config.Config, platformDataManager *grpc.PlatformDataManager, manager *dropletqueue.Manager, recv *receiver.Receiver, flowLogWriter *dbwriter.FlowLogWriter, flowLogId common.FlowLogID, exporters *exporters.Exporters, spanWriter *dbwriter.SpanWriter) (*Logger, error) {
	queueCount := config.DecoderQueueCount
	decodeQueues := manager.NewQueues(
		"1-receive-to-decode-"+datatype.MessageTypeString[msgType],
		config.DecoderQueueSize,
		queueCount,
		1,
		libqueue.OptionFlushIndicator(3*time.Second),
		libqueue.OptionRelease(func(p interface{}) { receiver.ReleaseRecvBuffer(p.(*receiver.RecvBuffer)) }))
	recv.RegistHandler(msgType, decodeQueues, queueCount)
	throttle := config.Throttle / queueCount

	throttlers := make([]*throttler.ThrottlingQueue, queueCount)
	decoders := make([]*decoder.Decoder, queueCount)
	platformDatas := make([]*grpc.PlatformInfoTable, queueCount)
	for i := 0; i < queueCount; i++ {
		flowTagWriter, err := flow_tag.NewFlowTagWriter(i, msgType.String(), common.FLOW_LOG_DB, config.FlowLogTTL.L7FlowLog, ckdb.TimeFuncTwelveHour, config.Base, &config.CKWriterConfig)
		if err != nil {
			return nil, err
		}
		appServiceTagWriter, err := flow_tag.NewAppServiceTagWriter(i, common.FLOW_LOG_DB, msgType.String(), config.FlowLogTTL.L7FlowLog, ckdb.TimeFuncTwelveHour, config.Base)
		if err != nil {
			return nil, err
		}
		throttlers[i] = throttler.NewThrottlingQueue(
			throttle,
			config.ThrottleBucket,
			flowLogWriter,
			int(flowLogId),
		)
		if platformDataManager != nil {
			platformDatas[i], _ = platformDataManager.NewPlatformInfoTable("flow-log-" + datatype.MessageTypeString[msgType] + "-" + strconv.Itoa(i))
			if i == 0 {
				debug.ServerRegisterSimple(ingesterctl.CMD_PLATFORMDATA_FLOW_LOG, platformDatas[i])
			}
		}
		decoders[i] = decoder.NewDecoder(
			i,
			msgType,
			platformDatas[i],
			queue.QueueReader(decodeQueues.FixedMultiQueue[i]),
			throttlers[i],
			flowTagWriter,
			appServiceTagWriter,
			spanWriter,
			exporters,
			config,
		)
	}
	return &Logger{
		Config:        config,
		Decoders:      decoders,
		PlatformDatas: platformDatas,
		FlowLogWriter: flowLogWriter,
	}, nil
}

func NewL4FlowLogger(config *config.Config, platformDataManager *grpc.PlatformDataManager, manager *dropletqueue.Manager, recv *receiver.Receiver, flowLogWriter *dbwriter.FlowLogWriter, exporters *exporters.Exporters) *Logger {
	msgType := datatype.MESSAGE_TYPE_TAGGEDFLOW
	queueCount := config.DecoderQueueCount
	queueSuffix := "-l4"
	decodeQueues := manager.NewQueues(
		"1-receive-to-decode"+queueSuffix,
		config.DecoderQueueSize,
		queueCount,
		1,
		libqueue.OptionFlushIndicator(3*time.Second),
		libqueue.OptionRelease(func(p interface{}) { receiver.ReleaseRecvBuffer(p.(*receiver.RecvBuffer)) }))

	recv.RegistHandler(msgType, decodeQueues, queueCount)

	throttle := config.Throttle / queueCount
	if config.L4Throttle != 0 {
		throttle = config.L4Throttle / queueCount
	}

	throttlers := make([]*throttler.ThrottlingQueue, queueCount)
	decoders := make([]*decoder.Decoder, queueCount)
	platformDatas := make([]*grpc.PlatformInfoTable, queueCount)

	for i := 0; i < queueCount; i++ {
		throttlers[i] = throttler.NewThrottlingQueue(
			throttle,
			config.ThrottleBucket,
			flowLogWriter,
			int(common.L4_FLOW_ID),
		)
		// 避免锁竞争：PlatformInfoTable包含大量的缓存数据（IP信息、Pod信息、服务信息等），如果多个数据类型共享，会产生严重的锁竞争 grpc_platformdata.go:497-521 。
		// 独立缓存策略：不同数据类型对平台数据的访问模式不同：

		// L4流日志主要查询IP-MAC映射
		// L7流日志需要服务、Pod信息
		// Flow metrics需要资源信息
		platformDatas[i], _ = platformDataManager.NewPlatformInfoTable("l4-flow-log-" + strconv.Itoa(i))
		if i == 0 {
			debug.ServerRegisterSimple(ingesterctl.CMD_PLATFORMDATA_FLOW_LOG, platformDatas[i])
		}
		decoders[i] = decoder.NewDecoder(
			i,
			msgType,
			platformDatas[i],
			queue.QueueReader(decodeQueues.FixedMultiQueue[i]),
			throttlers[i],
			nil, nil, nil,
			exporters,
			config,
		)
	}
	return &Logger{
		Config:        config,
		Decoders:      decoders,
		PlatformDatas: platformDatas,
		FlowLogWriter: flowLogWriter,
	}
}

func NewL7FlowLogger(config *config.Config, platformDataManager *grpc.PlatformDataManager, manager *dropletqueue.Manager, recv *receiver.Receiver, flowLogWriter *dbwriter.FlowLogWriter, exporters *exporters.Exporters, spanWriter *dbwriter.SpanWriter) (*Logger, error) {
	//设置 L7 专用队列后缀 -l7 和消息类型 MESSAGE_TYPE_PROTOCOLLOG
	queueSuffix := "-l7"
	queueCount := config.DecoderQueueCount
	msgType := datatype.MESSAGE_TYPE_PROTOCOLLOG

	//创建多队列解码管道，支持并行处理
	decodeQueues := manager.NewQueues(
		"1-receive-to-decode"+queueSuffix,
		config.DecoderQueueSize,
		queueCount,
		1,
		libqueue.OptionFlushIndicator(3*time.Second),
		libqueue.OptionRelease(func(p interface{}) { receiver.ReleaseRecvBuffer(p.(*receiver.RecvBuffer)) }))

	// 注册接收器处理 L7 协议日志消息，用于注册消息类型与处理队列映射关系的关键方法
	recv.RegistHandler(msgType, decodeQueues, queueCount)

	throttle := config.Throttle / queueCount
	if config.L7Throttle != 0 {
		throttle = config.L7Throttle / queueCount
	}
	//计算每个队列的限流阈值，支持全局和 L7 专用限流配置
	throttlers := make([]*throttler.ThrottlingQueue, queueCount)

	platformDatas := make([]*grpc.PlatformInfoTable, queueCount)
	decoders := make([]*decoder.Decoder, queueCount)
	var flowTagWriter *flow_tag.FlowTagWriter
	var appServiceTagWriter *flow_tag.AppServiceTagWriter
	var err error
	for i := 0; i < queueCount; i++ {
		if flowLogWriter != nil {
			//为每个队列创建完整的处理组件，包括流标签写入器和应用服务标签写入器，以及限流队列
			flowTagWriter, err = flow_tag.NewFlowTagWriter(i, msgType.String(), common.FLOW_LOG_DB, config.FlowLogTTL.L7FlowLog, ckdb.TimeFuncTwelveHour, config.Base, &config.CKWriterConfig)
			if err != nil {
				return nil, err
			}
			appServiceTagWriter, err = flow_tag.NewAppServiceTagWriter(i, common.FLOW_LOG_DB, msgType.String(), config.FlowLogTTL.L7FlowLog, ckdb.TimeFuncTwelveHour, config.Base)
			if err != nil {
				return nil, err
			}
		}
		throttlers[i] = throttler.NewThrottlingQueue(
			throttle,
			config.ThrottleBucket,
			flowLogWriter,
			int(common.L7_FLOW_ID),
		)
		//创建 L7 流日志专用的平台信息表
		platformDatas[i], _ = platformDataManager.NewPlatformInfoTable("l7-flow-log-" + strconv.Itoa(i))
		if i == 0 {
			debug.ServerRegisterSimple(ingesterctl.CMD_PLATFORMDATA_FLOW_LOG, platformDatas[i])
		}
		decoders[i] = decoder.NewDecoder(
			i,
			msgType,
			platformDatas[i],
			queue.QueueReader(decodeQueues.FixedMultiQueue[i]),
			throttlers[i],
			flowTagWriter,
			appServiceTagWriter,
			spanWriter,
			exporters,
			config,
		)
	}

	l := &Logger{
		Config:        config,
		Decoders:      decoders,
		PlatformDatas: platformDatas,
	}
	debug.ServerRegisterSimple(ingesterctl.CMD_L7_FLOW_LOG, l)
	return l, nil
}

func (l *Logger) HandleSimpleCommand(op uint16, arg string) string {
	sb := &strings.Builder{}
	sb.WriteString("last 10s counter:\n")
	for i, d := range l.Decoders {
		sb.WriteString(fmt.Sprintf("  decoder %d: %+v\n", i, d.GetLastCounter()))
	}
	return sb.String()
}

func (l *Logger) Start() {
	// 启动所有平台数据表，用于数据 enrichment
	for _, platformData := range l.PlatformDatas {
		if platformData != nil {
			platformData.Start()
		}
	}
	//! 并发启动所有解码器，负责从hander的处理队列中解析数据
	for _, decoder := range l.Decoders {
		go decoder.Run()
	}
}

func (l *Logger) Close() {
	for _, platformData := range l.PlatformDatas {
		if platformData != nil {
			platformData.ClosePlatformInfoTable()
		}
	}
}

func (s *FlowLog) Start() {
	if s.L4FlowLogger != nil {
		s.L4FlowLogger.Start()
	}
	if s.L7FlowLogger != nil {
		s.L7FlowLogger.Start()
	}
	if s.L4PacketLogger != nil {
		s.L4PacketLogger.Start()
	}
	if s.OtelLogger != nil {
		s.OtelLogger.Start()
	}
	if s.OtelCompressedLogger != nil {
		s.OtelCompressedLogger.Start()
	}
	if s.SkyWalkingLogger != nil {
		s.SkyWalkingLogger.Start()
	}
	if s.DdogLogger != nil {
		s.DdogLogger.Start()
	}
	if s.SpanWriter != nil {
		s.SpanWriter.Start()
	}
	if s.TraceTreeWriter != nil {
		s.TraceTreeWriter.Start()
	}
}

func (s *FlowLog) Close() error {
	if s.L4FlowLogger != nil {
		s.L4FlowLogger.Close()
	}
	if s.L7FlowLogger != nil {
		s.L7FlowLogger.Close()
	}
	if s.L4PacketLogger != nil {
		s.L4PacketLogger.Close()
	}
	if s.OtelLogger != nil {
		s.OtelLogger.Close()
	}
	if s.OtelCompressedLogger != nil {
		s.OtelCompressedLogger.Close()
	}
	if s.SkyWalkingLogger != nil {
		s.SkyWalkingLogger.Close()
	}
	if s.DdogLogger != nil {
		s.DdogLogger.Close()
	}
	if s.SpanWriter != nil {
		s.SpanWriter.Close()
	}
	if s.TraceTreeWriter != nil {
		s.TraceTreeWriter.Close()
	}
	return nil
}
