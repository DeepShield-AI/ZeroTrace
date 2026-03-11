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

package decoder

import (
	"bytes"
	"compress/zlib"
	"io"
	"strconv"
	"time"

	"github.com/golang/protobuf/proto"
	logging "github.com/op/go-logging"
	v1 "go.opentelemetry.io/proto/otlp/trace/v1"

	"github.com/zerotraceio/zerotrace/server/ingester/common"
	"github.com/zerotraceio/zerotrace/server/ingester/exporters"
	exportcommon "github.com/zerotraceio/zerotrace/server/ingester/exporters/common"
	exportconfig "github.com/zerotraceio/zerotrace/server/ingester/exporters/config"
	flowlogcommon "github.com/zerotraceio/zerotrace/server/ingester/flow_log/common"
	"github.com/zerotraceio/zerotrace/server/ingester/flow_log/config"
	"github.com/zerotraceio/zerotrace/server/ingester/flow_log/dbwriter"
	"github.com/zerotraceio/zerotrace/server/ingester/flow_log/log_data"
	"github.com/zerotraceio/zerotrace/server/ingester/flow_log/log_data/dd_import"
	"github.com/zerotraceio/zerotrace/server/ingester/flow_log/log_data/sw_import"
	"github.com/zerotraceio/zerotrace/server/ingester/flow_log/throttler"
	"github.com/zerotraceio/zerotrace/server/ingester/flow_tag"
	"github.com/zerotraceio/zerotrace/server/libs/codec"
	"github.com/zerotraceio/zerotrace/server/libs/datatype"
	"github.com/zerotraceio/zerotrace/server/libs/datatype/pb"
	flow_metrics "github.com/zerotraceio/zerotrace/server/libs/flow-metrics"
	"github.com/zerotraceio/zerotrace/server/libs/grpc"
	"github.com/zerotraceio/zerotrace/server/libs/queue"
	"github.com/zerotraceio/zerotrace/server/libs/receiver"
	"github.com/zerotraceio/zerotrace/server/libs/stats"
	"github.com/zerotraceio/zerotrace/server/libs/utils"
)

var log = logging.MustGetLogger("flow_log.decoder")

const (
	BUFFER_SIZE  = 1024
	L7_PROTO_MAX = datatype.L7_PROTOCOL_DNS + 1
)

// 流日志解码器的统计指标集合
type Counter struct {
	// RawCount 原始数据包计数，统计从队列接收的原始数据包数量
	// 不包括解码失败的数据，用于监控输入数据量
	RawCount int64 `statsd:"raw-count"`

	// L7HTTPCount HTTP协议处理计数，统计HTTP/1和HTTP/2协议的处理数量
	// 包括成功解码的HTTP请求数据
	L7HTTPCount int64 `statsd:"l7-http-count"`

	// L7HTTPDropCount HTTP协议丢弃计数，统计因限流被丢弃的HTTP数据
	// 用于监控HTTP数据的丢失情况
	L7HTTPDropCount int64 `statsd:"l7-http-drop-count"`

	// L7DNSCount DNS协议处理计数，统计DNS查询和响应的处理数量
	// 用于监控DNS流量
	L7DNSCount int64 `statsd:"l7-dns-count"`

	// L7DNSDropCount DNS协议丢弃计数，统计因限流被丢弃的DNS数据
	// 用于监控DNS数据的丢失情况
	L7DNSDropCount int64 `statsd:"l7-dns-drop-count"`

	// L7SQLCount SQL数据库协议处理计数，统计MySQL、PostgreSQL等SQL协议的处理数量
	// 用于监控数据库访问流量
	L7SQLCount int64 `statsd:"l7-sql-count"`

	// L7SQLDropCount SQL协议丢弃计数，统计因限流被丢弃的SQL数据
	// 用于监控数据库数据的丢失情况
	L7SQLDropCount int64 `statsd:"l7-sql-drop-count"`

	// L7NoSQLCount NoSQL数据库协议处理计数，统计Redis、MongoDB等NoSQL协议的处理数量
	// 用于监控NoSQL数据库访问流量
	L7NoSQLCount int64 `statsd:"l7-nosql-count"`

	// L7NoSQLDropCount NoSQL协议丢弃计数，统计因限流被丢弃的NoSQL数据
	// 用于监控NoSQL数据的丢失情况
	L7NoSQLDropCount int64 `statsd:"l7-nosql-drop-count"`

	// L7RPCCount RPC协议处理计数，统计Dubbo、gRPC等RPC协议的处理数量
	// 用于监控微服务间的RPC调用
	L7RPCCount int64 `statsd:"l7-rpc-count"`

	// L7RPCDropCount RPC协议丢弃计数，统计因限流被丢弃的RPC数据
	// 用于监控RPC数据的丢失情况
	L7RPCDropCount int64 `statsd:"l7-rpc-drop-count"`

	// L7MQCount 消息队列协议处理计数，统计Kafka、MQTT等消息队列协议的处理数量
	// 用于监控消息队列流量
	L7MQCount int64 `statsd:"l7-mq-count"`

	// L7MQDropCount 消息队列协议丢弃计数，统计因限流被丢弃的MQ数据
	// 用于监控消息队列数据的丢失情况
	L7MQDropCount int64 `statsd:"l7-mq-drop-count"`

	// ErrorCount 解码错误计数，统计解码过程中发生的错误数量
	// 包括数据格式错误、协议解析失败等
	ErrorCount int64 `statsd:"err-count"`

	// Count 总处理计数，统计成功解码的数据项总数
	// 用于监控解码器的处理吞吐量
	Count int64 `statsd:"count"`

	// DropCount 总丢弃计数，统计因限流被丢弃的数据项总数
	// 用于监控系统的数据丢失情况
	DropCount int64 `statsd:"drop-count"`

	// TotalTime 总处理时间，累计解码器运行的总时间（纳秒）
	// 用于计算平均处理时间和性能分析
	TotalTime int64 `statsd:"total-time"`

	// AvgTime 平均处理时间，单个数据项的平均处理时间（纳秒）
	// 通过 TotalTime / Count 计算得出，用于性能监控
	AvgTime int64 `statsd:"avg-time"`
}

type Decoder struct {
	// index 解码器实例索引，用于标识不同的解码器实例
	// 在多线程环境中，每个解码器有唯一的索引
	// 用于日志输出、统计信息和调试标识
	index int

	// msgType 消息类型，标识解码器处理的数据类型
	// 支持：协议日志、标记流、OpenTelemetry、数据包序列、SkyWalking、DataDog等
	// 决定解码器使用哪种处理逻辑来解析数据
	msgType datatype.MessageType

	// dataSourceID 数据源ID，用于标识数据来源
	// 由消息类型转换而来，用于导出器区分不同数据源
	// 在数据导出和统计时使用
	dataSourceID uint32

	// platformData 平台信息表，提供云平台资源信息
	// 用于数据enrichment，将网络流量与云资源关联
	// 包含Pod、主机、服务、IP等资源映射信息
	platformData *grpc.PlatformInfoTable

	// inQueue 输入队列，从队列中读取待解码的数据
	// 实现了QueueReader接口，支持批量读取
	// 数据来源于接收器，包含原始的网络数据包
	inQueue queue.QueueReader

	// throttler 限流队列，控制解码后数据的输出速率
	// 使用水库采样算法，在保证数据代表性的同时减少存储压力
	// 防止数据量过大导致系统过载
	throttler *throttler.ThrottlingQueue

	// flowTagWriter 流标签写入器，写入流标签信息到数据库
	// 用于存储流的元数据信息，如协议、端口、应用等
	// 支持流数据的快速检索和分析
	flowTagWriter *flow_tag.FlowTagWriter

	// appServiceTagWriter 应用服务标签写入器
	// 专门写入应用和服务相关的标签信息
	// 用于应用性能监控和服务拓扑分析
	appServiceTagWriter *flow_tag.AppServiceTagWriter

	// spanWriter Span写入器，写入分布式追踪的Span数据
	// 用于存储分布式追踪信息，支持调用链分析
	// 处理OpenTelemetry、SkyWalking等追踪数据
	spanWriter *dbwriter.SpanWriter

	// spanBuf Span缓冲区，用于批量处理Span数据
	// 减少频繁的数据库写入操作，提高性能
	// 达到批量大小时会触发批量写入
	spanBuf []interface{}

	// exporters 导出器，用于将数据导出到外部系统
	// 支持多种导出格式和目标，如Kafka、Elasticsearch等
	// 在数据写入数据库的同时进行导出
	exporters *exporters.Exporters

	// cfg 配置信息，包含解码器的各种配置参数
	// 如限流参数、缓存大小、调试开关等
	// 控制解码器的行为和性能参数
	cfg *config.Config

	// debugEnabled 调试开关，控制是否输出调试日志
	// 在调试模式下会输出详细的解码过程信息
	// 用于问题排查和性能分析
	debugEnabled bool

	// agentId, orgId, teamId Agent、组织、团队ID
	// 从接收的数据中提取，用于标识数据来源
	// 支持多租户环境下的数据隔离和统计
	agentId, orgId, teamId uint16

	// fieldsBuf 字段缓冲区，用于临时存储字段信息
	// 在生成流标签时使用，避免频繁内存分配
	// 复用内存提高性能
	fieldsBuf []interface{}

	// fieldValuesBuf 字段值缓冲区，用于临时存储字段值
	// 与fieldsBuf配合使用，存储字段对应的值
	// 同样用于内存复用和性能优化
	fieldValuesBuf []interface{}

	// counter 计数器，统计解码过程中的各种指标
	// 包括处理数量、错误数量、丢弃数量等
	// 用于监控解码器的运行状态和性能
	counter *Counter

	// lastCounter 上次计数器快照，用于OTLP调试
	// 保存上一次的统计信息，便于对比分析
	// 在调试模式下提供历史数据对比
	lastCounter Counter // for OTLP debug

	// Closable 可关闭接口，支持优雅关闭
	// 实现资源的清理和释放
	// 确保解码器在关闭时正确清理资源
	utils.Closable
}

func NewDecoder(
	index int, msgType datatype.MessageType,
	platformData *grpc.PlatformInfoTable,
	inQueue queue.QueueReader,
	throttler *throttler.ThrottlingQueue,
	flowTagWriter *flow_tag.FlowTagWriter,
	appServiceTagWriter *flow_tag.AppServiceTagWriter,
	spanWriter *dbwriter.SpanWriter,
	exporters *exporters.Exporters,
	cfg *config.Config,
) *Decoder {
	return &Decoder{
		index:               index,
		msgType:             msgType,
		dataSourceID:        exportconfig.FlowLogMessageToDataSourceID(msgType),
		platformData:        platformData,
		inQueue:             inQueue,
		throttler:           throttler,
		flowTagWriter:       flowTagWriter,
		appServiceTagWriter: appServiceTagWriter,
		spanWriter:          spanWriter,
		spanBuf:             make([]interface{}, 0, BUFFER_SIZE),
		exporters:           exporters,
		cfg:                 cfg,
		debugEnabled:        log.IsEnabledFor(logging.DEBUG),
		fieldsBuf:           make([]interface{}, 0, 64),
		fieldValuesBuf:      make([]interface{}, 0, 64),
		counter:             &Counter{},
	}
}

func (d *Decoder) GetCounter() interface{} {
	var counter *Counter
	counter, d.counter = d.counter, &Counter{}
	if counter.Count > 0 {
		counter.AvgTime = counter.TotalTime / counter.Count
	}
	d.lastCounter = *counter
	return counter
}

func (d *Decoder) GetLastCounter() *Counter {
	return &d.lastCounter
}

// Run 是解码器的主处理循环，负责持续处理流日志数据
// 该函数运行在独立的goroutine中，实现高并发数据处理
// ! 读取hander的处理队列
func (d *Decoder) Run() {
	// 注册性能监控指标，用于运维监控和调试
	// 包含线程索引和消息类型标签，便于区分不同的解码器实例
	common.RegisterCountableForIngester("decoder", d, stats.OptionStatTags{
		"thread":   strconv.Itoa(d.index),
		"msg_type": d.msgType.String()})

	// 创建批量处理缓冲区，减少系统调用开销
	// BUFFER_SIZE通常为1024，平衡内存使用和性能
	buffer := make([]interface{}, BUFFER_SIZE)

	// 创建解码器实例，用于解析二进制数据
	decoder := &codec.SimpleDecoder{}

	// 初始化各种协议的protobuf对象池，避免频繁创建销毁
	// 这些对象会被重复使用，提高性能
	pbTaggedFlow := pb.NewTaggedFlow()         // L4流数据
	pbTracesData := &v1.TracesData{}           // OpenTelemetry追踪数据
	pbThirdPartyTrace := &pb.ThirdPartyTrace{} // 第三方追踪数据(SkyWalking, Datadog)

	// 主处理循环：持续从队列获取并处理数据
	for {
		// 批量从输入队列获取数据，最多BUFFER_SIZE个
		// 这种批量处理方式显著提高了吞吐量
		n := d.inQueue.Gets(buffer)

		// 记录批处理开始时间，用于性能统计
		start := time.Now()

		// 遍历批量获取的数据项
		for i := 0; i < n; i++ {
			// 处理flush信号：nil值表示需要刷新缓冲区
			if buffer[i] == nil {
				d.flush()
				continue
			}

			// 原始数据计数：统计接收到的数据包总数
			d.counter.RawCount++

			// 类型断言：确保数据类型正确
			// RecvBuffer包含从agent接收的原始二进制数据
			recvBytes, ok := buffer[i].(*receiver.RecvBuffer)
			if !ok {
				log.Warning("get decode queue data type wrong")
				continue
			}

			// 初始化解码器，设置要解析的数据范围
			// Begin和End指定了有效数据在Buffer中的位置
			decoder.Init(recvBytes.Buffer[recvBytes.Begin:recvBytes.End])

			// 设置解码器上下文信息，用于多租户数据隔离
			// 这些信息在数据enrichment和路由时使用
			d.agentId, d.orgId, d.teamId = recvBytes.VtapID, uint16(recvBytes.OrgID), uint16(recvBytes.TeamID)

			// 根据消息类型分发到相应的处理函数
			// 每种消息类型都有专门的处理逻辑和数据格式
			switch d.msgType {
			case datatype.MESSAGE_TYPE_PROTOCOLLOG:
				// 处理应用层协议日志(HTTP、DNS、SQL等)
				d.handleProtoLog(decoder)
			case datatype.MESSAGE_TYPE_TAGGEDFLOW:
				// 处理L4流数据(TCP/UDP连接信息)
				d.handleTaggedFlow(decoder, pbTaggedFlow)
			case datatype.MESSAGE_TYPE_OPENTELEMETRY:
				// 处理OpenTelemetry追踪数据(未压缩)
				d.handleOpenTelemetry(decoder, pbTracesData, false)
			case datatype.MESSAGE_TYPE_OPENTELEMETRY_COMPRESSED:
				// 处理OpenTelemetry追踪数据(zlib压缩)
				d.handleOpenTelemetry(decoder, pbTracesData, true)
			case datatype.MESSAGE_TYPE_PACKETSEQUENCE:
				// 处理L4数据包序列(详细的包级别信息)
				d.handleL4Packet(decoder)
			case datatype.MESSAGE_TYPE_SKYWALKING:
				// 处理SkyWalking APM追踪数据
				d.handleSkyWalking(decoder, pbThirdPartyTrace, false)
			case datatype.MESSAGE_TYPE_DATADOG:
				// 处理Datadog APM追踪数据
				d.handleDatadog(decoder, pbThirdPartyTrace, false)
			default:
				// 未知消息类型，记录警告但继续处理
				log.Warningf("unknown msg type: %d", d.msgType)
			}

			// 释放RecvBuffer回对象池，避免内存泄漏
			// 这是高性能数据处理系统的关键优化
			receiver.ReleaseRecvBuffer(recvBytes)
		}

		// 累加处理时间，用于计算平均处理延迟
		d.counter.TotalTime += int64(time.Since(start))
	}
}

func (d *Decoder) handleTaggedFlow(decoder *codec.SimpleDecoder, pbTaggedFlow *pb.TaggedFlow) {
	for !decoder.IsEnd() {
		pbTaggedFlow.ResetAll()
		decoder.ReadPB(pbTaggedFlow)
		if decoder.Failed() {
			d.counter.ErrorCount++
			log.Errorf("flow decode failed, offset=%d len=%d", decoder.Offset(), len(decoder.Bytes()))
			return
		}
		if !pbTaggedFlow.IsValid() {
			d.counter.ErrorCount++
			log.Warningf("invalid flow %s", pbTaggedFlow.Flow)
			continue
		}
		d.sendFlow(pbTaggedFlow) //将 TaggedFlow 转换为 L4FlowLog 并写入存储系统
	}
}

// handleProtoLog 处理应用层协议日志数据
// 该函数负责解码二进制的protobuf数据，并将其转换为内部数据结构
func (d *Decoder) handleProtoLog(decoder *codec.SimpleDecoder) {
	// 循环处理解码器中的所有数据，直到数据结束
	for !decoder.IsEnd() {
		// 从对象池获取protobuf对象，避免频繁内存分配
		protoLog := pb.AcquirePbAppProtoLogsData()

		// 将二进制数据解码到protobuf结构体中
		// decoder.ReadPB会解析二进制流并填充protoLog对象
		decoder.ReadPB(protoLog)

		// 检查解码是否失败或数据是否有效
		// Failed()检查解码过程中的错误，IsValid()验证数据完整性
		if decoder.Failed() || !protoLog.IsValid() {
			// 增加错误计数，用于监控和调试
			d.counter.ErrorCount++
			// 释放protobuf对象回对象池
			pb.ReleasePbAppProtoLogsData(protoLog)
			// 记录详细的错误信息，包含偏移量和数据长度
			log.Errorf("proto log decode failed, offset=%d len=%d", decoder.Offset(), len(decoder.Bytes()))
			return
		}

		// 调用sendProto处理解码后的数据
		// 负责将protobuf转换为L7FlowLog并发送到下游处理链
		d.sendProto(protoLog)
	}
}

func decompressOpenTelemetry(compressed []byte) ([]byte, error) {
	reader, err := zlib.NewReader(bytes.NewReader(compressed))
	defer reader.Close()
	if err != nil {
		return nil, err
	}

	return io.ReadAll(reader)
}

func (d *Decoder) handleOpenTelemetry(decoder *codec.SimpleDecoder, pbTracesData *v1.TracesData, compressed bool) {
	var err error
	for !decoder.IsEnd() {
		pbTracesData.Reset()
		bytes := decoder.ReadBytes()
		if len(bytes) > 0 {
			if compressed {
				bytes, err = decompressOpenTelemetry(bytes)
			}
			if err == nil {
				err = proto.Unmarshal(bytes, pbTracesData)
			}
		}
		if decoder.Failed() || err != nil {
			if d.counter.ErrorCount == 0 {
				log.Errorf("OpenTelemetry log decode failed, offset=%d len=%d err: %s", decoder.Offset(), len(decoder.Bytes()), err)
			}
			d.counter.ErrorCount++
			return
		}
		d.sendOpenMetetry(pbTracesData)
	}
}

func (d *Decoder) sendOpenMetetry(tracesData *v1.TracesData) {
	if d.debugEnabled {
		log.Debugf("decoder %d vtap %d recv otel: %s", d.index, d.agentId, tracesData)
	}
	d.counter.Count++
	ls := log_data.OTelTracesDataToL7FlowLogs(d.agentId, d.orgId, d.teamId, tracesData, d.platformData, d.cfg)
	for _, l := range ls {
		l.AddReferenceCount()
		if !d.throttler.SendWithThrottling(l) {
			d.counter.DropCount++
		} else {
			d.fieldsBuf, d.fieldValuesBuf = d.fieldsBuf[:0], d.fieldValuesBuf[:0]
			l.GenerateNewFlowTags(d.flowTagWriter.Cache)
			d.flowTagWriter.WriteFieldsAndFieldValuesInCache()
			d.appServiceTagWrite(l)
			d.spanWrite(l)
		}
		l.Release()
	}
}

func (d *Decoder) handleSkyWalking(decoder *codec.SimpleDecoder, pbThirdPartyTrace *pb.ThirdPartyTrace, compressed bool) {
	var err error
	buffer := log_data.GetBuffer()
	for !decoder.IsEnd() {
		pbThirdPartyTrace.Reset()
		pbThirdPartyTrace.Data = buffer.Bytes()
		bytes := decoder.ReadBytes()
		if len(bytes) > 0 {
			// universal compression
			if compressed {
				bytes, err = decompressOpenTelemetry(bytes)
			}
			if err == nil {
				err = proto.Unmarshal(bytes, pbThirdPartyTrace)
			}
		}
		if decoder.Failed() || err != nil {
			if d.counter.ErrorCount == 0 {
				log.Errorf("skywalking data decode failed, offset=%d len=%d err: %s", decoder.Offset(), len(decoder.Bytes()), err)
			}
			d.counter.ErrorCount++
			continue
		}
		d.sendSkyWalking(pbThirdPartyTrace.Data, pbThirdPartyTrace.PeerIp, pbThirdPartyTrace.Uri)
		log_data.PutBuffer(buffer)
	}
}

func (d *Decoder) sendSkyWalking(segmentData, peerIP []byte, uri string) {
	if d.debugEnabled {
		log.Debugf("decoder %d vtap %d recv skywalking data length: %d", d.index, d.agentId, len(segmentData))
	}
	d.counter.Count++
	ls := sw_import.SkyWalkingDataToL7FlowLogs(d.agentId, d.orgId, d.teamId, segmentData, peerIP, uri, d.platformData, d.cfg)
	for _, l := range ls {
		l.AddReferenceCount()
		if !d.throttler.SendWithThrottling(l) {
			d.counter.DropCount++
		} else {
			d.fieldsBuf, d.fieldValuesBuf = d.fieldsBuf[:0], d.fieldValuesBuf[:0]
			l.GenerateNewFlowTags(d.flowTagWriter.Cache)
			d.flowTagWriter.WriteFieldsAndFieldValuesInCache()
			d.appServiceTagWrite(l)
			d.spanWrite(l)
		}
		l.Release()
	}
}

func (d *Decoder) handleDatadog(decoder *codec.SimpleDecoder, pbThirdPartyTrace *pb.ThirdPartyTrace, compressed bool) {
	var err error
	buffer := log_data.GetBuffer()
	for !decoder.IsEnd() {
		pbThirdPartyTrace.Reset()
		pbThirdPartyTrace.Data = buffer.Bytes()
		bytes := decoder.ReadBytes()
		if len(bytes) > 0 {
			// universal compression
			if compressed {
				bytes, err = decompressOpenTelemetry(bytes)
			}
			if err == nil {
				err = proto.Unmarshal(bytes, pbThirdPartyTrace)
			}
		}
		if decoder.Failed() || err != nil {
			if d.counter.ErrorCount == 0 {
				log.Errorf("datadog data decode failed, offset=%d len=%d err: %s", decoder.Offset(), len(decoder.Bytes()), err)
			}
			d.counter.ErrorCount++
			continue
		}
		d.sendDatadog(pbThirdPartyTrace)
		log_data.PutBuffer(buffer)
	}
}

func (d *Decoder) sendDatadog(ddogData *pb.ThirdPartyTrace) {
	if d.debugEnabled {
		log.Debugf("decoder %d vtap %d recv datadog data length: %d", d.index, d.agentId, len(ddogData.Data))
	}
	d.counter.Count++
	ls := dd_import.DDogDataToL7FlowLogs(d.agentId, d.orgId, d.teamId, ddogData, d.platformData, d.cfg)
	for _, l := range ls {
		l.AddReferenceCount()
		if !d.throttler.SendWithThrottling(l) {
			d.counter.DropCount++
		} else {
			d.fieldsBuf, d.fieldValuesBuf = d.fieldsBuf[:0], d.fieldValuesBuf[:0]
			l.GenerateNewFlowTags(d.flowTagWriter.Cache)
			d.flowTagWriter.WriteFieldsAndFieldValuesInCache()
			d.appServiceTagWrite(l)
			d.spanWrite(l)
		}
		l.Release()
	}
}

func (d *Decoder) handleL4Packet(decoder *codec.SimpleDecoder) {
	for !decoder.IsEnd() {
		l4Packet, err := log_data.DecodePacketSequence(d.agentId, d.orgId, d.teamId, decoder)
		if decoder.Failed() || err != nil {
			if d.counter.ErrorCount == 0 {
				log.Errorf("packet sequence decode failed, offset=%d len=%d, err: %s", decoder.Offset(), len(decoder.Bytes()), err)
			}
			l4Packet.Release()
			d.counter.ErrorCount++
			return
		}

		if d.debugEnabled {
			log.Debugf("decoder %d vtap %d recv l4 packet: %s", d.index, d.agentId, l4Packet)
		}
		d.counter.Count++
		d.throttler.SendWithoutThrottling(l4Packet)
	}
}

func (d *Decoder) sendFlow(flow *pb.TaggedFlow) {
	if d.debugEnabled {
		log.Debugf("decoder %d recv flow: %s", d.index, flow)
	}
	d.counter.Count++
	l := log_data.TaggedFlowToL4FlowLog(d.orgId, d.teamId, flow, d.platformData)

	if l.HitPcapPolicy() {
		d.export(l)
		d.throttler.SendWithoutThrottling(l)
	} else {
		l.AddReferenceCount()
		if !d.throttler.SendWithThrottling(l) {
			d.counter.DropCount++
		} else {
			d.export(l)
		}
		l.Release()
	}
}

func (d *Decoder) export(l exportcommon.ExportItem) {
	if d.exporters != nil {
		d.exporters.Put(d.dataSourceID, d.index, l)
	}
}

// spanWrite 是 DeepFlow Ingester 解码器中将 L7 流日志转换为分布式追踪 span 并批量写入的核心方法
func (d *Decoder) spanWrite(l *log_data.L7FlowLog) {
	if d.spanWriter == nil {
		return
	}

	if l == nil {
		if len(d.spanBuf) == 0 {
			return
		}
		d.spanWriter.Put(d.spanBuf)
		d.spanBuf = d.spanBuf[:0]
		return
	}
	//只有满足以下任一条件且存在 TraceId 的流日志才会被转换为 span：
	// 信号源条件：来自 eBPF 或 OpenTelemetry 的数据 decoder.go:449-450
	// 网关镜像条件：来自物理交换机镜像的网关 MAC 或 ID 流量 decoder.go:451-452
	// 云主机条件：云主机不支持 eBPF 时的客户端或服务器端流量 decoder.go:453

	if ((l.SignalSource == uint16(datatype.SIGNAL_SOURCE_EBPF) || l.SignalSource == uint16(datatype.SIGNAL_SOURCE_OTEL)) ||
		// Solving the service rendering problem of mirrored traffic on physical switches
		(l.TapPortType == datatype.TAPPORT_FROM_GATEWAY_MAC || l.TapPortType == datatype.TAPPORT_FROM_ID) ||
		// Resolving service rendering issues when cloud hosts do not support eBPF
		(l.TapSide == flow_metrics.Client.String() || l.TapSide == flow_metrics.Server.String())) &&
		l.TraceId != "" {
		l.AddReferenceCount()
		//将符合条件的 L7FlowLog 转换为 SpanWithTraceID 类型并添加到缓冲区
		d.spanBuf = append(d.spanBuf, (*dbwriter.SpanWithTraceID)(l))
		if len(d.spanBuf) >= BUFFER_SIZE {
			d.spanWriter.Put(d.spanBuf)
			d.spanBuf = d.spanBuf[:0]
		}
	}
}

func (d *Decoder) appServiceTagWrite(l *log_data.L7FlowLog) {
	if d.appServiceTagWriter == nil {
		return
	}
	if l.AppService == "" && l.AppInstance == "" {
		return
	}
	d.appServiceTagWriter.Write(l.Time, flowlogcommon.L7_FLOW_ID.String(), l.AppService, l.AppInstance, l.OrgId, l.TeamID)
}

// sendProto 处理解码后的协议日志数据
// 该函数负责数据转换、流量控制、标签生成和下游分发
func (d *Decoder) sendProto(proto *pb.AppProtoLogsData) {
	// 调试模式下记录接收到的协议数据
	if d.debugEnabled {
		log.Debugf("decoder %d recv proto: %s", d.index, proto)
	}

	// 将protobuf数据转换为L7FlowLog结构体
	// ProtoLogToL7FlowLog会进行数据enrichment，添加平台数据信息
	l := log_data.ProtoLogToL7FlowLog(d.orgId, d.teamId, proto, d.platformData, d.cfg)

	// 增加引用计数，防止在处理过程中被释放
	// 这是对象池管理的关键机制
	l.AddReferenceCount()

	// 通过限流器发送数据，返回是否发送成功
	// SendWithThrottling实现背压控制，防止下游过载
	sent := d.throttler.SendWithThrottling(l)

	if sent {
		// 数据成功发送，执行后续处理

		// 生成流标签，用于数据分类和查询
		if d.flowTagWriter != nil {
			// 重置缓冲区，复用内存
			d.fieldsBuf, d.fieldValuesBuf = d.fieldsBuf[:0], d.fieldValuesBuf[:0]
			// 生成新的流标签并缓存
			l.GenerateNewFlowTags(d.flowTagWriter.Cache)
			// 将标签字段和值写入缓存
			d.flowTagWriter.WriteFieldsAndFieldValuesInCache()
		}

		// 写入应用服务标签，用于服务发现和拓扑
		d.appServiceTagWrite(l)

		// 导出数据到外部系统（如Kafka、ES等）
		d.export(l)

		// 处理分布式追踪span数据
		// 将符合条件的L7FlowLog转换为Span数据写入ClickHouse
		d.spanWrite(l)
	}

	// 更新性能计数器，按协议类型统计
	// 第二个参数表示是否被丢弃
	d.updateCounter(datatype.L7Protocol(proto.Base.Head.Proto), !sent)

	// 释放L7FlowLog对象回对象池
	l.Release()

	// 释放protobuf对象回对象池
	proto.Release()
}

func (d *Decoder) updateCounter(l7Protocol datatype.L7Protocol, dropped bool) {
	d.counter.Count++
	drop := int64(0)
	if dropped {
		d.counter.DropCount++
		drop = 1
	}
	switch l7Protocol {
	case datatype.L7_PROTOCOL_HTTP_1, datatype.L7_PROTOCOL_HTTP_2:
		d.counter.L7HTTPCount++
		d.counter.L7HTTPDropCount += drop
	case datatype.L7_PROTOCOL_DNS:
		d.counter.L7DNSCount++
		d.counter.L7DNSDropCount += drop
	case datatype.L7_PROTOCOL_MYSQL, datatype.L7_PROTOCOL_POSTGRE:
		d.counter.L7SQLCount++
		d.counter.L7SQLDropCount += drop
	case datatype.L7_PROTOCOL_REDIS:
		d.counter.L7NoSQLCount++
		d.counter.L7NoSQLDropCount += drop
	case datatype.L7_PROTOCOL_DUBBO:
		d.counter.L7RPCCount++
		d.counter.L7RPCDropCount += drop
	case datatype.L7_PROTOCOL_MQTT:
		d.counter.L7MQCount++
		d.counter.L7MQDropCount += drop
	}
}

func (d *Decoder) flush() {
	if d.throttler != nil {
		d.throttler.SendWithThrottling(nil)
		d.throttler.SendWithoutThrottling(nil)
	}
	d.export(nil)
	if d.spanWriter != nil {
		d.spanWrite(nil)
	}
}
