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

package log_data

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"github.com/zerotraceio/zerotrace/server/ingester/config"
	"github.com/zerotraceio/zerotrace/server/ingester/flow_log/common"
	flowlogCfg "github.com/zerotraceio/zerotrace/server/ingester/flow_log/config"
	"github.com/zerotraceio/zerotrace/server/ingester/flow_tag"
	"github.com/zerotraceio/zerotrace/server/libs/ckdb"
	"github.com/zerotraceio/zerotrace/server/libs/datatype"
	"github.com/zerotraceio/zerotrace/server/libs/datatype/pb"
	flow_metrics "github.com/zerotraceio/zerotrace/server/libs/flow-metrics"
	"github.com/zerotraceio/zerotrace/server/libs/grpc"
	"github.com/zerotraceio/zerotrace/server/libs/nativetag"
	"github.com/zerotraceio/zerotrace/server/libs/pool"
	"github.com/zerotraceio/zerotrace/server/libs/utils"

	"github.com/google/gopacket/layers"
	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("flow_log.log_data")

type L7Base struct {
	// 知识图谱
	KnowledgeGraph

	Time uint32 `json:"time" category:"$tag" sub:"flow_info"` // s
	// 网络层
	IP40     uint32 `json:"ip4_0" category:"$tag" sub:"network_layer" to_string:"IPv4String"`
	IP41     uint32 `json:"ip4_1" category:"$tag" sub:"network_layer" to_string:"IPv4String"`
	IP60     net.IP `json:"ip6_0" category:"$tag" sub:"network_layer" to_string:"IPv6String"`
	IP61     net.IP `json:"ip6_1" category:"$tag" sub:"network_layer" to_string:"IPv6String"`
	IsIPv4   bool   `json:"is_ipv4" category:"$tag" sub:"network_layer"`
	Protocol uint8  `json:"protocol" category:"$tag" sub:"network_layer" enumfile:"l7_ip_protocol"`

	// 传输层
	ClientPort uint16 `json:"client_port" category:"$tag" sub:"transport_layer" `
	ServerPort uint16 `json:"server_port" category:"$tag" sub:"transport_layer"`

	// 流信息
	FlowID          uint64 `json:"flow_id" category:"$tag" sub:"flow_info"`
	TapType         uint8  `json:"capture_network_type_id" category:"$tag" sub:"capture_info"`
	NatSource       uint8  `json:"nat_source" category:"$tag" sub:"capture_info" enumfile:"nat_source"`
	TapPortType     uint8  `json:"capture_nic_type category:"$tag" sub:"capture_info"`
	SignalSource    uint16 `json:"signal_source" category:"$tag" sub:"capture_info" enumfile:"l7_signal_source"`
	TunnelType      uint8  `json:"tunnel_type" category:"$tag" sub:"tunnel_info"`
	TapPort         uint32 `json:"capture_nic" category:"$tag" sub:"capture_info"`
	TapSide         string `json:"observation_point" category:"$tag" sub:"capture_info" enumfile:"observation_point"`
	TapSideEnum     uint8
	VtapID          uint16 `json:"agent_id" category:"$tag" sub:"capture_info"`
	ReqTcpSeq       uint32 `json:"req_tcp_seq" category:"$tag" sub:"transport_layer"`
	RespTcpSeq      uint32 `json:"resp_tcp_seq" category:"$tag" sub:"transport_layer"`
	StartTime       int64  `json:"start_time" category:"$tag" sub:"flow_info"` // us
	EndTime         int64  `json:"end_time" category:"$tag" sub:"flow_info"`   // us
	GPID0           uint32 `json:"gprocess_id_0" category:"$tag" sub:"universal_tag"`
	GPID1           uint32 `json:"gprocess_id_1" category:"$tag" sub:"universal_tag"`
	BizType         uint8  `json:"biz_type" category:"$tag" sub:"business_info"`
	BizCode         string `json:"biz_code" category:"$tag" sub:"business_info"`
	BizScenario     string `json:"biz_scenario" category:"$tag" sub:"business_info"`
	BizResponseCode string `json:"biz_response_code" category:"$tag" sub:"business_info"`

	ProcessID0             uint32 `json:"process_id_0" category:"$tag" sub:"service_info"`
	ProcessID1             uint32 `json:"process_id_1" category:"$tag" sub:"service_info"`
	ProcessKName0          string `json:"process_kname_0" category:"$tag" sub:"service_info"`
	ProcessKName1          string `json:"process_kname_1" category:"$tag" sub:"service_info"`
	SyscallTraceIDRequest  uint64 `json:"syscall_trace_id_request" category:"$tag" sub:"tracing_info"`
	SyscallTraceIDResponse uint64 `json:"syscall_trace_id_response" category:"$tag" sub:"tracing_info"`
	SyscallThread0         uint32 `json:"syscall_thread_0" category:"$tag" sub:"tracing_info"`
	SyscallThread1         uint32 `json:"syscall_thread_1" category:"$tag" sub:"tracing_info"`
	SyscallCoroutine0      uint64 `json:"syscall_coroutine_0" category:"$tag" sub:"tracing_info"`
	SyscallCoroutine1      uint64 `json:"syscall_coroutine_1" category:"$tag" sub:"tracing_info"`
	SyscallCapSeq0         uint32 `json:"syscall_cap_seq_0" category:"$tag" sub:"tracing_info"`
	SyscallCapSeq1         uint32 `json:"syscall_cap_seq_1" category:"$tag" sub:"tracing_info"`

	EncodedSpan []byte
}

func L7BaseColumns() []*ckdb.Column {
	columns := []*ckdb.Column{}
	// 知识图谱
	columns = append(columns, KnowledgeGraphColumns...)
	columns = append(columns,
		ckdb.NewColumn("time", ckdb.DateTime).SetComment("精度: 秒"),
		// 网络层
		ckdb.NewColumn("ip4_0", ckdb.IPv4),
		ckdb.NewColumn("ip4_1", ckdb.IPv4),
		ckdb.NewColumn("ip6_0", ckdb.IPv6),
		ckdb.NewColumn("ip6_1", ckdb.IPv6),
		ckdb.NewColumn("is_ipv4", ckdb.UInt8).SetIndex(ckdb.IndexMinmax),
		ckdb.NewColumn("protocol", ckdb.UInt8).SetIndex(ckdb.IndexMinmax),

		// 传输层
		ckdb.NewColumn("client_port", ckdb.UInt16),
		ckdb.NewColumn("server_port", ckdb.UInt16).SetIndex(ckdb.IndexSet),

		// 流信息
		ckdb.NewColumn("flow_id", ckdb.UInt64).SetIndex(ckdb.IndexMinmax),
		ckdb.NewColumn("capture_network_type_id", ckdb.UInt8).SetIndex(ckdb.IndexSet),
		ckdb.NewColumn("nat_source", ckdb.UInt8).SetIndex(ckdb.IndexSet),
		ckdb.NewColumn("capture_nic_type", ckdb.UInt8).SetIndex(ckdb.IndexNone),
		ckdb.NewColumn("signal_source", ckdb.UInt16).SetIndex(ckdb.IndexNone),
		ckdb.NewColumn("tunnel_type", ckdb.UInt8).SetIndex(ckdb.IndexNone),
		ckdb.NewColumn("capture_nic", ckdb.UInt32).SetIndex(ckdb.IndexNone),
		ckdb.NewColumn("observation_point", ckdb.LowCardinalityString),
		ckdb.NewColumn("agent_id", ckdb.UInt16).SetIndex(ckdb.IndexSet),
		ckdb.NewColumn("req_tcp_seq", ckdb.UInt32),
		ckdb.NewColumn("resp_tcp_seq", ckdb.UInt32),
		ckdb.NewColumn("start_time", ckdb.DateTime64us).SetComment("精度: 微秒"),
		ckdb.NewColumn("end_time", ckdb.DateTime64us).SetComment("精度: 微秒"),
		ckdb.NewColumn("gprocess_id_0", ckdb.UInt32).SetComment("全局客户端进程ID"),
		ckdb.NewColumn("gprocess_id_1", ckdb.UInt32).SetComment("全局服务端进程ID"),
		ckdb.NewColumn("biz_type", ckdb.UInt8).SetComment("Business Type"),
		ckdb.NewColumn("biz_code", ckdb.String).SetIndex(ckdb.IndexBloomfilter),
		ckdb.NewColumn("biz_scenario", ckdb.String).SetIndex(ckdb.IndexBloomfilter),
		ckdb.NewColumn("biz_response_code", ckdb.String).SetIndex(ckdb.IndexBloomfilter),

		ckdb.NewColumn("process_id_0", ckdb.Int32).SetComment("客户端进程ID"),
		ckdb.NewColumn("process_id_1", ckdb.Int32).SetComment("服务端进程ID"),
		ckdb.NewColumn("process_kname_0", ckdb.String).SetComment("客户端系统进程"),
		ckdb.NewColumn("process_kname_1", ckdb.String).SetComment("服务端系统进程"),
		ckdb.NewColumn("syscall_trace_id_request", ckdb.UInt64).SetComment("SyscallTraceID-请求"),
		ckdb.NewColumn("syscall_trace_id_response", ckdb.UInt64).SetComment("SyscallTraceID-响应"),
		ckdb.NewColumn("syscall_thread_0", ckdb.UInt32).SetComment("Syscall线程-请求"),
		ckdb.NewColumn("syscall_thread_1", ckdb.UInt32).SetComment("Syscall线程-响应"),
		ckdb.NewColumn("syscall_coroutine_0", ckdb.UInt64).SetComment("Request Syscall Coroutine"),
		ckdb.NewColumn("syscall_coroutine_1", ckdb.UInt64).SetComment("Response Syscall Coroutine"),
		ckdb.NewColumn("syscall_cap_seq_0", ckdb.UInt32).SetComment("Syscall序列号-请求"),
		ckdb.NewColumn("syscall_cap_seq_1", ckdb.UInt32).SetComment("Syscall序列号-响应"),
	)

	return columns
}

// L7FlowLog 应用层流日志结构体
// 用于记录应用层协议的详细通信信息，是DeepFlow可观测性系统的核心数据结构
type L7FlowLog struct {
	// 继承引用计数，支持对象池管理，提高内存使用效率
	pool.ReferenceCount

	// 流日志唯一标识符，用于区分不同的流日志记录
	_id uint64 `json:"_id" category:"$tag" sub:"flow_info"`

	// 嵌入L7基础结构体，包含网络层、传输层等基础信息
	L7Base

	// ===== 应用层协议信息 =====

	// 应用层协议类型，如HTTP、DNS、MySQL、Redis等
	// 使用枚举值标识不同的应用协议
	L7Protocol uint8 `json:"l7_protocol" category:"$tag" sub:"application_layer" enumfile:"l7_protocol"`

	// 业务协议标识，用于标识自定义的业务协议
	BizProtocol string `json:"biz_protocol" category:"$tag" sub:"application_layer"`

	// 协议版本信息，如HTTP/1.1、HTTP/2等
	Version string `json:"version" category:"$tag" sub:"application_layer"`

	// 日志类型：0-请求、1-响应、2-会话
	Type uint8 `json:"type" category:"$tag" sub:"application_layer" enumfile:"l7_log_type"`

	// 是否使用TLS加密：0-否、1-是
	IsTLS uint8 `json:"is_tls" category:"$tag" sub:"application_layer"`

	// 是否为异步调用：0-否、1-是
	IsAsync uint8 `json:"is_async" category:"$tag" sub:"application_layer"`

	// 是否为反向流：0-否、1-是（用于标识流的方向）
	IsReversed uint8 `json:"is_reversed" category:"$tag" sub:"application_layer"`

	// ===== 请求详情信息 =====

	// 请求类型，如HTTP方法(GET、POST)、SQL命令(SELECT、INSERT)等
	RequestType string `json:"request_type" category:"$tag" sub:"application_layer"`

	// 请求域名，如HTTP的Host头、RPC服务名、DNS查询域名等
	RequestDomain string `json:"request_domain" category:"$tag" sub:"application_layer"`

	// 请求资源，如HTTP路径、RPC方法名、SQL具体语句等
	RequestResource string `json:"request_resource" category:"$tag" sub:"application_layer"`

	// API端点信息，用于标识具体的接口
	Endpoint string `json:"end_point" category:"$tag" sub:"service_info"`

	// ===== 可空字段（使用指针类型支持数据库NULL值） =====

	// 请求ID，用于关联请求和响应，如HTTP请求ID、RPC调用ID等
	// 使用指针类型，无意义时传递nil
	RequestId *uint64 `json:"request_id" category:"$tag" sub:"application_layer" data_type:"*uint64"`

	// 内部存储字段，不直接对外暴露
	requestId uint64

	// ===== 响应详情信息 =====

	// 响应状态：0-正常、1-异常、2-不存在、3-服务端异常、4-客户端异常
	ResponseStatus uint8 `json:"response_status" category:"$tag" sub:"application_layer" enumfile:"response_status"`

	// 响应码，如HTTP状态码、RPC响应码、SQL错误码等
	// 使用指针类型支持NULL值
	ResponseCode *int32 `json:"response_code" category:"$tag" sub:"application_layer" data_type:"*int32"`

	// 内部存储字段
	responseCode int32

	// 响应异常信息，记录具体的异常描述
	ResponseException string `json:"response_exception" category:"$tag" sub:"application_layer"`

	// 响应结果，如DNS解析结果等
	ResponseResult string `json:"response_result" category:"$tag" sub:"application_layer"`

	// ===== 分布式追踪信息 =====

	// HTTP代理客户端IP，记录经过代理前的真实客户端IP
	HttpProxyClient string `json:"http_proxy_client" category:"$tag" sub:"tracing_info"`

	// 请求方的X-Request-ID，用于链路追踪
	XRequestId0 string `json:"x_request_id_0" category:"$tag" sub:"tracing_info"`

	// 响应方的X-Request-ID，用于链路追踪
	XRequestId1 string `json:"x_request_id_1" category:"$tag" sub:"tracing_info"`

	// 分布式追踪ID，用于关联整个调用链
	TraceId string `json:"trace_id" category:"$tag" sub:"tracing_info"`

	// 辅助追踪ID，用于优化查询性能
	TraceId2 string `json:"trace_id_2" category:"$tag" sub:"tracing_info"`

	// 追踪ID索引，用于优化ClickHouse查询性能
	TraceIdIndex uint64

	// Span标识，标识分布式追踪中的具体操作单元
	SpanId string `json:"span_id" category:"$tag" sub:"tracing_info"`

	// 父Span标识，标识调用链中的上级操作
	ParentSpanId string `json:"parent_span_id" category:"$tag" sub:"tracing_info"`

	// Span类型，标识Span的角色（客户端、服务端等）
	SpanKind uint8

	// Span类型的指针版本，支持NULL值
	spanKind *uint8 `json:"span_kind" category:"$tag" sub:"tracing_info" enumfile:"span_kind" data_type:"*uint8"`

	// 应用服务名称，用于服务发现和拓扑
	AppService string `json:"app_service" category:"$tag" sub:"service_info"`

	// 应用实例标识，标识具体的服务实例
	AppInstance string `json:"app_instance" category:"$tag" sub:"service_info"`

	// ===== 性能指标信息 =====

	// 响应延迟，单位：微秒
	ResponseDuration uint64 `json:"response_duration" category:"$metrics" sub:"delay"`

	// 请求长度，单位：字节
	// 使用指针类型支持NULL值
	RequestLength *int64 `json:"request_length" category:"$metrics" sub:"throughput" data_type:"*int64"`

	// 内部存储字段
	requestLength int64

	// 响应长度，单位：字节
	// 使用指针类型支持NULL值
	ResponseLength *int64 `json:"response_length" category:"$metrics" sub:"throughput" data_type:"*int64"`

	// 内部存储字段
	responseLength int64

	// SQL影响行数，用于数据库操作统计
	// 使用指针类型支持NULL值
	SqlAffectedRows *uint64 `json:"sql_affected_rows" category:"$metrics" sub:"throughput" data_type:"*uint64"`

	// 内部存储字段
	sqlAffectedRows uint64

	// 方向得分，用于标识网络流的方向
	DirectionScore uint8 `json:"direction_score" category:"$metrics" sub:"l4_throughput"`

	// ===== 捕获字节数信息 =====

	// 捕获的请求字节数
	// 对于Packet信号源：表示AF_PACKET捕获的数据包长度（不包括L4头部）
	// 对于eBPF信号源：表示单个系统调用的字节数
	// 启用TCP流重组时：表示多个系统调用的总字节数
	CapturedRequestByte uint32 `json:"captured_request_byte" category:"$metrics" sub:"throughput"`

	// 捕获的响应字节数，含义同上
	CapturedResponseByte uint32 `json:"captured_response_byte" category:"$metrics" sub:"throughput"`

	// ===== 扩展属性信息 =====

	// 自定义属性名称数组，支持业务扩展
	AttributeNames []string `json:"attribute_names" category:"$tag" sub:"native_tag" data_type:"[]string"`

	// 自定义属性值数组，与AttributeNames一一对应
	AttributeValues []string `json:"attribute_values" category:"$tag" sub:"native_tag" data_type:"[]string"`

	// ===== 自定义指标信息 =====

	// 自定义指标名称数组，支持业务指标扩展
	MetricsNames []string `json:"metrics_names" category:"$metrics" data_type:"[]string"`

	// 自定义指标值数组，与MetricsNames一一对应
	MetricsValues []float64 `json:"metrics_values" category:"$metrics" data_type:"[]float64"`

	// ===== 事件信息 =====

	// 事件信息，记录OpenTelemetry等系统的事件数据
	Events string `json:"events" category:"$tag" sub:"application_layer"`
}

func L7FlowLogColumns() []*ckdb.Column {
	l7Columns := []*ckdb.Column{}
	l7Columns = append(l7Columns, ckdb.NewColumn("_id", ckdb.UInt64))
	l7Columns = append(l7Columns, L7BaseColumns()...)
	l7Columns = append(l7Columns,
		ckdb.NewColumn("l7_protocol", ckdb.UInt8).SetIndex(ckdb.IndexNone).SetComment("0:未知 1:其他, 20:http1, 21:http2, 40:dubbo, 60:mysql, 80:redis, 100:kafka, 101:mqtt, 120:dns"),
		ckdb.NewColumn("biz_protocol", ckdb.LowCardinalityString).SetIndex(ckdb.IndexNone).SetComment("应用协议"),
		ckdb.NewColumn("version", ckdb.LowCardinalityString).SetComment("协议版本"),
		ckdb.NewColumn("type", ckdb.UInt8).SetIndex(ckdb.IndexNone).SetComment("日志类型, 0:请求, 1:响应, 2:会话"),
		ckdb.NewColumn("is_tls", ckdb.UInt8),
		ckdb.NewColumn("is_async", ckdb.UInt8),
		ckdb.NewColumn("is_reversed", ckdb.UInt8),

		ckdb.NewColumn("request_type", ckdb.LowCardinalityString).SetComment("请求类型, HTTP请求方法、SQL命令类型、NoSQL命令类型、MQ命令类型、DNS查询类型"),
		ckdb.NewColumn("request_domain", ckdb.String).SetIndex(ckdb.IndexBloomfilter).SetComment("请求域名, HTTP主机名、RPC服务名称、DNS查询域名"),
		ckdb.NewColumn("request_resource", ckdb.String).SetIndex(ckdb.IndexBloomfilter).SetComment("请求资源, HTTP路径、RPC方法名称、SQL命令、NoSQL命令"),
		ckdb.NewColumn("endpoint", ckdb.String).SetIndex(ckdb.IndexBloomfilter).SetComment("端点"),
		ckdb.NewColumn("request_id", ckdb.UInt64Nullable).SetComment("请求ID, HTTP请求ID、RPC请求ID、MQ请求ID、DNS请求ID"),

		ckdb.NewColumn("response_status", ckdb.UInt8).SetComment("响应状态 0:正常, 1:异常 ,2:不存在，3:服务端异常, 4:客户端异常"),
		ckdb.NewColumn("response_code", ckdb.Int32Nullable).SetComment("响应码, HTTP响应码、RPC响应码、SQL响应码、MQ响应码、DNS响应码"),
		ckdb.NewColumn("response_exception", ckdb.String).SetComment("响应异常"),
		ckdb.NewColumn("response_result", ckdb.String).SetComment("响应结果, DNS解析地址"),

		ckdb.NewColumn("http_proxy_client", ckdb.String).SetComment("HTTP代理客户端"),
		ckdb.NewColumn("x_request_id_0", ckdb.String).SetIndex(ckdb.IndexBloomfilter).SetComment("XRequestID0"),
		ckdb.NewColumn("x_request_id_1", ckdb.String).SetIndex(ckdb.IndexBloomfilter).SetComment("XRequestID1"),
		ckdb.NewColumn("trace_id", ckdb.String).SetIndex(ckdb.IndexBloomfilter).SetComment("TraceID"),
		ckdb.NewColumn("_trace_id_2", ckdb.String).SetIndex(ckdb.IndexBloomfilter).SetComment("TraceID2"),
		ckdb.NewColumn("trace_id_index", ckdb.UInt64).SetIndex(ckdb.IndexMinmax).SetComment("TraceIDIndex"),
		ckdb.NewColumn("span_id", ckdb.String).SetComment("SpanID"),
		ckdb.NewColumn("parent_span_id", ckdb.String).SetComment("ParentSpanID"),
		ckdb.NewColumn("span_kind", ckdb.UInt8Nullable).SetComment("SpanKind"),
		ckdb.NewColumn("app_service", ckdb.LowCardinalityString).SetComment("app service"),
		ckdb.NewColumn("app_instance", ckdb.LowCardinalityString).SetComment("app instance"),

		ckdb.NewColumn("response_duration", ckdb.UInt64),
		ckdb.NewColumn("request_length", ckdb.Int64Nullable).SetComment("请求长度"),
		ckdb.NewColumn("response_length", ckdb.Int64Nullable).SetComment("响应长度"),
		ckdb.NewColumn("sql_affected_rows", ckdb.UInt64Nullable).SetComment("sql影响行数"),
		ckdb.NewColumn("direction_score", ckdb.UInt8).SetIndex(ckdb.IndexMinmax),
		ckdb.NewColumn("captured_request_byte", ckdb.UInt32),
		ckdb.NewColumn("captured_response_byte", ckdb.UInt32),

		ckdb.NewColumn("attribute_names", ckdb.ArrayLowCardinalityString).SetComment("额外的属性"),
		ckdb.NewColumn("attribute_values", ckdb.ArrayString).SetComment("额外的属性对应的值"),
		ckdb.NewColumn("metrics_names", ckdb.ArrayLowCardinalityString).SetComment("额外的指标"),
		ckdb.NewColumn("metrics_values", ckdb.ArrayFloat64).SetComment("额外的指标对应的值"),
		ckdb.NewColumn("events", ckdb.String).SetComment("OTel events"),
	)
	return l7Columns
}

func (h *L7FlowLog) NativeTagVersion() uint32 {
	return nativetag.GetTableNativeTagsVersion(h.KnowledgeGraph.OrgId, nativetag.L7_FLOW_LOG)
}

func (h *L7FlowLog) OrgID() uint16 {
	return h.KnowledgeGraph.OrgId
}

func base64ToHexString(str string) string {
	if len(str) < 2 || str[len(str)-1] != '=' {
		return str
	}
	bytes, err := base64.StdEncoding.DecodeString(str)
	if err == nil {
		return hex.EncodeToString(bytes)
	}
	return str
}

// for empty traceId, the traceId-index is the value of the previous traceId-index + 1, not 0.
// when the traceId-index data is stored in CK, the generated minmax index will have min non-zero, which improves the filtering performance of the minmax index
var lastTraceIdIndex uint64

func ParseTraceIdIndex(traceId string, traceIdIndexCfg *config.TraceIdWithIndex) uint64 {
	if traceIdIndexCfg.Disabled {
		return 0
	}
	if len(traceId) == 0 {
		return lastTraceIdIndex + 1
	}
	index, err := utils.GetTraceIdIndex(traceId, traceIdIndexCfg.TypeIsIncrementalId, traceIdIndexCfg.FormatIsHex, traceIdIndexCfg.IncrementalIdLocation.Start, traceIdIndexCfg.IncrementalIdLocation.Length)
	if err != nil {
		log.Debugf("parse traceIdIndex failed err %s", err)
		return lastTraceIdIndex + 1
	}
	lastTraceIdIndex = index
	return index
}

func (h *L7FlowLog) Fill(l *pb.AppProtoLogsData, platformData *grpc.PlatformInfoTable, cfg *flowlogCfg.Config) {
	h.L7Base.Fill(l, platformData)

	h.Type = uint8(l.Base.Head.MsgType)
	if l.Flags&uint32(pb.FlagBits_FLAG_TLS) != 0 {
		h.IsTLS = 1
	} else {
		h.IsTLS = 0
	}
	if l.Flags&uint32(pb.FlagBits_FLAG_ASYNC) != 0 {
		h.IsAsync = 1
	} else {
		h.IsAsync = 0
	}
	if l.Flags&uint32(pb.FlagBits_FLAG_REVERSED) != 0 {
		h.IsReversed = 1
	} else {
		h.IsReversed = 0
	}
	h.L7Protocol = uint8(l.Base.Head.Proto)
	if l.ExtInfo != nil && l.ExtInfo.ProtocolStr != "" {
		h.BizProtocol = l.ExtInfo.ProtocolStr
	} else {
		h.BizProtocol = datatype.L7Protocol(h.L7Protocol).String(h.IsTLS == 1)
	}

	h.ResponseStatus = uint8(datatype.STATUS_UNKNOWN)
	h.ResponseDuration = l.Base.Head.Rrt / uint64(time.Microsecond)
	// 协议结构统一, 不再为每个协议定义单独结构
	h.fillL7FlowLog(l, cfg)
}

func (h *L7FlowLog) fillTraceIds(t *pb.TraceInfo) {
	if t == nil {
		return
	}
	// get trace id from TraceIds field first
	for i, traceId := range t.TraceIds {
		if i == 0 {
			h.TraceId = traceId
		}
		if i == 1 {
			h.TraceId2 = traceId
		}
	}
	if h.TraceId == "" {
		h.TraceId = t.TraceId
	}
}

// requestLength,responseLength 等于 -1 会认为是没有值. responseCode=-32768 会认为没有值
func (h *L7FlowLog) fillL7FlowLog(l *pb.AppProtoLogsData, cfg *flowlogCfg.Config) {
	h.Version = l.Version
	h.requestLength = int64(l.ReqLen)
	h.responseLength = int64(l.RespLen)
	h.sqlAffectedRows = uint64(l.RowEffect)
	if h.sqlAffectedRows != 0 {
		h.SqlAffectedRows = &h.sqlAffectedRows
	}
	h.DirectionScore = uint8(l.DirectionScore)
	h.CapturedRequestByte = l.CapturedRequestByte
	h.CapturedResponseByte = l.CapturedResponseByte

	if l.Req != nil {
		h.RequestDomain = l.Req.Domain
		h.RequestResource = l.Req.Resource
		h.RequestType = l.Req.ReqType
		if h.requestLength != -1 && h.Type != uint8(datatype.MSG_T_RESPONSE) {
			h.RequestLength = &h.requestLength
		}
		h.Endpoint = l.Req.Endpoint
	}

	if l.Resp != nil {
		// if the l7 log type is Request, also need to read the response status
		h.ResponseStatus = uint8(l.Resp.Status)
		if h.Type != uint8(datatype.MSG_T_REQUEST) {
			h.ResponseResult = l.Resp.Result
			h.responseCode = l.Resp.Code
			h.ResponseException = l.Resp.Exception
			if h.ResponseException == "" {
				h.fillExceptionDesc(l)
			}

			if h.responseCode != datatype.L7PROTOCOL_LOG_RESP_CODE_NONE {
				h.ResponseCode = &h.responseCode
			}
			if h.responseLength != -1 {
				h.ResponseLength = &h.responseLength
			}
		}
	}

	if l.ExtInfo != nil {
		h.requestId = uint64(l.ExtInfo.RequestId)
		if h.requestId != 0 {
			h.RequestId = &h.requestId
		}
		h.AppService = l.ExtInfo.ServiceName
		h.XRequestId0 = l.ExtInfo.XRequestId_0
		h.XRequestId1 = l.ExtInfo.XRequestId_1
		h.HttpProxyClient = l.ExtInfo.ClientIp
		if l.ExtInfo.HttpUserAgent != "" {
			h.AttributeNames = append(h.AttributeNames, "http_user_agent")
			h.AttributeValues = append(h.AttributeValues, l.ExtInfo.HttpUserAgent)
		}
		if l.ExtInfo.HttpReferer != "" {
			h.AttributeNames = append(h.AttributeNames, "http_referer")
			h.AttributeValues = append(h.AttributeValues, l.ExtInfo.HttpReferer)
		}
		if l.ExtInfo.RpcService != "" {
			h.AttributeNames = append(h.AttributeNames, "rpc_service")
			h.AttributeValues = append(h.AttributeValues, l.ExtInfo.RpcService)
		}
		h.AttributeNames = append(h.AttributeNames, l.ExtInfo.AttributeNames...)
		h.AttributeValues = append(h.AttributeValues, l.ExtInfo.AttributeValues...)
		h.MetricsNames = append(h.MetricsNames, l.ExtInfo.MetricsNames...)
		h.MetricsValues = append(h.MetricsValues, l.ExtInfo.MetricsValues...)
	}
	if l.TraceInfo != nil {
		h.SpanId = l.TraceInfo.SpanId
		h.fillTraceIds(l.TraceInfo)
		h.ParentSpanId = l.TraceInfo.ParentSpanId
	}
	h.TraceIdIndex = ParseTraceIdIndex(h.TraceId, &cfg.Base.TraceIdWithIndex)

	// 处理内置协议特殊情况
	switch datatype.L7Protocol(h.L7Protocol) {
	case datatype.L7_PROTOCOL_KAFKA:
		if l.Req != nil {
			if h.responseCode == 0 && !IsKafkaSupportedCommand(l.Req.ReqType) {
				h.ResponseStatus = uint8(datatype.STATUS_TIMEOUT)
				h.ResponseCode = nil
			}
			h.RequestId = &h.requestId
		}
	case datatype.L7_PROTOCOL_SOFARPC:
		// assume protobuf and sofa rpc Always have request_id and maybe equal to 0
		h.RequestId = &h.requestId
	}
}

func IsKafkaSupportedCommand(cmd string) bool {
	for _, supportedCmd := range []datatype.KafkaCommand{datatype.Fetch, datatype.Produce, datatype.JoinGroup, datatype.LeaveGroup, datatype.SyncGroup} {
		if cmd == datatype.KafkaCommandString[supportedCmd] {
			return true
		}
	}
	return false
}

func (h *L7FlowLog) fillExceptionDesc(l *pb.AppProtoLogsData) {
	if h.ResponseStatus != uint8(datatype.STATUS_SERVER_ERROR) && h.ResponseStatus != uint8(datatype.STATUS_CLIENT_ERROR) {
		return
	}
	code := l.Resp.Code
	switch datatype.L7Protocol(h.L7Protocol) {
	case datatype.L7_PROTOCOL_HTTP_1, datatype.L7_PROTOCOL_HTTP_2:
		h.ResponseException = GetHTTPExceptionDesc(uint16(code))
	case datatype.L7_PROTOCOL_DNS:
		h.ResponseException = GetDNSExceptionDesc(uint16(code))
	case datatype.L7_PROTOCOL_DUBBO:
		h.ResponseException = GetDubboExceptionDesc(uint16(code))
	case datatype.L7_PROTOCOL_KAFKA:
		h.ResponseException = GetKafkaExceptionDesc(int16(code))
	case datatype.L7_PROTOCOL_MQTT:
		if l.Version != "5" {
			h.ResponseException = GetMQTTV3ExceptionDesc(uint16(code))
		} else {
			h.ResponseException = GetMQTTV5ExceptionDesc(uint16(code))
		}
	case datatype.L7_PROTOCOL_MYSQL, datatype.L7_PROTOCOL_REDIS:
		fallthrough
	default:
		h.ResponseException = l.Resp.Exception
	}
}

func (h *L7FlowLog) Release() {
	ReleaseL7FlowLog(h)
}

func (h *L7FlowLog) StartTime() time.Duration {
	return time.Duration(h.L7Base.StartTime) * time.Microsecond
}

func (h *L7FlowLog) EndTime() time.Duration {
	return time.Duration(h.L7Base.EndTime) * time.Microsecond
}

func (h *L7FlowLog) String() string {
	return fmt.Sprintf("L7FlowLog: %+v\n", *h)
}

func (h *L7FlowLog) ID() uint64 {
	return h._id
}

func (h *L7FlowLog) SetID(id uint64) {
	h._id = id
}

func (b *L7Base) Fill(log *pb.AppProtoLogsData, platformData *grpc.PlatformInfoTable) {
	l := log.Base
	// 网络层
	if l.IsIpv6 == 1 {
		b.IsIPv4 = false
		if len(b.IP60) > 0 {
			b.IP60 = b.IP60[:0]
		}
		b.IP60 = append(b.IP60, l.Ip6Src...)
		if len(b.IP61) > 0 {
			b.IP61 = b.IP61[:0]
		}
		b.IP61 = append(b.IP61, l.Ip6Dst...)
	} else {
		b.IsIPv4 = true
		b.IP40 = l.IpSrc
		b.IP41 = l.IpDst
	}

	// 传输层
	b.ClientPort = uint16(l.PortSrc)
	b.ServerPort = uint16(l.PortDst)

	// 流信息
	b.FlowID = l.FlowId

	b.TapType = uint8(l.TapType)
	tunnelType := datatype.TunnelType(0)
	var natSource datatype.NATSource
	b.TapPort, b.TapPortType, natSource, tunnelType = datatype.TapPort(l.TapPort).SplitToPortTypeTunnel()
	b.NatSource = uint8(natSource)
	b.SignalSource = uint16(datatype.SIGNAL_SOURCE_PACKET)
	if b.TapPortType == datatype.TAPPORT_FROM_OTEL {
		b.SignalSource = uint16(datatype.SIGNAL_SOURCE_OTEL)
	} else if b.TapPortType == datatype.TAPPORT_FROM_EBPF {
		b.SignalSource = uint16(datatype.SIGNAL_SOURCE_EBPF)
	}
	b.TunnelType = uint8(tunnelType)
	b.TapSide = flow_metrics.TAPSideEnum(l.TapSide).String()
	b.TapSideEnum = uint8(l.TapSide)

	b.VtapID = uint16(l.VtapId)
	b.ReqTcpSeq = l.ReqTcpSeq
	b.RespTcpSeq = l.RespTcpSeq
	b.StartTime = int64(l.StartTime) / int64(time.Microsecond)
	b.EndTime = int64(l.EndTime) / int64(time.Microsecond)
	b.Time = uint32(l.EndTime / uint64(time.Second))
	b.GPID0 = l.Gpid_0
	b.GPID1 = l.Gpid_1
	b.BizType = uint8(l.BizType)
	b.BizCode = log.BizCode
	b.BizScenario = log.BizScenario
	b.BizResponseCode = log.BizResponseCode

	b.ProcessID0 = l.ProcessId_0
	b.ProcessID1 = l.ProcessId_1
	b.ProcessKName0 = l.ProcessKname_0
	b.ProcessKName1 = l.ProcessKname_1
	b.SyscallTraceIDRequest = l.SyscallTraceIdRequest
	b.SyscallTraceIDResponse = l.SyscallTraceIdResponse
	b.SyscallThread0 = l.SyscallTraceIdThread_0
	b.SyscallThread1 = l.SyscallTraceIdThread_1
	b.SyscallCoroutine0 = l.SyscallCoroutine_0
	b.SyscallCoroutine1 = l.SyscallCoroutine_1
	b.SyscallCapSeq0 = l.SyscallCapSeq_0
	b.SyscallCapSeq1 = l.SyscallCapSeq_1

	// 知识图谱
	b.Protocol = uint8(log.Base.Protocol)

	b.KnowledgeGraph.FillL7(l, platformData, layers.IPProtocol(b.Protocol))

	// if ProcessId exists and GpId does not exist, get GpId through ProcessId
	if l.ProcessId_0 != 0 && l.Gpid_0 == 0 {
		b.GPID0 = platformData.QueryProcessInfo(b.OrgId, uint16(l.VtapId), l.ProcessId_0)
		b.TagSource0 |= uint8(flow_metrics.ProcessId)
	}
	if l.ProcessId_1 != 0 && l.Gpid_1 == 0 {
		b.GPID1 = platformData.QueryProcessInfo(b.OrgId, uint16(l.VtapId), l.ProcessId_1)
		b.TagSource1 |= uint8(flow_metrics.ProcessId)
	}
}

func (k *KnowledgeGraph) FillL7(l *pb.AppProtoLogsBaseInfo, platformData *grpc.PlatformInfoTable, protocol layers.IPProtocol) {
	k.fill(
		platformData,
		l.IsIpv6 == 1, l.IsVipInterfaceSrc == 1, l.IsVipInterfaceDst == 1,
		l.L3EpcIdSrc, l.L3EpcIdDst,
		l.IpSrc, l.IpDst,
		l.Ip6Src, l.Ip6Dst,
		l.MacSrc, l.MacDst,
		l.Gpid_0, l.Gpid_1,
		uint16(l.VtapId), l.PodId_0, l.PodId_1,
		uint16(l.PortDst),
		l.TapSide,
		protocol,
	)
}

var poolL7FlowLog = pool.NewLockFreePool(func() *L7FlowLog {
	return new(L7FlowLog)
})

func AcquireL7FlowLog() *L7FlowLog {
	l := poolL7FlowLog.Get()
	l.ReferenceCount.Reset()
	return l
}

func ReleaseL7FlowLog(l *L7FlowLog) {
	if l == nil {
		return
	}
	if l.SubReferenceCount() {
		return
	}
	*l = L7FlowLog{}
	poolL7FlowLog.Put(l)
}

var L7FlowLogCounter uint32

func ProtoLogToL7FlowLog(orgId, teamId uint16, l *pb.AppProtoLogsData, platformData *grpc.PlatformInfoTable, cfg *flowlogCfg.Config) *L7FlowLog {
	h := AcquireL7FlowLog()
	h.OrgId, h.TeamID = orgId, teamId
	h._id = genID(uint32(l.Base.EndTime/uint64(time.Second)), &L7FlowLogCounter, platformData.QueryAnalyzerID())
	h.Fill(l, platformData, cfg)
	return h
}

var extraFieldNamesNeedWriteFlowTag = [3]string{"app_service", "endpoint", "app_instance"}

// GenerateNewFlowTags 为L7流日志生成流标签
// 该方法将流日志中的属性和指标转换为可缓存的标签，用于优化查询性能和数据分类
func (h *L7FlowLog) GenerateNewFlowTags(cache *flow_tag.FlowTagCache) {
	// 初始化端点数量，默认为2（客户端和服务端）
	l := 2
	// 提取流两端的VPC ID数组
	L3EpcIDs := [2]int32{h.L3EpcID0, h.L3EpcID1}
	// 提取流两端的Pod命名空间ID数组
	PodNSIDs := [2]uint16{h.PodNSID0, h.PodNSID1}

	// 如果流的两端在同一个VPC和同一个Pod命名空间中，则只需要处理1个端点
	// 这种优化避免了重复处理相同的标签信息
	if h.L3EpcID0 == h.L3EpcID1 && h.PodNSID0 == h.PodNSID1 {
		l = 1
	}

	// 将结束时间从微秒转换为秒，作为标签的时间戳
	time := uint32(h.L7Base.EndTime / US_TO_S_DEVISOR)

	// 需要写入流标签的额外字段值（应用服务、端点、应用实例）
	// 这些是DeepFlow内置的重要字段，需要特殊处理
	extraFieldValuesNeedWriteFlowTag := [3]string{h.AppService, h.Endpoint, h.AppInstance}

	// 将用户自定义属性与内置字段合并，生成完整的属性名列表
	attributeNames := append(h.AttributeNames, extraFieldNamesNeedWriteFlowTag[:]...)
	// 对应地合并属性值列表
	attributeValues := append(h.AttributeValues, extraFieldValuesNeedWriteFlowTag[:]...)

	// 安全检查：避免因属性名和值数量不匹配导致的panic
	// 这种情况可能发生在数据异常或配置错误时
	namesLen, valuesLen := len(attributeNames), len(attributeValues)
	minNamesLen := namesLen
	if namesLen != valuesLen {
		log.Warningf("the lengths of AttributeNames (%v) and attributeValues (%v) is different", attributeNames, attributeValues)
		if namesLen > valuesLen {
			minNamesLen = valuesLen
		}
	}

	// 重置缓存缓冲区，复用内存避免频繁分配
	cache.Fields = cache.Fields[:0]
	cache.FieldValues = cache.FieldValues[:0]

	// 遍历每个需要处理的端点（1个或2个）
	for idx := 0; idx < l; idx++ {
		// 重置临时缓冲区，准备构建流标签信息
		flowTagInfo := &cache.FlowTagInfoBuffer
		*flowTagInfo = flow_tag.FlowTagInfo{
			Table:   common.L7_FLOW_ID.String(), // 表名标识
			VpcId:   L3EpcIDs[idx],              // 当前端点的VPC ID
			PodNsId: PodNSIDs[idx],              // 当前端点的Pod命名空间ID
			OrgId:   h.OrgId,                    // 组织ID（多租户隔离）
			TeamID:  h.TeamID,                   // 团队ID（细粒度权限控制）
		}

		// 处理所有属性名值对
		for i, name := range attributeNames[:minNamesLen] {
			flowTagInfo.FieldName = name

			// ===== 处理标签值（Tag + Value）=====
			// 用于存储具体的标签值，支持精确查询
			flowTagInfo.FieldValue = attributeValues[i]

			// 检查缓存中是否已存在相同的标签值
			// 使用LRU缓存避免重复写入相同的标签，提高性能
			if old, ok := cache.FieldValueCache.AddOrGet(*flowTagInfo, time); ok {
				// 如果缓存未过期且存在，则跳过处理
				if old+cache.CacheFlushTimeout >= time {
					// 如果没有新的fieldValue，当然也不会有新的field
					// 因此可以跳过循环中的其余处理
					continue
				} else {
					// 缓存已过期，更新缓存
					cache.FieldValueCache.Add(*flowTagInfo, time)
				}
			}
			// 创建新的标签值对象并添加到缓存
			tagFieldValue := flow_tag.AcquireFlowTag(flow_tag.TagFieldValue)
			tagFieldValue.Timestamp = time
			tagFieldValue.FlowTagInfo = *flowTagInfo
			cache.FieldValues = append(cache.FieldValues, tagFieldValue)

			// ===== 处理标签名（Only Tag）=====
			// extraFieldNamesNeedWriteFlowTag中的标签键不需要写入flow_tag表
			// 这些是内置字段，已经通过其他方式处理
			if i >= len(h.AttributeNames) {
				continue
			}
			// 清空字段值，只保留字段名用于标签名索引
			flowTagInfo.FieldValue = ""
			// 检查标签名缓存
			if old, ok := cache.FieldCache.AddOrGet(*flowTagInfo, time); ok {
				if old+cache.CacheFlushTimeout >= time {
					continue
				} else {
					cache.FieldCache.Add(*flowTagInfo, time)
				}
			}
			// 创建新的标签名对象并添加到缓存
			tagField := flow_tag.AcquireFlowTag(flow_tag.TagField)
			tagField.Timestamp = time
			tagField.FlowTagInfo = *flowTagInfo
			cache.Fields = append(cache.Fields, tagField)
		}

		// ===== 处理指标名称 =====
		// 指标只需要记录名称，不需要记录值（值存储在原始数据中）
		flowTagInfo.FieldType = flow_tag.FieldMetrics
		flowTagInfo.FieldValue = ""
		for _, name := range h.MetricsNames {
			flowTagInfo.FieldName = name
			// 检查指标名称缓存
			if old, ok := cache.FieldCache.AddOrGet(*flowTagInfo, time); ok {
				if old+cache.CacheFlushTimeout >= time {
					continue
				} else {
					cache.FieldCache.Add(*flowTagInfo, time)
				}
			}
			// 创建指标标签对象
			tagField := flow_tag.AcquireFlowTag(flow_tag.TagField)
			tagField.Timestamp = time
			tagField.FlowTagInfo = *flowTagInfo
			cache.Fields = append(cache.Fields, tagField)
		}
	}
}
