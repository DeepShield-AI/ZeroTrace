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

package dbwriter

import (
	"net"

	basecommon "github.com/deepflowio/deepflow/server/ingester/common"
	baseconfig "github.com/deepflowio/deepflow/server/ingester/config"
	"github.com/deepflowio/deepflow/server/ingester/flow_log/common"
	"github.com/deepflowio/deepflow/server/ingester/flow_log/config"
	logdata "github.com/deepflowio/deepflow/server/ingester/flow_log/log_data"
	"github.com/deepflowio/deepflow/server/ingester/pkg/ckwriter"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/codec"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/tracetree"
)

const (
	SPAN_WITH_TRACE_ID_TABLE = "span_with_trace_id"
)

type SpanWithTraceID logdata.L7FlowLog

func SpanWithTraceIDColumns() []*ckdb.Column {
	return []*ckdb.Column{
		ckdb.NewColumn("time", ckdb.DateTime),
		ckdb.NewColumn("trace_id", ckdb.String),
		ckdb.NewColumn("_trace_id_2", ckdb.String),
		ckdb.NewColumn("search_index", ckdb.UInt64),
		ckdb.NewColumn("encoded_span", ckdb.String),
	}
}

func (t *SpanWithTraceID) OrgID() uint16 {
	return t.OrgId
}

func (t *SpanWithTraceID) Release() {
	logdata.ReleaseL7FlowLog((*logdata.L7FlowLog)(t))
}

func (t *SpanWithTraceID) Encode() {
	encoder := &codec.SimpleEncoder{}
	t.EncodedSpan = t.EncodedSpan[:0]
	encoder.Init(t.EncodedSpan)
	encoder.WriteU8(tracetree.SPAN_TRACE_VERSION)
	encoder.WriteU32(uint32(t.EndTime % 1000000)) // only encode microsecond part less than 1 second
	encoder.WriteU16(t.SignalSource)
	encoder.WriteVarintU32(t.TapPort)
	encoder.WriteU8(t.TapPortType)
	encoder.WriteU8(t.TapType)
	encoder.WriteU8(t.AutoServiceType0)
	encoder.WriteU8(t.AutoServiceType1)
	if t.SignalSource == uint16(datatype.SIGNAL_SOURCE_EBPF) || t.SignalSource == uint16(datatype.SIGNAL_SOURCE_OTEL) {
		encoder.WriteU8(t.AutoInstanceType0)
		encoder.WriteU8(t.AutoInstanceType1)
	}
	encoder.WriteVarintU32(t.AutoServiceID0)
	encoder.WriteVarintU32(t.AutoServiceID1)
	if t.SignalSource == uint16(datatype.SIGNAL_SOURCE_EBPF) || t.SignalSource == uint16(datatype.SIGNAL_SOURCE_OTEL) {
		encoder.WriteVarintU32(t.AutoInstanceID0)
		encoder.WriteVarintU32(t.AutoInstanceID1)
	}
	encoder.WriteBool(t.IsIPv4)
	if t.IsIPv4 {
		encoder.WriteU32(t.IP40)
		encoder.WriteU32(t.IP41)
	} else {
		if len(t.IP60) == 0 {
			t.IP60 = net.IPv6zero
		}
		if len(t.IP61) == 0 {
			t.IP61 = net.IPv6zero
		}
		encoder.WriteIPv6(t.IP60)
		encoder.WriteIPv6(t.IP61)
	}
	encoder.WriteVarintU32(t.ProcessID0)
	encoder.WriteVarintU32(t.ProcessID1)
	encoder.WriteU16(t.VtapID)
	encoder.WriteU8(t.TapSideEnum)
	encoder.WriteVarintU32(t.ReqTcpSeq)
	encoder.WriteVarintU32(t.RespTcpSeq)
	encoder.WriteString255(t.XRequestId0)
	encoder.WriteString255(t.XRequestId1)
	encoder.WriteString255(t.SpanId)
	encoder.WriteString255(t.ParentSpanId)
	encoder.WriteString255(t.AppService)
	encoder.WriteString255(t.Endpoint)
	encoder.WriteString255(t.RequestType)
	encoder.WriteString255(t.RequestDomain)
	encoder.WriteString255(t.RequestResource)
	encoder.WriteString255(t.ResponseResult)
	encoder.WriteString255(t.BizProtocol)
	encoder.WriteString255(t.ResponseException)
	if t.RequestId != nil {
		encoder.WriteVarintU64(*t.RequestId)
	} else {
		encoder.WriteVarintU64(0)
	}
	encoder.WriteVarintU64(t.SyscallTraceIDRequest)
	encoder.WriteVarintU64(t.SyscallTraceIDResponse)
	encoder.WriteVarintU64(t.ResponseDuration)
	if t.ResponseCode != nil {
		encoder.WriteVarintU32(uint32(*t.ResponseCode))
	} else {
		encoder.WriteVarintU32(0)
	}
	encoder.WriteU8(t.ResponseStatus)
	encoder.WriteU8(t.Type)
	encoder.WriteU8(t.IsAsync)
	encoder.WriteU8(t.IsReversed)
	t.EncodedSpan = encoder.Bytes()
}

// GenSpanWithTraceIDCKTable 生成Span表的ClickHouse配置
// 定义了span_with_trace_id表的结构和存储参数
func GenSpanWithTraceIDCKTable(cluster, storagePolicy, ckdbType string, ttl int, coldStorage *ckdb.ColdStorage) *ckdb.Table {
	table := SPAN_WITH_TRACE_ID_TABLE             // 表名常量
	timeKey := "time"                             // 时间分区键
	engine := ckdb.MergeTree                      // 使用MergeTree引擎
	orderKeys := []string{"search_index", "time"} // 排序键

	return &ckdb.Table{
		Version:         basecommon.CK_VERSION,      // 表版本
		Database:        common.FLOW_LOG_DB,         // 数据库名
		DBType:          ckdbType,                   // 数据库类型
		LocalName:       table + ckdb.LOCAL_SUBFFIX, // 本地表名
		GlobalName:      table,                      // 全局表名
		Columns:         SpanWithTraceIDColumns(),   // 表列定义
		TimeKey:         timeKey,                    // 时间键
		TTL:             ttl,                        // 数据保留时间
		PartitionFunc:   DefaultPartition,           // 分区函数
		Engine:          engine,                     // 存储引擎
		Cluster:         cluster,                    // 集群配置
		StoragePolicy:   storagePolicy,              // 存储策略
		ColdStorage:     *coldStorage,               // 冷存储配置
		OrderKeys:       orderKeys,                  // 排序键
		PrimaryKeyCount: len(orderKeys),             // 主键数量
	}
}

// 负责将链路追踪的 Span 数据写入 ClickHouse 数据库
type SpanWriter struct {
	ckdbAddrs         *[]string                    // ClickHouse数据库地址列表，支持多节点集群
	ckdbUsername      string                       // ClickHouse数据库用户名，用于身份验证
	ckdbPassword      string                       // ClickHouse数据库密码，用于身份验证
	ckdbCluster       string                       // ClickHouse集群名称，用于分布式部署
	ckdbStoragePolicy string                       // ClickHouse存储策略，控制数据存储和分层
	ckdbColdStorages  map[string]*ckdb.ColdStorage // 冷存储配置映射，用于数据生命周期管理
	ttl               int                          // 数据生存时间（TTL），自动清理过期数据
	writerConfig      baseconfig.CKWriterConfig    // ClickHouse写入器配置，包含队列、批次等参数

	traceWriter *ckwriter.CKWriter // 实际的ClickHouse写入器实例，负责数据写入操作
}

// NewSpanWriter 创建Span写入器，用于将追踪数据写入ClickHouse
// 如果追踪树功能未启用，则返回nil
func NewSpanWriter(config *config.Config) (*SpanWriter, error) {
	// 检查追踪树功能是否启用
	if !*config.TraceTreeEnabled {
		return nil, nil
	}

	// 初始化SpanWriter结构体，配置ClickHouse连接参数
	w := &SpanWriter{
		ckdbAddrs:         config.Base.CKDB.ActualAddrs,      // ClickHouse地址列表
		ckdbUsername:      config.Base.CKDBAuth.Username,     // 数据库用户名
		ckdbPassword:      config.Base.CKDBAuth.Password,     // 数据库密码
		ckdbCluster:       config.Base.CKDB.ClusterName,      // 集群名称
		ckdbStoragePolicy: config.Base.CKDB.StoragePolicy,    // 存储策略
		ckdbColdStorages:  config.Base.GetCKDBColdStorages(), // 冷存储配置
		ttl:               config.FlowLogTTL.L7FlowLog,       // 数据保留时间
		writerConfig:      config.CKWriterConfig,             // 写入器配置
	}

	// 生成Span表的ClickHouse配置
	ckTable := GenSpanWithTraceIDCKTable(w.ckdbCluster, w.ckdbStoragePolicy, config.Base.CKDB.Type, w.ttl, ckdb.GetColdStorage(w.ckdbColdStorages, common.FLOW_LOG_DB, SPAN_WITH_TRACE_ID_TABLE))

	// 创建CKWriter实例，用于实际的数据写入
	ckwriter, err := ckwriter.NewCKWriter(*w.ckdbAddrs, w.ckdbUsername, w.ckdbPassword,
		SPAN_WITH_TRACE_ID_TABLE, config.Base.CKDB.TimeZone, ckTable, w.writerConfig.QueueCount, w.writerConfig.QueueSize, w.writerConfig.BatchSize, w.writerConfig.FlushTimeout, config.Base.CKDB.Watcher)
	if err != nil {
		return nil, err
	}
	w.traceWriter = ckwriter

	return w, nil
}

func (s *SpanWriter) Put(items []interface{}) {
	s.traceWriter.Put(items...)
}

func (s *SpanWriter) Start() {
	log.Info("flow log span writer starting")
	s.traceWriter.Run()
}

func (s *SpanWriter) Close() {
	s.traceWriter.Close()
}
