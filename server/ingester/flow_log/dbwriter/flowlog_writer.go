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
	logging "github.com/op/go-logging"

	basecommon "github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/config"
	"github.com/deepflowio/deepflow/server/ingester/flow_log/common"
	flowlogconfig "github.com/deepflowio/deepflow/server/ingester/flow_log/config"
	logdata "github.com/deepflowio/deepflow/server/ingester/flow_log/log_data"
	"github.com/deepflowio/deepflow/server/ingester/pkg/ckwriter"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
)

var log = logging.MustGetLogger("flow_log.dbwriter")

const (
	CACHE_SIZE       = 10240
	DefaultPartition = ckdb.TimeFuncHour
)

type FlowLogWriter struct {
	ckwriters []*ckwriter.CKWriter
}

func newFlowLogTable(id common.FlowLogID, columns []*ckdb.Column, engine ckdb.EngineType, cluster, storagePolicy, ckdbType string, ttl int, coldStorage *ckdb.ColdStorage) *ckdb.Table {
	timeKey := id.TimeKey()
	var orderKeys = []string{timeKey}
	flowKeys := []string{"l3_epc_id_1", "ip4_1", "ip6_1", "server_port"}
	switch id {
	case common.L7_FLOW_ID:
		orderKeys = append(orderKeys, "l7_protocol")
		orderKeys = append(orderKeys, flowKeys...)
	case common.L4_FLOW_ID:
		orderKeys = append(orderKeys, flowKeys...)
	case common.L4_PACKET_ID:
		orderKeys = append(orderKeys, "flow_id", "agent_id")
	default:
		panic("unreachalable")
	}

	return &ckdb.Table{
		Version:         basecommon.CK_VERSION,
		ID:              uint8(id),
		Database:        common.FLOW_LOG_DB,
		DBType:          ckdbType,
		LocalName:       id.String() + "_local",
		GlobalName:      id.String(),
		Columns:         columns,
		TimeKey:         timeKey,
		Engine:          engine,
		Cluster:         cluster,
		StoragePolicy:   storagePolicy,
		PartitionFunc:   DefaultPartition,
		TTL:             ttl,
		ColdStorage:     *coldStorage,
		OrderKeys:       orderKeys,
		PrimaryKeyCount: len(orderKeys),
	}
}

// GetFlowLogTables 创建流日志表的配置
// 返回包含L4流日志、L7流日志和L4数据包表的表配置数组
func GetFlowLogTables(engine ckdb.EngineType, cluster, storagePolicy, ckdbType string, l4LogTtl, l7LogTtl, l4PacketTtl int, coldStorages map[string]*ckdb.ColdStorage) []*ckdb.Table {
	return []*ckdb.Table{
		// 创建L4流日志表配置，包含网络层流数据
		newFlowLogTable(common.L4_FLOW_ID, logdata.L4FlowLogColumns(), engine, cluster, storagePolicy, ckdbType, l4LogTtl, ckdb.GetColdStorage(coldStorages, common.FLOW_LOG_DB, common.L4_FLOW_ID.String())),

		// 创建L7流日志表配置，包含应用层流数据
		newFlowLogTable(common.L7_FLOW_ID, logdata.L7FlowLogColumns(), engine, cluster, storagePolicy, ckdbType, l7LogTtl, ckdb.GetColdStorage(coldStorages, common.FLOW_LOG_DB, common.L7_FLOW_ID.String())),

		// 创建L4数据包表配置，包含数据包级别的详细数据
		newFlowLogTable(common.L4_PACKET_ID, logdata.L4PacketColumns(), engine, cluster, storagePolicy, ckdbType, l4PacketTtl, ckdb.GetColdStorage(coldStorages, common.FLOW_LOG_DB, common.L4_PACKET_ID.String())),
	}
}

// NewFlowLogWriter 创建流日志写入器
// 为每种类型的流日志表创建对应的CKWriter实例，用于写入ClickHouse
func NewFlowLogWriter(addrs []string, user, password, cluster, storagePolicy, timeZone, ckdbType string, ckWriterCfg config.CKWriterConfig, flowLogTtl flowlogconfig.FlowLogTTL, coldStorages map[string]*ckdb.ColdStorage, ckdbWatcher *config.Watcher) (*FlowLogWriter, error) {
	// 创建CKWriter数组，大小为流日志类型总数
	ckwriters := make([]*ckwriter.CKWriter, common.FLOWLOG_ID_MAX)
	var err error

	// 获取所有流日志表的配置
	tables := GetFlowLogTables(ckdb.MergeTree, cluster, storagePolicy, ckdbType, flowLogTtl.L4FlowLog, flowLogTtl.L7FlowLog, flowLogTtl.L4Packet, coldStorages)

	// 为每个表创建对应的CKWriter
	for i, table := range tables {
		// 使用表ID作为计数器名称
		counterName := common.FlowLogID(table.ID).String()

		// 创建CKWriter实例，配置队列、批处理等参数
		ckwriters[i], err = ckwriter.NewCKWriter(addrs, user, password, counterName, timeZone, table,
			ckWriterCfg.QueueCount, ckWriterCfg.QueueSize, ckWriterCfg.BatchSize, ckWriterCfg.FlushTimeout, ckdbWatcher)
		if err != nil {
			log.Error(err)
			return nil, err
		}

		// 启动CKWriter，开始处理数据写入
		ckwriters[i].Run()
	}

	// 返回FlowLogWriter实例，包含所有CKWriter
	return &FlowLogWriter{
		ckwriters: ckwriters,
	}, nil
}

func (w *FlowLogWriter) Put(index int, items ...interface{}) {
	w.ckwriters[index].Put(items...)
}

func (w *FlowLogWriter) Close() {
	for _, ckwriter := range w.ckwriters {
		ckwriter.Close()
	}
}
