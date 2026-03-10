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

package flow_tag

import (
	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/pool"
)

type AppServiceTag struct {
	// Time 时间戳（秒），记录标签的生成时间
	// 用于数据分区和时间序列分析
	// 在ClickHouse中作为时间分区的依据
	Time uint32 // s

	// Table 数据表名称，标识标签所属的数据表
	// 用于区分不同类型的数据，如流日志、流指标、事件等
	// 支持多表存储，便于数据管理和查询优化
	Table string

	// AppService 应用服务名称，标识应用程序的服务
	// 用于服务拓扑分析和应用性能监控
	// 通常与应用程序的业务功能相关，如"user-service"、"order-service"
	AppService string

	// AppInstance 应用实例名称，标识服务的具体实例
	// 用于区分同一服务的多个部署实例
	// 支持实例级别的监控和故障排查
	AppInstance string

	// TeamID 团队ID，用于多租户环境下的团队隔离
	// 支持基于团队的数据访问控制和资源配额管理
	// 在企业级多团队环境中使用
	TeamID uint16

	// OrgId 组织ID，用于多租户环境下的组织隔离
	// 支持基于组织的数据隔离和权限管理
	// 确保不同组织的数据安全性和隐私性
	OrgId uint16
}

func (t *AppServiceTag) NativeTagVersion() uint32 {
	return 0
}

func (t *AppServiceTag) OrgID() uint16 {
	return t.OrgId
}

func AppServiceTagColumns() []*ckdb.Column {
	columns := []*ckdb.Column{}
	columns = append(columns,
		ckdb.NewColumn("time", ckdb.DateTime),
		ckdb.NewColumn("table", ckdb.LowCardinalityString),
		ckdb.NewColumn("app_service", ckdb.LowCardinalityString),
		ckdb.NewColumn("app_instance", ckdb.LowCardinalityString),
		ckdb.NewColumn("team_id", ckdb.UInt16),
	)
	return columns
}

func GenAppServiceTagCKTable(cluster, storagePolicy, tableName, ckdbType string, ttl int, partition ckdb.TimeFuncType) *ckdb.Table {
	timeKey := "time"
	engine := ckdb.ReplacingMergeTree
	orderKeys := []string{"table", "app_service", "app_instance"}

	return &ckdb.Table{
		Version:         common.CK_VERSION,
		Database:        FLOW_TAG_DB,
		DBType:          ckdbType,
		LocalName:       tableName + ckdb.LOCAL_SUBFFIX,
		GlobalName:      tableName,
		Columns:         AppServiceTagColumns(),
		TimeKey:         timeKey,
		TTL:             ttl,
		PartitionFunc:   partition,
		Engine:          engine,
		Cluster:         cluster,
		StoragePolicy:   storagePolicy,
		OrderKeys:       orderKeys,
		PrimaryKeyCount: len(orderKeys),
	}
}

func (t *AppServiceTag) Release() {
	ReleaseAppServiceTag(t)
}

var appServiceTagPool = pool.NewLockFreePool(func() *AppServiceTag {
	return &AppServiceTag{}
})

func AcquireAppServiceTag() *AppServiceTag {
	f := appServiceTagPool.Get()
	return f
}

var emptyAppServiceTag = AppServiceTag{}

func ReleaseAppServiceTag(t *AppServiceTag) {
	if t == nil {
		return
	}
	*t = emptyAppServiceTag
	appServiceTagPool.Put(t)
}
