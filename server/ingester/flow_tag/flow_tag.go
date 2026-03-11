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
	"github.com/zerotraceio/zerotrace/server/ingester/common"
	"github.com/zerotraceio/zerotrace/server/libs/ckdb"
	"github.com/zerotraceio/zerotrace/server/libs/pool"
)

const (
	FLOW_TAG_DB = "flow_tag"
)

// TagType 定义流标签的类型，用于对不同标签数据进行分类
type TagType uint8

const (
	// TagField 表示标签字段定义（自定义字段名）
	// 用于存储标签字段的元数据，如字段名称、类型和属性
	// 映射到 ClickHouse 中的 "custom_field" 表
	TagField TagType = iota

	// TagFieldValue 表示标签字段值（自定义字段值）
	// 用于存储标签字段的实际值及其计数
	// 映射到 ClickHouse 中的 "custom_field_value" 表
	TagFieldValue

	// TagTypeMax 作为 TagType 枚举的边界标记
	// 用于定义标签类型的最大数量和数组大小
	TagTypeMax
)

func (t TagType) String() string {
	switch t {
	case TagField:
		return "custom_field"
	case TagFieldValue:
		return "custom_field_value"
	default:
		return "invalid tag type"
	}
}

type FieldType uint8

const (
	FieldTag FieldType = iota
	FieldMetrics
	FieldCustomTag
)

func (t FieldType) String() string {
	switch t {
	case FieldTag:
		return "tag"
	case FieldMetrics:
		return "metrics"
	case FieldCustomTag:
		return "custom_tag"
	default:
		return "invalid field type"
	}
}

type FieldValueType uint8

const (
	FieldValueTypeAuto FieldValueType = iota
	FieldValueTypeString
	FieldValueTypeFloat
	FieldValueTypeInt
)

func (t FieldValueType) String() string {
	switch t {
	case FieldValueTypeString:
		return "string"
	case FieldValueTypeFloat:
		return "float"
	case FieldValueTypeInt:
		return "int"
	default:
		return "invalid"
	}
}

// This structure will be used as a map key, and it is hoped to be as compact as possible in terms of memory layout.
// In addition, in order to distinguish as early as possible when comparing two values, put the highly distinguishable fields at the front.
type FlowTagInfo struct {
	// Table 数据表名称，标识标签所属的数据表
	// 在外部指标中表示虚拟表名（virtual_table_name）
	// 用于区分不同类型的数据，如流日志、流指标、事件、性能分析等
	// 支持多表存储，便于数据管理和查询优化
	Table string

	// FieldName 字段名称，标识标签的字段名
	// 用于存储和查询字段名信息，如协议名称、服务名称、端点名称等
	// 与FieldValue配合使用，构成完整的标签信息
	FieldName string

	// FieldValue 字段值，存储标签的具体值
	// 用于存储字段对应的值，如HTTP、MySQL、user-service、/api/users等
	// 可以为空字符串，仅存储字段名信息
	FieldValue string

	// FieldValueType 字段值类型，标识字段值的数据类型
	// 用于优化存储和查询性能，支持自动检测、字符串、浮点数、整数等类型
	// 在ClickHouse中使用LowCardinality类型优化存储
	FieldValueType FieldValueType

	// VtapId 虚拟点击点ID，标识DeepFlow Agent实例
	// 用于区分不同的数据采集点，支持多Agent部署
	// 在数据溯源和故障排查时使用
	VtapId uint16

	// TableId 表ID，仅用于Prometheus数据
	// 将表名转换为数字ID，优化Prometheus数据的存储和查询性能
	// 与字符串形式的Table字段对应，用于Prometheus特殊处理
	TableId uint32

	// FieldNameId 字段名ID，仅用于Prometheus数据
	// 将字段名转换为数字ID，优化Prometheus数据的存储和查询性能
	// 与字符串形式的FieldName字段对应，用于Prometheus特殊处理
	FieldNameId uint32

	// FieldValueId 字段值ID，仅用于Prometheus数据
	// 将字段值转换为数字ID，优化Prometheus数据的存储和查询性能
	// 与字符串形式的FieldValue字段对应，用于Prometheus特殊处理
	FieldValueId uint32

	// VpcId 虚拟私有云ID，标识网络隔离域
	// 用于多VPC环境下的数据隔离和管理
	// 注释表明可以使用int16类型以节省空间
	VpcId int32

	// PodNsId Pod命名空间ID，标识Kubernetes命名空间
	// 用于容器环境下的资源隔离和管理
	// 支持多租户和命名空间级别的数据组织
	PodNsId uint16

	// FieldType 字段类型，区分标签和指标
	// FieldTag：表示标签信息，如协议、服务、端点等
	// FieldMetrics：表示指标信息，如延迟、吞吐量、错误率等
	FieldType FieldType

	// OrgId 组织ID，用于多租户数据隔离
	// 不存储在数据库中，仅用于确定存储的数据库名称
	// 当OrgId为0或1时，存储在'flow_tag'数据库；否则存储在'<OrgId>_flow_tag'数据库
	OrgId uint16

	// TeamID 团队ID，用于组织内部的数据隔离
	// 支持企业级多团队环境下的数据访问控制
	// 与OrgId配合实现细粒度的权限管理
	TeamID uint16
}

type FlowTag struct {
	pool.ReferenceCount
	TagType

	Timestamp uint32 // s
	FlowTagInfo
}

func (t *FlowTag) NativeTagVersion() uint32 {
	return 0
}

func (t *FlowTag) OrgID() uint16 {
	return t.OrgId
}

func (t *FlowTag) Columns() []*ckdb.Column {
	columns := []*ckdb.Column{}
	columns = append(columns,
		ckdb.NewColumn("time", ckdb.DateTime),
		ckdb.NewColumn("table", ckdb.LowCardinalityString),
		ckdb.NewColumn("vpc_id", ckdb.Int32),
		ckdb.NewColumn("pod_ns_id", ckdb.UInt16),
		ckdb.NewColumn("field_type", ckdb.LowCardinalityString).SetComment("value: tag, custom_tag, metrics"),
		ckdb.NewColumn("field_name", ckdb.LowCardinalityString),
		ckdb.NewColumn("field_value_type", ckdb.LowCardinalityString).SetComment("value: string, float, int"),
		ckdb.NewColumn("team_id", ckdb.UInt16),
	)
	if t.TagType == TagFieldValue {
		columns = append(columns,
			ckdb.NewColumn("field_value", ckdb.String),
			ckdb.NewColumn("count", ckdb.UInt64))
	}
	return columns
}

// GenCKTable 为流标签生成 ClickHouse 表结构定义
// 根据标签类型（TagField 或 TagFieldValue）创建不同的表结构和引擎
//
// 参数说明:
//   - cluster: ClickHouse 集群名称
//   - storagePolicy: 存储策略，用于数据分布和存储优化
//   - tableName: 表名称
//   - ckdbType: ClickHouse 数据库类型（clickhouse 或 byconity）
//   - ttl: 数据保留时间（小时）
//   - partition: 分区函数类型，用于按时间分区
//
// 返回值:
//   - *ckdb.Table: 完整的 ClickHouse 表结构定义
func (t *FlowTag) GenCKTable(cluster, storagePolicy, tableName, ckdbType string, ttl int, partition ckdb.TimeFuncType) *ckdb.Table {
	// 时间字段名称，用于分区和 TTL
	timeKey := "time"
	// 默认使用 ReplacingMergeTree 引擎，用于去重和更新
	engine := ckdb.ReplacingMergeTree

	// 基础排序键，用于数据排序和查询优化
	orderKeys := []string{
		"table", "field_type", "field_name", "field_value_type",
	}

	// 如果是标签值类型，需要额外的排序键和不同的引擎
	if t.TagType == TagFieldValue {
		// 添加字段值到排序键，因为值表需要按值进行聚合
		orderKeys = append(orderKeys, "field_value")
		// 使用 SummingMergeTree 引擎，自动对 count 字段进行求和聚合
		engine = ckdb.SummingMergeTree
	}

	// 构建完整的 ClickHouse 表结构
	return &ckdb.Table{
		Version:         common.CK_VERSION,              // 表版本，用于结构变更时的自动更新
		Database:        FLOW_TAG_DB,                    // 固定数据库名 "flow_tag"
		DBType:          ckdbType,                       // 数据库类型
		LocalName:       tableName + ckdb.LOCAL_SUBFFIX, // 本地表名（带 _local 后缀）
		GlobalName:      tableName,                      // 全局表名
		Columns:         t.Columns(),                    // 动态生成的列结构
		TimeKey:         timeKey,                        // 时间字段名
		SummingKey:      "count",                        // SummingMergeTree 引擎的聚合字段（暂未使用）
		TTL:             ttl,                            // 数据保留时间
		PartitionFunc:   partition,                      // 分区函数
		Engine:          engine,                         // 表引擎类型
		Cluster:         cluster,                        // 集群名称
		StoragePolicy:   storagePolicy,                  // 存储策略
		OrderKeys:       orderKeys,                      // 排序键
		PrimaryKeyCount: len(orderKeys),                 // 主键数量（从排序键中计算）
	}
}

func (t *FlowTag) Release() {
	ReleaseFlowTag(t)
}

var flowTagPool = pool.NewLockFreePool(func() *FlowTag {
	return &FlowTag{}
})

func AcquireFlowTag(tagType TagType) *FlowTag {
	f := flowTagPool.Get()
	f.ReferenceCount.Reset()
	f.TagType = tagType
	return f
}

var emptyFlowTag = FlowTag{}

func ReleaseFlowTag(t *FlowTag) {
	if t == nil || t.SubReferenceCount() {
		return
	}
	*t = emptyFlowTag
	flowTagPool.Put(t)
}
