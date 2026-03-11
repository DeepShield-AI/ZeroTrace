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
	"fmt"
	"strconv"
	"strings"

	logging "github.com/op/go-logging"

	"github.com/zerotraceio/zerotrace/server/ingester/common"
	"github.com/zerotraceio/zerotrace/server/ingester/config"
	"github.com/zerotraceio/zerotrace/server/ingester/pkg/ckwriter"
	"github.com/zerotraceio/zerotrace/server/libs/ckdb"
	lru128 "github.com/zerotraceio/zerotrace/server/libs/hmap/lru"
	"github.com/zerotraceio/zerotrace/server/libs/lru"
	"github.com/zerotraceio/zerotrace/server/libs/stats"
	"github.com/zerotraceio/zerotrace/server/libs/utils"
)

var log = logging.MustGetLogger("flow_tag.dbwriter")

const (
	FLOW_TAG_CACHE_INIT_SIZE = 1 << 14
	MIN_FLUSH_CACHE_TIMEOUT  = 60
	PROMETHEUS_KEYWORD       = "prometheus"
)

type Counter struct {
	NewFieldCount        int64 `statsd:"new-field-count"`
	NewFieldValueCount   int64 `statsd:"new-field-value-count"`
	FieldCacheCount      int64 `statsd:"field-cache-count"`
	FieldValueCacheCount int64 `statsd:"field-value-cache-count"`
}

// 负责将流标签元数据写入 ClickHouse 数据库
type FlowTagWriter struct {
	// ckdbAddrs ClickHouse数据库地址列表
	// 用于连接ClickHouse集群，支持多个地址实现高可用
	// 在创建CKWriter时使用，建立数据库连接池
	ckdbAddrs *[]string

	// ckdbUsername ClickHouse数据库用户名
	// 用于数据库认证，确保访问权限控制
	ckdbUsername string

	// ckdbPassword ClickHouse数据库密码
	// 与用户名配合进行身份验证
	ckdbPassword string

	// writerConfig ClickHouse写入器配置
	// 包含队列数量、队列大小、批量大小、刷新超时等参数
	// 控制数据写入的性能和行为
	writerConfig *config.CKWriterConfig

	// ckwriters ClickHouse写入器数组，按标签类型分组
	// TagTypeMax定义了支持的标签类型数量
	// 每种标签类型有独立的写入器，优化存储和查询性能
	ckwriters [TagTypeMax]*ckwriter.CKWriter

	// Cache 流标签缓存，用于优化标签写入性能
	// 缓存字段名和字段值，避免重复写入相同数据
	// 通过LRU算法管理缓存大小，防止内存溢出
	Cache *FlowTagCache

	// counter 计数器，统计流标签写入的各项指标
	// 包括新字段数量、新字段值数量、缓存命中率等
	// 用于监控写入性能和系统状态
	counter *Counter

	// Closable 可关闭接口，支持优雅关闭
	// 实现资源的清理和释放，确保数据完整性
	utils.Closable
}

// 通过缓存机制优化写入性能
type FlowTagCache struct {
	// Id 缓存实例标识符
	// 用于区分不同的缓存实例，通常与解码器索引对应
	// 在日志输出和调试时使用
	Id int

	// FieldCache 字段名缓存，使用LRU算法
	// 缓存FlowTagInfo到时间戳的映射，避免重复写入相同字段
	// Key: FlowTagInfo（包含表名、字段名等），Value: 上次写入时间戳
	FieldCache *lru.Cache[FlowTagInfo, uint32]

	// FieldValueCache 字段值缓存，使用LRU算法
	// 缓存字段名和字段值的组合，避免重复写入相同标签值
	// Key: FlowTagInfo（包含字段值），Value: 上次写入时间戳
	FieldValueCache *lru.Cache[FlowTagInfo, uint32]

	// CacheFlushTimeout 缓存刷新超时时间（秒）
	// 控制缓存项的有效期，超过此时间的缓存项会被重新写入
	// 平衡数据新鲜度和写入性能
	CacheFlushTimeout uint32

	// PrometheusFieldCache Prometheus字段名专用缓存
	// 仅用于Prometheus数据，使用128位LRU缓存优化性能
	// Prometheus数据可以转换为ID，使用更高效的缓存结构
	PrometheusFieldCache *lru128.U128LRU

	// PrometheusFieldValueCache Prometheus字段值专用缓存
	// 与PrometheusFieldCache配合使用，缓存字段值信息
	// 同样使用128位LRU缓存，提高Prometheus数据处理效率
	PrometheusFieldValueCache *lru128.U128LRU

	// FlowTagInfoBuffer 流标签信息缓冲区
	// 临时存储FlowTagInfo对象，避免频繁内存分配
	// 在生成新流标签时复用，提高性能
	FlowTagInfoBuffer FlowTagInfo

	// Fields 字段数组缓冲区
	// 临时存储待写入的字段标签（TagField类型）
	// 达到批量大小时会触发批量写入，减少数据库操作
	Fields []interface{}

	// FieldValues 字段值数组缓冲区
	// 临时存储待写入的字段值标签（TagFieldValue类型）
	// 与Fields配合使用，分别处理字段名和字段值
	FieldValues []interface{}
}

func NewFlowTagCache(name string, id int, cacheFlushTimeout, cacheMaxSize uint32) *FlowTagCache {
	c := &FlowTagCache{
		Id:                id,
		CacheFlushTimeout: cacheFlushTimeout,
	}

	// Prometheus data can be converted into IDs so use LRU128, others use ordinary LRU
	if strings.Contains(name, PROMETHEUS_KEYWORD) {
		c.PrometheusFieldCache = lru128.NewU128LRU(fmt.Sprintf("%s-flow-tag-field_%d", name, id), int(cacheMaxSize)>>3, int(cacheMaxSize))
		c.PrometheusFieldValueCache = lru128.NewU128LRU(fmt.Sprintf("%s-flow-tag-field-value_%d", name, id), int(cacheMaxSize)>>3, int(cacheMaxSize))
	} else {
		c.FieldCache = lru.NewCache[FlowTagInfo, uint32](int(cacheMaxSize))
		c.FieldValueCache = lru.NewCache[FlowTagInfo, uint32](int(cacheMaxSize))
	}
	return c
}

// NewFlowTagWriter 创建一个新的流标签写入器实例
// 用于将流标签元数据写入ClickHouse数据库，支持字段名和字段值两种标签类型
// 通过缓存机制优化写入性能，避免重复写入相同数据
func NewFlowTagWriter(
	decoderIndex int, // 解码器索引，用于标识不同的写入器实例
	name string, // 写入器名称，用于日志输出和监控标识
	srcDB string, // 源数据库名称，用于构建表名
	ttl int, // 数据生存时间（TTL），控制数据保留期限
	partition ckdb.TimeFuncType, // 分区函数类型，用于时间分区策略
	config *config.Config, // 全局配置对象，包含数据库连接等配置
	writerConfig *config.CKWriterConfig) (*FlowTagWriter, error) { // ClickHouse写入器配置

	// 初始化FlowTagWriter结构体实例
	// 设置数据库连接信息和缓存配置
	w := &FlowTagWriter{
		ckdbAddrs:    config.CKDB.ActualAddrs,                                                                          // ClickHouse数据库地址列表
		ckdbUsername: config.CKDBAuth.Username,                                                                         // 数据库用户名
		ckdbPassword: config.CKDBAuth.Password,                                                                         // 数据库密码
		writerConfig: writerConfig,                                                                                     // 写入器配置参数
		Cache:        NewFlowTagCache(name, decoderIndex, config.FlowTagCacheFlushTimeout, config.FlowTagCacheMaxSize), // 创建流标签缓存
		counter:      &Counter{},                                                                                       // 初始化统计计数器
	}

	// 创建FlowTag实例用于生成表结构
	// 根据不同的标签类型生成对应的ClickHouse表定义
	t := FlowTag{}
	var err error

	// 遍历所有标签类型，为每种类型创建独立的写入器
	// 支持TagField（字段名）和TagFieldValue（字段值）两种类型
	for _, tagType := range []TagType{TagField, TagFieldValue} {
		// 构建表名，格式为：源数据库名_标签类型名
		tableName := fmt.Sprintf("%s_%s", srcDB, tagType.String())

		// 设置当前处理的标签类型
		t.TagType = tagType

		// 创建ClickHouse写入器实例
		// 配置数据库连接、表结构、队列参数等
		w.ckwriters[tagType], err = ckwriter.NewCKWriter(
			*w.ckdbAddrs,   // 数据库地址列表
			w.ckdbUsername, // 数据库用户名
			w.ckdbPassword, // 数据库密码
			fmt.Sprintf("%s-%s-%d", name, tableName, decoderIndex), // 写入器实例名称
			config.CKDB.TimeZone, // 时区配置
			t.GenCKTable(config.CKDB.ClusterName, config.CKDB.StoragePolicy, tableName, config.CKDB.Type, ttl, partition), // 生成表结构
			w.writerConfig.QueueCount,   // 队列数量
			w.writerConfig.QueueSize,    // 队列大小
			w.writerConfig.BatchSize,    // 批量大小
			w.writerConfig.FlushTimeout, // 刷新超时
			config.CKDB.Watcher)         // 数据库监听器
		if err != nil {
			return nil, err // 创建失败则返回错误
		}

		// 启动写入器，开始处理数据写入
		w.ckwriters[tagType].Run()
	}

	// 注册写入器到监控系统
	// 用于收集和上报写入器的性能指标
	common.RegisterCountableForIngester("flow_tag_writer", w, stats.OptionStatTags{
		"type":          srcDB + "_" + name,         // 标签类型
		"decoder_index": strconv.Itoa(decoderIndex), // 解码器索引
	})

	// 返回初始化完成的FlowTagWriter实例
	return w, nil
}

func (w *FlowTagWriter) Write(t TagType, values ...interface{}) {
	w.ckwriters[t].Put(values...)
}

func (w *FlowTagWriter) WriteFieldsAndFieldValuesInCache() {
	if len(w.Cache.Fields) != 0 {
		w.ckwriters[TagField].Put(w.Cache.Fields...)
		w.counter.NewFieldCount += int64(len(w.Cache.Fields))
	}
	if len(w.Cache.FieldValues) != 0 {
		w.ckwriters[TagFieldValue].Put(w.Cache.FieldValues...)
		w.counter.NewFieldValueCount += int64(len(w.Cache.FieldValues))
	}
}

func (w *FlowTagWriter) GetCounter() interface{} {
	var counter *Counter
	counter, w.counter = w.counter, &Counter{}
	if w.Cache.FieldCache != nil {
		counter.FieldCacheCount = int64(w.Cache.FieldCache.Len())
	} else {
		counter.FieldCacheCount = int64(w.Cache.PrometheusFieldCache.Size())
	}
	if w.Cache.FieldValueCache != nil {
		counter.FieldValueCacheCount = int64(w.Cache.FieldValueCache.Len())
	} else {
		counter.FieldValueCacheCount = int64(w.Cache.PrometheusFieldValueCache.Size())
	}
	return counter
}
