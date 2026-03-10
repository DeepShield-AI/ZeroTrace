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

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/config"
	"github.com/deepflowio/deepflow/server/ingester/pkg/ckwriter"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/lru"
	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

const (
	WRITER_QUEUE_COUNT   = 1
	WRITER_QUEUE_SIZE    = 64 << 10
	WRITER_BATCH_SIZE    = 32 << 10
	WRITER_FLUSH_TIMEOUT = 10
)

type AppServiceCounter struct {
	CacheExpiredCount int64 `statsd:"cache-expired-count"`
	CacheAddCount     int64 `statsd:"cache-add-count"`
	CacheHitCount     int64 `statsd:"cache-hit-count"`
	CacheCount        int64 `statsd:"cache-count"`
}

// 负责将应用服务标签元数据写入 ClickHouse 数据库
type AppServiceTagWriter struct {
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

	// ckwriter ClickHouse写入器，负责将应用服务标签写入数据库
	// 使用异步批量写入机制，提高写入性能
	// 内部维护队列和缓冲区，支持高并发写入
	ckwriter *ckwriter.CKWriter

	// Cache 应用服务标签缓存，使用LRU算法
	// 缓存AppServiceTag到时间戳的映射，避免重复写入相同标签
	// Key: AppServiceTag（包含服务、实例等信息），Value: 上次写入时间戳
	Cache *lru.Cache[AppServiceTag, uint32]

	// CacheFlushTimeout 缓存刷新超时时间（秒）
	// 控制缓存项的有效期，超过此时间的缓存项会被重新写入
	// 平衡数据新鲜度和写入性能，防止过期数据影响分析
	CacheFlushTimeout uint32

	// CacheKeyBuf 缓存键缓冲区，用于构建缓存键
	// 临时存储AppServiceTag对象，避免频繁内存分配
	// 在写入操作时复用，提高性能
	CacheKeyBuf AppServiceTag

	// counter 计数器，统计应用服务标签写入的各项指标
	// 包括缓存命中次数、缓存过期次数、缓存添加次数等
	// 用于监控写入性能和缓存效率
	counter *AppServiceCounter

	// Closable 可关闭接口，支持优雅关闭
	// 实现资源的清理和释放，确保数据完整性
	utils.Closable
}

// NewAppServiceTagWriter 创建一个新的应用服务标签写入器  
// 该写入器负责将应用服务和实例的标签信息写入ClickHouse数据库  
// 参数:  
//   - decoderIndex: 解码器索引，用于标识不同的解码器实例  
//   - db: 数据库名称前缀，用于构建表名  
//   - msgType: 消息类型，用于标识数据来源  
//   - ttl: 数据生存时间(Time To Live)，以秒为单位  
//   - partition: 分区函数类型，用于数据分区策略  
//   - config: 配置对象，包含ClickHouse连接信息和缓存配置  
// 返回:  
//   - *AppServiceTagWriter: 应用服务标签写入器实例  
//   - error: 错误信息，如果创建失败则返回相应错误  
func NewAppServiceTagWriter(  
	decoderIndex int,  
	db, msgType string,  
	ttl int,  
	partition ckdb.TimeFuncType,  
	config *config.Config) (*AppServiceTagWriter, error) {  
	  
	// 初始化AppServiceTagWriter结构体  
	w := &AppServiceTagWriter{  
		// 从配置中获取ClickHouse服务器地址列表  
		ckdbAddrs:         config.CKDB.ActualAddrs,  
		// 从配置中获取ClickHouse用户名  
		ckdbUsername:      config.CKDBAuth.Username,  
		// 从配置中获取ClickHouse密码  
		ckdbPassword:      config.CKDBAuth.Password,  
		// 创建LRU缓存，用于缓存应用服务标签，避免重复写入  
		// 缓存大小从配置中读取  
		Cache:             lru.NewCache[AppServiceTag, uint32](int(config.FlowTagCacheMaxSize)),  
		// 缓存刷新超时时间，用于控制缓存项的有效期  
		CacheFlushTimeout: config.FlowTagCacheFlushTimeout,  
		// 初始化计数器，用于统计缓存命中、过期等指标  
		counter:           &AppServiceCounter{},  
	}  
	  
	var err error  
	// 构建表名，格式为: {数据库名}_app_service  
	// 例如: flow_log_app_service  
	tableName := fmt.Sprintf("%s_app_service", db)  
	  
	// 创建ClickHouse写入器，用于将数据写入ClickHouse数据库  
	w.ckwriter, err = ckwriter.NewCKWriter(  
		*w.ckdbAddrs,                    // ClickHouse服务器地址列表  
		w.ckdbUsername,                  // ClickHouse用户名  
		w.ckdbPassword,                  // ClickHouse密码  
		// 构建写入器名称，格式为: tag-{表名}-{消息类型}-{解码器索引}  
		// 用于标识不同的写入器实例  
		fmt.Sprintf("tag-%s-%s-%d", tableName, msgType, decoderIndex),  
		config.CKDB.TimeZone,            // ClickHouse时区设置  
		// 生成ClickHouse表结构定义，包括集群、存储策略、表类型等  
		GenAppServiceTagCKTable(config.CKDB.ClusterName, config.CKDB.StoragePolicy, tableName, config.CKDB.Type, ttl, partition),  
		// 队列配置参数  
		WRITER_QUEUE_COUNT,   // 队列数量: 1  
		WRITER_QUEUE_SIZE,    // 队列大小: 64K  
		WRITER_BATCH_SIZE,    // 批处理大小: 32K  
		WRITER_FLUSH_TIMEOUT, // 刷新超时: 10秒  
		config.CKDB.Watcher   // ClickHouse监听器，用于监控配置变化  
	)  
	if err != nil {  
		// 如果创建ClickHouse写入器失败，返回错误  
		return nil, err  
	}  
	  
	// 启动ClickHouse写入器，开始处理数据写入  
	w.ckwriter.Run()  
  
	// 注册写入器到监控系统，用于收集性能指标  
	// 注册名称为"app_service_tag_writer"，并添加标签用于区分不同的写入器实例  
	common.RegisterCountableForIngester("app_service_tag_writer", w, stats.OptionStatTags{  
		"type": msgType,                                    // 消息类型标签  
		"decoder_index": strconv.Itoa(decoderIndex),        // 解码器索引标签  
	})  
	  
	// 返回创建成功的AppServiceTagWriter实例  
	return w, nil  
}

func (w *AppServiceTagWriter) Write(time uint32, table, appService, appInstance string, orgID, teamID uint16) {
	w.CacheKeyBuf.Table = table
	w.CacheKeyBuf.AppService = appService
	w.CacheKeyBuf.AppInstance = appInstance
	w.CacheKeyBuf.OrgId = orgID
	w.CacheKeyBuf.TeamID = teamID

	if old, get := w.Cache.AddOrGet(w.CacheKeyBuf, time); get {
		if old+w.CacheFlushTimeout >= time {
			w.counter.CacheHitCount++
			return
		} else {
			w.counter.CacheExpiredCount++
			w.Cache.Add(w.CacheKeyBuf, time)
		}
	}
	serviceTag := AcquireAppServiceTag()
	*serviceTag = w.CacheKeyBuf
	serviceTag.Time = time

	w.ckwriter.Put(serviceTag)
}

func (w *AppServiceTagWriter) GetCounter() interface{} {
	var counter *AppServiceCounter
	counter, w.counter = w.counter, &AppServiceCounter{}
	counter.CacheCount = int64(w.Cache.Len())
	return counter
}
