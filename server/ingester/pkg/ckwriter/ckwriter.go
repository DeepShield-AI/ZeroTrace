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

package ckwriter

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	server_common "github.com/deepflowio/deepflow/server/common"
	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/config"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/grpc"
	"github.com/deepflowio/deepflow/server/libs/nativetag"
	"github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/utils"

	"github.com/ClickHouse/ch-go"
	"github.com/ClickHouse/ch-go/proto"

	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("ckwriter")

const (
	FLUSH_TIMEOUT     = 10 * time.Second
	SQL_LOG_LENGTH    = 256
	SQL_RESULT_LENGTH = 1024
	RETRY_COUNT       = 2
)

var ckwriterManager = &CKWriterManager{}

type CKWriterManager struct {
	ckwriters []*CKWriter
	sync.Mutex
}

func RegisterToCkwriterManager(w *CKWriter) {
	ckwriterManager.Lock()
	if len(ckwriterManager.ckwriters) == 0 {
		server_common.SetOrgHandler(ckwriterManager)
		config.AddClickHouseEndpointsOnChange(ckwriterManager)
	}
	ckwriterManager.ckwriters = append(ckwriterManager.ckwriters, w)
	ckwriterManager.Unlock()
}

func (m *CKWriterManager) DropOrg(orgId uint16) error {
	log.Infof("call ckwriters drop org %d", orgId)
	ckwriterManager.Lock()
	for _, ckwriter := range m.ckwriters {
		log.Infof("ckwriter %s drop org %d", ckwriter.name, orgId)
		ckwriter.dropOrg(orgId)
	}
	ckwriterManager.Unlock()
	return nil
}

func (m *CKWriterManager) UpdateNativeTag(op nativetag.NativeTagOP, orgId uint16, nativeTag *nativetag.NativeTag) error {
	return nil
}

func (m *CKWriterManager) EndpointsChange(addrs []string) {
	ckwriterManager.Lock()
	for _, ckwriter := range m.ckwriters {
		log.Infof("ckwriter %s addrs change from %s to %s ", ckwriter.name, ckwriter.addrs, addrs)
		ckwriter.addrs = utils.CloneStringSlice(addrs)
		ckwriter.endpointsChange(addrs)
	}
	ckwriterManager.Unlock()
}

// 负责高效地将数据批量写入 ClickHouse
type CKWriter struct {
	// ClickHouse服务器地址列表，支持多个地址实现负载均衡和故障转移
	// 在集群环境中通常配置多个节点地址
	addrs []string

	// ClickHouse数据库用户名，用于身份验证
	user string

	// ClickHouse数据库密码，用于身份验证
	password string

	// 时区设置，用于时间字段的处理和转换
	// 影响时间相关的SQL操作和数据存储
	timeZone string

	// 表结构定义，包含数据库、表名、列定义、分区策略等信息
	// 用于创建和管理ClickHouse表
	table *ckdb.Table

	// 队列数量，决定并发处理的数据队列个数
	// 影响数据处理的并行度和吞吐量
	queueCount int

	// 每个队列的长度，控制内存使用和背压处理
	// 队列满时会采用覆盖策略丢弃旧数据
	queueSize int // 队列长度

	// 批量写入大小，累积多少行数据后一起写入ClickHouse
	// 较大的批次可以提高写入效率，但会增加延迟
	batchSize int // 累积多少行数据，一起写入

	// 刷新超时时间，即使未达到批次大小，超过此时间也会强制写入
	// 用于平衡延迟和吞吐量，防止数据长时间滞留内存
	flushDuration time.Duration // 超时写入

	// 统计计数器名称，用于记录写入成功/失败的统计数据
	// 若写入失败，会根据该数据上报告警
	counterName string // 写入成功失败的统计数据表名称，若写入失败，会根据该数据上报告警

	// CKWriter实例的唯一标识，格式为"数据库名-表名"
	// 用作队列名称和统计计数器名称，便于监控和管理
	name string // 数据库名-表名 用作 queue名字和counter名字

	// 固定多队列实现，用于数据缓冲和负载均衡
	// 支持按哈希键分配数据到不同队列
	dataQueues queue.FixedMultiQueue

	// 数据放入计数器，用于负载均衡和队列选择
	// 通过取模运算决定数据分配到哪个队列
	putCounter int

	// ClickHouse配置监听器，用于监听集群节点变化
	// 在集群模式下动态更新可用节点列表
	ckdbwatcher *config.Watcher

	// 队列上下文列表，每个队列对应一个上下文
	// 包含连接池、缓存、计数器等状态信息
	queueContexts []*QueueContext

	// 等待组，用于优雅关闭时等待所有goroutine完成
	wg sync.WaitGroup

	// 退出标志，用于通知所有goroutine停止工作
	exit bool
}

// QueueContext 队列上下文，管理 ClickHouse 连接池和组织缓存
// 每个 QueueContext 负责一个写入队列的连接管理和数据缓存
type QueueContext struct {
	endpointsChange bool         // 端点变更标志，标识是否需要重新建立连接
	orgCaches       []*Cache     // 所有组织的写入缓存数组，每个组织一个缓存实例
	addrs           []string     // ClickHouse 服务器地址列表
	user, password  string       // ClickHouse 认证凭据
	conns           []*ch.Client // ClickHouse 连接池，支持多个连接实现负载均衡
	connCount       int          // 连接池大小，即地址数量
	counter         Counter      // 写入性能计数器，统计成功/失败次数等指标
}

func (qc *QueueContext) EndpointsChange(addrs []string) {
	if !qc.endpointsChange || len(addrs) == 0 {
		return
	}
	for _, conn := range qc.conns {
		if conn != nil {
			conn.Close()
		}
	}
	qc.connCount = len(addrs)
	qc.conns = make([]*ch.Client, qc.connCount)
	for i, addr := range addrs {
		client, err := ch.Dial(
			context.Background(),
			ch.Options{
				Address:          addr,
				User:             qc.user,
				Password:         qc.password,
				HandshakeTimeout: time.Minute,
				DialTimeout:      5 * time.Second,
			},
		)

		if err != nil {
			log.Warningf("dial to %s failed, %s", addr, err)
		} else {
			qc.conns[i] = client
		}
	}
	qc.addrs = addrs
	qc.endpointsChange = false
	for _, cache := range qc.orgCaches {
		cache.tableCreated = false
	}
}

func (qc *QueueContext) Init(addrs []string, user, password string, table *ckdb.Table) error {
	qc.addrs = addrs
	qc.connCount = len(addrs)
	qc.conns = make([]*ch.Client, qc.connCount)
	for i := 0; i < qc.connCount; i++ {
		client, err := ch.Dial(
			context.Background(),
			ch.Options{
				Address:          addrs[i],
				User:             user,
				Password:         password,
				HandshakeTimeout: time.Minute,
				DialTimeout:      5 * time.Second,
			},
		)
		if err != nil {
			log.Warningf("dial to %s failed, %s", addrs[i], err)
		}
		qc.conns[i] = client
	}
	orgCaches := make([]*Cache, ckdb.MAX_ORG_ID+1)
	for i := range orgCaches {
		orgCaches[i] = new(Cache)
		orgCaches[i].orgID = uint16(i)
		orgCaches[i].queueContext = qc
		insertTable := fmt.Sprintf("%s.`%s`", table.OrgDatabase(uint16(i)), table.LocalName)
		orgCaches[i].prepare = fmt.Sprintf("INSERT INTO %s VALUES", insertTable)
	}
	qc.orgCaches = orgCaches
	qc.user, qc.password = user, password
	return nil
}

func (qc *QueueContext) initConn(connIndex int) error {
	if len(qc.addrs) <= connIndex {
		return fmt.Errorf("conn index (%d) is exceeded address range (%d)", connIndex, len(qc.addrs))
	}
	client, err := ch.Dial(
		context.Background(),
		ch.Options{
			Address:          qc.addrs[connIndex],
			User:             qc.user,
			Password:         qc.password,
			HandshakeTimeout: time.Minute,
			DialTimeout:      5 * time.Second,
		},
	)
	if err != nil {
		if qc.counter.WriteFailedCount == 0 {
			log.Warningf("dial to %s failed, %s", qc.addrs[connIndex], err)
		}
	} else {
		qc.conns[connIndex] = client
	}
	return err
}

type CKItem interface {
	OrgID() uint16
	Release()
	NativeTagVersion() uint32
	NewColumnBlock() ckdb.CKColumnBlock
	AppendToColumnBlock(ckdb.CKColumnBlock)
}

// ExecSQL 执行 ClickHouse SQL 语句，包含重试机制和日志记录
// 用于在 DeepFlow ingester 组件中执行所有 ClickHouse 数据库操作
//
// 参数说明:
//   - conn: ClickHouse 客户端连接
//   - query: 要执行的 SQL 语句
//
// 返回值:
//   - error: 执行过程中的错误信息，如果重试全部失败则返回最后的错误
func ExecSQL(conn *ch.Client, query string) error {
	// 记录 SQL 语句，如果超过最大日志长度则截断
	// SQL_LOG_LENGTH 常量定义为 256 字符
	if len(query) > SQL_LOG_LENGTH {
		log.Infof("Exec SQL: %s ...", query[:SQL_LOG_LENGTH])
	} else {
		log.Info("Exec SQL: ", query)
	}

	// 首次执行 SQL 语句
	err := conn.Do(context.Background(), ch.Query{Body: query})

	// 重试机制：如果执行失败且还有重试次数
	retryTimes := RETRY_COUNT // RETRY_COUNT 常量定义为 2
	for err != nil && retryTimes > 0 {
		// 记录失败信息和重试意图
		log.Warningf("Exec SQL (%s) failed: %s, will retry", query, err)

		// 等待 1 秒后重试，避免频繁重试造成压力
		time.Sleep(time.Second)

		// 重新执行 SQL 语句
		err = conn.Do(context.Background(), ch.Query{Body: query})

		// 如果重试成功，记录成功信息并返回
		if err == nil {
			log.Infof("Retry exec SQL (%s) success", query)
			return nil
		}

		// 减少剩余重试次数
		retryTimes--
	}

	// 所有重试都失败，返回最后的错误
	return err
}

func QuerySingleStringColumn(conn *ch.Client, query, columnName string) (string, error) {
	if len(query) > SQL_LOG_LENGTH {
		log.Infof("Query SQL: %s ...", query[:SQL_LOG_LENGTH])
	} else {
		log.Info("Query SQL: ", query)
	}

	var columnData proto.ColStr
	if err := conn.Do(context.Background(), ch.Query{
		Body: query,
		Result: proto.Results{
			{Name: columnName, Data: &columnData},
		},
	}); err != nil {
		log.Errorf("query failed: %v", err)
	}

	var result strings.Builder
	for i := 0; i < columnData.Rows(); i++ {
		result.WriteString(columnData.Row(i))
		result.WriteString("\n")
	}
	r := result.String()
	if len(query) > SQL_RESULT_LENGTH {
		log.Infof("Query SQL result: %s ...", r[:SQL_RESULT_LENGTH])
	} else {
		log.Info("Query SQL result: ", r)
	}
	return r, nil
}

// initTable 初始化 ClickHouse 数据库和表结构
// 为指定组织创建数据库、本地表、全局表以及聚合表（如果启用）
//
// 参数说明:
//   - conn: ClickHouse 客户端连接
//   - timeZone: 时区设置，用于时间字段的处理
//   - t: ClickHouse 表结构定义
//   - orgID: 组织ID，用于多租户支持
//
// 返回值:
//   - error: 初始化过程中的错误信息
func initTable(conn *ch.Client, timeZone string, t *ckdb.Table, orgID uint16) error {
	// 创建组织专属数据库（如果不存在）
	// 数据库名格式：{orgID}_{database}，如 "1_flow_metrics"
	if err := ExecSQL(conn, fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s", t.OrgDatabase(orgID))); err != nil {
		return err
	}

	// 创建本地表（实际存储数据的表）
	// 本地表名格式：{tableName}_local，如 "flow_metrics_1m_local"
	if err := ExecSQL(conn, t.MakeOrgLocalTableCreateSQL(orgID)); err != nil {
		return err
	}

	// 创建全局表（分布式表，用于集群查询）
	// 全局表名格式：{tableName}，如 "flow_metrics_1m"
	if err := ExecSQL(conn, t.MakeOrgGlobalTableCreateSQL(orgID)); err != nil {
		return err
	}

	// 处理 1小时/1天聚合表（如果启用）
	// 用于长期数据存储和历史查询优化
	if t.Aggr1H1D {
		// === 1小时聚合表处理 ===

		// 查询现有1小时聚合表的创建语句，用于检查表结构是否正确
		aggrTableCreateSQL, err := QuerySingleStringColumn(conn, fmt.Sprintf("SHOW CREATE TABLE %s", t.AggrTable1H(orgID)), "statement")
		if err != nil {
			log.Warningf("query 1h agg table failed: %s", err)
		}

		// 如果表结构不正确，先删除旧表
		if t.IsAggrTableWrong(aggrTableCreateSQL) {
			if err := ExecSQL(conn, t.MakeAggrTableDropSQL1H(orgID)); err != nil {
				log.Warningf("drop 1h agg table failed: %s", err)
			}
		}

		// 创建1小时聚合表（存储聚合后的数据）
		if err := ExecSQL(conn, t.MakeAggrTableCreateSQL1H(orgID)); err != nil {
			log.Warningf("create 1h agg table failed: %s", err)
		}

		// 创建1小时物化视图（用于自动聚合数据）
		if err := ExecSQL(conn, t.MakeAggrMVTableCreateSQL1H(orgID)); err != nil {
			log.Warningf("create 1h mv table failed: %s", err)
		}

		// 创建1小时本地视图（用于查询聚合数据）
		if err := ExecSQL(conn, t.MakeAggrLocalTableCreateSQL1H(orgID)); err != nil {
			log.Warningf("create 1h local table failed: %s", err)
		}

		// 创建1小时全局视图（分布式查询视图）
		if err := ExecSQL(conn, t.MakeAggrGlobalTableCreateSQL1H(orgID)); err != nil {
			log.Warningf("create 1h global table failed: %s", err)
		}

		// === 1天聚合表处理 ===

		// 查询现有1天聚合表的创建语句
		aggrTableCreateSQL, err = QuerySingleStringColumn(conn, fmt.Sprintf("SHOW CREATE TABLE %s", t.AggrTable1D(orgID)), "statement")
		if err != nil {
			log.Warningf("query 1d agg table failed: %s", err)
		}

		// 如果表结构不正确，先删除旧表
		if t.IsAggrTableWrong(aggrTableCreateSQL) {
			if err := ExecSQL(conn, t.MakeAggrTableDropSQL1D(orgID)); err != nil {
				log.Warningf("drop 1d agg table failed: %s", err)
			}
		}

		// 创建1天聚合表
		if err := ExecSQL(conn, t.MakeAggrTableCreateSQL1D(orgID)); err != nil {
			log.Warningf("create 1d agg table failed: %s", err)
		}

		// 创建1天物化视图
		if err := ExecSQL(conn, t.MakeAggrMVTableCreateSQL1D(orgID)); err != nil {
			log.Warningf("create 1d mv table failed: %s", err)
		}

		// 创建1天本地视图
		if err := ExecSQL(conn, t.MakeAggrLocalTableCreateSQL1D(orgID)); err != nil {
			log.Warningf("create 1d local table failed: %s", err)
		}

		// 创建1天全局视图
		if err := ExecSQL(conn, t.MakeAggrGlobalTableCreateSQL1D(orgID)); err != nil {
			log.Warningf("create 1d global table failed: %s", err)
		}
	}

	// 处理 1秒聚合表（如果启用）
	// 用于实时监控和短期数据分析
	if t.Aggr1S {
		// 创建1秒聚合表
		if err := ExecSQL(conn, t.MakeAggrTableCreateSQL1S(orgID)); err != nil {
			log.Warningf("create 1s agg table failed: %s", err)
		}

		// 创建1秒物化视图
		if err := ExecSQL(conn, t.MakeAggrMVTableCreateSQL1S(orgID)); err != nil {
			log.Warningf("create 1s mv table failed: %s", err)
		}

		// 创建1秒本地视图
		if err := ExecSQL(conn, t.MakeAggrLocalTableCreateSQL1S(orgID)); err != nil {
			log.Warningf("create 1s local table failed: %s", err)
		}

		// 创建1秒全局视图
		if err := ExecSQL(conn, t.MakeAggrGlobalTableCreateSQL1S(orgID)); err != nil {
			log.Warningf("create 1s global table failed: %s", err)
		}
	}

	// ByConity 数据库不支持修改时区，直接返回
	// ByConity 是 ClickHouse 的一个分支，有不同的特性支持
	if t.DBType == ckdb.CKDBTypeByconity {
		return nil
	}

	// 修改所有时间相关列的时区设置
	// 确保时间字段使用正确的时区进行存储和查询
	for _, c := range t.Columns {
		for _, table := range []string{t.GlobalName, t.LocalName} {
			// 生成时区修改SQL语句
			modTimeZoneSql := c.MakeModifyTimeZoneSQL(t.OrgDatabase(orgID), table, timeZone)
			if modTimeZoneSql == "" {
				break // 如果不需要修改时区，跳过
			}

			// 执行时区修改
			if err := ExecSQL(conn, modTimeZoneSql); err != nil {
				log.Warningf("modify time zone failed, error: %s", err)
			}
		}
	}

	return nil
}

// InitTable 创建ClickHouse连接并初始化指定组织的表结构
// 这是一个独立的工具函数，用于单次表初始化操作
// 参数:
//   - addr: ClickHouse服务器地址，格式为"host:port"
//   - user: 数据库用户名
//   - password: 数据库密码
//   - timeZone: 时区设置，用于时间字段的处理
//   - t: 表结构定义，包含数据库、表名、列定义等信息
//   - orgID: 组织ID，用于多租户隔离，会作为数据库名前缀
//
// 返回值:
//   - error: 操作过程中遇到的错误，成功时返回nil
func InitTable(addr, user, password, timeZone string, t *ckdb.Table, orgID uint16) error {
	// 建立与ClickHouse服务器的连接
	// 设置握手超时为1分钟，连接超时为5秒
	conn, err := ch.Dial(
		context.Background(),
		ch.Options{
			Address:          addr,
			User:             user,
			Password:         password,
			HandshakeTimeout: time.Minute,
			DialTimeout:      5 * time.Second,
		},
	)
	if err != nil {
		return err
	}

	// 调用内部initTable函数执行实际的表初始化操作
	// 包括创建数据库、本地表、全局表、聚合表等
	if err := initTable(conn, timeZone, t, orgID); err != nil {
		conn.Close() // 发生错误时确保关闭连接
		return err
	}
	conn.Close() // 成功完成后关闭连接

	return nil
}

// InitTable CKWriter结构体的方法，在指定队列的所有连接上初始化表
// 这个方法不仅初始化本地连接，还会在集群的其他节点上执行初始化
// 参数:
//   - queueID: 队列ID，指定使用哪个队列上下文的连接
//   - orgID: 组织ID，用于多租户隔离
//
// 返回值:
//   - error: 操作过程中遇到的错误，成功时返回nil
func (w *CKWriter) InitTable(queueID int, orgID uint16) error {
	// 获取指定队列的上下文，包含该队列的所有连接
	queueContext := w.queueContexts[queueID]

	// 遍历队列中的所有连接，确保每个连接都可用并执行表初始化
	for i, conn := range queueContext.conns {
		// 检查连接是否为空或已关闭，如果是则重新初始化连接
		if conn == nil || conn.IsClosed() {
			if err := queueContext.initConn(i); err != nil {
				return err
			}
			conn = queueContext.conns[i]
		}

		// 在当前连接上执行表初始化
		if err := initTable(conn, w.timeZone, w.table, orgID); err != nil {
			return err
		}
	}

	// 检查是否为独立模式（没有ckdbWatcher）
	// 在独立模式下，不需要处理集群中的其他节点
	if w.ckdbwatcher == nil {
		return nil
	}

	// 获取集群中除当前节点外的所有其他ClickHouse端点
	// 用于在集群的所有节点上执行表初始化，确保表结构一致性
	endpoints, err := w.ckdbwatcher.GetClickhouseEndpointsWithoutMyself()
	if err != nil {
		log.Warningf("get clickhouse endpoints without myself failed: %s", err)
		return err
	}

	// 遍历集群中的其他节点，在每个节点上执行表初始化
	for _, endpoint := range endpoints {
		// 构造节点的完整地址（host:port）
		nodeAddr := net.JoinHostPort(endpoint.Host, fmt.Sprintf("%d", endpoint.Port))

		// 调用独立的InitTable函数在远程节点上初始化表
		err := InitTable(nodeAddr, w.user, w.password, w.timeZone, w.table, orgID)
		if err != nil {
			// 远程节点初始化失败时记录警告，但不中断整个流程
			log.Warningf("node %s:%d init table failed. err: %s", endpoint.Host, endpoint.Port, err)
		} else {
			// 成功时记录信息日志
			log.Infof("node %s:%d init table %s success", endpoint.Host, endpoint.Port, w.table.LocalName)
		}
	}

	return nil
}

// NewCKWriter 创建一个新的 ClickHouse 写入器实例
// 用于高效地将数据批量写入 ClickHouse 数据库，支持多队列、多租户和自动重试机制
//
// 参数说明:
//   - addrs: ClickHouse 服务器地址列表，支持多个地址实现负载均衡和故障转移
//   - user: ClickHouse 认证用户名
//   - password: ClickHouse 认证密码
//   - counterName: 计数器名称，用于统计写入成功/失败次数和告警
//   - timeZone: 时区设置，用于时间字段的处理
//   - table: ClickHouse 表结构定义，包含数据库、表名、列定义等信息
//   - queueCount: 队列数量，用于并行处理数据，提高写入性能
//   - queueSize: 每个队列的最大长度，超过后会覆盖旧数据
//   - batchSize: 批量写入的行数阈值，达到此数量或超时触发写入
//   - flushTimeout: 刷新超时时间（秒），即使未达到批量大小也会强制写入
//   - ckdbwatcher: ClickHouse 配置监听器，用于动态更新配置
//
// 返回值:
//   - *CKWriter: 创建的 CKWriter 实例
//   - error: 创建过程中的错误信息
func NewCKWriter(addrs []string, user, password, counterName, timeZone string, table *ckdb.Table, queueCount, queueSize, batchSize, flushTimeout int, ckdbwatcher *config.Watcher) (*CKWriter, error) {
	// 记录创建参数，便于调试和监控
	log.Infof("New CK writer: Addrs=%v, user=%s, database=%s, table=%s, queueCount=%d, queueSize=%d, batchSize=%d, flushTimeout=%ds, counterName=%s, timeZone=%s",
		addrs, user, table.Database, table.LocalName, queueCount, queueSize, batchSize, flushTimeout, counterName, timeZone)

	// 参数验证：确保至少有一个 ClickHouse 地址
	if len(addrs) == 0 {
		return nil, fmt.Errorf("addrs is empty")
	}

	var err error

	// 初始化所有组织的数据库和表结构
	// 支持多租户架构，为每个组织创建独立的数据库和表
	for _, addr := range addrs {
		// 查询所有组织ID，用于多租户支持
		orgIds := grpc.QueryAllOrgIDs()
		if len(orgIds) > 1 {
			log.Infof("database %s get orgIDs: %v", table.Database, orgIds)
		}
		// 为每个组织初始化表结构
		for _, orgId := range orgIds {
			if err = InitTable(addr, user, password, timeZone, table, orgId); err != nil {
				return nil, err
			}
		}
	}

	// 创建队列上下文，每个上下文管理一个 ClickHouse 连接池
	queueContexts := make([]*QueueContext, queueCount)
	for i := range queueContexts {
		queueContexts[i] = &QueueContext{}
		// 初始化队列上下文，建立 ClickHouse 连接
		if err := queueContexts[i].Init(addrs, user, password, table); err != nil {
			return nil, err
		}
	}

	// 生成唯一的队列名称，格式：数据库名-表名-计数器名
	name := fmt.Sprintf("%s-%s-%s", table.Database, table.LocalName, counterName)

	// 创建覆盖式多队列，用于数据缓冲和批量处理
	dataQueues := queue.NewOverwriteQueues(
		name,                                    // 队列名称
		queue.HashKey(queueCount),               // 哈希键用于数据分片
		queueSize,                               // 队列大小
		queue.OptionFlushIndicator(time.Second), // 每秒触发一次刷新检查
		queue.OptionRelease(func(p interface{}) { p.(CKItem).Release() }), // 释放对象内存
		common.QUEUE_STATS_MODULE_INGESTER)                                // 统计模块标识

	// 构建并初始化 CKWriter 实例
	w := &CKWriter{
		addrs:         utils.CloneStringSlice(addrs),             // 克隆地址列表，避免外部修改
		user:          user,                                      // 认证用户名
		password:      password,                                  // 认证密码
		timeZone:      timeZone,                                  // 时区设置
		table:         table,                                     // 表结构定义
		queueCount:    queueCount,                                // 队列数量
		queueSize:     queueSize,                                 // 队列大小
		batchSize:     batchSize,                                 // 批量大小
		flushDuration: time.Duration(flushTimeout) * time.Second, // 刷新间隔
		counterName:   counterName,                               // 计数器名称
		queueContexts: queueContexts,                             // 队列上下文列表

		name:        name,        // 队列名称
		dataQueues:  dataQueues,  // 数据队列
		ckdbwatcher: ckdbwatcher, // 配置监听器
	}

	// 将写入器注册到管理器，用于统一管理和配置更新
	RegisterToCkwriterManager(w)
	return w, nil
}

func (w *CKWriter) dropOrg(orgId uint16) {
	for i, qc := range w.queueContexts {
		log.Debugf("ckwriter %s queue %d drop org %d", w.name, i, orgId)
		qc.orgCaches[orgId].dropTime = uint32(time.Now().Unix())
		qc.orgCaches[orgId].tableCreated = false
	}
}

func (w *CKWriter) endpointsChange(addrs []string) {
	for i := 0; i < len(w.queueContexts); i++ {
		log.Debugf("ckwriter %s queue %d endpoints will change to %s", w.name, i, addrs)
		w.queueContexts[i].endpointsChange = true
	}
}

func (w *CKWriter) Run() {
	for i := 0; i < w.queueCount; i++ {
		go w.queueProcess(i)
	}
}

type Counter struct {
	WriteSuccessCount int64 `statsd:"write-success-count"`
	WriteFailedCount  int64 `statsd:"write-failed-count"`
	RetryCount        int64 `statsd:"retry-count"`
	RetryFailedCount  int64 `statsd:"retry-failed-count"`
	OrgInvalidCount   int64 `statsd:"org-invalid-count"`
	utils.Closable
}

func (i *Counter) GetCounter() interface{} {
	var counter Counter
	counter, *i = *i, Counter{}

	return &counter
}

func (w *CKWriter) Put(items ...interface{}) {
	if w.queueSize == 0 {
		for _, item := range items {
			if ck, ok := item.(CKItem); ok {
				ck.Release()
			}
		}
		return
	}
	w.putCounter++
	w.dataQueues.Put(queue.HashKey(w.putCounter%w.queueCount), items...)
}

type Cache struct {
	queueContext  *QueueContext
	orgID         uint16
	prepare       string
	columnBlock   ckdb.CKColumnBlock
	ItemVersion   uint32
	protoInput    proto.Input
	size          int
	writeCounter  int
	lastWriteTime time.Time
	tableCreated  bool
	dropTime      uint32
}

func (c *Cache) Release() {
	c.size = 0
	c.columnBlock = nil
	c.protoInput = nil
}

func (c *Cache) OrgIdExists() bool {
	updateTime, exists := grpc.QueryOrgIDExist(c.orgID)
	if updateTime == 0 || c.dropTime == 0 {
		return exists
	}
	// dropped but not update org id list, return false
	if updateTime <= c.dropTime {
		return false
	}
	c.dropTime = 0
	return exists
}

// queueProcess 队列处理协程，负责从数据队列中获取数据并写入 ClickHouse
// 每个 CKWriter 启动多个这样的协程并行处理数据，提高写入性能
//
// 参数说明:
//   - queueID: 队列ID，用于标识当前处理的是哪个队列
func (w *CKWriter) queueProcess(queueID int) {
	// 获取当前队列的上下文，包含连接池、缓存等资源
	qc := w.queueContexts[queueID]

	// 注册性能计数器，用于监控写入性能
	// 包含线程ID、表名、计数器名等标签，便于统计分析
	common.RegisterCountableForIngester("ckwriter", &(qc.counter), stats.OptionStatTags{"thread": strconv.Itoa(queueID), "table": w.name, "name": w.counterName})

	// 将当前协程添加到 WaitGroup，用于优雅关闭
	w.wg.Add(1)
	defer w.wg.Done()

	// 创建用于批量获取数据的切片，减少内存分配
	rawItems := make([]interface{}, 1024)
	// 获取组织缓存数组，每个组织一个缓存实例
	orgCaches := qc.orgCaches

	// 主处理循环，直到收到退出信号
	for !w.exit {
		// 从队列中批量获取数据，使用哈希键确保数据均匀分布
		n := w.dataQueues.Gets(queue.HashKey(queueID), rawItems)

		// 遍历获取到的数据项
		for i := 0; i < n; i++ {
			item := rawItems[i]

			// 处理有效的数据项
			if ckItem, ok := item.(CKItem); ok {
				// 获取数据项所属的组织ID
				orgID := ckItem.OrgID()

				// 验证组织ID是否有效（最大支持1024个组织）
				if orgID > ckdb.MAX_ORG_ID {
					// 只在第一次遇到无效组织ID时记录警告，避免日志刷屏
					if qc.counter.OrgInvalidCount == 0 {
						log.Warningf("writer queue (%s) item wrong orgID %d", w.name, orgID)
					}
					qc.counter.OrgInvalidCount++
					continue // 跳过无效数据
				}

				// 获取对应组织的缓存
				cache := orgCaches[orgID]
				// 将数据项添加到缓存中
				cache.Add(ckItem)

				// 检查是否达到批量写入阈值
				if cache.size >= w.batchSize {
					// 执行批量写入
					w.Write(queueID, cache)
				}
			} else if IsNil(item) { // 处理刷新定时器信号
				// 获取当前时间，用于判断是否需要强制刷新
				now := time.Now()

				// 遍历所有组织的缓存
				for _, cache := range orgCaches {
					// 如果缓存中有数据且超过刷新间隔，强制写入
					if cache.size > 0 && now.Sub(cache.lastWriteTime) > w.flushDuration {
						w.Write(queueID, cache)
					}
				}
			} else {
				// 处理无效数据类型，记录警告日志
				log.Warningf("get writer queue data type wrong %T", item)
			}
		}
	}
}

func (c *Cache) Add(item CKItem) error {
	if IsNil(c.columnBlock) ||
		(c.size == 0 && c.ItemVersion != item.NativeTagVersion()) {
		c.columnBlock = item.NewColumnBlock()
		log.Infof("orgId %d (%s) update item version from %d to %d", c.orgID, c.prepare, c.ItemVersion, item.NativeTagVersion())
		c.ItemVersion = item.NativeTagVersion()
	}
	item.AppendToColumnBlock(c.columnBlock)
	item.Release()
	c.size++
	return nil
}

func (c *Cache) Write() error {
	if c.size == 0 {
		return nil
	}

	connIndex := c.writeCounter % c.queueContext.connCount
	conn := c.queueContext.conns[connIndex]
	if conn == nil || conn.IsClosed() {
		if err := c.queueContext.initConn(connIndex); err != nil {
			c.writeCounter++
			c.lastWriteTime = time.Now()
			c.size = 0
			c.columnBlock.Reset()
			return err
		}
		conn = c.queueContext.conns[connIndex]
	}
	c.protoInput = c.protoInput[:0]
	input := c.columnBlock.ToInput(c.protoInput)
	c.protoInput = input

	err := conn.Do(context.Background(), ch.Query{
		Body:  c.prepare,
		Input: input,
	})
	c.writeCounter++
	c.lastWriteTime = time.Now()
	c.size = 0
	c.columnBlock.Reset()
	if err != nil {
		return fmt.Errorf("batch item write block failed: %s", err)
	}
	return nil
}

func (w *CKWriter) ResetConnection(queueID, connID int) error {
	var err error
	// FIXME: do reset actually
	if !IsNil(w.queueContexts[queueID].conns[connID]) {
		return nil
	}
	w.queueContexts[queueID].conns[connID], err = ch.Dial(
		context.Background(),
		ch.Options{
			Address:          w.addrs[connID],
			User:             w.user,
			Password:         w.password,
			HandshakeTimeout: time.Minute,
			DialTimeout:      5 * time.Second,
		},
	)
	return err
}

// Write 执行缓存数据写入 ClickHouse 操作
// 负责将组织缓存中的数据批量写入到 ClickHouse 数据库
//
// 参数说明:
//   - queueID: 队列ID，用于获取对应的队列上下文
//   - cache: 组织缓存，包含要写入的数据和表状态信息
func (w *CKWriter) Write(queueID int, cache *Cache) {
	// 获取当前队列的上下文
	qc := w.queueContexts[queueID]

	// 检查并处理端点变更（如 ClickHouse 服务器地址变更）
	qc.EndpointsChange(w.addrs)

	// 记录缓存中的数据项数量
	itemsLen := cache.size

	// 防止频繁写入日志：只在第一次失败时记录详细日志
	logEnabled := qc.counter.WriteFailedCount == 0

	// 验证组织ID是否仍然有效
	// 组织可能已被删除，需要检查其存在性
	if !cache.OrgIdExists() {
		if logEnabled {
			log.Warningf("table (%s.%s) orgId is not exist, drop (%d) items",
				w.table.OrgDatabase(cache.orgID), w.table.LocalName, itemsLen)
		}
		// 更新无效组织计数器
		qc.counter.OrgInvalidCount += int64(itemsLen)
		// 释放缓存资源
		cache.Release()
		return
	}

	// 检查表是否已创建，如果未创建则先创建表
	if !cache.tableCreated {
		err := w.InitTable(queueID, cache.orgID)
		if err != nil {
			if logEnabled {
				log.Warningf("create table (%s.%s) failed, drop (%d) items: %s",
					w.table.OrgDatabase(cache.orgID), w.table.LocalName, itemsLen, err)
			}
			// 更新写入失败计数器
			qc.counter.WriteFailedCount += int64(itemsLen)
			cache.Release()
			return
		}
		// 标记表已创建，避免重复创建
		cache.tableCreated = true
	}

	// 执行实际的写入操作
	if err := cache.Write(); err != nil {
		if logEnabled {
			log.Warningf("write table (%s.%s) failed, drop (%d) items: %s",
				w.table.OrgDatabase(cache.orgID), w.table.LocalName, itemsLen, err)
		}
		// 写入失败，更新失败计数器
		qc.counter.WriteFailedCount += int64(itemsLen)
	} else {
		// 写入成功，更新成功计数器
		qc.counter.WriteSuccessCount += int64(itemsLen)
	}
}

func IsNil(i interface{}) bool {
	if i == nil {
		return true
	}
	vi := reflect.ValueOf(i)
	if vi.Kind() == reflect.Ptr {
		return vi.IsNil()
	}
	return false
}

func (w *CKWriter) Close() {
	w.exit = true
	w.wg.Wait()
	for _, qc := range w.queueContexts {
		for i, c := range qc.conns {
			if !IsNil(c) {
				c.Close()
				qc.conns[i] = nil
			}
		}
		qc.counter.Close()
	}

	for _, q := range w.dataQueues {
		q.Close()
	}

	log.Infof("ckwriter %s closed", w.name)
}
