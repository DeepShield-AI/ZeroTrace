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

package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	logging "github.com/op/go-logging"
	yaml "gopkg.in/yaml.v2"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
)

var log = logging.MustGetLogger("config")

const (
	DefaultLocalIP                  = "127.0.0.1"
	DefaultControllerPort           = 20035
	DefaultCheckInterval            = 180 // clickhouse是异步删除
	DefaultDiskUsedPercent          = 80
	DefaultDiskFreeSpace            = 300
	DefaultDFDiskPrefix             = "path_"           // In the config.xml of ClickHouse, the disk name of the storage policy 'df_storage' written by deepflow-server starts with 'path_'
	DefaultSystemDiskPrefix         = "default"         // In the config.xml of ClickHouse, the disk name of default storage policy 'default'
	DefaultByconityLocalDiskPrefix  = "server_local_"   // In the config.xml of ByConity, the disk name of the storage policy 'default'
	DefaultBycontiyS3DiskPrefix     = "server_s3_disk_" // In the config.xml of ByConity, the disk name of the storage policy 'cnch_default_s3'
	EnvK8sNodeIP                    = "K8S_NODE_IP_FOR_DEEPFLOW"
	EnvK8sPodName                   = "K8S_POD_NAME_FOR_DEEPFLOW"
	EnvK8sNodeName                  = "K8S_NODE_NAME_FOR_DEEPFLOW"
	EnvK8sNamespace                 = "K8S_NAMESPACE_FOR_DEEPFLOW"
	DefaultCKDBService              = "deepflow-clickhouse"
	DefaultByconityService          = "deepflow-byconity-server"
	DefaultCKDBServicePort          = 9000
	DefaultListenPort               = 20033
	DefaultGrpcBufferSize           = 104857600
	DefaultServiceLabelerLruCap     = 1 << 22
	DefaultCKDBEndpointTCPPortName  = "tcp-port"
	DefaultStatsInterval            = 10      // s
	DefaultFlowTagCacheFlushTimeout = 1800    // s
	DefaultFlowTagCacheMaxSize      = 1 << 18 // 256k
	IndexTypeHash                   = "hash"
	IndexTypeIncremetalIdLocation   = "incremental-id"
	FormatHex                       = "hex"
	FormatDecimal                   = "decimal"
	EnvRunningMode                  = "DEEPFLOW_SERVER_RUNNING_MODE"
	RunningModeStandalone           = "STANDALONE"
	DefaultByconityStoragePolicy    = "cnch_default_s3"
	// the maximum number of endpoints for a server corresponding to ClickHouse;
	//   any endpoints beyond this limit will be ignored
	MaxClickHouseEndpointsPerServer = 128
	DefaultDatasourceListenPort     = 20106
)

type DatabaseTable struct {
	Database      string `yaml:"database"`
	TablesContain string `yaml:"tables-contain"`
}

type DiskCleanup struct {
	DiskNamePrefix string `yaml:"disk-name-prefix"`
	UsedPercent    int    `yaml:"used-percent"` // 0-100
	FreeSpace      int    `yaml:"free-space"`   // Gb
	UsedSpace      int    `yaml:"used-space"`   // Gb
}

type CKDiskMonitor struct {
	CheckInterval    int             `yaml:"check-interval"` // s
	TTLCheckDisabled bool            `yaml:"ttl-check-disabled"`
	DiskCleanups     []DiskCleanup   `yaml:"disk-cleanups"`
	PriorityDrops    []DatabaseTable `yaml:"priority-drops"`
}

func (m *CKDiskMonitor) Validate() {
	if m.CheckInterval == 0 {
		m.CheckInterval = DefaultCheckInterval
	}
	for i := range m.DiskCleanups {
		clean := &m.DiskCleanups[i]
		if clean.FreeSpace == 0 {
			clean.FreeSpace = DefaultDiskFreeSpace
		}
		if clean.UsedPercent == 0 || clean.UsedPercent > 100 {
			clean.UsedPercent = DefaultDiskUsedPercent
		}
	}
}

type Disk struct {
	Type string `yaml:"type"`
	Name string `yaml:"name"`
}

type StorageSetting struct {
	Db        string   `yaml:"db"`
	Tables    []string `yaml:"tables,flow"`
	TTLToMove int      `yaml:"ttl-hour-to-move"`
}

type CKDBColdStorage struct {
	Enabled  bool             `yaml:"enabled"`
	ColdDisk Disk             `yaml:"cold-disk"`
	Settings []StorageSetting `yaml:"settings,flow"`
}

type HostPort struct {
	Host string `yaml:"host"`
	Port string `yaml:"port"`
}

type Auth struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type CKWriterConfig struct {
	QueueCount   int `yaml:"queue-count"`
	QueueSize    int `yaml:"queue-size"`
	BatchSize    int `yaml:"batch-size"`
	FlushTimeout int `yaml:"flush-timeout"`
}

type CKDB struct {
	External            bool      `yaml:"external"` // 是否使用外部ClickHouse实例
	Type                string    `yaml:"type"`     // 数据库类型：clickhouse或byconity
	Host                string    `yaml:"host"`     // ClickHouse服务地址
	actualAddrsValue    []string  // 实际的ClickHouse端点地址列表，长度不超过MaxClickHouseEndpointsPerServer
	ActualAddrs         *[]string // 指向实际地址列表的指针，供运行时使用
	Watcher             *Watcher  // Kubernetes端点监视器，用于动态发现ClickHouse实例
	Port                int       `yaml:"port"`                   // ClickHouse服务端口
	EndpointTCPPortName string    `yaml:"endpoint-tcp-port-name"` // Kubernetes服务TCP端口名称
	ClusterName         string    `yaml:"cluster-name"`           // ClickHouse集群名称
	StoragePolicy       string    `yaml:"storage-policy"`         // 存储策略名称
	TimeZone            string    `yaml:"time-zone"`              // 时区设置
}

func (c *CKDB) updateActualAddrs(endpoints []Endpoint) {
	if c.actualAddrsValue == nil {
		c.actualAddrsValue = make([]string, 0, MaxClickHouseEndpointsPerServer)
	}
	c.actualAddrsValue = c.actualAddrsValue[:0]
	for _, endpoint := range endpoints {
		c.actualAddrsValue = append(c.actualAddrsValue, endpoint.String())
	}
	c.ActualAddrs = &c.actualAddrsValue
}

// Ingester 组件的核心配置
type Config struct {
	// IsRunningModeStandalone 标识是否为独立运行模式
	// 独立模式下不支持水平扩展，只能单节点运行
	IsRunningModeStandalone bool

	// StorageDisabled 禁用数据存储功能
	// 为 true 时 Ingester 不再将数据写入 ClickHouse
	StorageDisabled bool `yaml:"storage-disabled"`

	// ListenPort Ingester 监听端口，用于接收来自 Agent 的数据
	// 默认值: 20033
	ListenPort uint16 `yaml:"listen-port"`

	// CKDB ClickHouse 数据库连接配置
	// 包含主机、端口、集群名、存储策略等参数
	CKDB CKDB `yaml:"ckdb"`

	// ControllerIPs Controller 组件的 IP 地址列表
	// 用于建立 gRPC 连接获取平台数据和配置信息
	ControllerIPs []string `yaml:"controller-ips,flow"`

	// ControllerPort Controller 组件的监听端口
	// 默认值: 20035
	ControllerPort uint16 `yaml:"controller-port"`

	// CKDBAuth ClickHouse 数据库认证信息
	// 包含用户名和密码
	CKDBAuth Auth `yaml:"ckdb-auth"`

	// IngesterEnabled 是否启用 Ingester 功能
	// false 时表示该节点仅作为 Controller 运行
	IngesterEnabled bool `yaml:"ingester-enabled"`

	// UDPReadBuffer UDP socket 接收缓冲区大小（字节）
	// 默认值: 64MB，用于优化大数据包接收性能
	UDPReadBuffer int `yaml:"udp-read-buffer"`

	// TCPReadBuffer TCP socket 接收缓冲区大小（字节）
	// 默认值: 4MB
	TCPReadBuffer int `yaml:"tcp-read-buffer"`

	// TCPReaderBuffer TCP 读取缓冲区大小（字节）
	// 默认值: 1MB
	TCPReaderBuffer int `yaml:"tcp-reader-buffer"`

	// CKDiskMonitor ClickHouse 磁盘监控配置
	// 监控磁盘使用率，自动清理过期数据防止磁盘满
	CKDiskMonitor CKDiskMonitor `yaml:"ck-disk-monitor"`

	// ColdStorage ClickHouse 冷存储配置
	// 用于数据生命周期管理，将热数据迁移到冷存储
	ColdStorage CKDBColdStorage `yaml:"ckdb-cold-storage"`

	// ckdbColdStorages 内部冷存储映射表
	// 存储数据库表到冷存储策略的映射关系
	ckdbColdStorages map[string]*ckdb.ColdStorage

	// NodeIP 当前节点的 IP 地址
	// 用于标识 Ingester 节点，支持多租户路由
	NodeIP string `yaml:"node-ip"`

	// GrpcBufferSize gRPC 消息缓冲区大小（字节）
	// 用于 Controller 与 Ingester 之间的数据同步
	// 默认值: 100MB
	GrpcBufferSize int `yaml:"grpc-buffer-size"`

	// ServiceLabelerLruCap 服务标签缓存 LRU 容量
	// 用于缓存服务标签信息，提升查询性能
	// 默认值: 4M
	ServiceLabelerLruCap int `yaml:"service-labeler-lru-cap"`

	// StatsInterval 统计信息上报间隔（秒）
	// 控制性能指标收集和上报频率
	// 默认值: 10秒
	StatsInterval int `yaml:"stats-interval"`

	// FlowTagCacheFlushTimeout 流标签缓存刷新超时时间（秒）
	// 控制流标签缓存的刷新频率
	// 默认值: 1800秒（30分钟）
	FlowTagCacheFlushTimeout uint32 `yaml:"flow-tag-cache-flush-timeout"`

	// FlowTagCacheMaxSize 流标签缓存最大大小
	// 限制缓存条目数量，防止内存溢出
	// 默认值: 256K
	FlowTagCacheMaxSize uint32 `yaml:"flow-tag-cache-max-size"`

	// DatasourceListenPort 数据源服务监听端口
	// 提供数据源管理 API
	// 默认值: 20106
	DatasourceListenPort uint16 `yaml:"datasource-listen-port"`

	// LogFile 日志文件路径
	// 控制日志输出位置
	LogFile string

	// LogLevel 日志级别
	// 支持: error, warn, info, debug
	LogLevel string

	// MyNodeName 当前节点名称
	// 通常为 Kubernetes 节点名或主机名
	MyNodeName string

	// TraceIdWithIndex Trace ID 配置
	// 控制 Trace ID 的生成和索引策略
	TraceIdWithIndex TraceIdWithIndex
}

type Location struct {
	Start  int    `yaml:"start"`
	Length int    `yaml:"length"`
	Format string `yaml:"format"`
}

type TraceIdWithIndex struct {
	Disabled              bool     `yaml:"disabled"`
	Type                  string   `yaml:"type"`
	IncrementalIdLocation Location `yaml:"incremental-id-location"`
	FormatIsHex           bool
	TypeIsIncrementalId   bool
}

type BaseConfig struct {
	LogFile          string           `yaml:"log-file"`
	LogLevel         string           `yaml:"log-level"`
	TraceIdWithIndex TraceIdWithIndex `yaml:"trace-id-with-index"`
	Base             Config           `yaml:"ingester"`
}

func sleepAndExit() {
	time.Sleep(time.Microsecond)
	os.Exit(1)
}

func (c *Config) Validate() error {
	//1. 选举机制
	// 独立模式: 不启动选举机制，因为没有Kubernetes模块 controller.go:81-83
	// 非独立模式: 启动Leader选举实现高可用
	//2. ClickHouse连接
	// 独立模式: 只支持单个ClickHouse节点，直接使用配置的host:port config.go:305-308
	// 非独立模式: 通过Kubernetes服务发现动态获取ClickHouse端点 config.go:405-412
	runningMode, _ := os.LookupEnv(EnvRunningMode)
	// in standalone mode, only supports single node and does not support horizontal expansion
	c.IsRunningModeStandalone = runningMode == RunningModeStandalone

	if !c.TraceIdWithIndex.Disabled {
		if c.TraceIdWithIndex.Type == "" {
			c.TraceIdWithIndex.Type = IndexTypeHash
		}

		if c.TraceIdWithIndex.Type != IndexTypeIncremetalIdLocation && c.TraceIdWithIndex.Type != IndexTypeHash {
			log.Errorf("invalid 'type'(%s) of 'trace-id-with-index', must be '%s' or '%s'", c.TraceIdWithIndex.Type, IndexTypeIncremetalIdLocation, IndexTypeHash)
			sleepAndExit()
		}
		c.TraceIdWithIndex.TypeIsIncrementalId = false
		if c.TraceIdWithIndex.Type == IndexTypeIncremetalIdLocation {
			c.TraceIdWithIndex.TypeIsIncrementalId = true
			location := c.TraceIdWithIndex.IncrementalIdLocation
			if location.Format != FormatHex && location.Format != FormatDecimal {
				log.Errorf("invalid 'format'(%s) of 'trace-id-with-index:incremetal-id-location', must be '%s' or '%s'", location.Format, FormatHex, FormatDecimal)
				sleepAndExit()
			}
			if location.Length == 0 || (location.Length > 20 && location.Format == FormatDecimal) || (location.Length > 16 && location.Format == FormatHex) {
				log.Errorf("invalid 'length'(%d) of 'trace-id-with-index:incremetal-id-location' out of range. when 'format' is '%s' range is (0, 20], 'format' is '%s' range is (0, 16]", location.Length, FormatDecimal, FormatHex)

				sleepAndExit()
			}
			c.TraceIdWithIndex.FormatIsHex = c.TraceIdWithIndex.IncrementalIdLocation.Format == FormatHex
		}
	}

	if len(c.ControllerIPs) == 0 {
		log.Warning("controller-ips is empty")
	} else {
		for _, ipString := range c.ControllerIPs {
			if net.ParseIP(ipString) == nil {
				return errors.New("controller-ips invalid")
			}
		}
	}

	if c.FlowTagCacheMaxSize == 0 {
		c.FlowTagCacheMaxSize = DefaultFlowTagCacheMaxSize
	}
	if c.FlowTagCacheFlushTimeout == 0 {
		c.FlowTagCacheFlushTimeout = DefaultFlowTagCacheFlushTimeout
	}

	level := strings.ToLower(c.LogLevel)
	c.LogLevel = "info"
	for _, l := range []string{"error", "warn", "info", "debug"} {
		if level == l {
			c.LogLevel = l
		}
	}

	if c.GrpcBufferSize <= 0 {
		c.GrpcBufferSize = DefaultGrpcBufferSize
	}

	if c.ServiceLabelerLruCap <= 0 {
		c.ServiceLabelerLruCap = DefaultServiceLabelerLruCap
	}

	if c.StatsInterval <= 0 {
		c.StatsInterval = DefaultStatsInterval
	}

	var myNodeName, myPodName, myNamespace string
	// in standalone mode, no 'EnvK8sNodeName', 'EnvK8sPodName', 'EnvK8sNamespace' environment variables
	if c.IsRunningModeStandalone {
		// in standalone mode, also can get NodeIP from 'EnvK8sNodeIP'
		nodeIP, _ := os.LookupEnv(EnvK8sNodeIP)
		if nodeIP == "" {
			nodeIP = DefaultLocalIP
		}
		c.NodeIP = nodeIP
		c.MyNodeName, _ = os.Hostname()
		if c.CKDB.Host == "" {
			c.CKDB.Host = DefaultLocalIP
		}
		if c.CKDB.Port == 0 {
			c.CKDB.Port = DefaultCKDBServicePort
		}
		// in standalone mode, only supports one ClickHouse node
		var actualAddrs []string
		actualAddrs = append(actualAddrs, net.JoinHostPort(c.CKDB.Host, strconv.Itoa(c.CKDB.Port)))
		c.CKDB.ActualAddrs = &actualAddrs
	} else {
		if c.NodeIP == "" && c.ControllerIPs[0] == DefaultLocalIP {
			nodeIP, exist := os.LookupEnv(EnvK8sNodeIP)
			if !exist {
				log.Errorf("Can't get env %s", EnvK8sNodeIP)
				sleepAndExit()
			}
			c.NodeIP = nodeIP
		}
		var exist bool
		myNodeName, exist = os.LookupEnv(EnvK8sNodeName)
		if !exist {
			log.Errorf("Can't get node name env %s", EnvK8sNodeName)
			sleepAndExit()
		}
		c.MyNodeName = myNodeName

		myPodName, exist = os.LookupEnv(EnvK8sPodName)
		if !exist {
			log.Errorf("Can't get pod name env %s", EnvK8sPodName)
			sleepAndExit()
		}
		myNamespace, exist = os.LookupEnv(EnvK8sNamespace)
		if !exist {
			log.Errorf("Can't get pod namespace env %s", EnvK8sNamespace)
			sleepAndExit()
		}
	}

	if c.StorageDisabled {
		return nil
	}
	c.CKDiskMonitor.Validate()

	if c.CKDB.Type == "" {
		c.CKDB.Type = ckdb.CKDBTypeClickhouse
	}

	if c.CKDB.Type != ckdb.CKDBTypeByconity && c.CKDB.Type != ckdb.CKDBTypeClickhouse {
		log.Errorf("the setting of 'ckdb.type' (%s) is invalid, should be '%s' or '%s'", c.CKDB.Type, ckdb.CKDBTypeClickhouse, ckdb.CKDBTypeByconity)
		sleepAndExit()
	}

	if c.CKDB.Host == "" {
		if c.CKDB.Type == ckdb.CKDBTypeClickhouse {
			c.CKDB.Host = DefaultCKDBService
		} else {
			c.CKDB.Host = DefaultByconityService
		}
	}
	if c.CKDB.Port == 0 {
		c.CKDB.Port = DefaultCKDBServicePort
	}
	if c.CKDB.EndpointTCPPortName == "" {
		c.CKDB.EndpointTCPPortName = DefaultCKDBEndpointTCPPortName
	}
	if c.CKDB.ClusterName == "" {
		if c.CKDB.External {
			c.CKDB.ClusterName = "default"
		} else {
			c.CKDB.ClusterName = ckdb.DF_CLUSTER
		}
	}
	if c.CKDB.StoragePolicy == "" {
		if c.CKDB.External {
			c.CKDB.StoragePolicy = "default"
		} else {
			c.CKDB.StoragePolicy = ckdb.DF_STORAGE_POLICY
		}
		if c.CKDB.Type == ckdb.CKDBTypeByconity {
			c.CKDB.StoragePolicy = DefaultByconityStoragePolicy
		}
	}
	if c.CKDB.TimeZone == "" {
		c.CKDB.TimeZone = ckdb.DF_TIMEZONE
	}

	var watcher *Watcher
	var err error
	for retryTimes := 0; ; retryTimes++ {
		if c.IsRunningModeStandalone {
			// in standalone mode, only supports one ClickHouse endpoint. no watcher required
			break
		}

		if retryTimes > 0 {
			time.Sleep(time.Second * 30)
		}
		if watcher == nil {
			watcher, err = NewWatcher(c, myNodeName, myPodName, myNamespace)
			if err != nil {
				log.Warningf("get kubernetes watcher failed: %s", err)
				continue
			}
		}

		endpoints, err := watcher.GetMyClickhouseEndpoints()
		if err != nil {
			log.Warningf("get clickhouse endpoints (%s) failed: %s", c.CKDB.Host, err)
			continue
		}
		c.CKDB.updateActualAddrs(endpoints)
		c.CKDB.Watcher = watcher
		log.Infof("get clickhouse actual address: %s", c.CKDB.actualAddrsValue)

		conns, err := common.NewCKConnections(c.CKDB.actualAddrsValue, c.CKDBAuth.Username, c.CKDBAuth.Password)
		if err != nil {
			log.Warningf("connect to clickhouse %s failed: %s", c.CKDB.actualAddrsValue, err)
			continue
		}

		if c.CKDB.Type != ckdb.CKDBTypeByconity {
			if err := CheckCluster(conns, c.CKDB.ClusterName); err != nil {
				log.Errorf("get clickhouse cluster (%s) info from table 'system.clusters' failed: %s", c.CKDB.ClusterName, err)
				continue
			}
		}

		if err := CheckStoragePolicy(conns, c.CKDB.StoragePolicy); err != nil {
			log.Errorf("get clickhouse storage policy (%s) info from table 'system.storage_polices' failed: %s", c.CKDB.StoragePolicy, err)
			continue
		}
		break
	}

	return c.ValidateAndSetckdbColdStorages()
}

func (c *Config) ValidateAndSetckdbColdStorages() error {
	c.ckdbColdStorages = make(map[string]*ckdb.ColdStorage)
	if !c.ColdStorage.Enabled {
		return nil
	}

	var diskType ckdb.DiskType
	if c.ColdStorage.ColdDisk.Type == "disk" {
		diskType = ckdb.Disk
	} else if c.ColdStorage.ColdDisk.Type == "volume" {
		diskType = ckdb.Volume
	} else {
		return fmt.Errorf("'ingester.ckdb-cold-storage.cold-disk.type' is '%s', should be 'volume' or 'disk'", c.ColdStorage.ColdDisk.Type)
	}

	if c.ColdStorage.ColdDisk.Name == "" {
		return errors.New("'ingester.ckdb-cold-storage.cold-disk.name' is empty")
	}

	for i, setting := range c.ColdStorage.Settings {
		if setting.Db == "" {
			return fmt.Errorf("'ingester.ckdb-cold-storage.settings[%d].db' is empty", i)
		}
		if setting.TTLToMove < 1 {
			return fmt.Errorf("'ingester.ckdb-cold-storage.settings[%d].ttl-hour-to-move' is '%d', should > 0", i, setting.TTLToMove)
		}
		for _, table := range setting.Tables {
			c.ckdbColdStorages[setting.Db+table] = &ckdb.ColdStorage{
				Enabled:   true,
				Type:      diskType,
				Name:      c.ColdStorage.ColdDisk.Name,
				TTLToMove: setting.TTLToMove,
			}
		}
		// If only 'db' is configured and 'tables' is not configured, then the same settings are made to the tables under db
		if len(c.ckdbColdStorages) == 0 {
			c.ckdbColdStorages[setting.Db] = &ckdb.ColdStorage{
				Enabled:   true,
				Type:      diskType,
				Name:      c.ColdStorage.ColdDisk.Name,
				TTLToMove: setting.TTLToMove,
			}
		}
	}
	return nil
}

func (c *Config) GetCKDBColdStorages() map[string]*ckdb.ColdStorage {
	return c.ckdbColdStorages
}

func Load(path string) *Config {
	configBytes, err := os.ReadFile(path)
	config := BaseConfig{
		LogFile:  "/var/log/deepflow/server.log",
		LogLevel: "info",
		Base: Config{
			ControllerIPs:   []string{DefaultLocalIP},
			ControllerPort:  DefaultControllerPort,
			CKDBAuth:        Auth{"default", ""},
			IngesterEnabled: true,
			UDPReadBuffer:   64 << 20,
			TCPReadBuffer:   4 << 20,
			TCPReaderBuffer: 1 << 20,
			CKDiskMonitor: CKDiskMonitor{
				DefaultCheckInterval,
				false,
				[]DiskCleanup{
					{
						DefaultSystemDiskPrefix,
						DefaultDiskUsedPercent,
						DefaultDiskFreeSpace,
						0,
					},
					{
						DefaultDFDiskPrefix,
						DefaultDiskUsedPercent,
						DefaultDiskFreeSpace,
						0,
					},
					{
						DefaultByconityLocalDiskPrefix,
						DefaultDiskUsedPercent,
						DefaultDiskFreeSpace,
						0,
					},
					{
						DefaultBycontiyS3DiskPrefix,
						DefaultDiskUsedPercent,
						DefaultDiskFreeSpace,
						0,
					},
				},
				[]DatabaseTable{{"flow_log", ""}, {"flow_metrics", "1s_local"}, {"profile", ""}, {"application_log", ""}, {"event", "file_event_local"}},
			},
			ListenPort:               DefaultListenPort,
			GrpcBufferSize:           DefaultGrpcBufferSize,
			ServiceLabelerLruCap:     DefaultServiceLabelerLruCap,
			StatsInterval:            DefaultStatsInterval,
			FlowTagCacheFlushTimeout: DefaultFlowTagCacheFlushTimeout,
			FlowTagCacheMaxSize:      DefaultFlowTagCacheMaxSize,
			DatasourceListenPort:     DefaultDatasourceListenPort,
		},
	}
	if err != nil {
		log.Error("Read config file error:", err)
		sleepAndExit()
	}
	if err = yaml.Unmarshal(configBytes, &config); err != nil {
		log.Error("Unmarshal yaml error:", err)
		sleepAndExit()
	}

	config.Base.TraceIdWithIndex = config.TraceIdWithIndex
	if err = config.Base.Validate(); err != nil {
		log.Error(err)
		sleepAndExit()
	}
	config.Base.LogFile = config.LogFile
	config.Base.LogLevel = config.LogLevel
	return &config.Base
}

func CheckCluster(conns common.DBs, clusterName string) error {
	sql := fmt.Sprintf("SELECT host_address,port FROM system.clusters WHERE cluster='%s'", clusterName)
	rows, err := conns.Query(sql)
	if err != nil {
		return err
	}
	var addr string
	var port uint16
	for rows[0].Next() {
		return rows[0].Scan(&addr, &port)
	}

	return fmt.Errorf("cluster '%s' not find", clusterName)
}

func CheckStoragePolicy(conns common.DBs, storagePolicy string) error {
	sql := fmt.Sprintf("SELECT policy_name FROM system.storage_policies WHERE policy_name='%s'", storagePolicy)
	rows, err := conns.Query(sql)
	if err != nil {
		return err
	}
	var policyName string
	for rows[0].Next() {
		return rows[0].Scan(&policyName)
	}
	return fmt.Errorf("storage policy '%s' not find", storagePolicy)
}
