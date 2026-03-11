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

package ingester

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/zerotraceio/zerotrace/server/ingester/app_log"
	"github.com/zerotraceio/zerotrace/server/ingester/ckmonitor"
	"github.com/zerotraceio/zerotrace/server/ingester/datasource"
	"github.com/zerotraceio/zerotrace/server/ingester/exporters"
	"github.com/zerotraceio/zerotrace/server/libs/grpc"
	"github.com/zerotraceio/zerotrace/server/libs/logger"
	"github.com/zerotraceio/zerotrace/server/libs/pool"
	"github.com/zerotraceio/zerotrace/server/libs/receiver"
	"github.com/zerotraceio/zerotrace/server/libs/stats"

	logging "github.com/op/go-logging"
	yaml "gopkg.in/yaml.v2"

	servercommon "github.com/zerotraceio/zerotrace/server/common"
	applicationlogcfg "github.com/zerotraceio/zerotrace/server/ingester/app_log/config"
	"github.com/zerotraceio/zerotrace/server/ingester/ckissu"
	"github.com/zerotraceio/zerotrace/server/ingester/common"
	"github.com/zerotraceio/zerotrace/server/ingester/config"
	eventcfg "github.com/zerotraceio/zerotrace/server/ingester/event/config"
	"github.com/zerotraceio/zerotrace/server/ingester/event/event"
	exporterscfg "github.com/zerotraceio/zerotrace/server/ingester/exporters/config"
	extmetricscfg "github.com/zerotraceio/zerotrace/server/ingester/ext_metrics/config"
	"github.com/zerotraceio/zerotrace/server/ingester/ext_metrics/ext_metrics"
	flowlogcfg "github.com/zerotraceio/zerotrace/server/ingester/flow_log/config"
	flowlog "github.com/zerotraceio/zerotrace/server/ingester/flow_log/flow_log"
	flowmetricscfg "github.com/zerotraceio/zerotrace/server/ingester/flow_metrics/config"
	flowmetrics "github.com/zerotraceio/zerotrace/server/ingester/flow_metrics/flow_metrics"
	pcapcfg "github.com/zerotraceio/zerotrace/server/ingester/pcap/config"
	"github.com/zerotraceio/zerotrace/server/ingester/pcap/pcap"
	profilecfg "github.com/zerotraceio/zerotrace/server/ingester/profile/config"
	"github.com/zerotraceio/zerotrace/server/ingester/profile/profile"
	prometheuscfg "github.com/zerotraceio/zerotrace/server/ingester/prometheus/config"
	"github.com/zerotraceio/zerotrace/server/ingester/prometheus/prometheus"
)

var log = logging.MustGetLogger("ingester") // 创建一个名为 "ingester" 的 Logger 实例，用于输出 Ingester 模块的日志

const (
	PROFILER_PORT                = 9526
	MAX_SLAVE_PLATFORMDATA_COUNT = 128
)

func Start(configPath string, shared *servercommon.ControllerIngesterShared) []io.Closer {
	//读取配置、设置日志级别、注册对象池与 GC 监控
	cfg := config.Load(configPath)
	bytes, _ := yaml.Marshal(cfg)

	logger.EnableStdoutLog()
	logger.EnableFileLog(cfg.LogFile)
	logLevel, _ := logging.LogLevel(cfg.LogLevel)
	logging.SetLevel(logLevel, "")

	log.Info("==================== Launching ZeroTrace-Server-Ingester ====================")
	log.Infof("ingester base config:\n%s", string(bytes))

	//为对象池（pool）注册监控指标，让每个对象池的使用情况（如正在使用的对象数、字节数）能被统计系统收集并上报
	// 设置一个全局回调，当内存池内部初始化一个新的 Counter 时，会自动调用这个传入的函数
	pool.SetCounterRegisterCallback(func(counter *pool.Counter) {
		tags := stats.OptionStatTags{ //回调从 pool.Counter 中提取池的名称、对象大小、每CPU池大小、初始满池大小，构造成统计标签
			"name":                counter.Name,
			"object_size":         strconv.Itoa(int(counter.ObjectSize)), //池中单个对象的大小（字节）。
			"pool_size_per_cpu":   strconv.Itoa(int(counter.PoolSizePerCPU)),
			"init_full_pool_size": strconv.Itoa(int(counter.InitFullPoolSize)),
		}
		common.RegisterCountableForIngester("pool", counter, tags)
		//通过 common.RegisterCountableForIngester 将计数器注册到 Ingester 的统计系统，指标会带上 "pool" 模块名和上述标签
	})
	//初始化 Ingester 的统计上报系统，配置指标标识、GC 监控、上报间隔与目标
	stats.SetHostname(cfg.MyNodeName)                                                   //设置所有统计指标的主机名标签，用于多实例区分
	stats.RegisterGcMonitor()                                                           //注册 Go 运行时 GC 监控指标（如堆大小、GC 次数等）到统计系统
	stats.SetMinInterval(time.Duration(cfg.StatsInterval) * time.Second)                //设置指标上报的最小间隔，实际会上对齐到 10 秒的倍数
	stats.SetRemoteType(stats.REMOTE_TYPE_DFSTATSD)                                     //DFSTATSD 模式使用 UDP 将 Protobuf 编码的指标批量发送到 SetDFRemote 指定的地址
	stats.SetDFRemote(net.JoinHostPort("127.0.0.1", strconv.Itoa(int(cfg.ListenPort)))) //Ingester 将指标发往本地端口，由本地 statsd 收集器或 Querier 的 statsd 服务接收并转发到时序库

	//创建 Ingester 的网络接收器，用于监听 UDP/TCP 端口并接收来自 Agent 的数据，但此时仅初始化对象，尚未启动监听
	receiver := receiver.NewReceiver(int(cfg.ListenPort), cfg.UDPReadBuffer, cfg.TCPReadBuffer, cfg.TCPReaderBuffer)

	ingesterOrgHandler := NewOrgHandler(cfg) //创建 Ingester 的多组织处理器，负责组织级数据库删除、缓存清理与原生标签管理
	closers := []io.Closer{}

	if cfg.IngesterEnabled {
		flowLogConfig := flowlogcfg.Load(cfg, configPath)
		bytes, _ = yaml.Marshal(flowLogConfig)
		log.Infof("flow log config:\n%s", string(bytes))

		flowMetricsConfig := flowmetricscfg.Load(cfg, configPath)
		bytes, _ = yaml.Marshal(flowMetricsConfig)
		log.Infof("flow metrics config:\n%s", string(bytes))

		extMetricsConfig := extmetricscfg.Load(cfg, configPath)
		bytes, _ = yaml.Marshal(extMetricsConfig)
		log.Infof("ext_metrics config:\n%s", string(bytes))

		eventConfig := eventcfg.Load(cfg, configPath)
		bytes, _ = yaml.Marshal(eventConfig)
		log.Infof("event config:\n%s", string(bytes))

		pcapConfig := pcapcfg.Load(cfg, configPath)
		bytes, _ = yaml.Marshal(pcapConfig)
		log.Infof("pcap config:\n%s", string(bytes))

		profileConfig := profilecfg.Load(cfg, configPath)
		bytes, _ = yaml.Marshal(profileConfig)
		log.Infof("profile config:\n%s", string(bytes))

		prometheusConfig := prometheuscfg.Load(cfg, configPath)
		bytes, _ = yaml.Marshal(prometheusConfig)
		log.Infof("prometheus config:\n%s", string(bytes))

		applicationLogConfig := applicationlogcfg.Load(cfg, configPath)
		bytes, _ = yaml.Marshal(applicationLogConfig)
		log.Infof("application log  config:\n%s", string(bytes))

		exportersConfig := exporterscfg.Load(cfg, configPath)
		bytes, _ = yaml.Marshal(exportersConfig)
		log.Infof("exporters config:\n%s", string(bytes))

		var issu *ckissu.Issu
		if !cfg.StorageDisabled {
			var err error
			// 版本检查：比较当前数据库版本与期望版本
			// 差异识别：确定需要应用的schema变更
			// 批量执行：按版本顺序执行必要的变更操作
			// 版本更新：更新数据库版本记录
			ds := datasource.NewDatasourceManager(cfg, flowMetricsConfig.CKReadTimeout) //提供 HTTP API（/v1/rpadd、/v1/rpmod、/v1/rpdel）用于增删改数据源及其 TTL，并维护 ClickHouse 连接
			ds.Start()                                                                  //启动 HTTP 服务器监听 cfg.DatasourceListenPort（默认 19311），并注册路由处理器
			closers = append(closers, ds)

			// clickhouse表结构变更处理
			issu, err = ckissu.NewCKIssu(cfg)
			checkError(err)
			// If there is a table name change, do the table name update first
			err = issu.RunRenameTable(ds)
			checkError(err)
			err = issu.RunRecreateTables()
			checkError(err)

			err = issu.Start()
			checkError(err)
			// after issu execution is completed, should close it to prevent the connection from occupying memory.
			issu.Close()
			issu = nil
		}

		// platformData manager init
		//初始化平台数据管理器（用于从 Controller 拉取资源元数据）和初始化并启动导出器（用于将数据转发到外部系统）
		controllers := make([]net.IP, len(cfg.ControllerIPs))
		for i, ipString := range cfg.ControllerIPs {
			controllers[i] = net.ParseIP(ipString)
			if controllers[i].To4() != nil {
				controllers[i] = controllers[i].To4()
			}
		}
		//创建一个从 Controller 拉取平台元数据（如 IP、Pod、服务信息）的客户端，供各管道进行标签注入
		platformDataManager := grpc.NewPlatformDataManager(
			controllers,
			int(cfg.ControllerPort),
			MAX_SLAVE_PLATFORMDATA_COUNT,
			cfg.GrpcBufferSize,
			cfg.NodeIP,
			receiver)
		//根据配置创建导出器实例（支持 Kafka、Prometheus、OTLP）
		exporters := exporters.NewExporters(exportersConfig)
		if exporters != nil {
			exporters.Start()
			closers = append(closers, exporters)
		}

		// 写流日志数据
		//创建并启动流日志处理管道，负责接收、解码、标签注入并写入 L4/L7 流日志与追踪数据
		flowLog, err := flowlog.NewFlowLog(flowLogConfig, shared.TraceTreeQueue, receiver, platformDataManager, exporters)
		checkError(err)
		flowLog.Start()
		closers = append(closers, flowLog)

		if !cfg.StorageDisabled {
			// 写ext_metrics数据
			extMetrics, err := ext_metrics.NewExtMetrics(extMetricsConfig, receiver, platformDataManager)
			checkError(err)
			extMetrics.Start()
			closers = append(closers, extMetrics)

			// 写遥测数据
			flowMetrics, err := flowmetrics.NewFlowMetrics(flowMetricsConfig, receiver, platformDataManager, exporters)
			checkError(err)
			flowMetrics.Start()
			closers = append(closers, flowMetrics)

			// write event data
			event, err := event.NewEvent(eventConfig, shared.ResourceEventQueue, receiver, platformDataManager, exporters)
			checkError(err)
			event.Start()
			closers = append(closers, event)

			// write pcap data
			pcaper, err := pcap.NewPcaper(receiver, pcapConfig)
			checkError(err)
			pcaper.Start()
			closers = append(closers, pcaper)

			// write profile data
			profile, err := profile.NewProfile(profileConfig, receiver, platformDataManager)
			checkError(err)
			profile.Start()
			closers = append(closers, profile)

			// write prometheus data
			prometheus, err := prometheus.NewPrometheusHandler(prometheusConfig, receiver, platformDataManager)
			checkError(err)
			prometheus.Start()
			closers = append(closers, prometheus)
			ingesterOrgHandler.SetPromHandler(prometheus)

			// write application log data
			applicationLog, err := app_log.NewApplicationLogger(applicationLogConfig, receiver, platformDataManager)
			checkError(err)
			applicationLog.Start()
			closers = append(closers, applicationLog)

			// 检查clickhouse的磁盘空间占用，达到阈值时，自动删除老数据
			cm, err := ckmonitor.NewCKMonitor(cfg)
			checkError(err)
			cm.Start()
			closers = append(closers, cm)
		}
	}
	// receiver后启动，防止启动后收到数据无法处理，而上报异常日志
	receiver.Start()
	closers = append(closers, receiver)
	servercommon.SetOrgHandler(ingesterOrgHandler)

	return closers
}

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
