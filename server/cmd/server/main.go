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

package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"

	"github.com/zerotraceio/zerotrace/server/common"
	"github.com/zerotraceio/zerotrace/server/controller/controller"
	"github.com/zerotraceio/zerotrace/server/controller/report"
	"github.com/zerotraceio/zerotrace/server/controller/trisolaris/utils"
	"github.com/zerotraceio/zerotrace/server/ingester/droplet/profiler"
	"github.com/zerotraceio/zerotrace/server/ingester/ingester"
	"github.com/zerotraceio/zerotrace/server/ingester/ingesterctl"
	"github.com/zerotraceio/zerotrace/server/libs/debug"
	"github.com/zerotraceio/zerotrace/server/libs/logger"
	"github.com/zerotraceio/zerotrace/server/mcp"
	"github.com/zerotraceio/zerotrace/server/querier/querier"

	logging "github.com/op/go-logging"
)

func execName() string {
	splitted := strings.Split(os.Args[0], "/")
	return splitted[len(splitted)-1]
}

var log = logging.MustGetLogger(execName())

const (
	PROFILER_PORT = 9526
)

var Branch, RevCount, Revision, CommitDate, goVersion, CompileTime string

var configPath = flag.String("f", "/etc/server.yaml", "Specify config file location")
var version = flag.Bool("version", false, "Display the version")


func main() {
	flag.Parse()
	if *version {
		fmt.Printf(
			"%s\n%s\n%s\n%s\n%s\n%s\n",
			"Name: zerotrace-server community edition",
			"Branch: "+Branch,
			"CommitID: "+Revision,
			"RevCount: "+RevCount,
			"Compiler: "+goVersion,
			"CompileTime: "+CompileTime,
		)
		os.Exit(0)
	}
	cfg := loadConfig(*configPath)
	logger.EnableStdoutLog()
	logger.EnableFileLog(cfg.LogFile)
	logLevel, _ := logging.LogLevel(cfg.LogLevel)
	logging.SetLevel(logLevel, "")

	log.Infof("zerotrace-server config: %+v", *cfg)

	debug.SetIpAndPort(ingesterctl.DEBUG_LISTEN_IP, ingesterctl.DEBUG_LISTEN_PORT)
	debug.NewLogLevelControl()
	profiler := profiler.NewProfiler(PROFILER_PORT)
	if cfg.Profiler {
		runtime.SetMutexProfileFraction(1)
		runtime.SetBlockProfileRate(1)
		profiler.Start()
	}

	if cfg.MaxCPUs > 0 {
		runtime.GOMAXPROCS(cfg.MaxCPUs)
	}

	NewContinuousProfiler(&cfg.ContinuousProfile).Start(false)
	NewFreeOSMemoryHandler(&cfg.FreeOSMemoryManager).Start(false)

	ctx, cancel := utils.NewWaitGroupCtx()
	defer func() {
		cancel()
		utils.GetWaitGroupInCtx(ctx).Wait() // wait for goroutine cancel
	}()

	report.SetServerInfo(Branch, RevCount, Revision)

	shared := common.NewControllerIngesterShared()

	go mcp.NewMCPServer(*configPath).Start()

	go controller.Start(ctx, *configPath, cfg.LogFile, shared)

	go querier.Start(*configPath, cfg.LogFile, shared)
	closers := ingester.Start(*configPath, shared)

	common.NewMonitor(cfg.MonitorPaths)

	// TODO: loghandle提取出来，并增加log
	// setup system signal
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	<-signalChannel

	wg := sync.WaitGroup{}
	wg.Add(len(closers))
	for _, closer := range closers {
		go func(c io.Closer) {
			c.Close()
			wg.Done()
		}(closer)
	}
	wg.Wait()
}
