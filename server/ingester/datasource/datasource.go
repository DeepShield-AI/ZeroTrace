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

package datasource

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/config"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/utils"
	"github.com/gorilla/mux"
	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("data_source")

const (
	MAX_DATASOURCE_COUNT = 64
)

type DatasourceManager struct {
	ckAddrs          *[]string                                       // 需要修改数据源的clickhouse地址, 支持多个
	currentCkAddrs   []string                                        // 当前使用的ClickHouse地址列表
	user             string                                          // ClickHouse数据库用户名
	password         string                                          // ClickHouse数据库密码
	readTimeout      int                                             // 数据库读取超时时间(秒)
	replicaEnabled   bool                                            // 是否启用副本功能
	ckdbColdStorages map[string]*ckdb.ColdStorage                    // 冷存储配置映射
	isModifyingFlags [ckdb.MAX_ORG_ID + 1][MAX_DATASOURCE_COUNT]bool // 数据源修改状态标记
	cks              common.DBs                                      // ClickHouse数据库连接池

	ckdbCluster       string // ClickHouse集群名称
	ckdbStoragePolicy string // ClickHouse存储策略
	ckdbType          string // ClickHouse类型(clickhouse/byconity)

	server *http.Server // HTTP服务器，用于接收数据源管理请求
}

func NewDatasourceManager(cfg *config.Config, readTimeout int) *DatasourceManager {
	m := &DatasourceManager{
		ckAddrs:           cfg.CKDB.ActualAddrs,
		currentCkAddrs:    utils.CloneStringSlice(*cfg.CKDB.ActualAddrs),
		user:              cfg.CKDBAuth.Username,
		password:          cfg.CKDBAuth.Password,
		readTimeout:       readTimeout,
		ckdbCluster:       cfg.CKDB.ClusterName,
		ckdbStoragePolicy: cfg.CKDB.StoragePolicy,
		ckdbType:          cfg.CKDB.Type,
		ckdbColdStorages:  cfg.GetCKDBColdStorages(),
		server: &http.Server{
			Addr:    ":" + strconv.Itoa(int(cfg.DatasourceListenPort)),
			Handler: mux.NewRouter(),
		},
	}
	cks, err := common.NewCKConnections(m.currentCkAddrs, m.user, m.password)
	if err != nil {
		log.Fatalf("create clickhouse connections failed: %s", err)
	}
	m.cks = cks
	return m
}

type JsonResp struct {
	OptStatus   string `json:"OPT_STATUS"`
	Description string `json:"DESCRIPTION,omitempty"`
}

func respSuccess(w http.ResponseWriter) {
	resp, _ := json.Marshal(JsonResp{
		OptStatus: "SUCCESS",
	})
	w.Write(resp)
	log.Info("resp success")
}

func respFailed(w http.ResponseWriter, desc string) {
	resp, _ := json.Marshal(JsonResp{
		OptStatus:   "FAILED",
		Description: desc,
	})
	w.Write(resp)
	log.Warningf("resp failed: %s", desc)
}

func respPending(w http.ResponseWriter, desc string) {
	resp, _ := json.Marshal(JsonResp{
		OptStatus:   "PENDING",
		Description: desc,
	})
	w.Write(resp)
	log.Infof("resp pending: %s", desc)
}

type AddBody struct {
	OrgID        int    `json:"org-id"`                // 组织ID，用于多租户数据隔离
	BaseRP       string `json:"base-rp"`               // 基础保留策略名称，作为聚合数据源
	DB           string `json:"db"`                    // 目标数据库名称
	Interval     int    `json:"interval"`              // 数据聚合间隔（分钟）
	Name         string `json:"name"`                  // 数据源名称
	Duration     int    `json:"retention-time"`        // 数据保留时间（小时）
	SummableOP   string `json:"summable-metrics-op"`   // 可累加指标的聚合函数（Sum/Max/Min）
	UnsummableOP string `json:"unsummable-metrics-op"` // 非累加指标的聚合函数（Avg/Max/Min）
}

type ModBody struct {
	OrgID    int    `json:"org-id"`
	DB       string `json:"db"`
	Name     string `json:"name"`
	Duration int    `json:"retention-time"`
}

type DelBody struct {
	OrgID int    `json:"org-id"`
	DB    string `json:"db"`
	Name  string `json:"name"`
}

func (m *DatasourceManager) rpAdd(w http.ResponseWriter, r *http.Request) {
	//接收包含组织ID、数据库名、基础表、聚合操作等参数的请求体
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Errorf("read body err, %v", err)
		respFailed(w, err.Error())
		return
	}
	var b AddBody
	if err = json.Unmarshal(body, &b); err != nil {
		log.Errorf("Unmarshal err, %v", err)
		respFailed(w, err.Error())
		return
	}
	log.Infof("receive rpadd request: %+v", b)

	err = m.Handle(b.OrgID, ADD, b.DB, b.BaseRP, b.Name, b.SummableOP, b.UnsummableOP, b.Interval, b.Duration)
	if err != nil {
		respFailed(w, err.Error())
		return
	}
	respSuccess(w)
}

func (m *DatasourceManager) rpMod(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Errorf("read body err, %v", err)
		respFailed(w, err.Error())
		return
	}
	var b ModBody
	if err = json.Unmarshal(body, &b); err != nil {
		log.Errorf("Unmarshal err, %v", err)
		respFailed(w, err.Error())
		return
	}
	log.Infof("receive rpmod request: %+v", b)

	err = m.Handle(b.OrgID, MOD, b.DB, "", b.Name, "", "", 0, b.Duration)
	if err != nil {
		if strings.Contains(err.Error(), "try again") {
			respPending(w, err.Error())
		} else {
			respFailed(w, err.Error())
		}
		return
	}

	respSuccess(w)
}

func (m *DatasourceManager) rpDel(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Errorf("read body err, %v", err)
		respFailed(w, err.Error())
		return
	}
	var b ModBody
	if err = json.Unmarshal(body, &b); err != nil {
		log.Errorf("Unmarshal err, %v", err)
		respFailed(w, err.Error())
		return
	}
	log.Infof("receive rpdel request: %+v", b)

	err = m.Handle(b.OrgID, DEL, b.DB, "", b.Name, "", "", 0, 0)
	if err != nil {
		respFailed(w, err.Error())
		return
	}
	respSuccess(w)
}

func (m *DatasourceManager) RegisterHandlers() {
	router := m.server.Handler.(*mux.Router)
	//在 HTTP 服务器上注册三个处理不同请求的 API 端点
	router.HandleFunc("/v1/rpadd/", m.rpAdd).Methods("POST")
	router.HandleFunc("/v1/rpmod/", m.rpMod).Methods("PATCH")
	router.HandleFunc("/v1/rpdel/", m.rpDel).Methods("DELETE")
	///v1/rpadd/：处理 POST 请求，调用 m.rpAdd 方法
	///v1/rpmod/：处理 PATCH 请求，调用 m.rpMod 方法
	///v1/rpdel/：处理 DELETE 请求，调用 m.rpDel 方法
}

func (m *DatasourceManager) Start() {
	m.RegisterHandlers()

	go func() {
		//启动一个新的 goroutine 来运行 HTTP 服务器，以便它能够同时处理其他任务
		if err := m.server.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("ListenAndServe() failed: %v", err)
		}
	}()
	log.Info("data_source manager started")
}

func (m *DatasourceManager) Close() error {
	if m.server == nil {
		return nil
	}
	m.cks.Close()
	ctx, cancel := context.WithTimeout(context.TODO(), 5*time.Second)

	err := m.server.Shutdown(ctx)
	if err != nil {
		log.Warningf("shutdown failed: %v", err)
	} else {
		log.Info("data_source manager stopped")
	}
	cancel()

	return err
}
