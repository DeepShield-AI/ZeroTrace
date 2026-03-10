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
	"strconv"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/config"
	"github.com/deepflowio/deepflow/server/ingester/ingesterctl"
	"github.com/deepflowio/deepflow/server/ingester/prometheus/prometheus"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/debug"
	"github.com/deepflowio/deepflow/server/libs/nativetag"
)
"""
在 DeepFlow 中，“组织”是多租户体系的核心隔离单元，通过独立的元数据库、时序库前缀、运行时实例与 ID 空间实现数据与资源隔离。
每个组织在 MySQL/PostgreSQL 中由 ORG 表记录，包含自增 ID、显示名称、业务标识 ORGID、全局唯一 lcuuid、所有者与软删除标记
server/controller/db/metadb/model/model.go

元数据库：默认组织用 deepflow，租户组织用 deepflow_tenant_{org_id}（如 deepflow_tenant_1）
ClickHouse：默认组织用无前库名（如 flow_log），租户组织用 {org_id-1:03d}_ 前缀（如 001_flow_log）
"""

//定义了需要删除的数据库名列表（如 flow_log、flow_metrics 等
var CleanDatabaseList = []string{
	"application_log", "deepflow_admin", "deepflow_tenant", "event", "ext_metrics",
	"flow_log", "flow_metrics", "flow_tag",
	"profile", "prometheus"}

// 负责多租户组织数据管理的核心处理器，主要用于处理组织级别的数据清理和标签管理
type OrgHandler struct {
	cfg        *config.Config
	promHander *prometheus.PrometheusHandler
}

func NewOrgHandler(cfg *config.Config) *OrgHandler {
	o := &OrgHandler{
		cfg: cfg,
	}
	debug.ServerRegisterSimple(ingesterctl.CMD_ORG_SWITCH, o)
	return o
}

func (o *OrgHandler) HandleSimpleCommand(operate uint16, arg string) string {
	orgId, err := strconv.Atoi(arg)
	if err != nil || !ckdb.IsValidOrgID(uint16(orgId)) {
		debug.SetOrgId(ckdb.DEFAULT_ORG_ID)
		return "set org: default"
	}
	debug.SetOrgId(orgId)
	return "set org: " + arg
}

func (o *OrgHandler) SetPromHandler(promHandler *prometheus.PrometheusHandler) {
	o.promHander = promHandler
}

// DropOrg方法负责删除指定组织的所有数据
func (o *OrgHandler) DropOrg(orgId uint16) error {
	log.Info("drop org id:", orgId)
	o.dropOrgCaches(orgId)
	return o.dropOrgDatabase(orgId)
}

// FIXME: After clearing the Org data, if the same Org ID is created again later, data writing will fail. You can restart deepflow-server to solve it.
func (o *OrgHandler) dropOrgDatabase(orgId uint16) error {
	if ckdb.IsDefaultOrgID(orgId) {
		return fmt.Errorf("can not drop default org id: %d", orgId)
	}
	conns, err := common.NewCKConnections(*o.cfg.CKDB.ActualAddrs, o.cfg.CKDBAuth.Username, o.cfg.CKDBAuth.Password)
	if err != nil {
		return err
	}
	defer conns.Close()

	for _, db := range CleanDatabaseList {
		sql := fmt.Sprintf("DROP DATABASE IF EXISTS %s", ckdb.OrgDatabasePrefix(orgId)+db)
		_, err := conns.ExecParallel(sql)
		if err != nil {
			return err
		}
	}
	return nil
}

func (o *OrgHandler) dropOrgCaches(orgId uint16) {
	if o.promHander == nil {
		return
	}
	o.promHander.DropOrg(orgId)
}

func (o *OrgHandler) UpdateNativeTag(op nativetag.NativeTagOP, orgId uint16, nativeTag *nativetag.NativeTag) error {
	if nativeTag == nil {
		return nil
	}

	if op == nativetag.NATIVE_TAG_ADD {
		return o.addNativeTag(orgId, nativeTag)
	} else if op == nativetag.NATIVE_TAG_DELETE {
		// the drop operation is time-consuming and should be handled asynchronously
		go o.dropNativeTag(orgId, nativeTag)
	} else {
		return fmt.Errorf("unknown native tag op %d", op)
	}
	return nil
}

func (o *OrgHandler) addNativeTag(orgId uint16, nativeTag *nativetag.NativeTag) error {
	if nativeTag == nil || len(nativeTag.ColumnNames) == 0 {
		return nil
	}
	conns, err := common.NewCKConnections(*o.cfg.CKDB.ActualAddrs, o.cfg.CKDBAuth.Username, o.cfg.CKDBAuth.Password)
	if err != nil {
		log.Error(err)
		return err
	}
	defer conns.Close()
	for _, conn := range conns {
		err := nativetag.CKAddNativeTag(o.cfg.CKDB.Type == ckdb.CKDBTypeByconity, true, conn, orgId, nativeTag)
		if err != nil {
			log.Error(err)
			return err
		}
	}
	return nil
}

func (o *OrgHandler) dropNativeTag(orgId uint16, nativeTag *nativetag.NativeTag) error {
	if nativeTag == nil || len(nativeTag.ColumnNames) == 0 {
		return nil
	}
	conns, err := common.NewCKConnections(*o.cfg.CKDB.ActualAddrs, o.cfg.CKDBAuth.Username, o.cfg.CKDBAuth.Password)
	if err != nil {
		log.Error(err)
		return err
	}
	defer conns.Close()
	for _, conn := range conns {
		err := nativetag.CKDropNativeTag(o.cfg.CKDB.Type == ckdb.CKDBTypeByconity, conn, orgId, nativeTag)
		if err != nil {
			log.Error(err)
		}
	}
	return nil
}
