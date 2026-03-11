START TRANSACTION;

-- modify start, add upgrade sql

UPDATE alarm_policy SET sub_view_url= "/v1/statistics/querier/UniversalHistory", sub_view_params="{\"DATABASE\":\"zerotrace_system\",\"TABLE\":\"zerotrace_server.monitor\",\"include_history\":\"true\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Avg(`metrics.load1`)*100/Avg(`metrics.cpu_num`) AS `load`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host_ip`\",\"METRICS\":[\"Avg(`metrics.load1`)*100/Avg(`metrics.cpu_num`) AS `load`\"]}]}",
    sub_view_metrics="[{\"METRIC_LABEL\":\"load\",\"unit\":\"%\"}]",
    target_field="load" WHERE name="数据节点负载高";

UPDATE alarm_policy SET sub_view_url= "/v1/statistics/querier/UniversalHistory", sub_view_params="{\"DATABASE\":\"ext_metrics\",\"TABLE\":\"influxdb.disk\",\"include_history\":\"true\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Last(`metrics.used_percent`) AS `disk_used_percent`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host_ip`, `tag.path`\",\"METRICS\":[\"Last(`metrics.used_percent`) AS `disk_used_percent`\"]}]}",
    sub_view_metrics="[{\"METRIC_LABEL\":\"disk_used_percent\",\"unit\":\"%\"}]",
    target_field="disk_used_percent" WHERE name="数据节点磁盘空间不足";

UPDATE alarm_policy SET sub_view_url= "/v1/statistics/querier/UniversalHistory", sub_view_params="{\"DATABASE\":\"zerotrace_system\",\"TABLE\":\"zerotrace_server.ingester.ckwriter\",\"include_history\":\"true\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.write_failed_count`) AS `ckwriter_failed_count`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.write_failed_count`) AS `ckwriter_failed_count`\"]}]}",
    sub_view_metrics="[{\"METRIC_LABEL\":\"ckwriter_failed_count\",\"unit\":\"次\"}]",
    target_field="ckwriter_failed_count" WHERE name="数据节点写入失败";

UPDATE alarm_policy SET sub_view_url= "/v1/statistics/querier/UniversalHistory", sub_view_params="{\"DATABASE\":\"ext_metrics\",\"TABLE\":\"zerotrace_server.monitor\",\"include_history\":\"true\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Last(`metrics.used_percent`) AS `disk_used_percent`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host_ip`, `tag.path`\",\"METRICS\":[\"Last(`metrics.used_percent`) AS `disk_used_percent`\"]}]}",
    sub_view_metrics="[{\"METRIC_LABEL\":\"disk_used_percent\",\"unit\":\"%\"}]",
    target_field="disk_used_percent" WHERE name="控制器磁盘空间不足";

UPDATE alarm_policy SET sub_view_url= "/v1/statistics/querier/UniversalHistory", sub_view_params="{\"DATABASE\":\"zerotrace_system\",\"TABLE\":\"zerotrace_server.monitor\",\"influxdb.disk\":\"true\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Avg(`metrics.load1`)/Avg(`metrics.cpu_num`) AS `load`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host_ip`\",\"METRICS\":[\"Avg(`metrics.load1`)/Avg(`metrics.cpu_num`) AS `load`\"]}]}",
    sub_view_metrics="[{\"METRIC_LABEL\":\"load\",\"unit\":\"%\"}]",
    target_field="load" WHERE name="控制器负载高";

UPDATE alarm_policy SET sub_view_url= "/v1/statistics/querier/UniversalHistory", sub_view_params="{\"DATABASE\":\"zerotrace_system\",\"TABLE\":\"zerotrace_agent_monitor\",\"include_history\":\"true\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Avg(`metrics.cpu_percent`)*100/Avg(`metrics.max_cpus`) AS `cpu_usage`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Avg(`metrics.cpu_percent`)*100/Avg(`metrics.max_cpus`) AS `cpu_usage`\"]}]}",
    sub_view_metrics="[{\"METRIC_LABEL\":\"cpu_usage\",\"unit\":\"%\"}]",
    target_field="cpu_usage" WHERE name="采集器CPU超限";

UPDATE alarm_policy SET sub_view_url= "/v1/statistics/querier/UniversalHistory", sub_view_params="{\"DATABASE\":\"zerotrace_system\",\"TABLE\":\"zerotrace_agent_monitor\",\"include_history\":\"true\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Last(`metrics.memory`)*1024*1024/Avg(`metrics.max_memory`) AS `used_bytes`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host_ip`\",\"METRICS\":[\"Last(`metrics.memory`)*1024*1024/Avg(`metrics.max_memory`) AS `used_bytes`\"]}]}",
    sub_view_metrics="[{\"METRIC_LABEL\":\"used_bytes\",\"unit\":\"%\"}]",
    target_field="used_bytes" WHERE name="采集器内存超限";

UPDATE alarm_policy SET sub_view_url= "/v1/statistics/querier/UniversalHistory", sub_view_params="{\"DATABASE\":\"zerotrace_system\",\"TABLE\":\"zerotrace_agent_monitor\",\"include_history\":\"true\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Avg(`metrics.sys_free_memory`)*100/Avg(`metrics.system_free_memory_limit`) AS `used_bytes`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Avg(`metrics.sys_free_memory`)*100/Avg(`metrics.system_free_memory_limit`) AS `used_bytes`\"]}]}",
    sub_view_metrics="[{\"METRIC_LABEL\":\"used_bytes\",\"unit\":\"%\"}]",
    target_field="used_bytes" WHERE name="采集器系统空闲内存比例超限";

UPDATE alarm_policy SET sub_view_url= "/v1/statistics/querier/UniversalHistory", sub_view_params="{\"DATABASE\":\"zerotrace_system\",\"TABLE\":\"zerotrace_agent_log_counter\",\"include_history\":\"true\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.warning`) AS `log_counter_warning`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.warning`) AS `log_counter_warning`\"]}]}",
    sub_view_metrics="[{\"METRIC_LABEL\":\"log_counter_warning\",\"unit\":\"条\"}]",
    target_field="log_counter_warning" WHERE name="采集器的WARN日志条数超限";

UPDATE alarm_policy SET sub_view_url= "/v1/statistics/querier/UniversalHistory", sub_view_params="{\"DATABASE\":\"zerotrace_system\",\"TABLE\":\"zerotrace_agent_log_counter\",\"include_history\":\"true\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.error`) AS `log_counter_error`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.error`) AS `log_counter_error`\"]}]}",
    sub_view_metrics="[{\"METRIC_LABEL\":\"log_counter_error\",\"unit\":\"条\"}]",
    target_field="log_counter_error" WHERE name="采集器的ERR日志条数超限";

UPDATE alarm_policy SET sub_view_url= "/v1/statistics/querier/UniversalHistory", sub_view_params="{\"DATABASE\":\"zerotrace_system\",\"TABLE\":\"zerotrace_server_controller_genesis_k8sinfo_delay\",\"include_history\":\"true\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Last(`metrics.avg`) AS `delay`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.cluster_id`\",\"METRICS\":[\"Last(`metrics.avg`) AS `delay`\"]}]}",
    sub_view_metrics="[{\"METRIC_LABEL\":\"delay\",\"unit\":\"秒\"}]",
    target_field="delay" WHERE name="K8s容器信息同步滞后";

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, "/v1/statistics/querier/UniversalHistory", "{\"QUERIER_REGION\":\"zerotrace\",\"DATABASE\":\"zerotrace_system\",\"TABLE\":\"zerotrace_agent_dispatcher\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.kernel_drops`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.kernel_drops`) AS `drop_packets`\"]}]}",
     "[{\"METRIC_LABEL\":\"drop_packets\",\"unit\":\"个\"}]",
     "采集器丢包(dispatcher)",  0, 1, 1, 21, 1, "", "", "drop_packets", 1, NULL, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, "/v1/statistics/querier/UniversalHistory", "{\"QUERIER_REGION\":\"zerotrace\",\"DATABASE\":\"zerotrace_system\",\"TABLE\":\"zerotrace_agent_queue\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.overwritten`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.overwritten`) AS `drop_packets`\"]}]}",
     "[{\"METRIC_LABEL\":\"drop_packets\",\"unit\":\"个\"}]",
     "采集器丢包(queue)",  0, 1, 1, 21, 1, "", "", "drop_packets", 1, NULL, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, "/v1/statistics/querier/UniversalHistory", "{\"QUERIER_REGION\":\"zerotrace\",\"DATABASE\":\"zerotrace_system\",\"TABLE\":\"zerotrace_agent_l7_session_aggr\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.throttle-drop`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.throttle-drop`) AS `drop_packets`\"]}]}",
     "[{\"METRIC_LABEL\":\"drop_packets\",\"unit\":\"个\"}]",
     "采集器丢包(l7_session_aggr)",  0, 1, 1, 21, 1, "", "", "drop_packets", 1, NULL, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, "/v1/statistics/querier/UniversalHistory", "{\"QUERIER_REGION\":\"zerotrace\",\"DATABASE\":\"zerotrace_system\",\"TABLE\":\"zerotrace_agent_flow_aggr\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.drop-in-throttle`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.drop-in-throttle`) AS `drop_packets`\"]}]}",
    "[{\"METRIC_LABEL\":\"drop_packets\",\"unit\":\"个\"}]",
     "采集器丢包(flow_aggr)",  0, 1, 1, 21, 1, "", "", "drop_packets", 1, NULL, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, "/v1/statistics/querier/UniversalHistory", "{\"QUERIER_REGION\":\"zerotrace\",\"DATABASE\":\"zerotrace_system\",\"TABLE\":\"zerotrace_server.ingester.recviver\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.udp_dropped`) AS `rx_drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.udp_dropped`) AS `rx_drop_packets`\"]}]}",
    "[{\"METRIC_LABEL\":\"rx_drop_packets\",\"unit\":\"个\"}]",
    "数据节点丢包(ingester.recviver)",  0, 1, 1, 21, 1, "", "", "rx_drop_packets", 1, NULL, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, "/v1/statistics/querier/UniversalHistory", "{\"QUERIER_REGION\":\"zerotrace\",\"DATABASE\":\"zerotrace_system\",\"TABLE\":\"zerotrace_server.ingester.trident_adapter\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.rx_dropped`) AS `rx_drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.rx_dropped`) AS `rx_drop_packets`\"]}]}",
     "[{\"METRIC_LABEL\":\"rx_drop_packets\",\"unit\":\"个\"}]",
     "数据节点丢包(ingester.trident_adapter)",  0, 1, 1, 21, 1, "", "", "rx_drop_packets", 1, NULL, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, "/v1/statistics/querier/UniversalHistory", "{\"QUERIER_REGION\":\"zerotrace\",\"DATABASE\":\"zerotrace_system\",\"TABLE\":\"zerotrace_server.ingester.queue\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.overwritten`) AS `rx_drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.overwritten`) AS `rx_drop_packets`\"]}]}",
     "[{\"METRIC_LABEL\":\"rx_drop_packets\",\"unit\":\"个\"}]",
     "数据节点丢包(ingester.queue)",  0, 1, 1, 21, 1, "", "", "rx_drop_packets", 1, NULL, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, "/v1/statistics/querier/UniversalHistory", "{\"QUERIER_REGION\":\"zerotrace\",\"DATABASE\":\"zerotrace_system\",\"TABLE\":\"zerotrace_server.ingester.decoder\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.drop_count`) AS `rx_drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.drop_count`) AS `rx_drop_packets`\"]}]}",
     "[{\"METRIC_LABEL\":\"rx_drop_packets\",\"unit\":\"个\"}]",
     "数据节点丢包(ingester.decoder.drop_count)",  0, 1, 1, 21, 1, "", "", "rx_drop_packets", 1, NULL, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, "/v1/statistics/querier/UniversalHistory", "{\"QUERIER_REGION\":\"zerotrace\",\"DATABASE\":\"zerotrace_system\",\"TABLE\":\"zerotrace_server.ingester.decoder\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.l7_dns_drop_count`) AS `rx_drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.l7_dns_drop_count`) AS `rx_drop_packets`\"]}]}",
     "[{\"METRIC_LABEL\":\"rx_drop_packets\",\"unit\":\"个\"}]",
     "数据节点丢包(ingester.decoder.l7_dns_drop_count)",  0, 1, 1, 21, 1, "", "", "rx_drop_packets", 1, NULL, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, "/v1/statistics/querier/UniversalHistory", "{\"QUERIER_REGION\":\"zerotrace\",\"DATABASE\":\"zerotrace_system\",\"TABLE\":\"zerotrace_server.ingester.decoder\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.l7_http_drop_count`) AS `rx_drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.l7_http_drop_count`) AS `rx_drop_packets`\"]}]}",
     "[{\"METRIC_LABEL\":\"rx_drop_packets\",\"unit\":\"个\"}]",
     "数据节点丢包(ingester.decoder.l7_http_drop_count)",  0, 1, 1, 21, 1, "", "", "rx_drop_packets", 1, NULL, @lcuuid);

DELETE FROM alarm_policy WHERE name IN ("采集器丢包", "数据节点丢包");

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.2.1.18';
-- modify end

COMMIT;

