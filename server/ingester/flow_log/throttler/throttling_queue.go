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

package throttler

import (
	"math/rand"
	"time"

	"github.com/zerotraceio/zerotrace/server/ingester/flow_log/dbwriter"
)

const (
	QUEUE_BATCH = 1 << 14
)

type throttleItem interface {
	Release()
}

// 这个 ThrottlingQueue 结构体实现了基于水库采样算法的流日志限流机制。
// 它通过时间桶和采样阈值控制数据量，在保证数据代表性的同时减少存储压力。
type ThrottlingQueue struct {
	// flowLogWriter 流日志写入器，负责将处理后的流日志写入数据库
	// 当采样缓存满时，会将采样的数据项批量写入此写入器
	// 如果为 nil，则只释放资源而不写入
	flowLogWriter *dbwriter.FlowLogWriter

	// index 队列索引，用于标识不同的限流队列实例
	// 在多队列环境中，每个队列有唯一的索引
	// 用于写入器区分不同队列的数据
	index int

	// Throttle 限流阈值，控制每个时间桶内保留的数据项数量
	// 值越大，保留的数据越多；值为 0 时禁用采样
	// 实际阈值为 Throttle * throttleBucket
	Throttle int

	// throttleBucket 时间桶大小（秒），用于分时段采样
	// 由于发送方有突发特性，需要累积一定时间进行采样
	// 使用时间桶算法将时间划分为固定大小的窗口
	throttleBucket int64

	// lastFlush 上次刷新时间戳（Unix秒）
	// 用于判断是否进入新的时间桶，触发采样数据刷新
	lastFlush int64

	// periodCount 当前时间桶内的数据项总数
	// 用于水库采样算法的概率计算
	// 随着数据项增加，采样概率会动态调整
	periodCount int

	// periodEmitCount 当前时间桶内实际采样的数据项数量
	// 不能超过 Throttle 阈值
	// 用于跟踪已使用的采样容量
	periodEmitCount int

	// sampleItems 采样数据项数组，存储被选中的数据项
	// 使用水库采样算法选择代表性数据
	// 容量为 Throttle，达到阈值后会替换已有项
	sampleItems []interface{}

	// nonSampleItems 非采样数据项数组，存储不需要采样的数据
	// 用于绕过限流机制的数据（如命中PCAP策略的数据）
	// 达到批量大小时会立即写入，不进行采样
	nonSampleItems []interface{}
}

func NewThrottlingQueue(throttle, throttleBucket int, flowLogWriter *dbwriter.FlowLogWriter, index int) *ThrottlingQueue {
	thq := &ThrottlingQueue{
		Throttle:       throttle * throttleBucket,
		throttleBucket: int64(throttleBucket),
		flowLogWriter:  flowLogWriter,
		index:          index,
	}

	if thq.Throttle > 0 {
		thq.sampleItems = make([]interface{}, thq.Throttle)
	}
	thq.nonSampleItems = make([]interface{}, 0, QUEUE_BATCH)
	return thq
}

func (thq *ThrottlingQueue) SampleDisabled() bool {
	return thq.Throttle <= 0
}

func (thq *ThrottlingQueue) flush() {
	if thq.periodEmitCount > 0 {
		if thq.flowLogWriter != nil {
			for i := 0; i < thq.periodEmitCount; i += QUEUE_BATCH {
				end := i + QUEUE_BATCH
				if end > thq.periodEmitCount {
					end = thq.periodEmitCount
				}
				thq.flowLogWriter.Put(thq.index, thq.sampleItems[i:end]...)
			}
		} else {
			for i := range thq.sampleItems[:thq.periodEmitCount] {
				if tItem, ok := thq.sampleItems[i].(throttleItem); ok {
					tItem.Release()
				}
			}
		}
	}
}

func (thq *ThrottlingQueue) SendWithThrottling(flow interface{}) bool {
	if thq.SampleDisabled() {
		thq.SendWithoutThrottling(flow)
		return true
	}

	now := time.Now().Unix()
	if now/thq.throttleBucket != thq.lastFlush/thq.throttleBucket {
		thq.flush()
		thq.lastFlush = now
		thq.periodCount = 0
		thq.periodEmitCount = 0
	}
	if flow == nil {
		return false
	}

	// Reservoir Sampling
	thq.periodCount++
	if thq.periodEmitCount < thq.Throttle {
		thq.sampleItems[thq.periodEmitCount] = flow
		thq.periodEmitCount++
		return true
	} else {
		r := rand.Intn(thq.periodCount)
		if r < thq.Throttle {
			if tItem, ok := thq.sampleItems[r].(throttleItem); ok {
				tItem.Release()
			}
			thq.sampleItems[r] = flow
		} else {
			if tItem, ok := flow.(throttleItem); ok {
				tItem.Release()
			}
		}
		return false
	}
}

func (thq *ThrottlingQueue) SendWithoutThrottling(flow interface{}) {
	if flow == nil || len(thq.nonSampleItems) >= QUEUE_BATCH {
		if len(thq.nonSampleItems) > 0 {
			if thq.flowLogWriter != nil {
				thq.flowLogWriter.Put(thq.index, thq.nonSampleItems...)
			} else {
				for i := range thq.nonSampleItems {
					if tItem, ok := thq.nonSampleItems[i].(throttleItem); ok {
						tItem.Release()
					}
				}
			}
			thq.nonSampleItems = thq.nonSampleItems[:0]
		}
	}
	if flow != nil {
		thq.nonSampleItems = append(thq.nonSampleItems, flow)
	}
}
