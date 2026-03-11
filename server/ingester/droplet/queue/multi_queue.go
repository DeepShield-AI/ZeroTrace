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

package queue

import (
	"errors"

	"github.com/zerotraceio/zerotrace/server/ingester/common"
	"github.com/zerotraceio/zerotrace/server/libs/queue"
)

// 这个 MultiQueue 结构体是一个增强的多队列实现，在基础队列功能上添加了监控和批量处理能力
type MultiQueue struct {
	// FixedMultiQueue 是基础的多队列实现，提供哈希索引的队列功能
	// 继承了其所有方法，包括 Get、Put、Gets、Puts、Len、Close 等
	// 通过位运算实现高效的哈希索引，避免求余计算
	queue.FixedMultiQueue

	// Monitor 嵌入的监控器，用于队列调试功能
	// 提供调试模式开关，可在调试时收集队列数据
	// 当调试开启时，队列数据会被发送到监控通道供调试使用
	*Monitor

	// readers 队列读取器数组，每个队列对应一个读取器
	// 用于从队列中读取数据，支持并发读取
	// 在 Init 方法中初始化，长度与队列数量相同
	readers []queue.QueueReader

	// writers 队列写入器数组，每个队列对应一个写入器
	// 用于向队列中写入数据，支持并发写入
	// 在 Init 方法中初始化，长度与队列数量相同
	writers []queue.QueueWriter

	// itemBatches 三维数组，用于批量处理数据项
	// 第一维：用户ID维度，支持多用户并发
	// 第二维：队列ID维度，对应不同的队列
	// 第三维：数据项数组，存储待批量发送的数据
	// 仅在队列数量大于1时初始化，用于优化批量写入性能
	itemBatches [][][]interface{}
}

func (q *MultiQueue) Init(name string, size, count, userCount int, unmarshaller Unmarshaller, options ...queue.Option) {
	q.Monitor = &Monitor{}
	q.Monitor.init(name, unmarshaller)
	options = append(options, common.QUEUE_STATS_MODULE_INGESTER)
	q.FixedMultiQueue = queue.NewOverwriteQueues(name, uint8(count), size, options...)

	//初始化每个队列的读取器和写入器
	q.readers = make([]queue.QueueReader, len(q.FixedMultiQueue))
	for i := 0; i < len(q.FixedMultiQueue); i++ {
		q.readers[i] = &Queue{q.FixedMultiQueue[i], q.Monitor}
	}
	q.writers = make([]queue.QueueWriter, len(q.FixedMultiQueue))
	for i := 0; i < len(q.FixedMultiQueue); i++ {
		q.writers[i] = &Queue{q.FixedMultiQueue[i], q.Monitor}
	}

	if count > 1 {
		batchSize := size
		if batchSize > 1024 {
			batchSize = 1024
		}
		// userCount在代码中写死了为1
		q.itemBatches = make([][][]interface{}, userCount)
		for userId, _ := range q.itemBatches {
			q.itemBatches[userId] = make([][]interface{}, count)
			for queueId, _ := range q.itemBatches[userId] {
				q.itemBatches[userId][queueId] = make([]interface{}, 0, batchSize)
			}
		}
	}
}

func (q *MultiQueue) Readers() []queue.QueueReader {
	return q.readers
}

func (q *MultiQueue) Writers() []queue.QueueWriter {
	return q.writers
}

func (q *MultiQueue) Get(key queue.HashKey) interface{} {
	return q.FixedMultiQueue.Get(key)
}

func (q *MultiQueue) Gets(key queue.HashKey, output []interface{}) int {
	return q.FixedMultiQueue.Gets(key, output)
}

func (q *MultiQueue) Put(key queue.HashKey, items ...interface{}) error {
	q.Monitor.send(items)
	return q.FixedMultiQueue.Put(key, items...)
}

// The userId key must be placed in keys[0] (with item keys)
func (q *MultiQueue) Puts(keys []queue.HashKey, items []interface{}) error {
	if len(keys) <= 1 || len(keys)-1 != len(items) {
		return errors.New("Requested keys and items are invalid")
	}
	userId := keys[0]
	keys = keys[1:]

	q.Monitor.send(items)
	userCount := uint8(len(q.itemBatches))
	if userCount == 0 {
		return q.FixedMultiQueue.Put(keys[0], items...)
	}

	itemBatches := q.itemBatches[userId%userCount]
	batchCount := uint8(len(itemBatches))
	for i, item := range items {
		index := keys[i] % batchCount
		itemBatches[index] = append(itemBatches[index], item)
		itemBatch := itemBatches[index]
		if len(itemBatch) == cap(itemBatch) {
			err := q.FixedMultiQueue.Put(queue.HashKey(index), itemBatch...)
			itemBatches[index] = itemBatch[:0]
			if err != nil {
				return err
			}
		}
	}
	for index, itemBatch := range itemBatches {
		if len(itemBatch) > 0 {
			err := q.FixedMultiQueue.Put(queue.HashKey(index), itemBatch...)
			itemBatches[index] = itemBatch[:0]
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (q *MultiQueue) Len(key queue.HashKey) int {
	return q.FixedMultiQueue.Len(key)
}
