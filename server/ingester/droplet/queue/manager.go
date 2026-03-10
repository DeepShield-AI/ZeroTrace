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
	"bytes"
	"encoding/gob"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	logging "github.com/op/go-logging"
	"github.com/spf13/cobra"

	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/debug"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

var log = logging.MustGetLogger("queue_manager")

// 这个 Manager 结构体是 DeepFlow 中队列调试系统的核心管理器，用于统一管理和监控多个队列实例
// queues: 一个映射表，键是队列名称（字符串），值是实现了 MonitorOperator 接口的队列对象
// 通过这个映射，Manager 可以按名称查找和操作不同的队列
// 每个队列都实现了 MonitorOperator 接口，支持：
// TurnOnDebug(): 开启调试模式，开始向指定客户端发送队列数据
// TurnOffDebug(): 关闭调试模式
type Manager struct {
	queues map[string]MonitorOperator
}

const (
	QUEUE_CMD_SHOW = iota
	QUEUE_CMD_MONITOR_ON
	QUEUE_CMD_MONITOR_OFF
	QUEUE_CMD_CLEAR
)

// NewManager 创建一个新的队列监控管理器实例
// 参数 module 是调试模块ID，用于标识不同的调试模块
// 返回初始化完成的 Manager 实例指针
func NewManager(module debug.ModuleId) *Manager {
	// 创建 Manager 结构体实例
	// Manager 负责管理多个队列监控器，提供统一的调试接口
	manager := &Manager{}

	// 初始化队列映射表，用于存储队列名称到监控操作器的映射关系
	// 键：队列名称（字符串），值：MonitorOperator 接口实例
	// 支持动态添加和管理多个队列的监控功能
	manager.queues = make(map[string]MonitorOperator)

	// 将管理器注册到调试系统中
	// 使管理器能够接收和处理调试命令，如开启/关闭队列调试
	// module 参数用于区分不同模块的调试请求
	debug.Register(module, manager)

	// 返回初始化完成的管理器实例
	return manager
}

func (m *Manager) RecvCommand(conn *net.UDPConn, remote *net.UDPAddr, operate uint16, arg *bytes.Buffer) {
	buffer := bytes.Buffer{}
	switch operate {
	case QUEUE_CMD_SHOW: // 显示所有队列名称
		names := make([]string, 0, len(m.queues))
		for name, _ := range m.queues {
			names = append(names, name)
		}
		encoder := gob.NewEncoder(&buffer)
		if err := encoder.Encode(names); err != nil {
			log.Error(err)
			return
		}
		debug.SendToClient(conn, remote, 0, &buffer)
		break
	case QUEUE_CMD_MONITOR_ON: // 开启指定队列的调试监控
		name := ""
		decoder := gob.NewDecoder(arg)
		if err := decoder.Decode(&name); err != nil {
			log.Error(err)
			return
		}
		if m.queues[name] == nil {
			log.Errorf("queue[%s] not found.", name)
			return
		}
		m.queues[name].TurnOnDebug(conn, remote)
		debug.SendToClient(conn, remote, 0, nil)
		break
	case QUEUE_CMD_MONITOR_OFF: // 关闭指定队列的调试监控
		name := ""
		decoder := gob.NewDecoder(arg)
		if err := decoder.Decode(&name); err != nil {
			log.Error(err)
			return
		}
		if m.queues[name] == nil {
			log.Errorf("queue[%s] not found.", name)
			return
		}
		m.queues[name].TurnOffDebug()
		break
	case QUEUE_CMD_CLEAR: // 关闭所有队列的调试状态
		for _, queue := range m.queues {
			queue.TurnOffDebug()
		}
		debug.SendToClient(conn, remote, 0, nil)
	default:
		log.Warningf("Trident Adapter recv unknown command (%v).", operate)
	}
}

func (m *Manager) NewQueue(name string, size int, options ...queue.Option) *Queue {
	q := &Queue{}
	q.Init(name, size, nil, options...)
	m.queues[name] = q
	return q
}

func (m *Manager) NewQueues(name string, size, count, userCount int, options ...queue.Option) *MultiQueue {
	q := &MultiQueue{}
	q.Init(name, size, count, userCount, nil, options...)
	m.queues[name] = q // 把队列加入到队列管理器的map中
	return q
}

func (m *Manager) NewQueueUnmarshal(name string, size int, unmarshaller Unmarshaller, options ...queue.Option) *Queue {
	q := &Queue{}
	q.Init(name, size, unmarshaller, options...)
	m.queues[name] = q
	return q
}

func (m *Manager) NewQueuesUnmarshal(name string, size, count, userCount int, unmarshaller Unmarshaller, options ...queue.Option) *MultiQueue {
	q := &MultiQueue{}
	q.Init(name, size, count, userCount, unmarshaller, options...)
	m.queues[name] = q
	return q
}

func sendCmdOnly(moduleId debug.ModuleId, operate int, arg *bytes.Buffer) (*net.UDPConn, *bytes.Buffer, error) {
	conn, result, err := debug.SendToServer(moduleId, debug.ModuleOperate(operate), arg)
	if err != nil {
		return conn, nil, err
	}
	return conn, result, nil
}

func sendCmd(moduleId debug.ModuleId, operate int, arg *bytes.Buffer, out interface{}) bool {
	_, result, err := sendCmdOnly(moduleId, operate, arg)
	if err != nil {
		fmt.Println(err)
		return false
	}
	decoder := gob.NewDecoder(result)
	if err = decoder.Decode(out); err != nil {
		fmt.Printf("%v: %v\n", err, out)
		return false
	}
	return true
}

func queueOperate(moduleId debug.ModuleId, name string, operate int) *net.UDPConn {
	buffer := bytes.Buffer{}
	encoder := gob.NewEncoder(&buffer)
	if err := encoder.Encode(name); err != nil {
		fmt.Printf("%v: %s\n", err, name)
		return nil
	}

	conn, _, err := sendCmdOnly(moduleId, operate, &buffer)
	if err != nil {
		return nil
	}
	return conn
}

func isNotTimeout(err error) bool {
	return !strings.Contains(err.Error(), "timeout")
}

func recvDebugMsg(moduleId debug.ModuleId, conn *net.UDPConn, name string) {
	sigs := make(chan os.Signal, 10)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGKILL, syscall.SIGQUIT, syscall.SIGSTOP)
	var message string
	for {
		select {
		case sig := <-sigs:
			queueOperate(moduleId, name, QUEUE_CMD_MONITOR_OFF)
			fmt.Printf("signal %v\n", sig)
			conn.Close()
			return
		default:
			conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			buffer, err := debug.RecvFromServer(conn)
			if err != nil {
				if isNotTimeout(err) {
					queueOperate(moduleId, name, QUEUE_CMD_MONITOR_OFF)
					fmt.Printf("ingesterctl.RecvFromDroplet: %v\n", err)
					return
				}
				break
			}

			decoder := gob.NewDecoder(buffer)
			if err := decoder.Decode(&message); err != nil {
				queueOperate(moduleId, name, QUEUE_CMD_MONITOR_OFF)
				fmt.Printf("decoder.Decode: %v\n", err)
				return
			}
			fmt.Printf("%s\n", message)
		}
	}
}

func RegisterCommand(moduleId debug.ModuleId, queueNames []string) *cobra.Command {
	gob.Register(&datatype.MetaPacket{})
	gob.Register(&datatype.TaggedMetering{})

	queue := &cobra.Command{
		Use:   "queue",
		Short: "monitor queue module",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("please run with 'show | monitor'.\n")
		},
	}

	show := &cobra.Command{
		Use:   "show",
		Short: "show queue list",
		Run: func(cmd *cobra.Command, args []string) {
			names := []string{}
			if sendCmd(moduleId, QUEUE_CMD_SHOW, nil, &names) {
				sort.Strings(names)
				fmt.Println("Queue List:")
				for i, name := range names {
					fmt.Printf("\t%3d:				%s\n", i+1, name)
				}
			}
		},
	}
	monitor := &cobra.Command{
		Use:       "monitor {name}",
		Short:     "monitor queue put data",
		ValidArgs: queueNames,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 {
				fmt.Println("please run with '{queue-name}'.")
				return
			}
			conn := queueOperate(moduleId, args[0], QUEUE_CMD_MONITOR_ON)
			if conn != nil {
				recvDebugMsg(moduleId, conn, args[0])
			}
		},
	}
	clear := &cobra.Command{
		Use:   "clear",
		Short: "clear all queue",
		Run: func(cmd *cobra.Command, args []string) {
			sendCmdOnly(moduleId, QUEUE_CMD_CLEAR, nil)
		},
	}
	queue.AddCommand(show)
	queue.AddCommand(monitor)
	queue.AddCommand(clear)
	return queue
}
