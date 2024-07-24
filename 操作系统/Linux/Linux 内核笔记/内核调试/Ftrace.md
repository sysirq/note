# 原理 

ftrace

#  ftrace 过滤控制相关文件

| 文件名             | 功能                                          |
| ------------------ | --------------------------------------------- |
| set_ftrace_filter  | function tracer 只跟踪某个函数                |
| set_ftrace_notrace | function tracer 不跟踪某个函数                |
| set_graph_function | function_graph tracer 只跟踪某个函数          |
| set_graph_notrace  | function_graph tracer 不跟踪某个函数          |
| set_event_pid      | trace event 只跟踪某个进程                    |
| set_ftrace_pid     | function/function_graph tracer 只跟踪某个进程 |


# 查看可以被trace的函数

```shell
cat /sys/kernel/debug/tracing/available_filter_functions
```

# 使用步骤

```shell
cat /sys/kernel/debug/tracing/available_tracers #查看可用的tracer类型
blk mmiotrace function_graph function nop


echo function > /sys/kernel/debug/tracing/current_tracer # 设置tracer

echo dev_attr_show > /sys/kernel/debug/tracing/set_ftrace_filter # set_ftrace_filter 表示要跟踪的函数 ， 还有一个函数调用图 set_graph_function

cat /sys/kernel/debug/tracing/tracing_on # 用于开关tracer 

cat /sys/kernel/debug/tracing/trace # 查看 trace 输出


# 关闭
echo > /sys/kernel/debug/tracing/set_ftrace_filter
echo 0 > /sys/kernel/debug/tracing/tracing_on
echo nop > /sys/kernel/debug/tracing/current_tracer
```

# 查看已经trace上的函数

```shell
cd /sys/kernel/debug/tracing
cat enabled_functions
```


# trace event

```shell
cd /sys/kernel/debug/tracing/events/sched/sched_switch
echo 1 > enable

echo 0 > /sys/kernel/debug/tracing/trace
cat /sys/kernel/debug/tracing/trace

# 信息过滤

cd /sys/kernel/debug/tracing/events/sched/sched_switch
cat format # 查看格式
echo "prev_comm == 'chrome' || next_comm == 'chrome'" > filter
```

# 查看函数调用栈

设置 echo 1 > options/func_stack_trace 即可在 trace 结果中获取追踪函数的调用栈。

# 从过滤列表中删除某个函数，使用“感叹号”

```shell
# cd /sys/kernel/debug/tracing
# cat set_ftrace_filter
dev_attr_store
dev_attr_show
ip_rcv
# echo '!ip_rcv' >> set_ftrace_filter
# cat set_ftrace_filter
dev_attr_store
dev_attr_show
```

# 获kernfs_fop_readdir的调用栈

```
root@debian:/sys/kernel/debug/tracing# echo nop > current_tracer
root@debian:/sys/kernel/debug/tracing# echo 0 > tracing_on 
root@debian:/sys/kernel/debug/tracing# echo > set_ftrace_filter 
root@debian:/sys/kernel/debug/tracing# echo > set_graph_function 
root@debian:/sys/kernel/debug/tracing# echo > trace
root@debian:/sys/kernel/debug/tracing# cat available_tracers 
blk mmiotrace function_graph function nop
root@debian:/sys/kernel/debug/tracing# echo function > current_tracer 
root@debian:/sys/kernel/debug/tracing# echo kernfs_fop_readdir > set_ftrace_filter 
root@debian:/sys/kernel/debug/tracing# echo 1 > options/func_stack_trace 
root@debian:/sys/kernel/debug/tracing# echo 1 > tracing_on 
。。。。。。触发。。。。。。
root@debian:/sys/kernel/debug/tracing# cat trace
# tracer: function
#
# entries-in-buffer/entries-written: 4/4   #P:4
#
#                                _-----=> irqs-off/BH-disabled
#                               / _----=> need-resched
#                              | / _---=> hardirq/softirq
#                              || / _--=> preempt-depth
#                              ||| / _-=> migrate-disable
#                              |||| /     delay
#           TASK-PID     CPU#  |||||  TIMESTAMP  FUNCTION
#              | |         |   |||||     |         |
              ls-706     [003] .....  3787.164718: kernfs_fop_readdir <-iterate_dir
              ls-706     [003] .....  3787.164733: <stack trace>
 => 0xffffffffc02b7083
 => kernfs_fop_readdir
 => iterate_dir
 => __x64_sys_getdents64
 => do_syscall_64
 => entry_SYSCALL_64_after_hwframe
              ls-706     [003] .....  3787.164860: kernfs_fop_readdir <-iterate_dir
              ls-706     [003] .....  3787.164866: <stack trace>
 => 0xffffffffc02b7083
 => kernfs_fop_readdir
 => iterate_dir
 => __x64_sys_getdents64
 => do_syscall_64
 => entry_SYSCALL_64_after_hwframe
root@debian:/sys/kernel/debug/tracing# 
```

# 获kernfs_fop_readdir的子调用栈

```
root@debian:/sys/kernel/debug/tracing# echo nop > current_tracer
root@debian:/sys/kernel/debug/tracing# echo 0 > tracing_on 
root@debian:/sys/kernel/debug/tracing# echo > set_ftrace_filter 
root@debian:/sys/kernel/debug/tracing# echo > set_graph_function 
root@debian:/sys/kernel/debug/tracing# echo > trace
root@debian:/sys/kernel/debug/tracing# cat available_tracers 
blk mmiotrace function_graph function nop
root@debian:/sys/kernel/debug/tracing# echo function_graph > current_tracer 
root@debian:/sys/kernel/debug/tracing# echo kernfs_fop_readdir > set_graph_function 
root@debian:/sys/kernel/debug/tracing# echo 1 > tracing_on 
。。。。。。触发。。。。。。
root@debian:/sys/kernel/debug/tracing# cat trace
# tracer: function_graph
#
# CPU  DURATION                  FUNCTION CALLS
# |     |   |                     |   |   |   |
 2)               |  kernfs_fop_readdir() {
 2)               |    filldir64() {
 2)   0.210 us    |      verify_dirent_name();
 2)   0.543 us    |    }
 2)   0.096 us    |    _raw_spin_lock();
 2)   0.096 us    |    _raw_spin_unlock();
 2)               |    filldir64() {
 2)   0.135 us    |      verify_dirent_name();
 2)   0.351 us    |    }
 2)               |    down_read() {
 2)   0.099 us    |      __cond_resched();
 2)   0.292 us    |    }
 2)   0.561 us    |    kernfs_dir_pos();
 2)   0.095 us    |    up_read();
 2)               |    filldir64() {
 2)   0.109 us    |      verify_dirent_name();
 2)   0.320 us    |    }
 2)               |    down_read() {
 2)   0.095 us    |      __cond_resched();
 2)   0.286 us    |    }
 2)   0.120 us    |    kernfs_dir_pos();
 2)   0.097 us    |    up_read();
 2)               |    filldir64() {
 2)   0.099 us    |      verify_dirent_name();
 2)   0.314 us    |    }
 2)               |    down_read() {
 2)   0.090 us    |      __cond_resched();
 2)   0.278 us    |    }
 2)   0.096 us    |    kernfs_dir_pos();
 2)   0.092 us    |    up_read();
 2)               |    filldir64() {
 2)   0.096 us    |      verify_dirent_name();
 2)   0.296 us    |    }
 2)               |    down_read() {
 2)   0.093 us    |      __cond_resched();
 2)   0.280 us    |    }
 2)   0.097 us    |    kernfs_dir_pos();
 2)   0.107 us    |    up_read();
 2)               |    filldir64() {
 2)   0.121 us    |      verify_dirent_name();
 2)   0.334 us    |    }
 2)               |    down_read() {
 2)   0.091 us    |      __cond_resched();
 2)   0.281 us    |    }
 2)   0.098 us    |    kernfs_dir_pos();
 2)   0.094 us    |    up_read();
 2)               |    filldir64() {
 2)   0.101 us    |      verify_dirent_name();
 2)   0.316 us    |    }
 2)               |    down_read() {
 2)   0.091 us    |      __cond_resched();
 2)   0.277 us    |    }
 2)   0.097 us    |    kernfs_dir_pos();
 2)   0.097 us    |    up_read();
 2)               |    filldir64() {
 2)   0.101 us    |      verify_dirent_name();
 2)   0.305 us    |    }
 2)               |    down_read() {
 2)   0.096 us    |      __cond_resched();
 2)   0.285 us    |    }
 2)   0.096 us    |    kernfs_dir_pos();
 2)   0.104 us    |    up_read();
 2)               |    filldir64() {
 2)   0.095 us    |      verify_dirent_name();
 2)   0.292 us    |    }
 2)               |    down_read() {
 2)   0.093 us    |      __cond_resched();
 2)   0.281 us    |    }
 2)   0.095 us    |    kernfs_dir_pos();
 2)   0.097 us    |    up_read();
 2)               |    filldir64() {
 2)   0.105 us    |      verify_dirent_name();
 2)   0.305 us    |    }
 2)               |    down_read() {
 2)   0.093 us    |      __cond_resched();
 2)   0.288 us    |    }
 2)   0.097 us    |    kernfs_dir_pos();
 2)   0.095 us    |    up_read();
 2)               |    filldir64() {
 2)   0.110 us    |      verify_dirent_name();
 2)   0.322 us    |    }
 2)               |    down_read() {
 2)   0.097 us    |      __cond_resched();
 2)   0.308 us    |    }
 2)   0.097 us    |    kernfs_dir_pos();
 2)   0.096 us    |    up_read();
 2)               |    filldir64() {
 2)   0.103 us    |      verify_dirent_name();
 2)   0.319 us    |    }
 2)               |    down_read() {
 2)   0.091 us    |      __cond_resched();
 2)   0.279 us    |    }
 2)   0.096 us    |    kernfs_dir_pos();
 2)   0.094 us    |    up_read();
 2)               |    filldir64() {
 2)   0.108 us    |      verify_dirent_name();
 2)   0.318 us    |    }
 2)               |    down_read() {
 2)   0.092 us    |      __cond_resched();
 2)   0.282 us    |    }
 2)   0.098 us    |    kernfs_dir_pos();
 2)   0.097 us    |    up_read();
 2)               |    filldir64() {
 2)   0.101 us    |      verify_dirent_name();
 2)   0.310 us    |    }
 2)               |    down_read() {
 2)   0.094 us    |      __cond_resched();
 2)   0.282 us    |    }
 2)   0.109 us    |    kernfs_dir_pos();
 2)   0.099 us    |    up_read();
 2)               |    filldir64() {
 2)   0.107 us    |      verify_dirent_name();
 2)   0.315 us    |    }
 2)               |    down_read() {
 2)   0.097 us    |      __cond_resched();
 2)   0.285 us    |    }
 2)   0.096 us    |    kernfs_dir_pos();
 2)   0.095 us    |    up_read();
 2)               |    filldir64() {
 2)   0.098 us    |      verify_dirent_name();
 2)   0.302 us    |    }
 2)               |    down_read() {
 2)   0.091 us    |      __cond_resched();
 2)   0.280 us    |    }
 2)   0.096 us    |    kernfs_dir_pos();
 2)   0.094 us    |    up_read();
 2)               |    filldir64() {
 2)   0.112 us    |      verify_dirent_name();
 2)   0.329 us    |    }
 2)               |    down_read() {
 2)   0.091 us    |      __cond_resched();
 2)   0.285 us    |    }
 2)   0.100 us    |    kernfs_dir_pos();
 2)   0.096 us    |    up_read();
 2)               |    filldir64() {
 2)   0.112 us    |      verify_dirent_name();
 2)   0.324 us    |    }
 2)               |    down_read() {
 2)   0.091 us    |      __cond_resched();
 2)   0.281 us    |    }
 2)   0.097 us    |    kernfs_dir_pos();
 2)   0.098 us    |    up_read();
 2)               |    filldir64() {
 2)   0.097 us    |      verify_dirent_name();
 2)   0.310 us    |    }
 2)               |    down_read() {
 2)   0.092 us    |      __cond_resched();
 2)   0.282 us    |    }
 2)   0.098 us    |    kernfs_dir_pos();
 2)   0.097 us    |    up_read();
 2)               |    filldir64() {
 2)   0.105 us    |      verify_dirent_name();
 2)   0.306 us    |    }
 2)               |    down_read() {
 2)   0.091 us    |      __cond_resched();
 2)   0.280 us    |    }
 2)   0.096 us    |    kernfs_dir_pos();
 2)   0.096 us    |    up_read();
 2)               |    filldir64() {
 2)   0.096 us    |      verify_dirent_name();
 2)   0.296 us    |    }
 2)               |    down_read() {
 2)   0.096 us    |      __cond_resched();
 2)   0.290 us    |    }
 2)   0.107 us    |    kernfs_dir_pos();
 2)   0.097 us    |    up_read();
 2)               |    filldir64() {
 2)   0.098 us    |      verify_dirent_name();
 2)   0.298 us    |    }
 2)               |    down_read() {
 2)   0.088 us    |      __cond_resched();
 2)   0.277 us    |    }
 2)   0.097 us    |    kernfs_dir_pos();
 2)   0.094 us    |    up_read();
 2)               |    filldir64() {
 2)   0.097 us    |      verify_dirent_name();
 2)   0.304 us    |    }
 2)               |    down_read() {
 2)   0.090 us    |      __cond_resched();
 2)   0.281 us    |    }
 2)   0.098 us    |    kernfs_dir_pos();
 2)   0.094 us    |    up_read();
 2)               |    filldir64() {
 2)   0.104 us    |      verify_dirent_name();
 2)   0.309 us    |    }
 2)               |    down_read() {
 2)   0.090 us    |      __cond_resched();
 2)   0.278 us    |    }
 2)   0.098 us    |    kernfs_dir_pos();
 2)   0.096 us    |    up_read();
 2)               |    filldir64() {
 2)   0.101 us    |      verify_dirent_name();
 2)   0.332 us    |    }
 2)               |    down_read() {
 2)   0.094 us    |      __cond_resched();
 2)   0.282 us    |    }
 2)   0.096 us    |    kernfs_dir_pos();
 2)   0.093 us    |    up_read();
 2)               |    filldir64() {
 2)   0.098 us    |      verify_dirent_name();
 2)               |      lock_mm_and_find_vma() {
 2)   0.097 us    |        down_read_trylock();
 2)   0.096 us    |        __cond_resched();
 2)               |        find_vma() {
 2)   0.094 us    |          __rcu_read_lock();
 2)   0.094 us    |          __rcu_read_unlock();
 2)   0.508 us    |        }
 2)   1.075 us    |      }
 2)               |      handle_mm_fault() {
 2)   0.097 us    |        __rcu_read_lock();
 2)   0.101 us    |        mem_cgroup_from_task();
 2)               |        __count_memcg_events() {
 2)   0.106 us    |          cgroup_rstat_updated();
 2)   0.342 us    |        }
 2)   0.097 us    |        __rcu_read_unlock();
 2)               |        __handle_mm_fault() {
 2)               |          vma_alloc_folio() {
 2)   0.099 us    |            __get_vma_policy();
 2)   0.090 us    |            policy_nodemask();
 2)   0.094 us    |            policy_node();
 2)               |            __folio_alloc() {
 2)               |              __alloc_pages() {
 2)   0.092 us    |                __cond_resched();
 2)   0.098 us    |                should_fail_alloc_page();
 2)               |                get_page_from_freelist() {
 2)   0.098 us    |                  _raw_spin_trylock();
 2)   0.095 us    |                  _raw_spin_unlock();
 2)   0.897 us    |                }
 2)   1.532 us    |              }
 2)   1.717 us    |            }
 2)   2.475 us    |          }
 2)               |          __mem_cgroup_charge() {
 2)               |            get_mem_cgroup_from_mm() {
 2)   0.091 us    |              __rcu_read_lock();
 2)   0.091 us    |              __rcu_read_lock();
 2)   0.098 us    |              __rcu_read_unlock();
 2)   0.091 us    |              __rcu_read_unlock();
 2)   0.848 us    |            }
 2)               |            charge_memcg() {
 2)   0.119 us    |              try_charge_memcg();
 2)   0.092 us    |              __rcu_read_lock();
 2)   0.094 us    |              __rcu_read_unlock();
 2)               |              __count_memcg_events() {
 2)   0.096 us    |                cgroup_rstat_updated();
 2)   0.291 us    |              }
 2)   0.095 us    |              memcg_check_events();
 2)   1.410 us    |            }
 2)   0.094 us    |            __rcu_read_lock();
 2)   0.091 us    |            __rcu_read_unlock();
 2)   2.903 us    |          }
 2)               |          __cgroup_throttle_swaprate() {
 2)               |            blk_cgroup_congested() {
 2)   0.092 us    |              __rcu_read_lock();
 2)   0.091 us    |              kthread_blkcg();
 2)   0.090 us    |              __rcu_read_unlock();
 2)   0.657 us    |            }
 2)   0.840 us    |          }
 2)   0.103 us    |          _raw_spin_lock();
 2)   0.090 us    |          add_mm_counter_fast();
 2)               |          page_add_new_anon_rmap() {
 2)               |            __mod_lruvec_page_state() {
 2)   0.092 us    |              __rcu_read_lock();
 2)               |              __mod_lruvec_state() {
 2)   0.095 us    |                __mod_node_page_state();
 2)               |                __mod_memcg_lruvec_state() {
 2)   0.090 us    |                  cgroup_rstat_updated();
 2)   0.296 us    |                }
 2)   0.659 us    |              }
 2)   0.090 us    |              __rcu_read_unlock();
 2)   1.228 us    |            }
 2)   0.096 us    |            __page_set_anon_rmap();
 2)   1.609 us    |          }
 2)               |          lru_cache_add_inactive_or_unevictable() {
 2)               |            folio_add_lru_vma() {
 2)   0.093 us    |              folio_add_lru();
 2)   0.273 us    |            }
 2)   0.452 us    |          }
 2)   0.091 us    |          _raw_spin_unlock();
 2)   9.504 us    |        }
 2) + 10.746 us   |      }
 2)   0.091 us    |      up_read();
 2) + 12.794 us   |    }
 2)               |    down_read() {
 2)   0.092 us    |      __cond_resched();
 2)   0.279 us    |    }
 2)   0.097 us    |    kernfs_dir_pos();
 2)   0.094 us    |    up_read();
 2)               |    filldir64() {
 2)   0.101 us    |      verify_dirent_name();
 2)   0.312 us    |    }
 2)               |    down_read() {
 2)   0.092 us    |      __cond_resched();
 2)   0.282 us    |    }
 2)   0.095 us    |    kernfs_dir_pos();
 2)   0.094 us    |    up_read();
 2)               |    filldir64() {
 2)   0.103 us    |      verify_dirent_name();
 2)   0.313 us    |    }
 2)               |    down_read() {
 2)   0.105 us    |      __cond_resched();
 2)   0.299 us    |    }
 2)   0.100 us    |    kernfs_dir_pos();
 2)   0.095 us    |    up_read();
 2) + 50.665 us   |  }
 2)               |  kernfs_fop_readdir() {
 2)               |    down_read() {
 2)   0.105 us    |      __cond_resched();
 2)   0.311 us    |    }
 2)   0.111 us    |    kernfs_dir_pos();
 2)   0.092 us    |    up_read();
 2)   1.009 us    |  }
root@debian:/sys/kernel/debug/tracing# 
```

# 资料

宋宝华：关于Ftrace的一个完整案例

https://mp.weixin.qq.com/s/aFpXGrQ7sHaZguL66QF-tA

使用 ftrace 来跟踪系统问题 - ftrace 介绍

https://www.jianshu.com/p/99e127973abe

Debugging the kernel using Ftrace - part 1

https://lwn.net/Articles/365835/

Debugging the kernel using Ftrace - part 2

https://lwn.net/Articles/366796/

Secrets of the Ftrace function tracer

https://lwn.net/Articles/370423/

在Linux下做性能分析2：ftrace

https://zhuanlan.zhihu.com/p/22130013

Ftrace 基本用法

https://tinylab.org/ftrace-usage/

Ftrace 进阶用法

https://tinylab.org/ftrace-2/
