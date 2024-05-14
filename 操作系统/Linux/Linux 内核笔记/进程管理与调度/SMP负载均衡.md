# CPU 域

SMT(Simultaneous MultiThreading) 超线程:一个物理核心可以有两个执行线程，被称为超线程技术。超线程使用相同的CPU资源且共享L1 cache，迁移进程不会影响Cache利用率。

MC 多核：每个物理核心独享L1 cache，多个物理核心可以组成一个cluster，cluster里的CPU共享L2 cache

# 负载均衡

由软中断函数处理(run_rebalance_domains处理)

run_rebalance_domains  --> rebalance_domains(struct rq *rq,enum cpu_idle_type idle);

# 函数关系

init_sched_domains --> build_sched_domains(const struct cpumask *cpu_map,struct sched_domain_attr *attr):参数cpu_map为cpu_active_mask，attr为NULL。

build_sched_domains:真正开始建立调度拓扑关系的函数，首先调用__visit_domain_allocation_hell 为default_topology(struct sched_domain_topology_level)定义的每个层级分配per-cpu的 sched_domain 和 sched_group。接下来调用build_sched_domain 为每个cpu在每个层初始化sched_domain

build_sched_domain: 将该CPU对应的default_topology层级下兄弟CPU bitmap 复制到 scehd_domain 中的 span 中（cpumask_and(sched_domain_span(sd), cpu_map, tl->mask(cpu));//tl->mask(cpu)返回位图），并建立调度域的父子关系

build_sched_domains --> build_sched_groups:在某个调度域里建立对应的调度组，struct sched_domain数据结构中的groups指针指向该调度域里的调度组链表，struct sched_group数据结构中的next成员把同一个调度域中所有调度组都串联成一个链表。

MC 层: 共享同一个 L2 cache 的 构成一个 domain

SMT 层: 共享同一个 L1 cache 的 构成一个 domain



MC 层的 调度组: 共享调度L1 cache 的，构成一个group

IDLE 层: 自成一组

# load_balance函数

1.找出最忙的组

2.从最忙的组中找出最忙的cpu

3.迁移最忙的CPU上的运行队列中的进程到该CPU

# find_busiest_group

在调度域中找到最忙的组

# find_busiest_qeueue

在最忙的组中找到最忙的CPU

# 唤醒进程



# 资料

1.Differences between physical CPU vs logical CPU vs Core vs Thread vs Socket

http://www.daniloaz.com/en/differences-between-physical-cpu-vs-logical-cpu-vs-core-vs-thread-vs-socket/

2.CPU - 物理核、逻辑核、超线程

http://debris.cjli.info/computer/hardware/cpu-physical-logic-ht.html

3.QEMU 的 CPU 配置

https://www.cnblogs.com/pengdonglin137/p/5023994.html

4.Linux Scheduling Domains

https://www.ibm.com/developerworks/cn/linux/l-cn-schldom/index.html

5.linux多CPU进程负载均衡解析

https://blog.csdn.net/wenwuge_topsec/article/details/14517733#

6.Linux调度域负载均衡-设计，实现和应用

https://www.oschina.net/question/234345_47501

7.Linux内核的进程负载均衡机制

https://cloud.tencent.com/developer/article/1409154