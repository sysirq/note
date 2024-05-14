# 时间记账

每一次时钟中断到来时，需要对当前运行的进程做一次时间记账，函数流程为：

```c
tick_sched_timer --> update_process_timers --> task_tick_fair --> entity_tick
```

entity_tick首先调用 update_curr , 通过进程的权重(nice值映射为prio，然后在映射为weight。其由set_load_weight函数实现)计算进程的虚拟运行时间应该增加多少，公式为：

```c
虚拟运行时间的增加值 = 实际运行时间 * nice值为0的进程权重 / 当前运行进程的权重 
```

其中 ，当进程的nice值越高，（nice值为0的进程权重 / 当前运行进程的权重） 计算结果就越大，相反则越小。

所以 nice值越高（优先级越低）的进程，虚拟运行时间的增加的越快，反之越慢

然后entity_tick调用check_preempt_tick确定当前进程是否应该被换出。

check_preempt_tick：首先根据当前系统中可运行进程，计算出当前进程可以运行的时间是多少（sched_slice函数实现，其中有个调度延迟sysctl_sched_latency，用来表示进程，在下一次运行时的最大间隔），计算方法为：（当前任务的权重/系统中所有可运行进程的权重）*调度延迟。但是当可运行进程的数目超过无穷大时，会造成当前进程可运行的时间为0，所以在计算当前进程可运行的时间时，当可运行任务的数目超过sched_nr_latency时，会保证每个可运行进程的可运行时间为sysctl_sched_min_granularity。

### 实验

分析代码我们知道，两个nice值之间权重的差值为1.25倍（prio_to_weight 数组上面得注释），那么相邻两个权重，他们获得的CPU百分比差值应该为10%。我们可以只给虚拟机设置一个CPU，然后跑两个死循环，分别给nice值为0，与nice值为1。

nice值为1的权重为：820

nice值为0的权重为：1024

那么nice值为1的将获得：820/(820+1024) ==  45%的处理器时间
而nice值为0的获得：1024/(820+1024) == 55%的处理器时间

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main(int argc,char *argv[])
{
	int i;
	int nice_val1,nice_val2;
	int child_pid;

	printf("Parent PID:%d\n",getpid());

	if(argc != 3){
		printf("need two nice values\n");
		return -1;
	}

	nice_val1 = atoi(argv[1]);
	nice_val2 = atoi(argv[2]);
	if(nice_val1<-20 || nice_val1 > 19){
		printf("nice1_val error\n");
		return -1;
	}
	
	if(nice_val2<-20 || nice_val2 > 19){
		printf("nice2_val error\n");
		return -1;
	}

	printf("nice_val1:%d nice_val2:%d\n",nice_val1,nice_val2);

	child_pid = fork();
	if(child_pid > 0){//parent
		printf("Children PID:%d\n",child_pid);
		if(nice(nice_val1) == -1){
			perror("nice");
			return -1;
		}
		for(;;)i++;
	}else if(child_pid == 0){//children
		if(nice(nice_val2) == -1){
			perror("nice");
			return -1;
		}
		for(;;)i++;
	
	}else{
		perror("fork error!");
		return -1;
	}

	return 0;
}
```

### 资料

linux - 进程友好性(优先级)设置对Linux没有影响

https://www.coder.work/article/173790

# 进程选择

CFS调度器挑选下一个运行的进程原则是：选择vruntime虚拟运行时间最小的进程。CFS调度器管理系统中可运行进程的数据结构是红黑树

```c
\\kernel\sched\fair.c
	.enqueue_task		= enqueue_task_fair,
	.dequeue_task		= dequeue_task_fair,

	.pick_next_task		= pick_next_task_fair,
	.put_prev_task		= put_prev_task_fair,
```

### 进程添加

向CFS调度器添加可运行进程的函数为：enqueue_task_fair

我知道的，添加可运行进程的场景有：进程第一次被创建 、 进程被唤醒。

在进程第一次被创建的情况下（fork系统调用）：会调用place_entity（流程为：do_fork->copy_process->sched_fork->task_fork_fair->place_entity）。在其中，会更具当前队列的min_vruntime计算出新进程的vruntime（比min_vruntime大，防止新进程恶意DoS系统，造成其他进程饥饿）。

在进程被唤醒时，也会调用place_entity（在enqueue_entity中调用）进行补偿：会根据当前运行队列的min_vruntime，计算出进程新的vruntime。（如果不这样做，那么进程由于睡眠了一段时间，其vruntime会远远小于当前所有可运行进程的vruntime，则会造成刚刚被唤醒的进程疯狂追赶其他进程的vruntime，造成饥饿现象）

### 进程选择

CFS调度器挑选下一个进程的函数为：pick_next_task_fair

其核心是选择红黑树最左边的节点，也就是vruntime最小的进程来运行。

分析会发现pick_next_task_fair会调用set_next_entity，设置下一个要运行的进程，他会调用__dequeue_entity将其从CFS红黑树中移除。

### 进程出队

CFS调度器进程出队的函数为:dequeue_task_fair

该函数会接收一个flags参数，其值为DEQUEUE_SLEEP（进程从TASK_RUNNING状态变为TASK_INTERRUPTIBLE等其他需要等待资源的状态）或为0，对于DEQUEUE_SLEEP，其虚拟时间保持不变，否则：se->vruntime -= cfs_rq->min_vruntime，这样做的原因是：取相对值，方便插入到另外一个CPU的运行队列上。

### tips

除了当前进程、等待资源满足的进程，其都在CFS队列中

### 资料

从几个问题开始理解CFS调度器

http://linuxperf.com/?p=42


# 负载均衡


处理器分为:NUMA Node、Socket、Core、Thread

对于操作系统，逻辑CPU的个数为：Node * Socket * Core * Thread

对于Core内的Thread共享L2缓存

对于Socket中的Core共享L3数据缓存

对于Node中的Socket，他们共享同一个内存，也就是Node中的Socket访问内存的时间是一样的

因此进程在同一Core中的Thread之间迁移，他们共享同一（L1指令数据缓存）L2数据缓存，所以受到影响较小

进程在同一Socket中的Core中迁移时，由于他们L1指令缓存数据缓存和L2数据缓存不共享,但L3共享，所以会受到影响

进程在同一Node中的Socket中迁移时，由于他们不共享L1、L2、L3缓存，只共享内存，所以会受到影响

而进程在不同Node之间迁移时，他们受到的影响最大，因为此时内存是不共享的

可以通过lscpu -p命令，得到cache与CPU之间的关系，也可以通过:
```shell
cat /sys/devices/system/cpu/cpu0/cache/index3/shared_cpu_list
```

PELT(Per-Entity Load Trace)：将1024us分为一个周期，统计进程在该周期处于runnable状态（等待CPU执行、已经在执行）的时间X，计算出该周期对系统负载的贡献X/1024。为了统计出进程对系统负载的贡献更准确，会将进程过去对系统负载的贡献加入计算，当前进程对系统负载的贡献计算公式为：

```
L = L0 + L1*y + L2*y^2 + L3*y^3......Ln*y^n
```

y为衰减因子，y^32为0.5，Ln为第n次周期的贡献。在计算当前进程对系统负载贡献时，有个技巧：以前的负载贡献总和*y + 当前负载贡献


__update_entity_runnable_avg：sa->runnable_avg_period 表示在系统中的贡献，sa->runnable_avg_sum表示runnable状态的贡献，都是用上面的计算负载贡献的公式计算（有优化）


__update_entity_load_avg_contrib：计算贡献

# 资料

Getting CPU architecture information with lscpu

https://diego.assencio.com/?index=614d73283d49e939ebfb648cfb86819d

per-entity load tracking

http://www.wowotech.net/process_management/PELT.html

# 抢占

### 用户抢占

- 从系统调用返回用户空间时

- 从中断处理程序返回用户空间时

### 内核抢占

在不支持内核抢占的内核中，内核代码会一直执行到返回用户空间时或调用schedule函数才能重新调度。

内核抢占的一个重要条件是：内核没有持有锁。因此引入了preempt_count，当使用锁时加1，解锁时减1，只有preempt_count为0，内核才能被抢占

- 中断程序返回内核空间时
- 内核代码再一次具有可抢占性时（解锁、开抢占）
- 内核中调用schedule（显式或隐式）