# 安装

Ubuntu系列：apt install linux-tools-common

Debian: apt install linux-perf

# 概念

PMU：Performance Monitor Unit

PMU允许软件针对某种硬件事件设置counter，此后处理器便开始统计该事件的发生次数，当发生的次数超过counter内设置的值后，便产生中断。

性能调优工具如perf的基本原理是对监测对象进行采样，最简单的情形是根据tick中断进行采样，这能获得程序主要时间耗费在什么函数上。

改变采样的触发条件，我们可以获得不同的统计数据

以tick作为事件触发采样便可以获得程序运行时间的分布

以 cache miss 事件触发采样便可以知道 cache miss 的分布，即 cache 失效经常发生在哪些程序代码中

# Perf 事件

能够触发Perf采样的事件，可以分为三类

*   Hardware Event：是由PMU硬件产生的事件，如cache命中
*   Software Event：是内核软件产生的事件，如进程切换，tick数
*   Tracepoint Event

可以使用 perf list 列出所有事件

# perf 常用选项

perf list：列出所有事件

perf stat：提供被调式程序的整体情况和汇总数据

perf top (-e EVENT 可选，指定事件)：用于实时显示当前系统的性能统计信息

perf record: eg (perf record – e cpu-clock -g ./t1 )

perf report

# perf 指定分类

pid, comm, dso, symbol, parent, srcline, weight, local\_weight, abort, in\_tx, transaction, overhead, sample, period.

# 指定性能事件

\-e &lt;event&gt; : u // userspace

\-e &lt;event&gt; : k // kernel

\-e &lt;event&gt; : h // hypervisor

\-e &lt;event&gt; : G // guest counting (in KVM guests)

\-e &lt;event&gt; : H // host counting (not in KVM guests)

# 常用命令行参数

    # perf top // 默认配置
    
    # perf top -G // 得到调用关系图
    
    # perf top -e cycles // 指定性能事件
    
    # perf top -p 23015,32476 // 查看这两个进程的cpu cycles使用情况
    
    # perf top -s comm,pid,symbol // 显示调用symbol的进程名和进程号
    
    # perf top --comms nginx,top // 仅显示属于指定进程的符号
    
    # perf top --symbols kfree // 仅显示指定的符号

\-p：stat events on existing process id (comma separated list). 仅分析目标进程及其创建的线程。

\-a：system-wide collection from all CPUs. 从所有CPU上收集性能数据。

\-r：repeat command and print average + stddev (max: 100). 重复执行命令求平均。

\-C：Count only on the list of CPUs provided (comma separated list), 从指定CPU上收集性能数据。

\-v：be more verbose (show counter open errors, etc), 显示更多性能数据。

\-n：null run - don't start any counters，只显示任务的执行时间 。

\-x SEP：指定输出列的分隔符。

\-o file：指定输出文件，--append指定追加模式。

\--pre &lt;cmd&gt;：执行目标程序前先执行的程序。

\--post &lt;cmd&gt;：执行目标程序后再执行的程序。

# 资料

Perf -- Linux下的系统性能调优工具，第 1 部分

<https://www.ibm.com/developerworks/cn/linux/l-cn-perf1/>

系统级性能分析工具 — Perf

<https://blog.csdn.net/zhangskd/article/details/37902159/>
