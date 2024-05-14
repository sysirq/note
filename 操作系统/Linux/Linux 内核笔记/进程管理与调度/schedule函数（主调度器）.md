调度时机分以下3种:

- 阻塞操作：互斥量(mutex)、信号量(semaphore)、等待队列(waitqueue)等
- 在中断返回前和系统调用返回用户空间时，去检查TIF_NEED_RESCHED标志位以判断是否需要调度。
- 将要被唤醒的进程不会马上调用schedule要求被调度，而是会被添加到CFS就绪队列中，并且设置TIF_NEED_RESCHED标志位。那么唤醒进程什么时候被调度呢？这要根据内核是否具有可抢占功能。

如果内核可抢占，则：

- 如果唤醒动作发生在系统调用或者异常处理上下文，在下一次调用preempt_enable时会检测是否需要抢占调度
- 如果唤醒动作发生在硬中断处理上下文中，硬件中断处理返回前会检查是否要抢占当前进程。

如果内核不可抢占:

- 当前进程调用 cond_resched()时会检查是否要调度
- 主动调用schedule()
- 调用或异常处理返回用户空间时
- 中断处理完成返回用户空间时


schedule --> __schedule

__schedule --> deactivate_task: 从运行队列中减掉该调度实体的负载贡献。

__schedule --> pick_next_task --> pick_next_task_fair: 选择下一个调度的进程

# 进程时间用完切换到下一个进程

调用pick_next_entity将当前进程重新加入到等待队列中，然后挑选下一个合适的进程

# 进程等待某个条件时放弃对CPU的使用

调用deactivate_task，减掉该调度实体对CPU负载的贡献。并将调度实体的on_rq设置为0，这样等会调用pick_next_entity时，该调度实体就不会被加入到等待队列中。

# 资料

1.linux 进程管理 调度

http://blog.chinaunix.net/uid-7500466-id-3990572.html