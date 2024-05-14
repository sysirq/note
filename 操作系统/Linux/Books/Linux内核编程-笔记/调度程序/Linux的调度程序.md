# 基础队列

在Linux中，运行队列由两个优先级数组组成

    活跃数组：存放时间片还没耗尽的进程
    
    到期数组：存放时间片已经耗尽的进程
    
# 基础函数 

schedule:负责把CPU的控制权传递给不同的进程

scheduler_tick：内核周期性调用的系统定时器，检查当前进程是否该被schedule

Linux内核编程 中 图7-1 调度进程，详细讲解了这两个函数的配合

context_switch：切换虚拟地址、以及进程task_struct结构

deactivate_task：从运行队列删除进程

activate_task：讲进程加入到运行队列

# 动态优先级的计算
基于它先前的行为以及用户指定的nice值

# 内核抢占

显示内核抢占

隐式内核抢占

# 自旋锁与信号量

``` C
\\include/linux/spinlock.h
spin_lock_init:初始化自旋锁

spin_lock:上锁
spin_lock_irqsave：上锁前禁止中断（禁止中断可以确保临界区中的任何操作不被打断）

spin_unlock
spin_unlock_irqrestore


\\include/linux/semaphore.h
sema_init:初始化

dow

up
```

# 系统时钟：关于时间和定时器