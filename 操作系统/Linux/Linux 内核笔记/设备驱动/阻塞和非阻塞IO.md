用户以非阻塞的方式访问设备文件，则当设备资源不可获取时，设备驱动的xxx_read、xxx_write等操作立即返回，read()，write()等系统调用也随即被返回，应用程序收到-EAGAIN返回值。

# 等待队列

### 定义等待队列头部

```c
wait_queue_head_t my_queue;
```

wait_queue_head_t 是 __wait_queue_head 结构体的一个typedef。

```c
struct __wait_queue_head {
	spinlock_t		lock;
	struct list_head	task_list;
};
typedef struct __wait_queue_head wait_queue_head_t;
```

### 初始化等待队列头部

```c
init_waitqueue_head(&mu_queue);
```

下面的DECLARE_WAIT_QUEUE_HEAD宏可以作为定义并初始化等待队列头部的快捷方式

```c
DECLARE_WAIT_QUEUE_HEAD(my_head);
```

### 定义等待队列元素

```c
DECLARE_WAITQUEUE(name,tsk);
```

### 添加删除等待队列元素

```c
void add_wait_queue(wait_queue_head_t *q,wait_queue_t *wait);
void remove_wait_queue(wait_queue_head_t *q,wait_queue_t *wait);
```

### 等待事件

```c
wait_event(queue,condition);
wait_event_interruptible(queue,condition);
wait_event_timeout(queue,condition,timeout);
wait_event_interruptible_timeout(queue,condition,timeout);
```

queue作为等待队列头部的队列被唤醒.timeout 以jiffy为单位

### 唤醒队列

```c
void wait_up(wait_queue_head_t *queue);
```

### 在等待队列上睡眠

```c
sleep_on(wait_queue_head_t *q);
interruptible_sleep_on(wait_queue_head_t *q);
```

将进程设置为TASK_UNINTERRUPTIBLE，并定义一个等待队列，将其加入q中

### eg

```c
static ssize_t xxx_write(struct file *file,const char *buffer,size_t count,loff_t *ppos)
{
    ...
    DECLARE_WAITQUEUE(wait,current);
    add_wait_queue(&xxx_wait,&wait);
    
    do{
        avail = device_writeable(...);
        if(avail < 0){
            if(file->f_flags & O_NONBLOCK){
                ret = -EAGAIN;
                goto out;
            }
            __set_current_state(TASK_INTERRUPTIBLE);
            schedule();
            if(signal_pending){
                ret = -ERESTARTSYS;
                goto out;
            }
        }
    }while(avail<0)
    
    device_write(...);
out:
    remove_wait_queue(&xxx_wait,&wait);
    set_current_state(TASK_RUNNING);
    return ret;
}
```

# 轮询操作

设备驱动中poll函数的原型：

```c
unsigned int (*poll) (struct file *, struct poll_table_struct *);
```

第一个参数为file结构体指针，第2个参数为轮询表指针。这个函数应该进行两项工作:

- 对可能引起设备文件状态变化的等待队列调用poll_wait函数，将对应的等待队列头部添加到poll_table中
- 返回表示是否能对设备进行无阻塞读、写访问的掩码

用于向poll_table注册等待队列的关键poll_wait函数的原型如下:

```c
static inline void poll_wait(struct file * filp, wait_queue_head_t * wait_address, poll_table *p);
```

把当前进程添加到p参数指定的等待列表（poll_table）中，实际作用是让唤醒参数wait_address对应的等待队列可以唤醒因select而睡眠的进程。

驱动程序poll函数应该返回设备资源的可获取状态，即POLLIN、POLLOUT、POLLPRI、POLLERR、POLLNVAL

eg:

```c
static unsigned int xxx_poll(struct file *filp,poll_table *wait)
{
    unsigned int mask = 0;
    struct xxx_dev *dev = filp->private_data;
    
    ...
    poll_wait(filp,&dev->r_wait,wait);
    poll_wait(filp,&dev->w_wait,wait);
    
    if(...)
        mask |= POLLIN | POLLRDNORM;
        
    if(...)
        mask |= POLLOUT | POLLWRNORM;
    ...
    return mask;
}
```

### poll 内核实现

do_sys_poll

poll_wait函数让等待队列中有事件发生时，能唤醒调用select的进程。

# 资料

1.set_current_state 应用

https://www.xuebuyuan.com/1104793.html
