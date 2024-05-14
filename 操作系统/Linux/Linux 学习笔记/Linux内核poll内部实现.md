# 前言

poll机制用于实现IO多路复用。所谓IO多路复用，通俗的讲，其实就是线程复用，使其能在一个线程上处理多个IO。

# 用户空间

用户通过调用用户空间的poll函数使用该机制。

# 驱动部分的实现

用户如果要在自己的驱动中实现poll机制，则必须实现:
struct file_operations中的
unsigned int (*poll) (struct file *, struct poll_table_struct *) 函数

该函数主要调用：

static inline void poll_wait(struct file * filp, wait_queue_head_t * wait_address, poll_table *p)

用于将一个wait_queue加入到poll_table中

然后检查相应状态,设置并返回给用户

eg(LDD 3):

```c
static unsigned int scull_p_poll(struct file *filp, poll_table *wait)
{
    struct scull_pipe *dev = filp->private_data;
    unsigned int mask = 0;
    /*
    * The buffer is circular; it is considered full
    * if "wp" is right behind "rp" and empty if the
    * two are equal.
    */
    down(&dev->sem);
    poll_wait(filp, &dev->inq, wait);
    poll_wait(filp, &dev->outq, wait);
    if (dev->rp != dev->wp)
        mask |= POLLIN | POLLRDNORM; /* readable */
    if (spacefree(dev))
        mask |= POLLOUT | POLLWRNORM; /* writable */
    up(&dev->sem);
    return mask;
}

```


# 内核实现分析

下面以内核版本4.10.0进行分析

在内核，实现为do_sys_poll(/fs/select.c)

```C
int do_sys_poll(struct pollfd __user *ufds, unsigned int nfds,
		struct timespec64 *end_time)
{
..................................
    poll_initwait(&table);
    fdcount = do_poll(head, &table, end_time);
    poll_freewait(&table);
..................................
}
```

do_sys_poll 函数主要就是创建一个 struct poll_wqueues 的结构体，然后调用 do_poll。

其中 struct poll_wqueues结构体：
```c
struct poll_wqueues {
	poll_table pt;
	struct poll_table_page *table;
	struct task_struct *polling_task;
	int triggered;
	int error;
	int inline_index;
	struct poll_table_entry inline_entries[N_INLINE_POLL_ENTRIES];
};
```

do_poll(/fs/select)函数,主要是一个for循环,会将struct poll_wqueues 的 poll_table pt作为参数，传递给相应文件的poll函数。如果检查到任意一个文件能使用，就返回，否则就等待，直到有可用的文件为止。

然后文件的poll函数，调用poll_wait函数

poll_wait函数，接着调用__pollwait函数.

```c
static void __pollwait(struct file *filp, wait_queue_head_t *wait_address,
				poll_table *p)
{
	struct poll_wqueues *pwq = container_of(p, struct poll_wqueues, pt);
	struct poll_table_entry *entry = poll_get_entry(pwq);
	if (!entry)
		return;
	entry->filp = get_file(filp);
	entry->wait_address = wait_address;
	entry->key = p->_key;
	init_waitqueue_func_entry(&entry->wait, pollwake);
	entry->wait.private = pwq;
	add_wait_queue(wait_address, &entry->wait);
}
```

分析，可知，获取一个poll_table_entry,对其进行初始化，然后将当前进程加入到等待队列中，等待事件的发生。

# 总结

对一个程序的分析，最重要的是对其数据结构的分析。

当用户调用poll函数时，内核会创建一个struct poll_wqueues，然后将其中的poll_table 传递给文件的poll函数，然后由poll函数调用poll_wait，将当前调用进程加入等待队列中，等待事件的发生。

当一个进程，poll多个文件描述符时，该进程会被加载进多个等待队列中。