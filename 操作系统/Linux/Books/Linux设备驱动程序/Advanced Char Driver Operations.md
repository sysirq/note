# ioctl

```c

//user space
int ioctl(int fd,unsigned long cmd,...);

//kernel space
int (*ioctl)(struct inode *inode,struct file* filp,unsigned int cmd,unsigned long arg)
```

# Blocking I/O

```c
#include <linux/wait.h>

wait_queue_head_t my_queue;

DECLARE_WAIT_QUEUE_HEAD(name);

init_waitqueue_head(&my_queue);

```

#### 

```c
wait_event(queue,condition);

wait_event_interruptible(queue,condition);

wait_event_timeout(queue,condition,timeout);

wait_event_interruptible_timeout(queue,condition,timeout);

void wake_up(wait_queue_head_t *queue);

void wake_up_interruptible(wait_queue_head_t *queue);
```

# Manual sleeps

```c
DEFINE_WAIT(my_wait);

void prepare_to_wait(wait_queue_head_t *queue,wait_queue_t *wait,int state);

void schedule();//combine with condition check 

void finish_wait(wait_queue_head_t *queue,wait_queue_t *wait);

```

# poll and select

```c
unsigned int (*poll)(struct file *filp,struct poll_table *wait);
```

eg:

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