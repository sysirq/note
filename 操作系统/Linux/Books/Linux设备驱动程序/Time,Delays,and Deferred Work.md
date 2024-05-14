# Measuring Time Lapses

The counter and the utility functions to read it live in <linux/jiffies.h>.Needless to say both jiffies and jiffies_64 must be considered read-only.

# Processor-Specific Registers

```
#include <asm/msr.h>

rdtsc(low32,high32);
rdtscl(low32);
rdtscll(var64);
```

As an example using only the low half of the register,the following lines measure the execution of the instruction itself:
```
unsigned long ini,end;
rdtscl(ini);rdtscl(end);
printk("time lapse:%li\n",end - ini);
```

architecture-independent function:

```c
#nclude <linux/timex.h>
cycles_t get_cycles(void);
```

# Delaying Execution

```c
#include <linux/wait.h>

long wait_event_timeout(wait_queue_head_t q,condition,long timeout);

long wait_event_interruptible_timeout(wait_queue_head_t q,condition,long timeout);

wait_queue_head_t wait;
init_waitqueue_head(&wait);
wait_event_interruptible_timeout(wait,0,delay);
```

Timeout value(delay) represents the number of jiffies to wait

```
#include <linux/sched.h>
signed long schedule_timeout(signed long timeout);

set_current_state(TASK_INTERRUPTIBLE);
schedule_timeout(delay);
```

# Short Delays

```c
#include <linux/delay.h>

void ndelay(unsigned long nsecs);
void udelay(unsigned long usecs); 
void mdelay(unsgined long msecs);
```

# Kernel Timer

A kernel timer is a data structure that instructs the kernel to execute a user-defined function with a user-defined argument at user-defined time.

- Timer functions must be atomic

- No access to user space is allowed

- No sleeping or scheduling may be performed

It's also worth knowing that in an SMP system,the timer function is executed by the same CPU that registered it

#### The Timer API

```c
#include <linux/time.h>

struct timer_list{
    /*.................*/
    unsigned long expires;
    void (*function)(unsigned long );
    unsigned long data;
};

void init_timer(struct timer_list* timer);

struct timer_list TIMER_INITIALIZER(_function,_expires,_data);

void add_timer(struct timer_list *timer);
int del_timer(struct timer_list *timer);

```

# Tasklets

Unlike kernel timers,however,you can't ask to execute the function at a speciic time.

Actually,a tasklet ,just like a kernel timer,is executed in the context of a "soft interrupt",a kernel mechanism that executes asynchronous task with hardware interrupts enabled.

```c
#include <linux/interrupt.h>

struct tasklet_struct{
    /*...*/
    void (*func)(unsigned long);
    unsigned long data;
};

void tasklet_init(struct tasklet_struct *t,void (*func)(unsigned long),unsigned long data);
DECLARE_TASKLET(name,func,data);
DECLATE_TASKLET_DISABLE(name,func,data);
```