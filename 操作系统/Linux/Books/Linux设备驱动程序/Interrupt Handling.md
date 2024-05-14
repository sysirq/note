# Installig an Interrupt Handler

```C
#include <linux/interrupt.h>

int request_irq(unsigned int irq,
    irqreturn_t (*handler)(int,void*,struct pt_regs*),
    unsigned long flags,
    const char *dev_name,
    void*dev_id);

void free_irq(unsigned int irq,void *dev_id);
```

For what it's worth,the i386 and x86_64 architectures define a function for querying the availability of an interrupt line:

```c
int can_request_irq(unsigned int irq,unsigned long flags);
```

This function returns a nonzero value if an attemp to allocate the given interrupt succeeds.

# Autodetecting the IRQ Number

the driver tells the device to generate interrupts and watches what happens.If everything goes well,only one interrupt line is activated.

### Kernel-assisted probing

### Do-it-yourself probing

# Fast and Slow Handlers

Fast interrupts (SA_INTERRUPT) are executed with all other interrupts disabled on the current processor.

### The internals of interrupt handing on the x86

The lowest level of interrupt handling can be found in entry.S,an assembly-language file that handles much of the machine-level work.By way of a bit of assembler trickery and some macros,a bit of code is assigned to every possible interrupt.In each case,the code pushes the interrupt number on the stack and jumps to a common segment,which calls do_IRO,defined in irq.c

# Handler Arguments and Return Value

# Enabling and Disabling Interrupts

### Disabling a single interrupt

```c
#include <asm/irq.h>

void disable_irq(int irq);
void disable_irq_nosyn(int irq);
void enable_irq(int irq);
```

### Disabling all interrupts

```c
#include <asm/system.h>

void local_irq_save(unsigned long flags);
void local_irq_disable(void);

void local_irq_restore(unsigned long flags);
void local_irq_enable(void);
```

# Top and Bottom Halves

The big difference between the top-half handler and the bottom half is that all interrupts are enabled during execution of the bottom half

The Linux kernel has two different machanisms that may be uesd to implement bottom-half processing,both of which were introduced in Chapter 7,Tasklets are often the preferred mechanism for bottom-half processing;they are very fast,but all tasklet code must be atomic,The alternative to tasklets is workqueues,which may have a higher latency but that are allowed to sleep.

### Tasklets

Remember that tasklets are a special function that may be scheduled to run,in software interrupt context,at a system-determined safe time.

Tasklets also guaranteed to run on the same CPU as the funcion that first schedules them.

Tasklets must be declared with the DECLARE_TASKLET macro:

```c
DECLARE_TASKLET(name,function,data)
```

The function tasklet_schedule is used to schedule a tasklet for running.

eg:
```c
void short_do_tasklet(unsigned long);
DECLARE_TASKLET(short_tasklet,short_do_tasklet,0);

tasklet_schedule(&short_tasklet);
```

### workqueues

Recall that workqueues invoke a function at some future time in the context of a special worker process.Since the workqueue function runs in process context,it can sleep if need be.

```c
struct work_struct short_wq;

INIT_WORK(&short_wq,(void (*)(void*))short_do_workqueue,NULL);

schedule_work(&short_wq);
```