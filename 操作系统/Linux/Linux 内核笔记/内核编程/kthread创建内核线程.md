```c
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/delay.h>

#define MAX_KTHREADS 10

static struct task_struct *threads[MAX_KTHREADS];

static int do_thread(void *data)
{
	int id = (int)data;
	int i = 0;

	while(!kthread_should_stop()){
		msleep(1000);
		printk("thread_id:%d time:%d\n",id,i++);
	}
	return 0;
}

static int create_threads(void)
{
	int i;
	struct task_struct *thread;
	for(i = 0;i<MAX_KTHREADS;i++){
		thread = kthread_run(do_thread,(void*)(i),"thread-%d",i);
		if(IS_ERR(thread)) return PTR_ERR(thread);
		threads[i] = thread;
	}

	return 0;
}

static void destroy_threads(void)
{
	int i;
	for(i = 0;i<MAX_KTHREADS;i++){
		if(threads[i])
			kthread_stop(threads[i]);
	}
}

static int __init kthread_example_init(void)
{
	printk("call %s\n",__func__);
	if(create_threads() != 0) goto err;
	return 0;
err:
	destroy_threads();
	return -1;
}

static void __exit kthread_example_exit(void)
{
	printk("call %s\n",__func__);
	destroy_threads();
}

module_init(kthread_example_init);
module_exit(kthread_example_exit);
MODULE_LICENSE("GPL");
```

mdelay:会占用CPU资源，导致其他功能（时间中断--》调度）此时无法使用CPU资源

msleep:不会占用CPU资源，其他模块此时也可以使用CPU资源。

thread_run：创建内核线程并允许

thread_stop：停止内核线程，前提是该内核线程未退出

thread_should_stop：接受thread_stop发出的停止消息