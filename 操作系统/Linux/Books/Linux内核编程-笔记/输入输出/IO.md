# 总线
分类：

    地址总线
    
    数据总线
    
    控制总线

# 外围设备
北桥：连接高速、高性能的外围设备

南桥：连接低速设备

# IO访问方式
内存映射IO

短裤映射IO

# 设备分类
字符设备

块设备

网络设备

时钟设备

终端设备

# 块设备写过程（读类似）

应用程序层(调用fopen、fread)=>

文件系统层（加入请求队列）=>

通用块设备层（请求队列实用程序）=>

设备=>

# 请求队列

# IO调度算法
空操作I/O调度程序

最后期限调度程序

预期I/O调度程序

# 简单字符设备驱动

```c
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/device.h>

#define DEV_NAME "hello"

struct class *hello_class;
struct device *hello_device;
int Major = 0;

int hello_open(struct inode *pinode,struct file *pfile){
	printk("hello_open() done!");
	return 0;
}

int hello_close(struct inode *pinode,struct file *pfile){
	printk("hello_close() done!");
	return 0;
}

struct file_operations hello_fops = {
	.open = hello_open,
	.release = hello_close
};

static int __init myInit(void){
	int retval = register_chrdev(Major,DEV_NAME,&hello_fops);
	if(retval < 0){
		printk("hello: can't register\n");
		return retval;
	}
	else{
		Major = retval;
		printk("hello:registered,Major=%d\n",Major);
		
		hello_class = class_create(THIS_MODULE,DEV_NAME);
		
		hello_device = device_create(hello_class,NULL,MKDEV(Major,0),NULL,DEV_NAME);
	}
	return 0;
}

static void __exit myExit(void){
	device_destroy(hello_class,MKDEV(Major,0));
	class_destroy(hello_class);
	unregister_chrdev(Major,DEV_NAME);
	printk("Bye,Hello\n");
}

module_init(myInit);
module_exit(myExit);
MODULE_LICENSE("GPL");
```