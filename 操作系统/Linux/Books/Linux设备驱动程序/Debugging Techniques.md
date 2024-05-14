# Debugging by Printing

printk lets you classify messages accoring to their severity by associating different loglevels.

There are eight possible loglevel strings,defined in the header linux/kernel.h; we list them in order of decreasing severity:

KERN_EMERG

KERN_ALERT

KERN_CRIT

KERN_ERR

KERN_WARNING

KERN_NOTICE

KERN_INFO

KERN_DEBUG

### Printng Device Numbers

```c
int print_dev_t(char *buffer,dev_t dev);

char *format_dev_t(char *buffer,dev_t dev);
```

# Using the /proc Filesystem (kernel version 2.6)

The /proc filesystem is a special,software-created filesystem that is used by the kernel to export information to the world.

### Implementing files in /proc

All modules that work with /proc should include linux/proc_fs.h to define the proper functions.

When a process reads from your /proc file,the kernel allocates a page of memory where the driver can write data to be returned to user space.That buffer is passed to your function,which is a method called read_proc:

```c
int (*read_proc)(char *page,char **start,off_t offset,int count,int *eof,void *data);
```

### Creating your /proc file

once you have a read_proc function defined,you need to connect it to an entry in the /proc hierarchy.This is done with a call to create_proc_read_entry:

```c
struct proc_dir_entry *create_proc_read_entry(const char *name,mode_t mode,struct proc_dir_entry *base,read_proc_t *read_proc,void *data);

remove_proc_entry(const char *name,NULL);
```
# Using the /proc Filesystem (kernel version 4.6)

We can create a proc entry using the function:

```c
static inline struct proc_dir_entry *proc_create(const char *name, umode_t mode,struct proc_dir_entry *parent, const struct file_operations *proc_fops);
```

The proc entry that was created will be removed in the exit function using remove_proc_entry.

```c
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kdev_t.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#define PROC_NAME "hello"
#define CAPACITY 100

struct buf{
	char *msg;
	int len;
	int capacity;
} my_buf;

ssize_t main_proc_read(struct file *filp,char *buf,size_t count,loff_t *offp);
ssize_t main_proc_write(struct file *filp,const char *buf,size_t count,loff_t *offp);

struct file_operations proc_fops = {
	.read = main_proc_read,
	.write = main_proc_write,
};

ssize_t main_proc_write(struct file *filp,const char *buf,size_t count,loff_t *offp)
{
	int remain_len = my_buf.capacity - my_buf.len;
	
	int len = count > remain_len ? remain_len:count;
	
	if(remain_len == 0) return -ENOMEM;

	copy_from_user(my_buf.msg + my_buf.len,buf,len);
	my_buf.len += len;
	return len;
}

ssize_t main_proc_read(struct file *filp,char *buf,size_t count,loff_t *offp)
{
	int len = count > my_buf.len ? my_buf.len:count;
	copy_to_user(buf,my_buf.msg,len);
	my_buf.len -= len;
	return len;
}

void create_new_proc_entry(void)
{
	proc_create(PROC_NAME,0,NULL,&proc_fops);
	my_buf.capacity = CAPACITY;
	my_buf.msg = kmalloc(CAPACITY,GFP_KERNEL);
	my_buf.len = 0;
}


static int __init main_init(void)
{
	printk("main init\n");
	create_new_proc_entry();
	return 0;
}

static void __exit main_exit(void)
{
	remove_proc_entry(PROC_NAME,NULL);
	kfree(my_buf.msg);
	printk("main exit\n");
}

module_init(main_init);
module_exit(main_exit);
MODULE_LICENSE("GPL");
```

link: http://tuxthink.blogspot.com/2017/03/creating-proc-read-and-write-entry.html

### The ioctl Method

# Debugging by Watching

strace receives information from the kernel itself.This means that a program can be traced regardless of whether or not it was compiled with debugging support and whether or not it is stripped.

the most useful of which are -t to display the time when each call is executed,-T to display the time spent in the call, -e to limit the types of call traced, and -o to redirect the output to a file.By default,strace prints tracing information on stderr.

# Debugging System Faults

Even though an oops usually does not bring down the entire system, you may well find yourself needing to reboot after one happens.

### Oops Message

An oops displays the processor status at the time of the fault,including the contents of the CPU registers and other seemingly incomprehensible information.

http://www.cnblogs.com/wwang/archive/2010/11/14/1876735.html

#### Magic SysRq key

Magic SysRq is invoked with the combination of the Alt and SysRq keys on the PC keyboard,

r Turns off keyboard raw mode;

k Invokes the "secure attention key" function

s Performs an emergency synchronization of all disks

u Unmount.Attempts to remount all disks in a read-only mode.

b Immediately reboots the system.

p Prints processor registers information

t Prints the current task list

m Prints memory information

link:https://www.ibm.com/developerworks/cn/linux/l-cn-sysrq/index.html

# Debuggers and Related Tools

### Using gdb

```
gdb /usr/src/linux/vmlinux /proc/kcore
```

The first argument is the name of the uncompressed ELF kernel executable,not the zImage or bzImage. The second argument on the gdb command line is the name of the core file.

Issue the command core-file /proc/kcore whenever you want to flush the gdb cache;

however,always need to issue core-file when reading a new datum.

### The kdb Kernel Debugger

### The kgdb Patches