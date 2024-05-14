注意 may_open 和 vfs_statx 要根据内核版本调整

may_open_isra 是直接传值（isra后缀）

```c
#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/namei.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/fcntl.h>

static const char *protect_dir_paths[] = {"/tmp/space/"};
static const char *not_alloc_progs[] = {"cat"};

static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"};
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t my_kallsyms_lookup_name;
static void init_ksymbol(void)
{

    register_kprobe(&kp);
    my_kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
#define FTRACE_OPS_FL_RECURSION FTRACE_OPS_FL_RECURSION_SAFE
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
#define ftrace_regs pt_regs

static __always_inline struct pt_regs *ftrace_get_regs(struct ftrace_regs *fregs)
{
    return fregs;
}
#endif

/*
 * There are two ways of preventing vicious recursive loops when hooking:
 * - detect recusion using function return address (USE_FENTRY_OFFSET = 0)
 * - avoid recusion by jumping over the ftrace call (USE_FENTRY_OFFSET = 1)
 */
#define USE_FENTRY_OFFSET 0

/**
 * struct ftrace_hook    describes the hooked function
 *
 * @name:           the name of the hooked function
 *
 * @function:       the address of the wrapper function that will be called instead of
 *                     the hooked function
 *
 * @original:           a pointer to the place where the address
 *                     of the hooked function should be stored, filled out during installation of
 *             the hook
 *
 * @address:        the address of the hooked function, filled out during installation
 *             of the hook
 *
 * @ops:                ftrace service information, initialized by zeros;
 *                      initialization is finished during installation of the hook
 */
struct ftrace_hook
{
    const char *name;
    void *function;
    void *original;

    unsigned long address;
    struct ftrace_ops ops;
};

#define HOOK(_name, _function, _original) \
    {                                     \
        .name = (_name),                  \
        .function = (_function),          \
        .original = (_original),          \
    }

static int resolve_hook_address(struct ftrace_hook *hook)
{
    hook->address = my_kallsyms_lookup_name(hook->name);

    if (!hook->address)
    {
        printk("unresolved symbol: %s\n", hook->name);
        return -1;
    }

    *((unsigned long *)hook->original) = hook->address;

    return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                    struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
    struct pt_regs *regs = ftrace_get_regs(fregs);
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

    if (!within_module(parent_ip, THIS_MODULE))
        regs->ip = (unsigned long)hook->function;
}

static int fh_install_hook(struct ftrace_hook *hook)
{
    int err;

    err = resolve_hook_address(hook);
    if (err)
        return err;

    hook->ops.func = fh_ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY | FTRACE_OPS_FL_RECURSION;

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (err)
    {
        printk("ftrace_set_filter_ip() failed: %d\n", err);
        return err;
    }

    err = register_ftrace_function(&hook->ops);
    if (err)
    {
        printk("register_ftrace_function() failed: %d\n", err);

        /* Don’t forget to turn off ftrace in case of an error. */
        ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);

        return err;
    }

    return 0;
}

void fh_remove_hook(struct ftrace_hook *hook)
{
    int err;

    err = unregister_ftrace_function(&hook->ops);
    if (err)
    {
        printk("unregister_ftrace_function() failed: %d\n", err);
    }

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
    if (err)
    {
        printk("ftrace_set_filter_ip() failed: %d\n", err);
    }
}

// 0 allow
// -1 not allow
static int check_allow_access(char *path)
{
    int i;
    int path_hit = 0;
    int prog_hit = 0;
    if (!get_current())
        return -1;

    for (i = 0; i < ARRAY_SIZE(protect_dir_paths); i++)
    {
        if ((strlen(path) >= strlen(protect_dir_paths[i])) && (strncmp(path, protect_dir_paths[i], strlen(protect_dir_paths[i])) == 0))
        {
            path_hit = 1;
            break;
        }
    }

    for (i = 0; i < ARRAY_SIZE(not_alloc_progs); i++)
    {
        if ((strlen(get_current()->comm) >= strlen(not_alloc_progs[i])) && (strncmp(get_current()->comm, not_alloc_progs[i], strlen(not_alloc_progs[i])) == 0))
        {
            prog_hit = 1;
            break;
        }
    }

    if ((prog_hit == 1) && (path_hit == 1))
    {
        return -1;
    }
    else
    {
        return 0;
    }
}

static asmlinkage int (*real_may_open)(struct user_namespace *mnt_userns, struct path *path, int acc_mode, int flag);
static asmlinkage int fh_may_open(struct user_namespace *mnt_userns, struct path *path, int acc_mode, int flag)
{
    int ret;
    char buf[255] = {0};
    char *cp;

    cp = d_path(path, buf, 255);
    if (!IS_ERR(cp))
    {
        if ((check_allow_access(cp)) == 0)
        {
            ret = real_may_open(mnt_userns, path, acc_mode, flag);
        }
        else
        {
            ret = -ENOENT;
        }
    }
    else
    {
        ret = real_may_open(mnt_userns, path, acc_mode, flag);
    }

    return ret;
}

static asmlinkage int (*real_vfs_statx)(int dfd, const char __user *filename, int flags,
                                        struct kstat *stat, u32 request_mask);
static asmlinkage int fh_vfs_statx(int dfd, const char __user *filename, int flags, struct kstat *stat, u32 request_mask)
{
    int ret;
    int error;
    struct path path;
    char buf[255];
    char *cp;
    unsigned int lookup_flags = LOOKUP_FOLLOW | LOOKUP_AUTOMOUNT;

    error = user_path_at(dfd, filename, lookup_flags, &path);

    if (error)
    {
        ret = real_vfs_statx(dfd, filename, flags, stat, request_mask);
    }
    else
    {
        cp = d_path(&path, buf, 255);
        if (!IS_ERR(cp))
        {
            if ((check_allow_access(cp)) == 0)
            {
                ret = real_vfs_statx(dfd, filename, flags, stat, request_mask);
            }
            else
            {
                ret = -ENOENT;
            }
        }
        else
        {
            ret = real_vfs_statx(dfd, filename, flags, stat, request_mask);
        }
    }

    return ret;
}

static struct ftrace_hook hooked_functions[] = {
    HOOK("may_open", fh_may_open, &real_may_open),
    HOOK("vfs_statx", fh_vfs_statx, &real_vfs_statx),
};

static int __init hello_init(void)
{
    int i;
    printk("hello module init\n");

    init_ksymbol();

    for (i = 0; i < ARRAY_SIZE(hooked_functions); i++)
    {
        fh_install_hook(hooked_functions + i);
    }

    return 0;
}

static void __exit hello_exit(void)
{
    int i;
    printk("hello module exit\n");

    for (i = 0; i < ARRAY_SIZE(hooked_functions); i++)
    {
        fh_remove_hook(hooked_functions + i);
    }
}

module_init(hello_init);
module_exit(hello_exit);
MODULE_LICENSE("GPL");
```

