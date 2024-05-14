```c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/types.h>

#define KPROBE_HASH_BITS 6
#define KPROBE_TABLE_SIZE (1 << KPROBE_HASH_BITS)

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

struct mutex *p_kprobe_mutex = NULL;
struct hlist_head *p_kprobe_table = NULL;
struct hlist_head orig_kprobe_table[KPROBE_TABLE_SIZE];

static void traverse_kprobe_table(void)
{
    struct hlist_head *head;
	struct kprobe *p;
	unsigned int i;

    mutex_lock(p_kprobe_mutex);
    for (i = 0; i < KPROBE_TABLE_SIZE; i++) {
        head = p_kprobe_table + i;
        hlist_for_each_entry_rcu(p, head, hlist){
            printk("kprobe name :%s\n",p->symbol_name);
        }
    }
    mutex_unlock(p_kprobe_mutex);
}

static void backup_and_reset_kprobe_table(void)
{
    int i = 0;

    mutex_lock(p_kprobe_mutex);
    
    memcpy(orig_kprobe_table,p_kprobe_table,sizeof(orig_kprobe_table));
    for (i = 0; i < KPROBE_TABLE_SIZE; i++) {
        INIT_HLIST_HEAD(p_kprobe_table + i);
    }
    
    mutex_unlock(p_kprobe_mutex);
}

static void restore_kprobe_table(void)
{
    mutex_lock(p_kprobe_mutex);
    
    memcpy(p_kprobe_table,orig_kprobe_table,sizeof(orig_kprobe_table));
    
    mutex_unlock(p_kprobe_mutex);
}

static int __init hello_init(void)
{
    printk("hello init\n");
    init_ksymbol();

    p_kprobe_mutex = (struct mutex*)my_kallsyms_lookup_name("kprobe_mutex");
    if(p_kprobe_mutex == NULL){
        printk("get kprobe mutex error\n");
        return -1;
    }

    p_kprobe_table = (struct hlist_head *)my_kallsyms_lookup_name("kprobe_table");
    if(p_kprobe_table == NULL){
        printk("get kprobe table error\n");
        return -1;
    }

    printk("===================init==========================\n");
    traverse_kprobe_table();

    
    backup_and_reset_kprobe_table();

    printk("===================reset==========================\n");
    traverse_kprobe_table();

    restore_kprobe_table();

    printk("===================restore========================\n");
    traverse_kprobe_table();

    return 0;
}

static void __exit hello_exit(void)
{
    printk("hello exit\n");
}

module_init(hello_init);
module_exit(hello_exit);
MODULE_LICENSE("GPL");
```

