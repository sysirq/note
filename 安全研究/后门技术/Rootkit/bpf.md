![image.png](images/WEBRESOURCE19769019c37efea4aef2e7ea6c7783e6image.png)


# ebpf MAP

BPF Map本质上是以「键/值」方式存储在内核中的数据结构

### Hash Maps

- `BPF_MAP_TYPE_HASH`：初始化时需要指定**支持的最大条目数**（max_entries）。 满了之后继续插入数据时，会报 `E2BIG` 错误。
- `BPF_MAP_TYPE_PERCPU_HASH`
- `BPF_MAP_TYPE_LRU_HASH`：普通 hash map 的问题是有大小限制，超过最大数量后无法再插入了。LRU map 可以避 免这个问题，如果 map 满了，再插入时它会自动将**最久未被使用（least recently used）**的 entry 从 map 中移除。`
- `BPF_MAP_TYPE_LRU_PERCPU_HASH`
- `BPF_MAP_TYPE_HASH_OF_MAPS`:**第一个 map 内的元素是指向另一个 map 的指针**

内核中用链表实现

### Array Maps

- `BPF_MAP_TYPE_ARRAY`:**key 就是数组中的索引（index）**（因此 key 一定 是整形），因此无需对 key 进行哈希。
- `BPF_MAP_TYPE_PERCPU_ARRAY`
- `BPF_MAP_TYPE_PROG_ARRAY`
- `BPF_MAP_TYPE_PERF_EVENT_ARRAY`
- `BPF_MAP_TYPE_ARRAY_OF_MAPS`
- `BPF_MAP_TYPE_CGROUP_ARRAY`

### 创建

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);  // BPF map 类型
    __type(key, __be32);              // 
    __type(value, struct pair);       // 
    __uint(max_entries, 1024);        // 最大 entry 数量
} hash_map SEC(".maps");
```

### 操作（BPF object 与 Userspace program使用的函数）

- bpf_map_lookup_elem：通过key查询BPF Map，得到对应value（内核空间与用户空间都能使用）
- bpf_map_update_elem：通过key-value更新BPF Map，如果这个key不存在，也可以作为新的元素插入到BPF Map中去（内核空间与用户空间都能使用）
```c
//最后一个参数可选如下三个参数：
#define BPF_ANY 0//如果key已经存在，则更新对应的value，如果key不存在就创建新的key-value
#define BPF_NOEXIST 1//只要key对应的在map里还不存在，则创建新的key-value，否则返回出错
#define BPF_EXIST 2//查找key指定的key-value，并更新，否则返回出错
```
- bpf_map_get_next_key：这个函数可以用来遍历BPF Map（只能在用户空间程序调用）
- bpf_map_delete_elem:：元素删除（内核空间与用户空间都能使用）

# 函数签名

### BPF_PROG_TYPE_TRACEPOINT

对于系统调用 可以通过 

```c
root@debian:/home/sysirq# cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_getdents64/format
name: sys_enter_getdents64
ID: 773
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:unsigned int fd;	offset:16;	size:8;	signed:0;
	field:struct linux_dirent64 * dirent;	offset:24;	size:8;	signed:0;
	field:unsigned int count;	offset:32;	size:8;	signed:0;

print fmt: "fd: 0x%08lx, dirent: 0x%08lx, count: 0x%08lx", ((unsigned long)(REC->fd)), ((unsigned long)(REC->dirent)), ((unsigned long)(REC->count))
root@debian:/home/sysirq# 
```

查看到函数签名:

```c
/**
 * >> cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_getdents64/format
 */
struct sys_getdents64_enter_ctx {
    unsigned long long unused;
    int __syscall_nr;
    unsigned int padding;
    unsigned int fd;
    struct linux_dirent64 *dirent;
    unsigned int count;
};

SEC("tp/syscalls/sys_enter_getdents64")
int tp_sys_enter_getdents64(struct sys_getdents64_enter_ctx *ctx){
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    if(pid_tgid<0){
        //bpf_printk("Out\n");
        return -1;
    }
    return handle_tp_sys_enter_getdents64(ctx, pid_tgid);
}
```

# ebpf调试

```c
bpf_printk()
```

输出：
```
cat /sys/kernel/debug/tracing/trace
```

# 简单epbf程序

环境安装：

```sh
apt install clang gcc-multilib libbpf-dev m4 linux-headers-$(uname -r)
```

传入参数：struct pt_regs *ctx

这个变量内的很多字段是平台相关的，但也有一些通用函数，例如 regs_return_value(regs)，返回的是存储程序返回值的寄存器内的值（x86 上对应的是 ax 寄存器）。

prog1.c:

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h>


#define __TARGET_ARCH_x86
#include <bpf/bpf_tracing.h>

struct event {
    int pid;
    char comm[64];
    char filename[256];
};

struct {
    __uint(type,BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries,256*1024);
}ringbuf SEC(".maps");

SEC("kprobe/do_sys_openat2")
int kprobe_do_sys_open(struct pt_regs *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid();
    struct event *evt = bpf_ringbuf_reserve(&ringbuf,sizeof(struct event),0);
    if(!evt){
        bpf_printk("bpf_ringbuf_reserve failed");
        return 1;
    }
    char *filename = (char *)PT_REGS_PARM2(ctx);//参数获取

    evt->pid = pid;
    bpf_get_current_comm(evt->comm,sizeof(evt->comm));
    bpf_probe_read_user(evt->filename, sizeof(evt->filename), filename);
    bpf_ringbuf_submit(evt,0);
    return 0;
}

char _licensep[] SEC("license") = "GPL";
```

loader.c:

```sh
#include <stdio.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

struct event {
    int pid;
    char comm[64];
    char filename[256];
};

static int event_logger(void *ctx,void *data,size_t len)
{
    struct event *evt = (struct event *)data;
    printf("PID: %d , COMM: %s , Filename: %s \n",evt->pid,evt->comm,evt->filename);
    return 0;
}

int main()
{
    const char *filename = "prog1.o";
    const char *progname = "kprobe_do_sys_open";
    const char *mapname  = "ringbuf";
    struct bpf_object *bpfObject = bpf_object__open(filename);

    if(!bpfObject){
        printf("Failed to open %s\n",filename);
        return 1;
    }

    int err = bpf_object__load(bpfObject);
    if(err){
        printf("Failed to load %s\n",filename);
        return 1;
    }

    struct bpf_program* bpfProg = bpf_object__find_program_by_name(bpfObject,progname);
    if(!bpfProg){
        printf("Failed to find %s\n",progname);
        return 1;
    }

    int rbFd = bpf_object__find_map_fd_by_name(bpfObject,mapname);
    struct ring_buffer *ringBuffer = ring_buffer__new(rbFd,event_logger,NULL,NULL);
    if(!ringBuffer){
        printf("Failed to create ring buffer\n");
        return 1;
    }

    bpf_program__attach(bpfProg);
    while(1){
        ring_buffer__consume(ringBuffer);
    }

    return 0;
}
```

makefile:

```makefile
all:
	clang -O2 -g -target bpf -c prog1.c -o prog1.o
	clang -O2 -g -Wall -I/usr/include -I/usr/include/bpf -lbpf -o loader loader.c
clean:
	rm -rf loader prog1.o
```



Output:

![image-20240521204641633](images/image-20240521204641633.png)

### 参考资料

Tracing System Calls Using eBPF - Part 1

https://falco.org/blog/tracing-syscalls-using-ebpf-part-1/


# XDP

开发环境准备：

```
apt install xdp-tools libxdp-dev
```

XDP 程序执行时 skb 都还没创建，开销非常低，因此效率非常高。适用于 DDoS 防御、四层负载均衡等场景。

禁止 ping 该机器

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <linux/ip.h>


SEC("xdp_drop")
int icmp_drop_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    __u16 h_proto;

    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_DROP;

    h_proto = eth->h_proto;

    if (h_proto == htons(ETH_P_IP)){
        struct iphdr *ip = (struct iphdr*)((char*)data +sizeof(struct ethhdr));
        if( (void*)((char *)ip + sizeof(struct iphdr)) > data_end){
            return XDP_DROP;
        }

        if(ip->protocol ==  IPPROTO_ICMP){
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

编译：

```sh
clang -O2 -g -target bpf -c prog1.c -o prog1.o
```

加载：

```
xdp-loader load -m skb -s xdp_drop ens3 prog1.o
```

卸载：

```
xdp-loader unload -a ens3
```



### 自定义Loader

丢弃进入的ICMP包,并统计

prog1.c

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <linux/ip.h>

struct {
    __uint(type,BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key,__u32);
    __type(value,long);
    __uint(max_entries,1);
}rxcnt SEC(".maps");

SEC("xdp_drop_icmp")
int xdp_drop_icmp_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    __u16 h_proto;
    __u32 key = 0;
    long *value;
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_DROP;

    h_proto = eth->h_proto;

    if (h_proto == htons(ETH_P_IP)){
        struct iphdr *ip = (struct iphdr*)((char*)data +sizeof(struct ethhdr));
        if( (void*)((char *)ip + sizeof(struct iphdr)) > data_end){
            return XDP_DROP;
        }

        if(ip->protocol ==  IPPROTO_ICMP){
            value = bpf_map_lookup_elem(&rxcnt,&key);
            if(value){
                *value += 1;
            }
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

loader.c

```c
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#include <stdio.h>
#include <net/if.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>

static int ifindex;
struct xdp_program *prog = NULL;

/* This function will remove XDP from the link when the program exits. */
static void int_exit(int sig)
{
    xdp_program__detach(prog,ifindex,XDP_MODE_SKB,0);
    xdp_program__close(prog);
    exit(0);
}

/* This function will count the per-CPU number of packets and print out
 * the total number of dropped packets number and PPS (packets per second).
 */
static void poll_stats(struct bpf_map *map, int interval)
{
    int ncpus = libbpf_num_possible_cpus();
    if(ncpus < 0){
        printf("Error get possible cpus\n");
        return;
    }
    long values[ncpus],prev[ncpus],total_pkts = 0;
    int i;
    __u32 key = 0;

    memset(prev,0,sizeof(prev));

    while(1){
        long sum = 0;

        sleep(interval);
        assert(bpf_map__lookup_elem(map,&key,sizeof(key),values,sizeof(values),0) == 0);
        for(i = 0;i<ncpus;i++){
            sum += (values[i] - prev[i]);
        }
        if(sum){
            total_pkts += sum;
            printf("total dropped %10lu, %10lu pkt/s\n",
                   total_pkts, sum / interval);
        }
        memcpy(prev, values, sizeof(values));
    }
}

int main(int argc,char *argv[])
{
    int ret;
    struct bpf_map *map;
    struct bpf_object *bpf_obj;
    if(argc != 2){
        printf("Usage: %s IFNAME\n",argv[0]);
        return 1;
    }

    ifindex = if_nametoindex(argv[1]);
    if(ifindex == 0){
        perror("get ifinde from interface name failed\n");
        return 1;
    }
    printf("ifindex: %d\n",ifindex);

    /*load XDP object by libxdp*/
    prog = xdp_program__open_file("prog1.o","xdp_drop_icmp",NULL);
    if(!prog){
        printf("Error,load xdp prog failed\n");
        return 1;
    }
    /* attach XDP program to interface with skb mode
     * Please set ulimit if you got an -EPERM error.
    */
    ret = xdp_program__attach(prog,ifindex,XDP_MODE_SKB,0);
    if(ret){
        printf("Error,set xdp fd on %d failed\n",ifindex);
        return ret;
    }

    bpf_obj = xdp_program__bpf_obj(prog);
    map = bpf_object__find_map_by_name(bpf_obj,"rxcnt");
    if(map == NULL){
        printf("Error, get map from bpf obj failed\n");
        return -1;
    }

    /* Remove attached program when it is interrupted or killed */
    signal(SIGINT, int_exit);
    signal(SIGTERM, int_exit);

    poll_stats(map,2);

    return 0;
}
```

Makefile:

```makefile
all:
	clang -O2 -g -target bpf -c prog1.c -o prog1.o
	clang -O2 -g -Wall -I/usr/include -I/usr/include/bpf -lbpf -lxdp -o loader loader.c
clean:
	rm -rf loader prog1.o
```

### 参考资料

Get started with XDP

https://developers.redhat.com/blog/2021/04/01/get-started-with-xdp

xdp-tutorial

https://github.com/xdp-project/xdp-tutorial

# TC

它的位置已经完成了sk_buff的分配，比xdp晚。



统计到该主机的TCP连接（源地址、源端口）



prog1.c

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <netinet/in.h>
#include <linux/pkt_cls.h>

struct {
    __uint(type,BPF_MAP_TYPE_LRU_HASH);
    __type(key,__u32);
    __type(value,__u16);
    __uint(max_entries,1024);
}hash_map SEC(".maps");

SEC("tc")
int tc_ingress_prog(struct __sk_buff *ctx)
{
    void *data_end = (void*)(__u64)ctx->data_end;
    void *data = (void*)(__u64)ctx->data;

    struct ethhdr *l2;
    struct iphdr *l3;
    struct tcphdr *l4;

    if(ctx->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    l2 = data;
    if((void*)(l2+1) > data_end )
        return TC_ACT_OK;
    
    l3 = (struct iphdr*)(l2+1);
    if((void*)(l3+1) > data_end || l3->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    l4 = (struct tcphdr*)(l3+1);
    if((void*)(l4+1) > data_end)
        return TC_ACT_OK;
    
    __u32 key = l3->saddr;
    __u16 *value = (__u16*)bpf_map_lookup_elem(&hash_map,&key);
    if(value == NULL){
        __u16 v = (__u16)l4->source;
        bpf_map_update_elem(&hash_map,&key,&v,BPF_NOEXIST);
    }else{
        *value = l4->source;
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
```



loader.c:

```c
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>

int exiting = 0;

static void int_exit(int sig)
{
    exiting = 1;
}

static int load_egress_program(const char *ifname) {
    struct bpf_object *obj;
    int prog_fd, err;
    int ifindex;
    struct bpf_map *map;

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        perror("if_nametoindex");
        return 1;
    }

    obj = bpf_object__open_file("prog1.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        return 1;
    }

    prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "tc_ingress_prog"));
    if (prog_fd < 0) {
        fprintf(stderr, "ERROR: finding egress program in BPF object failed\n");
        return 1;
    }

    map = bpf_object__find_map_by_name(obj,"hash_map");
    if(map == NULL){
        printf("Error, get map from bpf obj failed\n");
        return -1;
    }

    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,.attach_point = BPF_TC_INGRESS);
    hook.ifindex = ifindex;
    err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST) {
        fprintf(stderr, "ERROR: creating TC hook failed: %d\n", err);
        return 1;
    }

    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .handle = 1, .priority = 1, .prog_fd = prog_fd);
    err = bpf_tc_attach(&hook, &opts);
    if (err) {
        fprintf(stderr, "ERROR: attaching BPF program failed: %d\n", err);
        return 1;
    }

    printf("Successfully attached BPF program to %s\n", ifname);
    
    signal(SIGINT, int_exit);
    signal(SIGTERM, int_exit);

    while( exiting == 0 ){
        
        sleep(1);
        printf("========================================================================\n");
        __u32 key = 0;
        __u32 prev_key = 0;
        __u16 value;
        if(bpf_map__get_next_key(map,NULL,&key,sizeof(__u32)) != 0)
            continue;

        do{

            if( bpf_map__lookup_elem(map,&key,sizeof(key),&value,sizeof(value),0) == 0 ){
                printf("ip:%d.%d.%d.%d port: %d \n",((uint8_t*)&key)[0],((uint8_t*)&key)[1],((uint8_t*)&key)[2],((uint8_t*)&key)[3],ntohs(value));
            }

            prev_key = key;
        }while(bpf_map__get_next_key(map,&prev_key,&key,sizeof(__u32)) == 0);

    }

    bpf_tc_detach(&hook,&opts);
    bpf_tc_hook_destroy(&hook);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    return load_egress_program(argv[1]);
}
```

makefile

```makefile
all:
	clang -O2 -g -target bpf -c prog1.c -o prog1.o
	clang -O2 -g -Wall -I/usr/include -I/usr/include/bpf -lbpf -o loader loader.c
clean:
	rm -rf loader prog1.o
```

### 资料

eBPF Tutorial by Example 20: tc Traffic Control

https://eunomia.dev/tutorials/20-tc/

你的第一个TC BPF 程序

https://davidlovezoe.club/wordpress/archives/952

libbpf-bootstrap开发指南：网络包监测-tc

https://blog.csdn.net/qq_32378713/article/details/131751988

# BTF CO-RE

```sh
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

### Reading kernel data

this will records CO-RE relocation information

- bpf_core_read()

```c
struct task_struct *task = (void *)bpf_get_current_task();
struct task_struct *parent_task;
int err;

err = bpf_core_read(&parent_task, sizeof(void *), &task->parent);
if (err) {
    /* handle error */
}

/* parent_task contains the value of task->parent pointer */
```

- bpf_core_read_str()

```c
struct my_kernel_type {
    const char *name;
    char type[32];
};


struct my_kernel_type *t = ...;
const char *p;
char str[32];

/* get string pointer, CO-RE-relocatable */
bpf_core_read(&p, sizeof(p), &t->name);
/* read the string, non-CO-RE-relocatable, pointer is valid regardless */
bpf_probe_read_kernel_str(str, sizeof(str), p);



char str[32];

/* read string as CO-RE-relocatable */
bpf_core_read_str(str, sizeof(str), &t->type);
```

- BPF_CORE_READ()

```c
/* direct pointer dereference */
name = t->mm->exe_file->fpath.dentry->d_name.name;

/* using BPF_CORE_READ() helper */
name = BPF_CORE_READ(t, mm, exe_file, fpath.dentry, d_name.name);
```

- BPF_CORE_READ_INTO()

```c
struct task_struct *t = ...;
const char *name;
int err;

err = BPF_CORE_READ_INTO(&name, t, mm, binfmt, executable, fpath.dentry, d_name.name);
if (err) { /* handle errors */ }
/* now `name` contains the pointer to the string */
```

- BPF_CORE_READ_STR_INTO()

### BTF-enabled BPF program types with direct memory reads

- BTF-enabled raw tracepoint (SEC("tp_btf/...") in libbpf lingo);
- fentry/fexit/fmod_ret BPF programs;

### Reading bitfields and integers of varying sizes

- BPF_CORE_READ_BITFIELD()
- BPF_CORE_READ_BITFIELD_PROBED()

### LINUX_KERNEL_VERSION

```c
#include <bpf/bpf_helpers.h>

extern int LINUX_KERNEL_VERSION __kconfig;

...

if (LINUX_KERNEL_VERSION > KERNEL_VERSION(5, 15, 0)) {
    /* we are on v5.15+ */
}
```

```c
extern u32 LINUX_KERNEL_VERSION __kconfig;
extern u32 CONFIG_HZ __kconfig;

u64 utime_ns;

if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(4, 11, 0))
    utime_ns = BPF_CORE_READ(task, utime);
else
    /* convert jiffies to nanoseconds */
    utime_ns = BPF_CORE_READ(task, utime) * (1000000000UL / CONFIG_HZ);
```

### struct flavors

```c
/* up-to-date thread_struct definition matching newer kernels */
struct thread_struct {
    ...
    u64 fsbase;
    ...
};

/* legacy thread_struct definition for <= 4.6 kernels */
struct thread_struct___v46 { /* ___v46 is a "flavor" part */
    ...
    u64 fs;
    ...
};

extern int LINUX_KERNEL_VERSION __kconfig;
...

struct thread_struct *thr = ...;
u64 fsbase;
if (LINUX_KERNEL_VERSION > KERNEL_VERSION(4, 6, 0))
    fsbase = BPF_CORE_READ((struct thread_struct___v46 *)thr, fs);
else
    fsbase = BPF_CORE_READ(thr, fsbase);
```

### 根据用户提供的配置改变行为

main.bpf.c:

```c
const bool use_fancy_helper;
const u32 fallback_value;

...

u32 value;
if (use_fancy_helper)
    value = bpf_fancy_helper(ctx);
else
    value = bpf_default_helper(ctx) * fallback_value;
```

main.c：

```c
	skel = main_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}
	skel->rodata->use_fancy_helper = true;
	skel->rodata->fallback_value = 10;
	err = main_bpf__load(skel);
```

### 有用的函数

- bpf_core_enum_value_exists()
- bpf_core_field_exists()
- bpf_core_type_exists()
- bpf_core_type_size()
- bpf_core_field_size()
- bpf_core_enum_value

### 开发流程

- 目录结构

```
bpf/
libbpf/
src/
tools/
Makefile
```

- 切换到工作目录

下载libbpf做为子模块,并编译

```sh
git submodule add https://github.com/libbpf/libbpf.git

make -C libbpf/src BUILD_STATIC_ONLY=1 DESTDIR=$(pwd)/bpf install
```

此时会生成libbpf 与 bpf 目录

- 切换到src目录

生成vmlinux.h

```sh
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

hello_world.bpf.c:

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

SEC("raw_tp/pelt_se_tp")
int BPF_PROG(handle_pelt_se, struct sched_entity *se)
{
	int cpu = BPF_CORE_READ(se, cfs_rq, rq, cpu);

	bpf_printk("[%d] Hello world!", cpu);
	return 0;
}
```

hello_world.c

```c
#include <bpf/libbpf.h>
#include <signal.h>
#include <stdio.h>

#include "hello_world.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

int main(int argc, char **argv)
{
	struct hello_world_bpf *skel;
	int err;

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = hello_world_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	err = hello_world_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	err = hello_world_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	while (!exiting);

cleanup:
	hello_world_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
```

Makefile:

```makefile
CC = clang
CFLAGS_EBPF = -g -O2 -Wall -target bpf
CFLAGS_EXEC = -g -O2 -Wall
INCLUDES = -I bpf/usr/include 

STATIC_LIB = bpf/usr/lib64/libbpf.a

EXECSOURCES = src/hello_world.c
EXECOBJS = $(EXECSOURCES:.c=.o)

EBPFSOURCES = src/hello_world.bpf.c
EBPFOBJS = $(EBPFSOURCES:.c=.o)
EBPFSKEL = $(EBPFSOURCES:.bpf.c=.bpf.skel.h)

TARGET = hello_world

all:$(TARGET)

$(TARGET) : $(EBPFSKEL) $(EXECOBJS) 
	$(CC) -static $(CFLAGS_EXEC) $(INCLUDES) $(EXECOBJS) $(STATIC_LIB) -lelf -lz  -o $@

src/%.o:src/%.c
	$(CC) $(CFLAGS_EXEC) $(INCLUDES) -c $< -o $@

src/%.bpf.skel.h:src/%.bpf.o
	sudo bpftool gen skeleton $< > $@

src/%.bpf.o:src/%.bpf.c
	$(CC) $(CFLAGS_EBPF) $(INCLUDES) -c $< -o $@

	
clean:
	rm -rf $(TARGET) $(EBPFOBJS) $(EBPFSKEL) $(EXECOBJS)
```



### 资料

BPF CO-RE (Compile Once – Run Everywhere)

https://nakryiko.com/posts/bpf-portability-and-co-re/

BPF CO-RE reference guide

https://nakryiko.com/posts/bpf-core-reference-guide/

BPF CO-RE的探索与落地

https://www.strickland.cloud/post/1

Intro to BPF CO-RE

https://layalina.io/2022/04/23/intro-to-bpf-co-re.html

# ebpf有用的helper函数

```
bpf_get_current_comm （获取进程命 task_struct -> comm）
```

# ebpf rootkit 原理

ebpf没法修改系统调用的参数与返回值，也无法修改内核数据结构，但是他可以通过两个函数：

- `bpf_probe_read_user` 

- `bpf_probe_write_user`.

修改用户空间的数据。

结合起来，在用户空间和内核之间有选择地更改数据的能力是一种强大的攻击性原语，可以有广泛的可能用途。

# 修改文件

![Picture highlighting how eBPF can intercept paramaters and return codes from syscalls](images/syscall_flow_03.png)

# 隐藏进程与文件

通过隐瞒/proc/伪文件夹的内容来隐藏进程



原理：

getdents, getdents64 - get directory entries 

修改getdents返回的 struct linux_dirent 结构，跳过要隐藏的文件



```c
SEC("tp/syscalls/sys_enter_getdents64")
int handle_getdents_enter(struct trace_event_raw_sys_enter *ctx)

SEC("tp/syscalls/sys_exit_getdents64")
int handle_getdents_exit(struct trace_event_raw_sys_exit *ctx)
```





# 劫持执行

当程序调用execve时更改可执行文件的文件路径，使其为恶意程序的路径，然后把原始execve的参数传递给恶意程序，然后恶意程序在启动原始程序，避免用户察觉。

# 假装系统调用

```c
// Attach to the 'write' syscall
SEC("fmod_ret/__x64_sys_write")
int BPF_PROG(fake_write, struct pt_regs *regs)
{
    // Get expected write amount
    u32 count = PT_REGS_PARM3(regs);

    // Overwrite return
    return count;
}
```

# 资料

Linux中基于eBPF的恶意利用与检测机制

https://www.cnxct.com/evil-use-ebpf-and-how-to-detect-ebpf-rootkit-in-linux/

DEF CON 29: Bad BPF - Warping reality using eBPF

https://blog.tofile.dev/2021/08/01/bad-bpf.html

Abusing eBPF to build a rootkit

https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-With-Friends-Like-EBPF-Who-Needs-Enemies.pdf

ebpf-slide

https://github.com/gojue/ebpf-slide

bpf.h

https://github.com/torvalds/linux/blob/0c0ddd6ae47c9238c18f475bcca675ca74c9dc31/include/uapi/linux/bpf.h

ebpfkit

https://github.com/Gui774ume/ebpfkit

TripleCross

https://github.com/h3xduck/TripleCross

bad-bpf

https://github.com/pathtofile/bad-bpf

BPF 进阶笔记（二）：BPF Map 类型详解：使用场景、程序示例

http://arthurchiao.art/blog/bpf-advanced-notes-2-zh/

eBPF 开发实践教程：基于 CO-RE，通过小工具快速上手 eBPF 开发

https://eunomia.dev/zh/tutorials/