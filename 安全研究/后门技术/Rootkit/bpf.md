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

