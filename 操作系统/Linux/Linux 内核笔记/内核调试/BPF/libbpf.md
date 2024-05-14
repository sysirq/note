# 0x00

```
apt install clang gcc-multilib libbpf-dev m4 linux-headers-$(uname -r)
```

# Ring buffers

eBPF ring buffer, also known as bpf_ringbuf, is a mechanism provided by the Linux kernel for efficient communication between eBPF programs and user-space programs.

It allows the exchange of data and events between eBPF programs running in the kernel and user-space applications. It is a MPSC (Multi Producer Single Consumer) queue and can be safely shared across multiple CPUs simultaneously.

Let's have a look at a few functions that we'll be using to write an eBPF program that sends data to userspace.

```c
//This function is used to reserve size bytes of space in a BPF ring buffer.
void *bpf_ringbuf_reserve(void *ringbuf,u64 size,u64 flags);

//This function is used to read a null terminated string from user-space memory into the destination dst
//The dst parameter is a pointer to the destination buffer in the kernel 
//space. unsafe_ptr is a pointer to the source string in the user-space.
static long(*bpf_probe_read_user_str)(void *dst,unsigned int size,const void *unsafe_ptr);

//This function is used to submit data that had previously been reserved in a ringbuf
static void (*bpf_ringbuf_submit)(void *data,unsigned long long flags);

//This function is used to find the file descriptor of a named map.
int bpf_object__find_map_fd_by_name (const struct bpf_object *obj,const char *name);

//This function is used to attach an eBPF program to a kernel tracepoint.
struct bpf_link *bpf_program__attach_tracepoint (const struct bpf_program *prog,const char *tp_category,const char *tp_name);

//This function is used for creating and opening a new ringbuf manager.
struct ring_buffer *ring_buffer__new(int map_fd,ring_buffer_sample_fn sample_cb,void *ctx,const struct ring_buffer_opts *opts);

//Used to remove or consume data from a ring buffer
int ring_buf__consume(struct ring_buffer *cb);
```

# Attaching eBPF programs to hooks and events

Here is an eBPF program that runs when the execve system call is made：

```c

#include <linux/bpf.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>
#include <string.h>

struct{
    __uint(type,BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries,256*1024);
}ringbuf SEC(".maps");

struct execve_params{
    __u64 __unused;
    __u64 __unused2;
    char *filename;
};

struct event{
    int pid;
    char filename[512];
};


char faildMsg[] SEC(".rodata") = "bpf_ringbuf_reverse failed";

SEC("tp/syscalls/sys_enter_execve")
int detect_execve(struct execve_params *params)
{
    __u32 pid = bpf_get_current_pid_tgid()>>32;
    struct event* evt = bpf_ringbuf_reserve(&ringbuf,sizeof(struct event),0);
    if(!evt){
        bpf_printk("%s\n",faildMsg);
        return 1;
    }
    evt->pid = pid;
    bpf_probe_read_user_str(evt->filename,sizeof(evt->filename),params->filename);
    bpf_ringbuf_submit(evt,0);
    return 0;
}
char _license[] SEC("license") = "GPL";
```

* In the eBPF programming context, the macro SEC() from the bpf/bpf_helper.h header file plays a crucial role. It allows the programmer to specify the section in which a function or variable will be placed within the eBPF object file. This becomes essential when loading eBPF programs into the kernel using mechanisms like the bpf() system call.
* By organizing functions and variables into named sections, the eBPF loader can efficiently locate and load the required code and data. Specifically, when dealing with tracepoint events, the SEC format follows the pattern SEC("tp/\<category>/\<name>"), where \<category> and \<name> represent the respective tracepoint category and event name.
* tp/syscalls/sys_enter_execve refers to a tracepoint that records when a process spawns the execve system call.
* A list of all the available tracepoints is present in the /sys/kernel/debug/tracing/available\_events file. The format for each line in the file is \<category>:\<name>. For example, syscalls\:sys\_enter\_execve.

Let's compile the program. The following command can be used to do this task:
```
clang -O2 -g -target bpf -c prog1.c -o prog1.o
```

==-g to generate btf segment==

Now, we need to write a loader program that loads and attaches this program. This loader program is used to load and attach an eBPF program to the Linux kernel. It opens and loads the eBPF object file, checks for errors during the process, finds a specific eBPF program within the loaded object, and attaches it to the kernel. Once attached, the eBPF program will be executed when certain events occur. The program enters an infinite loop at the end, indicating that it will continue running until it is manually terminated.

```c
#include <stdio.h>
#include <bpf/libbpf.h>
#include <unistd.h>

struct event{
    __u32 pid;
    char filename[512];
};

int event_logger(void *ctx, void *data, size_t size)
{
    struct event *evt = (struct event *)data;

    printf("PID = %d and filename=%s\n",evt->pid,evt->filename);

    return 0;
}

int main(){
    const char *filename = "prog1.o";
    const char *mapname = "ringbuf";
    const char *progname = "detect_execve";
    struct bpf_object *bpfObject = NULL;

    int err;


    bpfObject = bpf_object__open(filename);
    if(!bpfObject){
        printf("Error! Failed to load %s\n",filename);
        return 1;
    }

    err = bpf_object__load(bpfObject);
    if(err){
        printf("Failed to load %s\n",filename);
        return 1;
    }

    int rbfd = bpf_object__find_map_fd_by_name(bpfObject,mapname);
    struct ring_buffer *ringBuffer = ring_buffer__new(rbfd,event_logger,NULL,NULL);
    if(!ringBuffer){
        printf("Failed to create ring buffer\n");
        return 1;
    }

    struct bpf_program *bpfProg = bpf_object__find_program_by_name(bpfObject,progname);
    if(!bpfProg){
        printf("Failed to find %s\n",progname);
        return 1;
    }
    bpf_program__attach(bpfProg);

    while (1)
    {
        ring_buffer__consume(ringBuffer);
        sleep(1);
    }
    
    return 0;
}
```

The infinite loop is necessary to ensure that the program continuously checks for new events in the ring buffer. Without the loop, the program would only consume events that were already in the buffer at the time of the initial ring_buffer__consume() call. By looping and calling ring_buffer__consume() repeatedly, the program can retrieve events as soon as they become available and process them in real-time. The sleep(1) call within the loop serves to reduce the CPU usage of the program by introducing a one-second delay between each call to ring_buffer__consume().

Let's compile and run this program

```
clang -O2 -g -Wall -I/usr/include -I/usr/include/bpf -lbpf -o loader loader.c

sudo ./loader
```
# 资料

Tracing System Calls Using eBPF - Part 1

<https://falco.org/blog/tracing-syscalls-using-ebpf-part-1/>

Tracing System Calls Using eBPF - Part 2

<https://falco.org/blog/tracing-system-calls-using-ebpf-part-2/>

A practical guide to BTF (BPF Type Format)

https://www.airplane.dev/blog/btf-bpf-type-format