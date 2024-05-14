# BPF是什么

BPF全称是「Berkeley Packet Filter」**，翻译过来是**「伯克利包过滤器」。

简单解释BPF作用，BPF提供了一种当内核或应用特定事件发生时候，执行一段代码的能力。BPF 采用了虚拟机指令规范，所以也可以看一种虚拟机实现，使我们可以在不修改内核源码和重新编译的情况下，提供一种扩展内核的能力的方法。

# BPF能干嘛

BPF程序不像一般程序可以独立运行，它是被动运行的，需要事件触发才能运行，有点类似js里面的监听，监听到按钮点击执行一小段代码。这些事件包括系统调用，内核跟踪，内核函数，用户函数，网络事件等。

具体能干嘛那，作用还是很强大,可以进行系统故障诊断，因为其有透视内核的能力；网络性能优化，因为它可以在内核态接收网络包，并做修改和转发；系统安全，因为它可以中断非法连接等；性能监控，因为其透视能力，可以查看函数耗费时间从而我们可以知道问题到底出在哪里。

经典的BPF的工作模式是用户使用BPF虚拟机的指令集定义过滤表达式，传递给内核，由解释器运行，使得包过滤器可以直接在内核态工作，避免向用户态复制数据，从而提升性能

# BPF超能的核心技能点——BPF Hooks

第一个核心技能点是「BPF Hooks」，即BPF钩子，也就是在内核中，哪些地方可以加载BPF程序，在目前的Linux内核中已经有了近10种的钩子，如下所示：

1.  kernel functions (kprobes)
2.  userspace functions (uprobes)
3.  system calls
4.  fentry/fexit
5.  Tracepoints
6.  network devices (tc/xdp)
7.  network routes
8.  TCP congestion algorithms
9.  sockets (data level)

从文件打开、创建TCP链接、Socket链接到发送系统消息等几乎所有的系统调用，加上用户空间的各种动态信息，都能加载BPF程序，可以说是无所不能。它们在内核中形成不同的BPF程序类型，在加载时会有类型判断（内核函数：load\_and\_attach）。

# BPF超能的核心技能点——BPF Map

一个程序通常复杂的逻辑都有一个必不可少的部分，那就是记录数据的状态。对于BPF程序来说，可以在哪里存储数据状态、统计信息和指标信息呢？这就是BPF Map的作用，BPF程序本身只有指令，不会包含实际数据及其状态。我们可以在BPF程序创建BPF Map，这个Map像其他编程语言具有的Map数据结构类似，也有很多类型，常用的就是Hash和Array类型，如下所示：

*   Hash tables, Arrays
*   LRU (Least Recently Used)
*   Ring Buffer
*   Stack Trace
*   LPM (Longest Prefix match)

下面所示是一个典型的BPF Map创建代码：

```c
struct bpf_map_def SEC("maps") my_bpf_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 100,
    .map_flags = BPF_F_NO_PREALLOC,
}
```

值得一提的是：

*   BPF Map是可以被用户空间访问并操作的
*   BPF Map是可以与BPF程序分离的，即当创建一个BPF Map的BPF程序运行结束后，该BPF Map还能存在，而不是随着程序一起消亡

基于上面两个特点，意味着我们可以利用BPF Map持久化数据，在不丢失重要数据的同时，更新BPF程序逻辑，实现在不同程序之间共享信息，在收集统计信息或指标等场景下，尤其有用。

# BPF超功能的核心技能点——BPF Helper Function

第三个核心技能点——「BPF Helper Function」，即BPF辅助函数。

它们是面向开发者的，提供操作BPF程序和BPF Map的工具类函数。由于内核本身会有不定期更新迭代，如果直接调用内核模块，那天可能就不能用了，因此通过定义和维护BPF辅助函数，由BPF辅助函数来去面对后端的内核函数的变化，对开发者透明，形成稳定API接口。

例如，BPF程序不知道如何生成一个随机数，有一个BPF辅助函数会可以帮你检索并询问内核，完成”给我一个随机数”的任务，或者”从BPF Map中读取某个值”等等。任何一种与操作系统内核的交互都是通过BPF辅助函数来完成的，由于这些都是稳定的API，所以BPF程序可以跨内核版本进行移植。

下图是部分BPF辅助函数的列表：

*   Random numbers
*   Get current time
*   Map access
*   Get process/cgroup context
*   Manipulate network packets and forwarding
*   Access socket data
*   Perform tail call
*   Access process stack
*   Access syscall arguments

# BPF超能力的限制

BPF技术虽然强大，但是为了保证内核的处理安全和及时响应，内核对于BPF 技术也给予了诸多限制，如下是几个重点限制：

*   eBPF 程序不能调用任意的内核函数，只限于内核模块中列出的 BPF Helper 函数，函数支持列表也随着内核的演进在不断增加
*   eBPF程序不允许包含无法到达的指令，防止加载无效代码，延迟程序的终止
*   eBPF 程序中循环次数限制且必须在有限时间内结束
*   eBPF 堆栈大小被限制在 MAXBPFSTACK，截止到内核 Linux 5.8 版本，被设置为 512。目前没有计划增加这个限制，解决方法是改用 BPF Map，它的大小是无限的。
*   eBPF 字节码大小最初被限制为 4096 条指令，截止到内核 Linux 5.8 版本， 当前已将放宽至 100 万指令（ BPF\_COMPLEXITY\_LIMIT\_INSNS），对于无权限的BPF程序，仍然保留4096条限制 ( BPF\_MAXINSNS )

# Development Toolchains

Several development toolchains exist to assist in the development and management of eBPF programs. All of them address different needs of users:

### bcc

BCC is a framework that enables users to write python programs with eBPF programs embedded inside them. The framework is primarily targeted for use cases which involve application and system profiling/tracing where an eBPF program is used to collect statistics or generate events and a counterpart in user space collects the data and displays it in a human readable form. Running the python program will generate the eBPF bytecode and load it into the kernel.

### bpftrace

bpftrace is a high-level tracing language for Linux eBPF and available in semi-recent Linux kernels (4.x). bpftrace uses LLVM as a backend to compile scripts to eBPF bytecode and makes use of BCC for interacting with the Linux eBPF subsystem as well as existing Linux tracing capabilities: kernel dynamic tracing (kprobes), user-level dynamic tracing (uprobes), and tracepoints. The bpftrace language is inspired by awk, C, and predecessor tracers such as DTrace and SystemTap.

### eBPF Go Library

The eBPF Go library provides a generic eBPF library that decouples the process of getting to the eBPF bytecode and the loading and management of eBPF programs. eBPF programs are typically created by writing a higher level language and then use the clang/LLVM compiler to compile to eBPF bytecode.

### libbpf C/C++ Library

The libbpf library is a C/C++-based generic eBPF library which helps the loading of eBPF object files generated from the clang/LLVM compiler into the kernel and generally abstracts interaction with the BPF system call by providing easy to use library APIs for applications.

# 编写BPF程序

在很多情况下，eBPF不是直接使用，而是通过Cilium、bcc或bpftrace等项目间接使用，这些项目提供了eBPF之上的抽象，不需要直接编写程序，而是提供了指定基于意图的定义的能力，然后用eBPF实现。

如果不存在更高层次的抽象，则需要直接编写程序。Linux内核期望eBPF程序以字节码的形式加载。虽然直接编写字节码当然是可能的，但更常见的开发实践是利用像LLVM这样的编译器套件将伪c代码编译成eBPF字节码。

确定所需的钩子后，可以使用bpf系统调用将eBPF程序加载到Linux内核中。这通常是使用一个可用的eBPF库来完成的。

当程序被加载到Linux内核中时，它在被附加到所请求的钩子上之前要经过两个步骤

*   Verification : The verification step ensures that the eBPF program is safe to run
*   JIT Compilation : The Just-in-Time (JIT) compilation step translates the generic bytecode of the program into the machine specific instruction set to optimize execution speed of the program

# 资料

bpf-developer-tutorial

<https://github.com/eunomia-bpf/bpf-developer-tutorial>

eBPF Tutorial by Example 8: Monitoring Process Exit Events, Print Output with Ring Buffer

<https://medium.com/@yunwei356/ebpf-tutorial-by-example-8-monitoring-process-exit-events-print-output-with-ring-buffer-73291d5e3a50>
