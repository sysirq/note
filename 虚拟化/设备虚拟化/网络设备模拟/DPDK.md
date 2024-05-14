# 基础篇

### cache

1级cache：分指令和数据cache，每个处理器核心都拥有仅属于自己的一级cache

2级cache：不分指令和数据cache，每个处理器核心都拥有仅属于自己的一级cache

3级cache：不分指令和数据cache，由所有核心所共享

对于各级cache的访问时间，在Intel的处理器上一直保持的非常稳定，一级cache访问是4个指令周期，二级cache是12个指令周期，三级cache是26-31个指令周期

cache和内存以块为单位进行数据交换，块的大小通常以在内存的一个存储周期中能够访问到的数据长度为限（64字节）。

根据Cache和内存之间的映射关系的不同，cache可以分为三类：第一类是全关联型Cache(full associative cache)，第二类是直接关联型Cache(direct mapped cache)，第三类是组关联型Cache(N-ways associative cache)

全关联Cache：TLB就是这种cache，内存中的任何一块内存都可以映射到cache中的任意一块位置上。在cache中，需要建立一个目录表，目录表的每个表项都有三部分组成：内存地址、cache块号和一个有效位。使用全关联cache，块的冲突最小，但是太贵。。

直接关联Cache：内存中的一块内存只能映射到Cache中的一个特定的块。假设一个cache中总共存在N个cache line，那么内存被分为N等份，其中每等分对应一个cache line。cache的目录表只有两部分组成：区号和有效位，内存地址被分为三部分：区号，块号，块内地址。特定：命中率低，但实现简单，匹配速度快

组关联Cache：前两种的折中，内存被分为多个组，一个组的大小为多个Cache line的大小，一个组映射到对应的多个连续的Cache line，也就是一个Cache组，并且该组内的任意一块可以映射到对应Cache组的任意一个。可以看出，在组外，其采用直接关联Cache的映射方式，而在组内，采用全关联Cache的映射方式。

cache一致性问题的根源是因为存在多个处理器独占的Cache，而不是多个处理器。（cache一致性协议MESI（Modified Exclusive Shared Invalid）协议）

### 大页

可以通过Linux内核启动参数进行设置：default_hugepagesz=1G hugepagesz=1G hugepages=4。（fstable nodev /mnt/huge hugetlbfs defaults 0 0）

也可以在系统启动之后进行修改:echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kb/nr_hugepages

### DDIO

Data Direct IO：这种技术使外部网卡和CPU通过LLC cache直接交换数据，绕过了内存这个相对慢速的部件

DDIO技术在处理器和外设之间交换数据时，减少了处理器和外设访问内存的次数，也减少了Cache写回的等待，提高了系统的吞吐量和减少了数据交换的延迟

### NUMA系统

### 并行计算

指令并行度、多核并发

CPU物理核主要的基本组件：CPU寄存器集合、中断逻辑、执行单元和Cache

超线程在一个CPU物理核中提供两个逻辑执行线程，逻辑线程共享流水线、执行单元和缓存。

多核体系结构则是在一个CPU封装里放入了多个对等的物理核。

一个物理封装的CPU（通过physical id区分判断）可以有多个核（core id）。而每个核可以有多个逻辑CPU（通过processor区分）

Socket、Core、Thread

### 线程独占

Linux内核提供了启动参数isolcpus。对于有4个CPU的服务器，在启动的时候加入启动参数isolcpus=2,3。那么系统启动后将不使用CPU2、CPU3（逻辑CPU）.注意，这里说的不使用不是绝对地不使用，系统启动后仍然可以通过taskset命令指定哪些程序在这些核心中运行。

### 指令并发与数据并行

现代多核处理器几乎都采用了超标量的体系结构来提高指令的并发度，并进一步地允许对无依赖关系的指令乱序执行。

### 无锁机制

当前，高性能的服务器软件在大部分情况下是运行在多核服务器上的，在多个CPU上，锁竞争有时比数据拷贝、上下文切换等更伤害系统的性能。

无锁环形缓冲区

### PCIe 与包处理IO

PCIe规范遵循开放系统互联参考模型，自上而下分为事务层传输层、数据链路层、物理层

# DPDK编译

meson ninja安装：

```
apt install python3-pip

pip3 install --upgrade pip

pip3 install meson ninja

```

dpdk 编译

```
meson build 

cd build

meson configure #  列出选项

meson configure -Dbuildtype=debug

meson configure -Ddebug=true

meson configure -Denable_kmods=true

ninja
ninja install
ldconfig
```

```python
project('dpdk-app', 'c')

dpdk = dependency('libdpdk')
sources = files('main.c')
executable('dpdk-app', sources, dependencies: dpdk)

```

# DPDK网卡绑定与解绑

```

modprobe uio

cd $(DPDK-DIR)/build/kernel/linux/igb_uio

insmod igb_uio.ko

ifconfig ens36 down

$(DPDK-DIR)/usertools/dpdk-devbind.py --bind=igb_uio ens36

完成绑定


解绑：

(DPDK-DIR)/usertools/dpdk-devbind.py -u 02:04.0

```

EAL（Environmental Abstraction Layer）抽象层选项对于所有的DPDK程序都是可以使用的:

```

-c COREMASK or -l CORELIST: An hexadecimal bit mask of the cores to run on. Note that core numbering can change between platforms and should be determined beforehand. The corelist is a set of core numbers instead of a bitmap core mask.
-n NUM: Number of memory channels per processor socket.
-b <domain:bus:devid.func>: Blacklisting of ports; prevent EAL from using specified PCI device (multiple -b options are allowed).
--use-device: use the specified Ethernet device(s) only. Use comma-separate [domain:]bus:devid.func values. Cannot be used with -b option.
--socket-mem: Memory to allocate from hugepages on specific sockets. In dynamic memory mode, this memory will also be pinned (i.e. not released back to the system until application closes).
--socket-limit: Limit maximum memory available for allocation on each socket. Does not support legacy memory mode.
-d: Add a driver or driver directory to be loaded. The application should use this option to load the pmd drivers that are built as shared libraries.
-m MB: Memory to allocate from hugepages, regardless of processor socket. It is recommended that --socket-mem be used instead of this option.
-r NUM: Number of memory ranks.
-v: Display version information on startup.
--huge-dir: The directory where hugetlbfs is mounted.
mbuf-pool-ops-name: Pool ops name for mbuf to use.
--file-prefix: The prefix text used for hugepage filenames.
--proc-type: The type of process instance.
--vmware-tsc-map: Use VMware TSC map instead of native RDTSC.
--base-virtaddr: Specify base virtual address.
--vfio-intr: Specify interrupt type to be used by VFIO (has no effect if VFIO is not used).
--legacy-mem: Run DPDK in legacy memory mode (disable memory reserve/unreserve at runtime, but provide more IOVA-contiguous memory).
--single-file-segments: Store memory segments in fewer files (dynamic memory mode only - does not affect legacy memory mode).

```

查看CPU拓扑图

```
sudo yum install hwloc
./lstopo
```

####

# 资料

缓存一致性协议之MESI

https://www.jianshu.com/p/0e036fa7af2a

Meson Tutorial

https://mesonbuild.com/Tutorial.html

https://mesonbuild.com/Quick-guide.html

EAL parameters

http://doc.dpdk.org/guides/linux_gsg/linux_eal_parameters.html