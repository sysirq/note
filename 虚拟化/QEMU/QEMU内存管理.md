# AddressSpace

表示一段地址空间，如内存地址空间，IO地址空间，其包含了一些列的MemoryRegion，由AddressSpace的root指向根MemoryRegion。组织成一颗树结构（每个MemoryRegion能包含subregion）。

AddressSpace也映射到FaltView，从FlatView可以得到MemoryRegionSection

# MemoryRegion

表示虚拟机中的一段内存区域。在pc_memory_init中创建

可将MemoryRegion划分为以下三种类型：

- 根级MemoryRegion:直接通过memory_region_init初始化，没有自己的内存，用于管理subregion。如system_memory
- 实体MemoryRegion:通过memory_region_init_ram初始化，有自己的内存，大小为size。如ram_memory，pci_memory等
- 别名MemoryRegion：通过memory_region_init_alias初始化，没有自己的内存，表示实体MemoryRegion的一部分，通过alias成员指向实体MemoryRegion，alias_offset为实体MemoryRegion中的偏移量。

# MemoryRegionSection

MemoryRegionSection指向MemoryRegion的一部分，([offset_within_region,offset_within_region+size])。是注册到KVM的基本单位。

# MemoryListener

用于指向address_space成员发生变化时调用的回调函数。通过memory_region_transcation_commit调用

# RAMBlock

保存qemu申请的虚拟内存空间

# AddressSpaceDispatch

用于根据GPA找到对应的HVA。

相应的创建调用流程为：memory_region_transaction_commit--》flatviews_reset--》generate_memory_topology--》flatview_add_to_dispatch。

查找函数为address_space_translate

# 内存初始化过程

首先调用cpu_exec_init_all->memory_map_init：创建system_memory和system_io，用于分别作为address_space_memory和address_space_io AddressSpace的根。

然后调用configure_accelerator->kvm_init，为address_space_memory和address_space_io注册MemoryListener

在调用pc_memory_init，创建真正的内存，然后调用memory_region_transaction_commit完成事件提交（调用相应的注册了的MemoryListener 和 更新 GPA到 HVA的映射关系）

# 从客户机物理地址找到对应宿主机的虚拟地址

### 方法一：

从AddressSpace结构中的current_map中的ranges数组中进行查找

### 方法二：

从AddressSpace结构中的root进行查找

### 方法三：

根据AddressSpace结构中的current_map中的dispatch中进行查找或者调用phys_page_find

# 资料

【系列分享】QEMU内存虚拟化源码分析

https://www.anquanke.com/post/id/86412

QEMU学习笔记——内存

https://www.binss.me/blog/qemu-note-of-memory/

qemu-kvm内存虚拟化1

https://www.cnblogs.com/ck1020/p/6729224.html

qemu-kvm内存虚拟化2

https://www.cnblogs.com/ck1020/p/6738116.html