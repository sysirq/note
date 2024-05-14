内核中通过alloc_vmcs分配VMCS结构

# 虚拟机控制结构(VMCS)

该结构管理着进入和退出 VMX non-root operation以及在VMX non-root operation中的行为。


一个逻辑处理器可能维护多个活跃的VMCS，但是只有一个是 current的。在任何给定时间，最多一个活跃的VMCS是当前的VMCS。

VMPTRLD 指令的操作数字段是VMCS的地址，当执行完该指令时，该VMCS既是活跃的也是当前的VMCS

VMCLEAR 指令的操作数字段是VMCS的地址，当执行完该指令时，该VMCS既不是活跃的也不是当前的。

VMCS的启动状态决定该VMCS应使用哪个VM-entry指令：VMLAUNCH指令需要VMCS的启动状态为clear，VMRESUME指令需要VMCS的启动状态为launched。逻辑处理器在相应的VMCS区域中维护VMCS的启动状态。

VMCS的启动状态转换关系：

如果当前VMCS的启动状态为clear，成功执行完VMLAUNCH指令后，状态变为launched

当对一个VMCS执行完VMCLEAR指令后，启动状态变为clear。

没有其他方法来修改VMCS的启动状态，包括VMWRITE。也没有其他方法去读，包括VMREAD。

VMPTRLD:对应于vmcs_load函数

VMCLEAR:对应于vmcs_clear函数

# VMCS的格式

前四个字节的0-30位是VMCS的修订标识符，不同的修订标识符使用不同的VMCS格式结构，31位指示当前VMCS是否是一个影子VMCS。

当创建一个VMCS时，我们必须设置修订标识符，如果我们设置的修订标识符和处理器支持的修订标识符不同时，VMPTRLD将失败。

4-8字节是VMX-abort indicator

后面部分是VMCS数据，该部分控制VMX non-root operation 和 VMX 转换。

内核中在alloc_vmcs函数中分配VMCS结构，并设置修正标识符。

# VMCS数据的布局

VMCS数据分为六个逻辑组

- 客户机状态部分(Guest-state area)：当遇到VM exit时，客户机的处理器状态保存在该部分。VM entries时，从这里恢复。
- 宿主机状态部分(Host-state area)：当遇到VM exit时，处理器状态从这里恢复。
- VM-execution控制字段(VM-execution control fields)：控制处理器在VMX non-root operation下的行为，它们在一定程度上决定了VM退出的原因。
- VM-exit 控制字段(VM-exit control fileds)：控制VM退出
- VM-entry 控制字段(VM-entry control fields)：控制VM进入
- VM-exit信息字段(VM-exit information fields)：描述VM退出的原因。

# 客户机状态区域

每次VM entry时，客户机的状态从这里加载。每次VM exit时，客户机状态保存在这里。

### 客户机寄存器状态

- 控制寄存器CR0,CR3,CR4
- 调试寄存器DR7
- RSP,RIP,RFLAGS
- CS,SS,DS,ES,FS,GS,LDTR,TR(每个寄存器都有Selector、Base address、Segment limit、Access right字段)
- GDTR,IDTR(每个都有GDTR、IDTR字段)
- MSR

### 客户机状态（非寄存器）

客户机除了寄存器状态外，还有一些非寄存器状态
 
- Activity state(32位)：该字段标识逻辑处理器的活动状态。当逻辑处理器正常执行指令时，它处于活动状态。某些指令的执行和某些事件的发生可能会导致逻辑处理器过渡到非活动状态，在这种状态中它停止执行指令。0：Activity，1：HLT，2：Shutdown，3：Wait-for-SIPI
- Interruptibility state（32位）:
- Pending debug exceptions
- Guest interrupt status
- ....省略....

# 宿主机状态区域

每次VM exit时，处理器状态都是从这里读取的。

所有的在宿主机状态区域的字段都对应到处理器寄存器。

- CR0,CR3,CR4
- RSP,RIP
- Selector for segment registers CS,SS,DS,ES,FS,GS
- FS,GS,TR,CDTR,IDTR
- MSR

# VM EXECUTION 控制字段

vm执行控制字段控制VMX非根操作

### Pin-Based VM-Execution Controls

控制异步事件的处理（32位）（例如：中断）

### Processor-Based VM-Execution Controls

控制同步事件的处理（两个32位）（主要是执行特殊指令引起的）

### Exception Bitmap

32位，每位对应一个异常。如果位为1，会导致VM exit，否则传递给客户机处理

### I/O-Bitmap Addresses

### Time-Stamp Counter Offset and Multiplier

### Guest/Host Masks and Read Shadows for CR0 and CR4

控制访问这些（CR0或CR4）寄存器的指令的执行（In general,bits set to 1 in a guest/host mask correspond to bits "owned" by the host）

### CR3-Target Controls

### Controls for APIC Virtualization

软件通过三种机制访问本地处理器的APIC的寄存器。

### MSR-Bitmap Address

# VM-Exit CONTROL FIELDS

控制VM Exit行为。

### VM-Exit Controls

控制 VM exits的基本操作

### VM-Exit Controls for MSRs

# VM-ENTRY CONTROL FIELDS

控制VM entries行为。

### VM-Entry Controls

控制VM entries的基础操作

### VM-Entry Controls for MSRs

### VM-Entry Controls for Event injection

VM Entry可以配置为通过IDT传递事件来结束。这个过程被称为事件注入，通过以下三个字段控制：

- VM-entry interruption-information field:此字段提供有关要注入的事件的详细信息
- VM-entry exception error code
- VM-entry instruction length

# VM-EXIT INFORMATION FIELDS

### Basic VM-Exit information

- Exit reason
- Exit qualification
- Guest-linear address
- Guest-physical address

### Information for VM Exits Due to Vectored Events

- VM-exit interruption information
- VM-exit interruption error code

### Information for VM Exits That Occur During Event Delivery

### Information for VM Exits Due to Instruction Execution

### VM-Instruction Error Field

# VMCS TYPES:ORDINARY AND SHADOW

# SOFTWARE USE OF THE VMCS AND RELATED STRUCTURE

### Software Use of Virtual-Machine Control Structures

VMCS不能在多个逻辑处理器上被激活。如果VMCS需要迁移到另一个逻辑处理器，当前处理器需要执行VMCLEAR，然后另一个处理器执行VMPTRLD

软件不能通过传统的内存读写访问当前VMCS的数据部分，需要通过VMREAD、VMWRITE指令进行。部分原因是用于存储VMCS数据的格式是特定于实现的，而不是体系结构定义的，还因为逻辑处理器可能在处理器上维护活动VMCS的一些VMCS数据，而不是在VMCS区域中。

### VMREAD,VMWRITE,and Encodings of VMCS Fields

VMCS的每一个字段都与一个32位值有关，该值是其编码

- Field width
- Field Type:指定VMCS字段的类型：control,guest-state,host-state,VM-exit information
- Index
- Access type

### Initializing a VMCS

在第一次将VMCS用于VM entry之前，应该对vmcs执行VMCLEAR。（VMCLEAR指令初始化它的操作数所引用的VMCS区域中的任何特定于实现的信息）

然后软件应该使用VMWRITE初始化VMCS中的字段

### VMXON Region

在执行VMXON之前，软件应该分配一块内存（4KB）用于逻辑处理器支持VMX operation。这块内存的物理地址用作 VMXON的操作数。

在执行VMXON之前，应该将revision identifier写入分配的内存块（具体来说，它应该将31位的VMCS修订标识符写到VMXON区域前4个字节的30位0;第31位应该被清除为0）。软件应该为每个逻辑处理器使用一个单独的区域，并且不应该在逻辑处理器上执行VMXON和VMXOFF之间访问或修改逻辑处理器的VMXON区域。