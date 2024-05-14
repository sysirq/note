现在来关注VMX非根模式和传统处理器模式的区别

# 导致VM退出的指令

### Faults 和 VM Exits 的相对优先级

- 某些异常优先于VM exits，包括：无效操作码异常，基于特权级别的错误
- Faults incurred(发生) while fetching instruction operands have priority over VM exits that are conditioned based on the contents of those operands
- VM exits caused by execution of the INS and OUTS instructions
- Fault-like VM exits have priority over exceptions other than those mentioned above.

### 导致VM无条件退出的指令

如下：CPUID、GETSEC、INVD、and XSETBV，以及包括VMX引入的指令：INVEPT, INVVPID, VMCALL,2 VMCLEAR, VMLAUNCH, VMPTRLD, VMPTRST, VMRESUME, VMXOFF, and VMXON

### 导致VM有条件退出的指令

根据虚拟机执行控制的设置(VM-execution controls fields)，某些指令会导致虚拟机在VMX非根操作中退出。

- CLTS
- ENCLS
- HLT
- IN、OUT指令家族
- MOV form CR3
- MOV from CR8
- MOV to CR0
- MOV to CR3
- MOV to CR4
- MOV to CR8

...................省略.....................

# VMX NON-ROOT OPERATION中指令行为的变化

- MOV from CR0.The behavior of MOV from CR0 is determined by the CR0 guest/host mask and the CR0 read shadow
- MOV from CR3 

...................省略.....................

# VMX NON-ROOT OPERATION 的其他一些改变

事件阻塞的处理和任务切换在VMX non-root operation下有所不同。

### 事件阻塞

"external-interrupt exiting" VM-execution control

### 任务切换的处理

VMX non-root operation中并不允许任务转换。任何在VMX non-root operation中尝试任务转换都会导致VM exits

# VMX NON-ROOT OPERATION的专有特性

### VMX-Preemption Timer

"activate VMX-preemption timer" VM-execution control filed.

timer递减，递减到0时导致VM exit

### Monitor Trap Flag

monitor trap flag 是一种调试功能，可以在VMX non-root operation中的特定指令边界导致VM exit(The monitor trap flag is a debugging feature that causes VM exits to occur on certain instruction boundaries in VMX non-root operation)。

### 使用EPT进行客户机的物理地址转换

extended page-table mechanism(EPT)是（处理器提供）用于支持物理内存虚拟化的一种特性

### APIC 虚拟化

当启用APIC虚拟化时，处理器模拟对APIC的访问，跟踪虚拟APIC的状态，交付虚拟中断，且都在VMX non-root operation中完成不用VM exit

### VM Functions

VM function 由处理器提供，可以在VMX non-root operation中调用而不导致VM exit。VMFUNC指令，EAX指定哪个VM function被调用。

#### Enabling VM functions

Software enables VM functions generally by setting the "enable VM functions" VM-exeution control.A specific VM function is enabled by setting the corresponding VM-function control.

### Virtualization Exceptions

虚拟化异常是一种新的处理器异常，他使用向量20

A virtualization exception can occur only in VMX non-root operation.

# UNRESTRICTED GUESTS