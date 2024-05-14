之所以需要在硬件中加入虚拟化的支持，原因是多方面的。首先，由于原有的硬件体系结构在虚拟化方面存在缺陷，例如虚拟化漏洞，导致单纯的软件虚拟化方法存在种种问题，如降优先级的方法存在Ring Compression问题。BT技术存在难以修复处理自修改代码及自参考代码的问题。其次，由于硬件架构的限制，某些虚拟化功能尽管可以用软件方法来实现，但是实现起来非常复杂，一个典型的例子是内存虚拟化的影子页表。最后，某些通过软件方法实现的虚拟化功能性能不佳，例如I/O设备的虚拟化。

Intel VT是Intel平台上硬件虚拟化技术的总称。在CPU虚拟化方面，Intel提供了VT-x(Intel Virtualization technology for x86)技术；在内存虚拟化方面,Intel VT提供了EPT(Extended Page Table)技术；在I/O设备虚拟化方面,Intel VT提供了 VT-d(Intel Virtualization Technology for Direct I/O)等技术。

# CPU虚拟化的硬件支持

VT-x引入了两种操作模式，统称为VMX操作模式
- VMX Root Operation
- VMX Non-Root Operation

每种模式下都有相应的Ring0 ~ Ring3.

为了更好地支持CPU虚拟化，VT-x引入了VMCS(Virtual-Machine Control Structure,虚拟机控制结构)。VMCS保存虚拟CPU需要的相关状态，例如CPU在根模式和非根模式下的特权寄存器的值。

### VMCS

VMCS是保存在内存中的数据结构，包含了虚拟CPU的相关寄存器的内容和虚拟CPU相关的控制信息，每个VMCS对应一个虚拟CPU。

VMCS在使用时需要与物理CPU绑定。在任意给定时刻，VMCS与物理CPU是一对一的绑定关系。

VT-x提供了两条指令用于VMCS的绑定与解除绑定。

- VMPTRLD
- VMCLEAR

VT-x定义了VMCS的具体格式和内容。规定它是一个最大不超过4KB的内存块，并要求是4KB对齐的。

- 偏移0处是VMCS版本标识，表示VMCS数据格式的版本号。
- 偏移4处是VMX中止指示，VM-Exit执行不成功时产生VMX中止，CPU会在此处存入VMX中止的原因。
- 偏移8处是VMCS数据域，该域的格式是CPU相关的。

VMCS主要的信息存放在“VMCS数据域”，VT-x提供了两条指令用于访问VMCS：

- VMREAD <索引>
- VMWRITE <索引> <数据>

VT-x 为VMCS数据域的每个字段也定义了相应的“索引”。

具体而言，VMCS数据域包括下列6大类信息。

- 客户机状态域
- 宿主机状态域
- VM-Entry控制域
- VM-Execution控制域
- VM-Exit控制域
- VM-Exit信息域

#### 客户机状态域

客户机状态域中首先包含了一些寄存器的值，这些寄存器是必须由CPU进行切换的，如段寄存器、CR3、IDTR和CDTR。CPU通过这些寄存器的切换来实现客户机地址空间和VMM地址空间的切换。客户机状态域中并不包含通用寄存器和浮点寄存器，它们的保存和恢复由VMM决定，可提高效率和增强灵活性。

#### 宿主机状态域

宿主机状态域只在VM-Exit时被恢复，在VM-Entry时不用保存。这是因为宿主机状态域的内容通常几乎不需要改变，例如VM-Exit的入口RIP在VMM整个运行期间都是不变的。

当VM-Exit发生时，宿主机状态域中的CS:RIP制定了VM-Exit的入口地址，SS、RSP制定了VMM的栈地址。

### VMX操作模式

VMX操作模式打开与关闭指令

- VMXON
- VMXOFF

### VM-Entry/VM-Exit

#### VM-Entry

VT-x为VM-Entry提供了两条指令

- VMLAUNCH
- VMRESUME

VM-Entry的具体行为由VM-Entry控制域规定。

- IA-32e mode guest：决定VM-Entry后处理器是否处于64位。
- MSR VM-Entry控制
- 事件注入控制:在VM-Entry时，如果需要，VMM可以操作VMCS中相关的字段来向客户机虚拟CPU注入一个事件。

VM-Entry控制域中的"事件注入控制"用到了VM-Entry Interruption-Information字段。

#### VM-Entry的过程

当CPU执行VMLAUNCH/VMRESUME进行VM-Entry时，处理器要进行下面的步骤。

- 执行基本的检查来确保VM-Entry能开始
- 对VMCS中的宿主机状态域的有效性进行检查，以确保下一次VM-Exit发生时可以正确地从客户机切换到VMM环境。
- 检查VMCS中客户机状态域的有效性
- 根据VMCS中VM-Entry MSR-load区域装载MSR寄存器
- 根据VMCS中VM-Entry事件注入控制的配置，可能需要注入一个事件到客户机中

### VM-Exit

引发VM-Exit的原因很多，例如在非根模式执行了敏感指令、发生了中断等。处理VM-Exit事件是VMM模拟指令、虚拟特权资源的一大任务。

#### 非根模式下敏感指令

敏感指令如果运行在VMX非根操作模式，其行为可能发生变化。具体来说有如下三种可能。

- 行为不变化，但不引起VM-Exit：例如SYSENTER指令。
- 行为变化，产生VM-Exit：这就是典型需要截获并模拟的敏感指令。
- 行为变化，产生VM-Exit可控：这类敏感指令是否产生VM-Exit，可以通过VM-Execution域控制。

#### VM-Execution控制域

该控制域主要控制三个方面：

- 控制某条敏感指令是否产生VM-Exit，如果产生VM-Exit，则由VMM模拟该指令。
- 在某些敏感指令不产生VM-Exit时，控制该指令的行为。
- 异常和中断是否产生VM-Exit

#### VM-Exit控制域

#### VM-Exit信息域

其提供的信息可以分为如下4类：

- 基本的VM-Exit信息，包括如下内容：Exit Reason、Exit qualification
- 事件触发导致的VM-Exit的信息。事件是指外部中断、异常和NMI。可以通过VM-Exit interruption information字段和VM-Exit interruption error code 字段获取额外信息。
- 事件注入导致的VM-Exit信息。
- 执行指令导致的VM-Exit的信息。

#### VM-Exit的具体过程