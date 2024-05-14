I/O APIC和LAPIC的配置是在MMIO的帮助下完成的。尽管可以重新配置，但LAPIC寄存器通常位于地址0xFEE00000上，而I/O APIC寄存器位于地址0xFEС00000上。

# Local APIC的处理过程

- 判断该中断的destination是否为当前APIC，如果不是则忽略，否则继续处理
- 如果是SMI/NMI/INIT/ExtINT, or SIPI（这些中断都负责特殊的系统管理任务，外设一般不会使用）被直接送到CPU执行，否则执行下一步。
- 设置Local APIC 的IRR寄存器的对应bit位。
- 如果该中断优先级高于当前CPU正在执行的中断，且当前CPU没有屏蔽中断(按照X86和LINUX的实现，这时是屏蔽了中断的)，则该高优先级中断会中断当前正在执行的中断(置ISR位，并开始执行)，低优先级中断会在高优先级中断完成后继续执行，否则只有等到当前中断执行完成(写了EOI寄存器)后才能开始执行下一个中断。
- 在CPU可以处理下一个中断的时候，从IRR中选取最高优先级的中断，清0 IRR中的对应位，并设置ISR中的对应位，然后ISR中最高优先级的中断被发送到CPU执行(如果其它优先级和屏蔽检查通过)。
-  CPU执行中断处理例程，在合适的时机(在IRET指令前)通过写EOI寄存器来确认中断处理已经完成，写EOI寄存器会导致local APIC清理ISR的对应bit，对于level trigged中断，还会向所有的I/O APIC发送EOI message，通告中断处理已经完成。

对应通过local APIC发送到CPU的中断，按照其vector进行优先级排序：
优先级=vector/16
数值越大，优先级越高。由于local APIC允许的vector范围为[16,255]，而X86系统预留了[0,31]作为系统保留使用的vector，实际的用户定义中断的优先级的取值范围为[2,15]，在每个优先级内部，vector的值越大，优先级越高。
Local APIC中还有一个关于中断优先级的寄存器TPR(task priority register)寄存器：用于确定打断线程执行需要的中断优先级级别，只有优先级高于设置值的中断才会被CPU执行 (SMI/NMI/INIT/ExtINT, or SIPI不受限制)，也就是除了特殊中断外，优先级低于TPR指定值的中断将被忽略。


# 资料

External Interrupts in the x86 system. Part 1. Interrupt controller evolution

https://habr.com/en/post/446312/


External Interrupts in the x86 system. Part 2. Linux kernel boot options

https://habr.com/ru/post/501660/

External Interrupts in the x86 system. Part 3. Interrupt routing setup in a chipset, with the example of coreboot

https://habr.com/en/post/501912/

APIC

https://wiki.osdev.org/APIC

Linux中断机制之一：硬件处理

https://blog.csdn.net/phenix_lord/article/details/45116259

KVM中断注入机制（里面有中断优先级的介绍）

https://blog.csdn.net/huang987246510/article/details/103397763?utm_medium=distribute.pc_relevant.none-task-blog-BlogCommendFromMachineLearnPai2-4.edu_weight&depth_1-utm_source=distribute.pc_relevant.none-task-blog-BlogCommendFromMachineLearnPai2-4.edu_weight