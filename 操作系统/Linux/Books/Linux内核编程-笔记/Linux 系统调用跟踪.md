# 内核版本
Linux-4.17.3

体系结构:x86_64

# int 0x80 中断的注册
其在 /init/main.c 中的 start_kernel函数中调用trap_init(/arch/x86/kernel/traps.c)进行注册,

进一步跟踪发现注册函数为idt_setup_traps(/arch/x86/kernel/idt.c),其调用idt_setup_from_table

# int 0x80 入口

位于/arch/x86/entry/目录下的 entry汇编文件


# 系统调用表初始化

位于/arch/x86/entry/目录下的 syscall C源文件中

# 系统调用在用户空间的命名 与内核中实现的命名 的对比
如 fork，在 内核中实现的命名为 sys_fork

# 系统调用触发流程

entry_64.S(/arch/x86/entry)--->do_syscall_64.c(/arch/x86/entry/common.c)--->具体的函数