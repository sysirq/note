- 对于通过ftrace进行hook的rootkit，我们可以直接查看/sys/kernel/debug/tracing/enabled_functions 来定位该rootkit

```cmd
root@debian:/home/sysirq/Work/rootkit/lkm# cat /sys/kernel/debug/tracing/enabled_functions 
__x64_sys_kill (1) R I  	tramp: 0xffffffffc03ab000 (fh_ftrace_thunk+0x0/0x40 [example]) ->ftrace_ops_assist_func+0x0/0x100
__x64_sys_mkdir (1) R I  	tramp: 0xffffffffc0389000 (fh_ftrace_thunk+0x0/0x40 [example]) ->ftrace_ops_assist_func+0x0/0x100
__x64_sys_getdents64 (1) R I  	tramp: 0xffffffffc03ad000 (fh_ftrace_thunk+0x0/0x40 [example]) ->ftrace_ops_assist_func+0x0/0x100
random_read_iter (1) R I  	tramp: 0xffffffffc03b5000 (fh_ftrace_thunk+0x0/0x40 [example]) ->ftrace_ops_assist_func+0x0/0x100
tcp_diag_dump [tcp_diag] (1) R I  	tramp: 0xffffffffc03bd000 (fh_ftrace_thunk+0x0/0x40 [example]) ->ftrace_ops_assist_func+0x0/0x100
```

- 获取内核text section的起始地址与结束地址

```c
root@debian:~# cat /proc/kallsyms | grep _stext
ffffffff8f800000 T _stext
root@debian:~# cat /proc/kallsyms | grep _etext
ffffffff90601b42 T _etext
```

/include/asm-generic/sections.h:

```c
/*
 * Usage guidelines:
 * _text, _data: architecture specific, don't use them in arch-independent code
 * [_stext, _etext]: contains .text.* sections, may also contain .rodata.*
 *                   and/or .init.* sections
 * [_sdata, _edata]: contains .data.* sections, may also contain .rodata.*
 *                   and/or .init.* sections.
 * [__start_rodata, __end_rodata]: contains .rodata.* sections
 * [__start_ro_after_init, __end_ro_after_init]:
 *		     contains .data..ro_after_init section
 * [__init_begin, __init_end]: contains .init.* sections, but .init.text.*
 *                   may be out of this range on some architectures.
 * [_sinittext, _einittext]: contains .init.text.* sections
 * [__bss_start, __bss_stop]: contains BSS sections
 *
 * Following global variables are optional and may be unavailable on some
 * architectures and/or kernel configurations.
 *	_text, _data
 *	__kprobes_text_start, __kprobes_text_end
 *	__entry_text_start, __entry_text_end
 *	__ctors_start, __ctors_end
 *	__irqentry_text_start, __irqentry_text_end
 *	__softirqentry_text_start, __softirqentry_text_end
 *	__start_opd, __end_opd
 */
extern char _text[], _stext[], _etext[];
extern char _data[], _sdata[], _edata[];
extern char __bss_start[], __bss_stop[];
extern char __init_begin[], __init_end[];
extern char _sinittext[], _einittext[];
extern char __start_ro_after_init[], __end_ro_after_init[];
extern char _end[];
extern char __per_cpu_load[], __per_cpu_start[], __per_cpu_end[];
extern char __kprobes_text_start[], __kprobes_text_end[];
extern char __entry_text_start[], __entry_text_end[];
extern char __start_rodata[], __end_rodata[];
extern char __irqentry_text_start[], __irqentry_text_end[];
extern char __softirqentry_text_start[], __softirqentry_text_end[];
extern char __start_once[], __end_once[];
```

- 遍历ftrace 与 kprobe链表 检查可疑的hook:如 不是在 内核text section中的hook，就要认真检查一下
- volatility：https://github.com/volatilityfoundation/volatility