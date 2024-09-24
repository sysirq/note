# ftrace hook 检查思路

对于通过ftrace进行hook的rootkit，我们可以直接查看/sys/kernel/debug/tracing/enabled_functions 来定位该rootkit

```cmd
root@debian:/home/sysirq/Work/rootkit/lkm# cat /sys/kernel/debug/tracing/enabled_functions 
__x64_sys_kill (1) R I  	tramp: 0xffffffffc03ab000 (fh_ftrace_thunk+0x0/0x40 [example]) ->ftrace_ops_assist_func+0x0/0x100
__x64_sys_mkdir (1) R I  	tramp: 0xffffffffc0389000 (fh_ftrace_thunk+0x0/0x40 [example]) ->ftrace_ops_assist_func+0x0/0x100
__x64_sys_getdents64 (1) R I  	tramp: 0xffffffffc03ad000 (fh_ftrace_thunk+0x0/0x40 [example]) ->ftrace_ops_assist_func+0x0/0x100
random_read_iter (1) R I  	tramp: 0xffffffffc03b5000 (fh_ftrace_thunk+0x0/0x40 [example]) ->ftrace_ops_assist_func+0x0/0x100
tcp_diag_dump [tcp_diag] (1) R I  	tramp: 0xffffffffc03bd000 (fh_ftrace_thunk+0x0/0x40 [example]) ->ftrace_ops_assist_func+0x0/0x100
```

# ebpf木马检查思路

- 对于ebpf木马，我们可以通过查看 /proc/kallsyms

```cmd
root@debian:/home/sysirq/Work/rootkit/ebpf# cat /proc/kallsyms | grep '\[bpf\]'
ffffffffc0166794 t bpf_prog_3650d9673c54ce30_sd_devices	[bpf]
ffffffffc016690c t bpf_prog_6deef7357e7b4530_sd_fw_egress	[bpf]
ffffffffc01669a0 t bpf_prog_6deef7357e7b4530_sd_fw_ingress	[bpf]
ffffffffc0168bb4 t bpf_prog_6deef7357e7b4530_sd_fw_egress	[bpf]
ffffffffc0168c18 t bpf_prog_6deef7357e7b4530_sd_fw_ingress	[bpf]
ffffffffc016cb7c t bpf_prog_ee0e253c78993a24_sd_devices	[bpf]
ffffffffc016f34c t bpf_prog_8470ed2b25b99116_sd_devices	[bpf]
ffffffffc016f564 t bpf_prog_6deef7357e7b4530_sd_fw_egress	[bpf]
ffffffffc016f5fc t bpf_prog_6deef7357e7b4530_sd_fw_ingress	[bpf]
ffffffffc01723a8 t bpf_prog_3b15d563d774482f_tp_sys_enter_getdents64	[bpf]
ffffffffc01726d4 t bpf_prog_a46aa1590dfd4014_my_strcmp	[bpf]
ffffffffc0172410 t bpf_prog_c440e718f526652f_tp_sys_exit_getdents64	[bpf]
ffffffffc017288c t bpf_prog_5bcc54dcd3ad9b99_xdp_prog	[bpf]
ffffffffc0172b40 t bpf_dispatcher_xdp	[bpf]
root@debian:/home/sysirq/Work/rootkit/ebpf# 
```

可以看到 getdents64 、xdp 被hook

进一步可以通过`bpftool prog`查看系统加载的bpf程序:

```log
root@vmcloud:~# bpftool prog
3: cgroup_device  name sd_devices  tag 3650d9673c54ce30  gpl
	loaded_at 2024-09-13T15:19:29+0800  uid 0
	xlated 504B  jited 310B  memlock 4096B
4: cgroup_skb  name sd_fw_egress  tag 6deef7357e7b4530  gpl
	loaded_at 2024-09-13T15:19:29+0800  uid 0
	xlated 64B  jited 55B  memlock 4096B
5: cgroup_skb  name sd_fw_ingress  tag 6deef7357e7b4530  gpl
	loaded_at 2024-09-13T15:19:29+0800  uid 0
	xlated 64B  jited 55B  memlock 4096B
6: cgroup_skb  name sd_fw_egress  tag 6deef7357e7b4530  gpl
	loaded_at 2024-09-13T15:19:30+0800  uid 0
	xlated 64B  jited 55B  memlock 4096B
7: cgroup_skb  name sd_fw_ingress  tag 6deef7357e7b4530  gpl
	loaded_at 2024-09-13T15:19:30+0800  uid 0
	xlated 64B  jited 55B  memlock 4096B
8: cgroup_device  name sd_devices  tag 1f97e470ec084ee5  gpl
	loaded_at 2024-09-13T15:19:31+0800  uid 0
	xlated 464B  jited 289B  memlock 4096B
9: cgroup_device  name sd_devices  tag 3650d9673c54ce30  gpl
	loaded_at 2024-09-13T15:19:34+0800  uid 0
	xlated 504B  jited 310B  memlock 4096B
10: cgroup_device  name sd_devices  tag c2c0d3eb960f5beb  gpl
	loaded_at 2024-09-13T15:19:36+0800  uid 0
	xlated 560B  jited 352B  memlock 4096B
11: cgroup_device  name sd_devices  tag 8470ed2b25b99116  gpl
	loaded_at 2024-09-13T15:19:36+0800  uid 0
	xlated 744B  jited 448B  memlock 4096B
12: cgroup_skb  name sd_fw_egress  tag 6deef7357e7b4530  gpl
	loaded_at 2024-09-13T15:19:36+0800  uid 0
	xlated 64B  jited 55B  memlock 4096B
13: cgroup_skb  name sd_fw_ingress  tag 6deef7357e7b4530  gpl
	loaded_at 2024-09-13T15:19:36+0800  uid 0
	xlated 64B  jited 55B  memlock 4096B
17: kprobe  name kprobe_proc_fork_connector  tag 720d4dee3eddd03c  gpl
	loaded_at 2024-09-13T15:19:48+0800  uid 0
	xlated 1784B  jited 922B  memlock 4096B  map_ids 1,2
	btf_id 123
18: kprobe  name kretprobe_sys_execve  tag 77a4082c7c0023a8  gpl
	loaded_at 2024-09-13T15:19:48+0800  uid 0
	xlated 51488B  jited 28729B  memlock 53248B  map_ids 1,2
	btf_id 123
19: kprobe  name kprobe_tcp_connect  tag 09e8dbcb10840dde  gpl
	loaded_at 2024-09-13T15:19:48+0800  uid 0
	xlated 2376B  jited 1399B  memlock 4096B  map_ids 1,2
	btf_id 123
20: kprobe  name kretprobe_inet_csk_accept  tag 41e7d7bf6b48f276  gpl
	loaded_at 2024-09-13T15:19:48+0800  uid 0
	xlated 3096B  jited 1872B  memlock 4096B  map_ids 1,2
	btf_id 123
21: kprobe  name kprobe_do_sys_open  tag 4b7702c59503c020  gpl
	loaded_at 2024-09-13T15:19:48+0800  uid 0
	xlated 1528B  jited 817B  memlock 4096B  map_ids 1,2
	btf_id 123
22: kprobe  name kprobe_do_sys_openat2  tag 04d028cbdcbc2101  gpl
	loaded_at 2024-09-13T15:19:48+0800  uid 0
	xlated 1624B  jited 866B  memlock 4096B  map_ids 1,2
	btf_id 123
23: kprobe  name kprobe_unix_stream_connect  tag 9b4f64ed77684c36  gpl
	loaded_at 2024-09-13T15:19:48+0800  uid 0
	xlated 1312B  jited 685B  memlock 4096B  map_ids 1,2
	btf_id 123
24: kprobe  name uprobe_getaddrinfo  tag 665305b3ee618a3b  gpl
	loaded_at 2024-09-13T15:19:48+0800  uid 0
	xlated 1392B  jited 722B  memlock 4096B  map_ids 1,2
	btf_id 123
25: kprobe  name uprobe_gethostbyname  tag 665305b3ee618a3b  gpl
	loaded_at 2024-09-13T15:19:48+0800  uid 0
	xlated 1392B  jited 722B  memlock 4096B  map_ids 1,2
	btf_id 123
26: kprobe  name uprobe_gethostbyname2  tag 665305b3ee618a3b  gpl
	loaded_at 2024-09-13T15:19:48+0800  uid 0
	xlated 1392B  jited 722B  memlock 4096B  map_ids 1,2
	btf_id 123
27: kprobe  name uprobe_gethostbyname_r  tag 665305b3ee618a3b  gpl
	loaded_at 2024-09-13T15:19:48+0800  uid 0
	xlated 1392B  jited 722B  memlock 4096B  map_ids 1,2
	btf_id 123
28: kprobe  name uprobe_gethostbyname2_r  tag 665305b3ee618a3b  gpl
	loaded_at 2024-09-13T15:19:48+0800  uid 0
	xlated 1392B  jited 722B  memlock 4096B  map_ids 1,2
	btf_id 123
```

然后通过`lsof | grep bpf`定位到大概的pid

# 其他检查思路

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