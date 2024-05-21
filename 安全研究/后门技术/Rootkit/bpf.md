![image.png](images/WEBRESOURCE19769019c37efea4aef2e7ea6c7783e6image.png)

# ebpf有用的helper函数

```
bpf_get_current_comm （获取进程命 task_struct -> comm）
```

# ebpf rootkit 原理

ebpf没法修改系统调用的参数与返回值，也无法修改内核数据结构，但是他可以通过两个函数：

- `bpf_probe_read_user` 

- `bpf_probe_write_user`.

修改用户空间的数据。

结合起来，在用户空间和内核之间有选择地更改数据的能力是一种强大的攻击性原语，可以有广泛的可能用途。

# 修改文件

![Picture highlighting how eBPF can intercept paramaters and return codes from syscalls](images/syscall_flow_03.png)

# 隐藏进程

通过隐瞒/proc/伪文件夹的内容来隐藏进程

# 劫持执行

当程序调用execve时更改可执行文件的文件名

# 假装系统调用

```c
// Attach to the 'write' syscall
SEC("fmod_ret/__x64_sys_write")
int BPF_PROG(fake_write, struct pt_regs *regs)
{
    // Get expected write amount
    u32 count = PT_REGS_PARM3(regs);

    // Overwrite return
    return count;
}
```

# 资料

Tracing System Calls Using eBPF - Part 1

https://falco.org/blog/tracing-syscalls-using-ebpf-part-1/

Linux中基于eBPF的恶意利用与检测机制

https://www.cnxct.com/evil-use-ebpf-and-how-to-detect-ebpf-rootkit-in-linux/

DEF CON 29: Bad BPF - Warping reality using eBPF

https://blog.tofile.dev/2021/08/01/bad-bpf.html

Abusing eBPF to build a rootkit

https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-With-Friends-Like-EBPF-Who-Needs-Enemies.pdf

ebpf-slide

https://github.com/gojue/ebpf-slide

bpf.h

https://github.com/torvalds/linux/blob/0c0ddd6ae47c9238c18f475bcca675ca74c9dc31/include/uapi/linux/bpf.h

ebpfkit

https://github.com/Gui774ume/ebpfkit

TripleCross

https://github.com/h3xduck/TripleCross

bad-bpf

https://github.com/pathtofile/bad-bpf



