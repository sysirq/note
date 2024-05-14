# 系统调用表
首先系统会注册0x80中断，然后填写系统调用表(其实就是函数数组).
系统调用表注册如下:
```c
// /arch/x86/entry/syscall_64.c
asmlinkage const sys_call_ptr_t sys_call_table[__NR_syscall_max+1] = {
	/*
	 * Smells like a compiler bug -- it doesn't work
	 * when the & below is removed.
	 */
	[0 ... __NR_syscall_max] = &sys_ni_syscall,
#include <asm/syscalls_64.h>
};
```
其中 asm/syscalls_64.h 是临时生成的.

# 对应内核中系统调用的实现代码
如 exit函数，其内核实现代码位于 /kernel/exit.c
```c
    SYSCALL_DEFINE1(exit, int, error_code)
    {
    	do_exit((error_code&0xff)<<8);
    }
```

其SYSCALL_DEFINE 在 /include/linux/syscall.h中定义
``` c
#define SYSCALL_DEFINE0(sname)					\
	SYSCALL_METADATA(_##sname, 0);				\
	asmlinkage long sys_##sname(void)

#define SYSCALL_DEFINE1(name, ...) SYSCALL_DEFINEx(1, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE2(name, ...) SYSCALL_DEFINEx(2, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE3(name, ...) SYSCALL_DEFINEx(3, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE4(name, ...) SYSCALL_DEFINEx(4, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE5(name, ...) SYSCALL_DEFINEx(5, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE6(name, ...) SYSCALL_DEFINEx(6, _##name, __VA_ARGS__)
```

其最终会展开为sys_exit函数。引入这个的原因是将32位数据转换为64位数据

#  参考资料
1. http://blog.csdn.net/hazir/article/details/12052199
2. http://blog.csdn.net/hazir/article/details/11835025