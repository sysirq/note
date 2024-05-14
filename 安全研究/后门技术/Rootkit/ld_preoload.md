The LD_PRELOAD envar is not the only place where users can specify shared objects to be loaded first.

The dynamic linker also consults the file ==/etc/ld.so.preload== which can also contain user-specified paths to shared objects.

In the case that paths are defined both in the envar and in this file, the envar takes precedence

 Additionally, the ld.so.preload file causes a system-wide configuration change, resulting in shared objects being preloaded by any binary on the system.
 
 ```
 gcc -Wall -fPIC -shared -o libprocesshider.so processhider.c -ldl
 gcc -Wall -fPIC -shared -o myfopen.so myfopen.c
 ```

# Dynamic linker modifications

By modifying the dynamic linker's libraries, we're able to overwrite any occurrences of "/etc/ld.so.preload" with our own file location.

# 检查方法

- 通过LDD命令检查

```
hn-machine ~/Work/preload/test$ ldd /bin/echo                                                                                                                                                                                         
	linux-vdso.so.1 (0x00007ffea5035000)
	/home/john/Work/preload/test/myfopen.so (0x00007f540be2f000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f540bbf4000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f540be40000)
In our own fopen,opening /lib/terminfo/x/xterm-256color
```

- 查看LD_PRELOAD环境变量
- 查看/etc/ld.so.preload
这种情况需要小心，可能对方已经修改了ld-linux-x86-64.so.2（动态连接器）


# 资料

A Simple LD_PRELOAD Tutorial

https://catonmat.net/simple-ld-preload-tutorial

A Simple LD_PRELOAD Tutorial, Part Two

https://catonmat.net/simple-ld-preload-tutorial-part-two

libprocesshider

https://github.com/gianlucaborello/libprocesshider

Hiding Linux processes for fun + profit

https://sysdig.com/blog/hiding-linux-processes-for-fun-and-profit/

vlany

https://github.com/mempodippy/vlany

Linux 修改 ELF 解决 glibc 兼容性问题

https://cloud.tencent.com/developer/article/1758586

如何使用新的glibc来编译自己的程序

https://www.cnblogs.com/shihuvini/p/10551298.html