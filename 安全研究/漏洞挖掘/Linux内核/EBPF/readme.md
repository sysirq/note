# 其所在syscall
https://elixir.bootlin.com/linux/v4.17/source/kernel/bpf/syscall.c#L2035

# 静态合法性检查
https://elixir.bootlin.com/linux/v4.17/source/kernel/bpf/verifier.c#L4598

# 可能存在的绕过
#### 条件竞争
思路一：
    利用map array 的值
    
    分析发现：对map的操作需要root权限，所以这种方法行不通

# 指令集
https://elixir.bootlin.com/linux/v4.17/source/samples/bpf/libbpf.h

# 参考资料
1.http://man7.org/linux/man-pages/man2/bpf.2.html