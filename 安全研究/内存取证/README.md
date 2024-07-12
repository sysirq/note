# 安装

```shell
git clone https://github.com/volatilityfoundation/volatility.git
```

# 关键文件

对于Linux需要dwarf调试文件， 以及 符号文件 System.map，用于构建profile 

# Linux隐藏进程查找方法

- 从 kmem_cache : task_struct 中查找进程
- 从pid_hash table 中查找：alloc_pid

# 资料

volatility

https://github.com/volatilityfoundation/volatility

https://volatilityfoundation.org

https://github.com/volatilityfoundation/volatility/wiki/Installation