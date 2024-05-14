# API

查找空闲内存：

```c
phys_addr_t __init_memblock memblock_find_in_range_node(phys_addr_t size,
					phys_addr_t align, phys_addr_t start,
					phys_addr_t end, int nid);
```

删除内存区：

```c
int __init_memblock memblock_remove_range(struct memblock_type *type,
					  phys_addr_t base, phys_addr_t size);
```

添加内存区:

```c
int __init_memblock memblock_add_range(struct memblock_type *type,
				phys_addr_t base, phys_addr_t size,
				int nid, unsigned long flags);
```

# 初始化

在x86_64的体系结构下，memblock_x86_fill函数，读取e820提供的内存视图对memblock进行初始化。

# 内存分配

使用memblock进行内存分配，主要是对memblock.reserve中的region操作，而memblock.memory保持不变。

# 资料

1.Linux kernel memory management Part 1.

https://0xax.gitbooks.io/linux-insides/content/MM/linux-mm-1.html

2.Linux内核初期内存管理---memblock

http://www.maxwellxxx.com/linuxmemblock

3.【理解Linux内存管理

https://blog.csdn.net/gatieme/article/category/6393814/1?