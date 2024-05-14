# 结构

磁盘结构：

启动块--块组0--块组1--块组2--块组3

块组结构：

超级块--组描述符块（全部组的）--数据位图--inode位图--inode表--数据

# 磁盘中的数据结构

### 超级块

```c
static struct file_system_type ext2_fs_type;

ext2_super_block
```

### 组描述符

```c
struct ext2_group_desc;
```

### inode

```c
struct ext2_inode;
```

### 目录

```c
struct ext2_dir_entry_2;

typedef struct ext2_dir_entry_2 ext2_dirent;
```

# 内存中的数据结构

虚拟文件系统在struct super_block和struct inode结构分别提供了一个特定于文件系统的成员，名称分别是s_fs_info和i_private。这两个数据成员由各种文件系统的实现使用，用于存储这两个结构中与文件系统无关的数据成员所未能涵盖的信息。Ext2文件i同将ext2_sb_info和ext2_inode_info结构用于该目的。

# 文件系统操作

虚拟文件系统和具体实现之间的关联大体上由4个结构建立，结构中包含了一系列的函数指针。所有的文件系统都必须实现该关联。

- file_operations
- inode_operations
- address_space_operations
- super_oprations

Ext2对不同的文件类型提供了不同的file_operations实例，对于普通文件:ext2_file_operations(大多数指向VFS的标准函数)。对于目录:ext2_dir_operations。

inode_operations实例，对于普通文件为:ext2_file_inode_operations。对于目录:ext2_dir_inode_operations。

address_space_operations实例，ext2_aosp

super_operations:ext2_sops

# file_system_type

ext2_fs_type

# 文件系统操作

### 装载

ext2_fill_super:读取磁盘上的超级块与组块描述符，并建立与super_block、ext2_super_info之间的关系

### 读取并产生数据块和间接块

ext2_get_block

### 创建和删除inode

ext2_create

ext2_mkdir

# 资料

认识 EXT2 文件系统

https://www.cnblogs.com/ggjucheng/archive/2012/08/22/2651641.html

Linux Ext2 文件系统分析

https://www.ibm.com/developerworks/community/blogs/5144904d-5d75-45ed-9d2b-cf1754ee936a/entry/linux_ext2_%25e6%2596%2587%25e4%25bb%25b6%25e7%25b3%25bb%25e7%25bb%259f%25e5%2588%2586%25e6%259e%2590?lang=en

深入解析 ext2 文件系统

http://blog.chinaunix.net/uid-24774106-id-3266816.html

Why do inode numbers start from 1 and not 0?

https://stackoverflow.com/questions/2099121/why-do-inode-numbers-start-from-1-and-not-0

Why does '/' have the inode 2?

https://unix.stackexchange.com/questions/198673/why-does-have-the-inode-2