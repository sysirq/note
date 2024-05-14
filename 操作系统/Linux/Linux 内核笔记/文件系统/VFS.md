从功能的角度来看，文件系统可以划分为以下几种：

- 磁盘文件系统(ext3、ext4)
- 网络文件系统(nfs、smbfs)
- 虚拟文件系统(procfs、sysfs)

# 关键数据结构

### superblock

存储用于挂载文件系统时，会用到的信息。

- inode and blocks locations
- file system block size
- maximum filename length
- maximum file size
- the location of the root inode

struct super_block、struct super_operations

### inode

保存文件信息

- file type
- file size
- access rights
- access or modify time
- location of data on the disk

注意：inode不会保存文件名称，文件名称保存在dentry中，这样，一个inode可以有多个文件名

struct inode、struct inode_operations

### file

File is the component of the file system model that is closest the user.The structure exists only as a VFS entity in memory and has no physical correspondent on disk.

包含的信息:

- file cursor position
- file opening rights
- pointer to the associated inode


struct file 、struct file_operations

### dentry

用于关联inode和文件名。

其包含的信息:

- an integer that identifies the inode
- a string representing its name

注意：the dentry has a correspondent on the disk.but the correspondence is not direct because each file system keeps the dentries in a specific way

struct dentry、struct dentry_operations

# 注册和卸载文件系统

The structure describing a particular file system is struct file_system_type:

```c
#include <linux/fs.h>

struct file_system_type {
         const char *name;
         int fs_flags;
         struct dentry *(*mount) (struct file_system_type *, int,
                                   const char *, void *);
         void (*kill_sb) (struct super_block *);
         struct module *owner;
         struct file_system_type * next;
         struct hlist_head fs_supers;
         struct lock_class_key s_lock_key;
         struct lock_class_key s_umount_key;
         //...
};
```

- name is a string representing the name that will identify a file system(the argument passed to mount -t)
- owner is THIS_MODULE for file systems implemented in modules,and NULL if they are written directly into the kernel.
- The mount function reads the superblock from the disk in memory when loading the file system.The function is unique to each file system.
- The kill_sb function releases the super-block from memory.
- fs_flags specifies the flags with the file system must be mounted.
- fs_supers is a list containing all the superblocks associated with this file system.Since the same file system can be mounted multiple times,there will be a separate superblock for each mount.


函数:register_filesystem、unregister_filesystem


# Functions mount、kill_sb

# Superblock in VFS

A superblock will contain information about the block device used,the list of inodes,a pointer to the inode of the file system root directory,and a pointer to the superblock operations

```c
struct super_block {
        //...
        dev_t                   s_dev;              /* identifier */
        unsigned char           s_blocksize_bits;   /* block size in bits */
        unsigned long           s_blocksize;        /* block size in bytes */
        unsigned char           s_dirt;             /* dirty flag */
        loff_t                  s_maxbytes;         /* max file size */
        struct file_system_type *s_type;            /* filesystem type */
        struct super_operations *s_op;              /* superblock methods */
        //...
        unsigned long           s_flags;            /* mount flags */
        unsigned long           s_magic;            /* filesystem’s magic number */
        struct dentry           *s_root;            /* directory mount point */
        //...
        char                    s_id[32];           /* informational name */
        void                    *s_fs_info;         /* filesystem private info */
};

struct super_operations {
       //...
       int (*write_inode) (struct inode *, struct writeback_control *wbc);
       struct inode *(*alloc_inode)(struct super_block *sb);
       void (*destroy_inode)(struct inode *);

       void (*put_super) (struct super_block *);
       int (*statfs) (struct dentry *, struct kstatfs *);
       int (*remount_fs) (struct super_block *, int *, char *);
       //...
};
```

- the physical device on which it resides
- block size
- the maximum size of a file
- fie system type
- the operations it supports
- magic number
- the root directory dentry


# Buffer cache

struct buffer_head:

- b_data,pointer to a memory area where the data was read from or where the data must be written to
- b_size,buffer size
- b_bdev,the block device
- b_blocknr,the number of block on the device that has been loaded or needs to be saved on the disk
- b_state,the status of the buffer

Functions and useful macros

- S_ISDIR(inode->i_mode)
- S_ISREG(inode->i_mode)

# 装载与卸载

### vfsmount

每个装载的文件系统都对应于一个vfsmount结构的实例。其关键字段：

- mnt_mntpoint是当前文件系统的装载点在其父目录中的dentry结构。
- mnt_root文件系统本身的相对根目录所对应的dentry保存在mnt_root中。
- mnt_sb指针建立了与相关的超级块之间的关联
- mnt_parent指向父文件系统的vfsmount结构
- mnt_mounts如果当前文件系统下挂载了其他的子文件系统，那么这些子文件系统通过自身vfsmount中的mnt_child字段组成的一个链表，该链表头为父文件系统中的mnt_mounts字段。

### super_block

在装载新文件系统时，vfsmount并不是唯一需要在内存中创建的结构。装载操作开始于超级块的读取。

其关键字段

- s_blocksize、s_blocksize_bits指定了文件系统的块长度。
- s_maxbytes保存了文件系统可以处理的最大文件长度。
- s_type指向文件系统类型的指针
- s_root将超级块与全局根目录的dentry项关联起来。
- s_dirty是一个表头，用于脏inode的链表
- s_dirt是一个简单的整型变量，指示超级块是否变脏
- s_fs_info 私有数据指针

### 函数

sys_mount、sys_umount

# inode 查找

主要函数为:link_path_walk

# 资料

File system drivers (Part 1)

https://linux-kernel-labs.github.io/master/labs/filesystems_part1.html

File system drivers (Part 2)

https://linux-kernel-labs.github.io/master/labs/filesystems_part2.html#lab-objectives

Linux内核文件系统挂载分析

https://edsionte.com/techblog/archives/4389

linux文件系统之mount流程分析

https://www.cnblogs.com/cslunatic/p/3683117.html

解析 Linux 中的 VFS 文件系统机制

https://www.ibm.com/developerworks/cn/linux/l-vfs/index.html