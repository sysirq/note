# Ext2文件系统

### 物理结构

#### 结构概观

块组是该文件系统的基本成分，容纳了文件系统的其他结构。每个文件系统都由大量块组组成，在硬盘上相继排布：

```
-----------------------------------------------------------------
|       |           | 数据  | inode |           |               |
|超级块 |  组描述符 | 位图  | 位图  |   inode表 |   数据库      |
|       |           |       |       |           |               |
-----------------------------------------------------------------
|1个块  |k个块      |1个块  | 1个块 | n个块     |   m个块       |

```

```
-----------------------------------------------------
|       |           |           |       |           |
|启动块 |   块组0   |   块组1   |   ... |   块组n   |
|       |           |           |       |           |
-----------------------------------------------------
```

- 超级块是用于存储文件系统自身元数据的核心结构。其中的信息包括空闲与已使用块的数目、块长度、当前文件系统状态（在启动时用于检测前一次崩溃）、各种时间戳（例如，上一次装载文件系统的时间以及上一次写入操作的时间）。它还包括一个表示文件系统类型的魔数，这样mount例程能够确认文件系统的类型是否正确。 
- 组描述符包含的信息反映了文件系统中各个块组的状态，例如，块组中空闲块和inode的数目。每个块组都包含了文件系统中所有块组的组描述符信息。 
- 数据块位图和inode位图用于保存长的比特位串。这些结构中的每个比特位都对应于一个数据块或inode，用于表示对应的数据块或inode是空闲的，还是被使用中。  
- inode表包含了块组中所有的inode，inode用于保存文件系统中与各个文件和目录相关的所有元数据。
- 数据块部分包含了文件系统中的文件的有用数据。

#### 间接

inode，间接索引数据块（直接块，一次间接块，二次间接块）

#### 碎片

Ext2文件系统尽力防止碎片。在无法避免碎片时，它试图将同一文件的块维持在同一个块组中。

### 数据结构

#### 超级块

超级块是文件系统的核心结构，保存了文件系统所有的特征数据。内核在装载文件系统时，最先看到的就是超级块的内容。超级块的数据使用ext2_read_super例程读取，内核通常借助file_system_type结构中的read_super函数指针来调用该函数。

```c
<ext2_fs.h>

struct ext2_super_block {
	__le32	s_inodes_count;		/* Inodes count */
	__le32	s_blocks_count;		/* Blocks count */
	__le32	s_r_blocks_count;	/* Reserved blocks count */
	__le32	s_free_blocks_count;	/* Free blocks count */
	__le32	s_free_inodes_count;	/* Free inodes count */
	__le32	s_first_data_block;	/* First Data Block */
	__le32	s_log_block_size;	/* Block size *///将块长度除以1024之后，再取以二为底的对数
	__le32	s_log_frag_size;	/* Fragment size */
	__le32	s_blocks_per_group;	/* # Blocks per group *///每个块组中块的数目
	__le32	s_frags_per_group;	/* # Fragments per group */
	__le32	s_inodes_per_group;	/* # Inodes per group *///每个块组中inode的数目
	__le32	s_mtime;		/* Mount time */
	__le32	s_wtime;		/* Write time */
	__le16	s_mnt_count;		/* Mount count *///计算了上一次检查以来装载操作的次数，
	__le16	s_max_mnt_count;	/* Maximal mount count *///两次检查之间可以执行的装载操作的大数目
	__le16	s_magic;		/* Magic signature *///魔数
	__le16	s_state;		/* File system state *///文件系统当前状态
	__le16	s_errors;		/* Behaviour when detecting errors */
	__le16	s_minor_rev_level; 	/* minor revision level */
	__le32	s_lastcheck;		/* time of last check *///上一次检查的日期
	__le32	s_checkinterval;	/* max. time between checks */
	__le32	s_creator_os;		/* OS */
	__le32	s_rev_level;		/* Revision level */
	__le16	s_def_resuid;		/* Default uid for reserved blocks *///指定了一个系统用户的用户ID与组ID，对该用户已经专门分配了一定数目的块。对应的块数存储在s_r_blocks_count中。这些块其他用户无法使用
	__le16	s_def_resgid;		/* Default gid for reserved blocks */
	/*
	 * These fields are for EXT2_DYNAMIC_REV superblocks only.
	 *
	 * Note: the difference between the compatible feature set and
	 * the incompatible feature set is that if there is a bit set
	 * in the incompatible feature set that the kernel doesn't
	 * know about, it should refuse to mount the filesystem.
	 * 
	 * e2fsck's requirements are more strict; if it doesn't know
	 * about a feature in either the compatible or incompatible
	 * feature set, it must abort and not try to meddle with
	 * things it doesn't understand...
	 */
	__le32	s_first_ino; 		/* First non-reserved inode */
	__le16   s_inode_size; 		/* size of inode structure */
	__le16	s_block_group_nr; 	/* block group # of this superblock */
	__le32	s_feature_compat; 	/* compatible feature set *///兼容特性
	__le32	s_feature_incompat; 	/* incompatible feature set *///不兼容特性
	__le32	s_feature_ro_compat; 	/* readonly-compatible feature set *///只读特性
	__u8	s_uuid[16];		/* 128-bit uuid for volume */
	char	s_volume_name[16]; 	/* volume name */
	char	s_last_mounted[64]; 	/* directory where last mounted */
	__le32	s_algorithm_usage_bitmap; /* For compression */
	/*
	 * Performance hints.  Directory preallocation should only
	 * happen if the EXT2_COMPAT_PREALLOC flag is on.
	 */
	__u8	s_prealloc_blocks;	/* Nr of blocks to try to preallocate*/
	__u8	s_prealloc_dir_blocks;	/* Nr to preallocate for dirs */
	__u16	s_padding1;
	/*
	 * Journaling support valid if EXT3_FEATURE_COMPAT_HAS_JOURNAL set.
	 */
	__u8	s_journal_uuid[16];	/* uuid of journal superblock */
	__u32	s_journal_inum;		/* inode number of journal file */
	__u32	s_journal_dev;		/* device number of journal file */
	__u32	s_last_orphan;		/* start of list of inodes to delete */
	__u32	s_hash_seed[4];		/* HTREE hash seed */
	__u8	s_def_hash_version;	/* Default hash version to use */
	__u8	s_reserved_char_pad;
	__u16	s_reserved_word_pad;
	__le32	s_default_mount_opts;
 	__le32	s_first_meta_bg; 	/* First metablock block group */
	__u32	s_reserved[190];	/* Padding to the end of the block */
};
```

超级块的长度总是1024字节。这是通过在结构末尾增加一个填充成员来解决的(s_reserved)

#### 组描述符

```c
<ext2_fs.h>
struct ext2_group_desc
{
	__le32	bg_block_bitmap;		/* Blocks bitmap block */
	__le32	bg_inode_bitmap;		/* Inodes bitmap block */
	__le32	bg_inode_table;		/* Inodes table block */
	__le16	bg_free_blocks_count;	/* Free blocks count */
	__le16	bg_free_inodes_count;	/* Free inodes count */
	__le16	bg_used_dirs_count;	/* Directories count */
	__le16	bg_pad;
	__le32	bg_reserved[3];
};
```

每个块组都包含许多组描述符，文件系统中的每个块组都对应于一个组描述符副本。因此从每个块组，都可以确定系统中所有其他块组的下列信息：

- 块和inode位图的位置
- inode表的位置
- 空闲块和inode的数目


#### inode

```c
struct ext2_inode {
	__le16	i_mode;		/* File mode *///访问权限和文件类型
	__le16	i_uid;		/* Low 16 bits of Owner Uid */
	__le32	i_size;		/* Size in bytes */
	__le32	i_atime;	/* Access time */
	__le32	i_ctime;	/* Creation time */
	__le32	i_mtime;	/* Modification time */
	__le32	i_dtime;	/* Deletion Time */
	__le16	i_gid;		/* Low 16 bits of Group Id */
	__le16	i_links_count;	/* Links count *///硬链接数目
	__le32	i_blocks;	/* Blocks count */
	__le32	i_flags;	/* File flags */
	union {
		struct {
			__le32  l_i_reserved1;
		} linux1;
		struct {
			__le32  h_i_translator;
		} hurd1;
		struct {
			__le32  m_i_reserved1;
		} masix1;
	} osd1;				/* OS dependent 1 */
	__le32	i_block[EXT2_N_BLOCKS];/* Pointers to blocks *///指向文件数据块的指针，默认情况下，EXT2_N_BLOCKS设置为12 + 3。前12个元素用于寻址直接块，后3个用于实现简单、二次和三次间接。
	__le32	i_generation;	/* File version (for NFS) */
	__le32	i_file_acl;	/* File ACL */
	__le32	i_dir_acl;	/* Directory ACL */
	__le32	i_faddr;	/* Fragment address */
	union {
		struct {
			__u8	l_i_frag;	/* Fragment number */
			__u8	l_i_fsize;	/* Fragment size */
			__u16	i_pad1;
			__le16	l_i_uid_high;	/* these 2 fields    */
			__le16	l_i_gid_high;	/* were reserved2[0] */
			__u32	l_i_reserved2;
		} linux2;
		struct {
			__u8	h_i_frag;	/* Fragment number */
			__u8	h_i_fsize;	/* Fragment size */
			__le16	h_i_mode_high;
			__le16	h_i_uid_high;
			__le16	h_i_gid_high;
			__le32	h_i_author;
		} hurd2;
		struct {
			__u8	m_i_frag;	/* Fragment number */
			__u8	m_i_fsize;	/* Fragment size */
			__u16	m_pad1;
			__u32	m_i_reserved2[2];
		} masix2;
	} osd2;				/* OS dependent 2 */
};

```

#### 目录和文件

对于Ext2文件系统，每个目录表示为一个inode，会对其分配数据块。数据块中包含了用于描述目录项的结构：

```c
<ext2_fs.h>
struct ext2_dir_entry_2 {
	__le32	inode;			/* Inode number */
	__le16	rec_len;		/* Directory entry length */  //偏移量，表示从rec_len字段末尾到下一个rec_len字段末尾的偏移量
	__u8	name_len;		/* Name length */
	__u8	file_type;
	char	name[EXT2_NAME_LEN];	/* File name */
};

enum {//文件类型
	EXT2_FT_UNKNOWN,
	EXT2_FT_REG_FILE,
	EXT2_FT_DIR,
	EXT2_FT_CHRDEV,
	EXT2_FT_BLKDEV,
	EXT2_FT_FIFO,
	EXT2_FT_SOCK,
	EXT2_FT_SYMLINK,
	EXT2_FT_MAX
};
```

文件的类型并未定义在inode自身，而是在对应目录项的file_type字段中。但对于不同的文件类型，inode的内容也会不同。应该注意到，只有目录和普通文件才会占用硬盘的数据块，所有其他类型都可以使用inode中的信息完全描述。

#### 内存中的数据结构

虚拟文件系统在struct super_block和struct inode结构分别提供了一个特定于文件系统的成员，名称分别是s_fs_inof和i_private。这两个数据成员由各种文件系统的实现使用，用于储存这两个结构中与文件系统无关的数据成员所未能涵盖的信息。Ext2文件系统将ext2_sb_info和ext2_inode_info结构用于该目的。后者与硬盘上的对应物相比，没什么特别之处。

```c
<ext2_fs_sb.h>
struct ext2_sb_info {
	unsigned long s_frag_size;	/* Size of a fragment in bytes */
	unsigned long s_frags_per_block;/* Number of fragments per block */
	unsigned long s_inodes_per_block;/* Number of inodes per block */
	unsigned long s_frags_per_group;/* Number of fragments in a group */
	unsigned long s_blocks_per_group;/* Number of blocks in a group */
	unsigned long s_inodes_per_group;/* Number of inodes in a group */
	unsigned long s_itb_per_group;	/* Number of inode table blocks per group */
	unsigned long s_gdb_count;	/* Number of group descriptor blocks */
	unsigned long s_desc_per_block;	/* Number of group descriptors per block */
	unsigned long s_groups_count;	/* Number of groups in the fs */
	unsigned long s_overhead_last;  /* Last calculated overhead */
	unsigned long s_blocks_last;    /* Last seen block count */
	struct buffer_head * s_sbh;	/* Buffer containing the super block */
	struct ext2_super_block * s_es;	/* Pointer to the super block in the buffer */
	struct buffer_head ** s_group_desc;
	unsigned long  s_mount_opt;//保存了装载选项
	unsigned long s_sb_block;//如果超级块不是从默认的块1读取，而是从其他块读取（在第一个超级块损坏的情况下），对应的块（相对值）保存在s_sb_block中。 
	uid_t s_resuid;
	gid_t s_resgid;
	unsigned short s_mount_state;//装载状态
	unsigned short s_pad;
	int s_addr_per_block_bits;
	int s_desc_per_block_bits;
	int s_inode_size;
	int s_first_ino;
	spinlock_t s_next_gen_lock;
	u32 s_next_generation;
	unsigned long s_dir_count;//目录的总数
	u8 *s_debts;//是一个指针，指向一个数组（数组项为8位数字，该数组通常比较短），每个数组项对应于一个块组
	struct percpu_counter s_freeblocks_counter;
	struct percpu_counter s_freeinodes_counter;
	struct percpu_counter s_dirs_counter;
	struct blockgroup_lock s_blockgroup_lock;
	/* root of the per fs reservation window tree */
	spinlock_t s_rsv_window_lock;
	struct rb_root s_rsv_window_root;
	struct ext2_reserve_window_node s_rsv_window_head;
};
```

### 创建文件系统

尽管mke2fs设计为处理块特殊文件，也可以将其用于块介质上的某个普通文件，并创建一个文件系统。这是因为根据UNIX的哲学“万物皆文件”，可以用同样的例程处理普通文件和块设备，至少从用户空间的角度来看是这样。在试验文件系统结构时，用普通文件代替块特殊文件是一种很好的方法，这无需访问保存了重要数据的现存文件系统，也不必费力处理缓慢的软驱。为此，我在下面简要 地讨论一下相关的操作。 

首先，使用dd标准实用程序，创建一个长度适宜的文件。 
```
wolfgang@meitner> dd if=/dev/zero of=img.1440 bs=1k count=1440  
1550+0 records in  
1440+0 records out  
 ```
这创建了一个长度为1.4 MiB的文件，与3.5英寸软盘的容量相同。该文件只包含字节0（即ASCII 值0），由/dev/zero产生。

mke2fs在该文件上创建一个文件系统： 
```
wolfgang@meitner> /sbin/mke2fs img.1440  
mke2fs 1.40.2 (12-Jul-2007)  
img.1440 is not a block special device.  
Proceed anyway? (y,n) y  
File System label=  
OS type: Linux  
Block size=1024 (log=0) 
Fragment size=1024 (log=0)  
184 inodes, 1440 blocks  
72 blocks (5.00%) reserved for the super user  
First data block=1  
Maximum file system blocks=1572864  
1 block group  
8192 blocks per group, 8192 fragments per group  
184 inodes per group 
...
```

空的文件系统没什么意思，因此我们需要一种方法，向示例文件系统填充数据。可使用环回接口 装载该文件系统，如下例所示： 
```
wolfgang@meitner> mount -t ext2 -o loop=/dev/loop0 img.1440 /mnt  
```

### 文件系统操作

虚拟文件系统和具体实现之间的关联大体上由3个结构建立，结构中包含了一系列的函数指针。所有的文件系统都必须实现该关联。 

- 用于操作文件内容的操作保存在file_operations中
- 用于此类文件对象自身的操作保存在inode_operations中
- 用于一般地址空间的操作保存在address_space_operations中

Ext2文件系统对不同的文件类型提供了不同的file_operations实例。很自然，最常用的变体是用于普通文件，定义如下：

```c
<fs/ext2/file.c>
const struct file_operations ext2_file_operations = {
	.llseek		= generic_file_llseek,
	.read		= do_sync_read,
	.write		= do_sync_write,
	.aio_read	= generic_file_aio_read,
	.aio_write	= generic_file_aio_write,
	.ioctl		= ext2_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= ext2_compat_ioctl,
#endif
	.mmap		= generic_file_mmap,
	.open		= generic_file_open,
	.release	= ext2_release_file,
	.fsync		= ext2_sync_file,
	.splice_read	= generic_file_splice_read,
	.splice_write	= generic_file_splice_write,
};
```

目录也有自身的file_operations实例。

```c
<fs/ext2/dir.c>
const struct file_operations ext2_dir_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.readdir	= ext2_readdir,
	.ioctl		= ext2_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= ext2_compat_ioctl,
#endif
	.fsync		= ext2_sync_file,
};
```

普通文件的inode_operations初始化如下:

```c
<fs/ext2/file.c>
const struct inode_operations ext2_file_inode_operations = {
	.truncate	= ext2_truncate,
#ifdef CONFIG_EXT2_FS_XATTR
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= ext2_listxattr,
	.removexattr	= generic_removexattr,
#endif
	.setattr	= ext2_setattr,
	.permission	= ext2_permission,
};
```

目录有更多可用的inode操作

```c
<fs/ext2/namei.c>
const struct inode_operations ext2_dir_inode_operations = {
	.create		= ext2_create,
	.lookup		= ext2_lookup,
	.link		= ext2_link,
	.unlink		= ext2_unlink,
	.symlink	= ext2_symlink,
	.mkdir		= ext2_mkdir,
	.rmdir		= ext2_rmdir,
	.mknod		= ext2_mknod,
	.rename		= ext2_rename,
#ifdef CONFIG_EXT2_FS_XATTR
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= ext2_listxattr,
	.removexattr	= generic_removexattr,
#endif
	.setattr	= ext2_setattr,
	.permission	= ext2_permission,
};
```

文件系统和块层通过address_space_operations关联

```c
<fs/ext2/inode.c>
const struct address_space_operations ext2_aops = {
	.readpage		= ext2_readpage,
	.readpages		= ext2_readpages,
	.writepage		= ext2_writepage,
	.sync_page		= block_sync_page,
	.write_begin		= ext2_write_begin,
	.write_end		= generic_write_end,
	.bmap			= ext2_bmap,
	.direct_IO		= ext2_direct_IO,
	.writepages		= ext2_writepages,
	.migratepage		= buffer_migrate_page,
};
```

用于与超级块交互

```c
<fs/ext2/super.c>
static const struct super_operations ext2_sops = {
	.alloc_inode	= ext2_alloc_inode,
	.destroy_inode	= ext2_destroy_inode,
	.read_inode	= ext2_read_inode,
	.write_inode	= ext2_write_inode,
	.delete_inode	= ext2_delete_inode,
	.put_super	= ext2_put_super,
	.write_super	= ext2_write_super,
	.statfs		= ext2_statfs,
	.remount_fs	= ext2_remount,
	.clear_inode	= ext2_clear_inode,
	.show_options	= ext2_show_options,
#ifdef CONFIG_QUOTA
	.quota_read	= ext2_quota_read,
	.quota_write	= ext2_quota_write,
#endif
};
```

#### 装载和卸载

```c
<fs/ext2.super.c>
static struct file_system_type ext2_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "ext2",
	.get_sb		= ext2_get_sb,
	.kill_sb	= kill_block_super,
	.fs_flags	= FS_REQUIRES_DEV,
};
```

mount系统调用根据get_sb来读取文件系统超级块的内容。

```c
fs/ext2/super.c  
static int ext2_get_sb(struct file_system_type *fs_type,
                      int flags, const char *dev_name, void *data, struct vfsmount *mnt)  
{    
    return get_sb_bdev(fs_type, flags, dev_name, data, ext2_fill_super, mnt);  
}  
```

ext2_fill_super用数据填充一个超级块对象

#### 读取并产生数据块和间接块

- 找到数据块
- 
ext2_get_block是一个关键函数，它将Ext2的实现与虚拟文件系统的默认函数关联起来（get_block_t）。

```c
<fs.h>  
typedef int (get_block_t)(struct inode *inode, sector_t iblock,
                struct buffer_head *bh_result, int create);  
```

该函数不仅读取块，还从内存向块设备的数据块写入数据。