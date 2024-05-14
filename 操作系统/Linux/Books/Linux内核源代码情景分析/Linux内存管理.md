# 主要函数以及数据结构

内核地址空间中，虚拟地址与物理地址之间的转换函数：

```c
#include <asm/page.h>

__pa(x); //将x虚拟地址转换为物理地址

__va(x); //将x物理地址转换为虚拟地址

```

pgd、pud、pmd、pt表中的数据结构:

```c
#include <asm/pgtable_types.h>

typedef struct { pgdval_t pgd; } pgd_t;

typedef struct { pudval_t pud; } pud_t;

typedef struct { pmdval_t pmd; } pmd_t;

typedef struct { pteval_t pte; } pte_t;

typedef unsigned long	pteval_t;

typedef unsigned long	pmdval_t;

typedef unsigned long	pudval_t;

typedef unsigned long	pgdval_t;

typedef unsigned long	pgprotval_t;

typedef struct pgprot { pgprotval_t pgprot; } pgprot_t; //用于描述页面属性的

```

page frame到page结构的转换

```c
#include <asm-generic/memory_model.h>

#define pfn_to_page __pfn_to_page

page_to_pfn

```

由于现在内存模型为SPARSEMEM模型，所以现在pfn到page结构的转换并不是像以前一样通过mem_map page数组计算得到。

稀疏内存的初始化是在paging_init函数中进行的

判断pfn是否有效：

```c
#include <linux/mmzone.h>
static inline int pfn_valid(unsigned long pfn)
{
	if (pfn_to_section_nr(pfn) >= NR_MEM_SECTIONS)
		return 0;
	return valid_section(__nr_to_section(pfn_to_section_nr(pfn)));
}
```

Linux 内核中，每一页物理内存都属于特定的区,如ZONE_DMA、ZONE_DMA32、ZONE_NORMAL、ZONE_HIGHMEM等。内核中用struct zone 代表一个该内存区。每一个内存区都属于特定的结点，每个结点用pg_data_t或pglist_data结构表示。

遍历pg_data_t结构，以及其中的zone结构的代码如下:

```c
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <asm/mmzone_64.h>

static int __init my_test_init(void)
{
	int i = 0;
	int j;
	struct zone *zone;
	printk("my test init\n");
	
	for(i = 0;i<MAX_NUMNODES;i++){
		if( !node_data[i] || !node_data[i]->node_present_pages )continue;

		printk("node id:%d\n",i);
		printk("node_start_pfn:%ld\n",node_data[i]->node_start_pfn);
		printk("node_present_pages:%ld\n",node_data[i]->node_present_pages);
		printk("node_spanned_pages:%ld\n",node_data[i]->node_spanned_pages);

		for(j = 0; j<MAX_NR_ZONES;j++){
			zone = &node_data[i]->node_zones[j];
			if(zone->present_pages == 0) continue;
			printk("	zone id:%d\n",j);
			printk("	zone_start_pfn:%ld\n",zone->zone_start_pfn);
			printk("	zone_present_pages:%ld\n",zone->present_pages);
			printk("	zone_spanned_pages:%ld\n",zone->spanned_pages);
		}
	}

	for(i = 1048576;i<1048576+262144+20;i++){
		if(!pfn_valid(i)){
			printk("pfn not valid:%d\n",i);
		}
	}

	return 0;
}

static void __exit my_test_exit(void)
{
	printk("my test exit\n\n");
}

MODULE_LICENSE("GPL");
module_init(my_test_init);
module_exit(my_test_exit);
```

每个进程的虚拟地址空间用struct mm_struct 结构表示，虚拟空间中的一个个虚拟空间段用struct vm_area_struct表示。

遍历某进程虚拟地址空间中的vma结构

```c
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched/signal.h>
#include <asm/pgtable_types.h>

static int __init my_test_init(void)
{
	struct task_struct *ptask;
	struct vm_area_struct *vma;
	
	int mypid = 4831;

	for_each_process(ptask){
		if(ptask->pid == mypid) break;
	}
	if(ptask->pid != mypid) return -1;

	vma = ptask->mm->mmap;
	
	for( vma ; vma ; vma=vma->vm_next ){
		printk("0x%lx -------- 0x%lx\n",vma->vm_start,vma->vm_end);
	}

	return 0;
}

static void __exit my_test_exit(void)
{
	printk("my test exit\n\n");
}

MODULE_LICENSE("GPL");
module_init(my_test_init);
module_exit(my_test_exit);
```

find_vma函数用于在一个虚拟地址空间中，找到一个对应地址的一个虚拟地址区间。


中断：当发生中断的时候，CPU会将下一条指令压栈，做为返回时去执行的指令。

异常：当发生异常的时候，CPU会将导致异常的（未执行完成）指令压栈，做为返回时执行的指令。

因此缺页中断叫法是错误的，应该被称为缺页异常。

# 内存中越界访问

情景：用户mmap一段空间，建立了一段虚拟空间区间，然后unmap掉了，用户再去访问该区间会造成越界访问。

do_page_fault的处理流程：

- 通过读取cr2寄存器，得到映射失败的线性地址
- 通过find_vma查找包含该线性地址的vma
- 没有找到，则发生越界访问，向程序发送SIGSEGV信号,程序退出。

# 用户堆栈扩展

do_page_fault的处理流程：

- 通过读取cr2寄存器，得到映射失败的线性地址
- 判断该地址是否在sp指针下方的一段空间中
- 调用expand_stack，扩展堆栈区对应的vma的大小
- 调用handle_mm_fault->handle_pte_fault->do_anonymous_page
- do_anonymous_page中建立映射

# 物理页面的使用和周转

当一个pte_t指向的数据在物理内存中时，则该pte指向物理内存地址。如果数据已经被换出，则该pte_t变成一个swp_entry_t，指向数据所在交换设备的页号。

swap_info_struct 结构的数组 swap_info

swap_avail_head链表中保存所有可用的swap_info_struct（空间还没有使用完的），swap_active_head 链表保存所有的swap_info_struct

swp_entry_t分为4个部分：
- 第一部分：offset（页在交换设备的位置）
- 第二部分：type（指页面在那个交换设备中）
- 第三部分：radix_tree部分
- 第四部分：P位

```c
static inline swp_entry_t swp_entry(unsigned long type, pgoff_t offset);
static inline unsigned swp_type(swp_entry_t entry);
static inline pgoff_t swp_offset(swp_entry_t entry);
static inline swp_entry_t pte_to_swp_entry(pte_t pte);
```

释放交换页面的函数:

mm/swapfile.c:swap_free

获得一个交换页面的函数：

mm/swapfile.c:get_swap_page

将一个页面加入swap cache中

mm/swap_state.c:add_to_swap_cache


注意，只有用户空间中的页面是可以回收的，内核空间中的页面是不可以回收的。在缺页中断中，每次分配的页，都会加入到对应的LRU链表中

遍历page LRU的操作：

```c
static int __init simple_init(void)
{
	int i = 0;
	int j;
	int k;
	struct zone *zone;
	struct lruvec *lruvec;
	unsigned long flags = 0;
	int lru_count;
	const char *str;

	printk("simple module init\n");
	
	for(i = 0;i<MAX_NUMNODES;i++){
		if( !node_data[i] || !node_data[i]->node_present_pages )continue;

		printk("node id:%d\n",i);
		printk("node_start_pfn:%ld\n",node_data[i]->node_start_pfn);
		printk("node_present_pages:%ld\n",node_data[i]->node_present_pages);
		printk("node_spanned_pages:%ld\n",node_data[i]->node_spanned_pages);

		for(j = 0; j<MAX_NR_ZONES;j++){
			zone = &node_data[i]->node_zones[j];
			if(zone->present_pages == 0) continue;
			
			
			printk("\tzone id:%d\n",j);
			printk("\tzone_start_pfn:%ld\n",zone->zone_start_pfn);
			printk("\tzone_present_pages:%ld\n",zone->present_pages);
			printk("\tzone_spanned_pages:%ld\n",zone->spanned_pages);

			spin_lock_irqsave(&zone->lru_lock,flags);
			lruvec = &zone->lruvec;
			for(k = LRU_INACTIVE_ANON;k<NR_LRU_LISTS;k++){
				switch(k){
				case LRU_INACTIVE_ANON:
					str="LRU_INACTIVE_ANON";
					break;
				case LRU_ACTIVE_ANON:
					str="LRU_ACTIVE_ANON";
					break;
				case LRU_INACTIVE_FILE:
					str="LRU_INACTIVE_FILE";
					break;
				case LRU_ACTIVE_FILE:
					str="LRU_ACTIVE_FILE";
					break;
				case LRU_UNEVICTABLE:
					str="LRU_UNEVICTABLE";
					break;
				default:
					printk("error???????\n");
				}

				if(list_empty(&lruvec->lists[k])){
					printk("\t\t%s empty\n",str);
				}else{
					struct page *page;
					lru_count = 0;
					list_for_each_entry(page,&lruvec->lists[k],lru){
						lru_count++;
					}
					printk("\t\t%s not empty,page count:%d\n",str,lru_count);
				}

			}
			spin_unlock_irqrestore(&zone->lru_lock,flags);
		}
	}

	return 0;
}
```

输出：

```
[ 1693.905195] simple module init
[ 1693.909260] node id:0
[ 1693.913126] node_start_pfn:1
[ 1693.916800] node_present_pages:65406
[ 1693.920792] node_spanned_pages:65503
[ 1693.924600] 	zone id:0
[ 1693.929347] 	zone_start_pfn:1
[ 1693.933641] 	zone_present_pages:3998
[ 1693.937466] 	zone_spanned_pages:4095
[ 1693.941177] 		LRU_INACTIVE_ANON not empty,page count:36
[ 1693.941177] 		LRU_ACTIVE_ANON not empty,page count:139
[ 1693.941177] 		LRU_INACTIVE_FILE not empty,page count:184
[ 1693.941177] 		LRU_ACTIVE_FILE not empty,page count:405
[ 1693.941177] 		LRU_UNEVICTABLE empty
[ 1693.960620] 	zone id:1
[ 1693.964087] 	zone_start_pfn:4096
[ 1693.968114] 	zone_present_pages:61408
[ 1693.972089] 	zone_spanned_pages:61408
[ 1693.975919] 		LRU_INACTIVE_ANON not empty,page count:400
[ 1693.975919] 		LRU_ACTIVE_ANON not empty,page count:1908
[ 1693.975919] 		LRU_INACTIVE_FILE not empty,page count:2479
[ 1693.975919] 		LRU_ACTIVE_FILE not empty,page count:5168
[ 1693.975919] 		LRU_UNEVICTABLE empty
[ 1704.263177] simple module exit
```

# 物理页面的分配

函数：struct page * alloc_pages(gfp_t gfp_mask,unsigned order);

2.4.0内核代码内存分配流程：

1.首先获得当前CPU所在节点结构（pg_data_t）。然后根据分配标志（gfp_mask）得到分配策略（pg_data_t结构中的node_zonelists数组元素）

2.当发现可分配页面短缺时，唤醒kswapd和bdflush两个线程

3.如果分配策略中的zone有满足：空闲内存页的数量，在low水平之上，则分配

4.如果现在还是没有分配到页面，则考虑分配策略中zone中的不活跃干净页面

5.如果还是没有分配到页面，则考虑回写不活跃脏页面，让其变为不活跃干净页面（分配大块内存时）。

6.如果还是没有分配到页面，则以min阈值进行页面分配

7.还是没有分配到页面，则说明系统有问题。

内存分配失败的原因有两种方面，一种是系统中可分配内存页面的总量实在已经太少了，二是分配的是大块内存，而系统中当前没有大块内存

4.0.0内核代码内存分配流程：

快速分配：

1.还是先获得分配策略(node_zonelists)

2.检查分配策略中的每个zone：检查空闲内存是否在指定水位之上的，如果在则尝试从其分配，没有的话，看能不能进行页面回收，如果可以的话，先进行页面回收在进行判断水位、分配。

如果还是没分配到内存则进入到慢速分配:

1.唤醒kswapd进程

2.尝试分配

3.如果失败，则判断是否可以在低水位下进行分配

4.进行页面compaction，在进行分配(异步)

5.进行页面compaction，在进行分配(同步)

# 内存回收

kswapd守护进程：

1.判断可供分配的页面是否短缺（inactive_shortage函数和free_shortage函数）

2.如果页面短缺，先尝试将不活跃脏页面写出，变成不活跃干净页面（page_launder函数），在不活跃脏页面链表中，有大概率该页面已经是干净的，可以直接将其移动到不活跃干净页面。（不活跃干净页面可以用来直接分配）

3.如果页面还是短缺，将活跃队列中的页面老化(refill_inactive)，调用swap_out将一个进程中满足条件的活跃页面转移到不活跃脏页面队列中（第一步总是转入到不活跃脏页面队列中）。

对各种（不活跃、活跃）队列中页面的扫描次数的增加，会使页面的老化速度也增加。因此页面的寿命实际上是以扫描的次数为单位的。

新版内核中：

对内存管理区调用shrink_zone --》 shrink_lruvec --》 shrink_list --》 shrink_active_list和shrink_inactive_list --》shrink_page_list进行页面回收。页面属于某个内存管理区zone的lru（lruvec字段）链表中（（匿名、映射）活跃、不活跃）（在缺页异常时加入页对应内存管理区的lru链表中）。

# 内核缓冲区的管理

在slab方法中，每个重要的数据结构都有一个自己的专用缓冲区队列，每个队列中的对象个数是动态变化的，不够时临时添加。

每个对象的缓冲区队列并非由各个对象直接构成，而是由一连串的“大块”（slab）构成，每个大块中则包含对象。

缓冲区队列中的大块（slab）根据对象的使用状态处于三种状态中：完全分配完毕，部分分配，处于空闲状态

每个大块（slab）上有个对象链接数组，用来实现一个空闲对象链。

每个大块（slab）的头部有一个小小的区域是不使用的，称为着色区。用于将同一对象缓冲区中，不同大块（slab）中的相对位置相同的对象错开，改善高速缓存的效率。

树形结构：

- 总根cache_cache是一个kmem_cache_t结构，用来维持第一层slab队列，这些slab上的对象都是kmem_cache_t数据结构。
- 每个第一层slab上的每个对象，即kmem_cache_t数据结构都是队列头，用来维持一个第二层slab队列。
- 第二层队列基本上都是某种对象，即数据结构专用的。
- 每个第二层slab上都维持着一个空闲对象队列。

其中，最高层次的slab队列是cache_cache，队列中的每个slab载有若干个kmem_cache_t数据结构。而这样的数据结构又是某个数据结构的缓冲区头部。

```c
void *kmem_cache_alloc(kmem_cache_t *cachep,int flags);
void *kmem_cache_free(kmem_cache_t *cachep,void *objp);

void *kmalloc(size_t size,int flags);
void kfree(const void *objp);

void *vmalloc(unsigned long size);
void vfree(void *addr);
```

当数据结构较大时，因而不属于“小对象”时，slab的结构略有不同。不同之处是不将slab的控制结构放在它所代表的slab上，而是将其游离出来，集中放在另外的slab上。

kswap扫描各个slab队列，找出和收集空闲不用的slab，并释放所占用的页面。

### 专用缓冲区队列的建立

kmem_cache_create:

1.首先从cache_cache中分配一个kmem_cache_t结构

2.进行一些列的计算，以确定最佳的slab构成（包括一个slab由几个页面构成，划分成多少个对象）

### 缓冲区的分配与释放

kmem_cache_alloc:

1.查看是否有空闲slab，如果没有则分配一个slab

2.否则从已有的slab中，分配一个对象

对于分配用于slab的每个页面的page数据结构，要通过宏操作SET_PAGE_CACHE和SET_PAGE_SLAB，设置其链接指针prev和next，使它们分别指向所属的slab和slab队列。同时，还要把page结构中的PG_slab标志位设置为1.


kmem_cache_free:

根据释放后，slab的状态（空闲、部分空闲）做相应处理

# 外部设备存储空间的地址映射

ioremap、iounmap函数

对于内存页面的管理，通常我们都是先从虚拟空间分配一个虚拟区间，然后为虚拟区间分配相应的物理内存页面并建立映射。

ioremap：

先从内核虚拟地址空间中分配一个虚拟地址区间（内核的内存描述符为init_mm，内核的虚拟地址区间描述符为vm_struct（vm_area_struct是用户虚拟地址区间描述符），链接成为vmlist链表），然后在建立到外部设备存储空间的映射。

mmap

# 资料

关于稀疏内存实验的总结

https://blog.csdn.net/huyahuioo/article/details/53286445

Linux内核资料集合

http://140.120.7.21/