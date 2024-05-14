slub分配器特点是简化设计理念，并同时保留slab分配器的设计思想：每个缓存由多个slab组成，每个slab包含多个对象。

# 初始化

start_kernel --> mm_init --> kmem_cache_init

kmem_cache_init:初始化 用于分配 struct kmem_cache 与 struct kmem_cache_node 的缓存，，并初始化用于kmalloc的缓存

# 创建过程

kmem_cache_create --> kmem_cache_sanity_check（进行参数安全检查），__kmem_cache_alias（检查是否存在满足创建条件的cache,如果存在满足条件的cache，直接返回），do_kmem_cache_create（创建cache）

__kmem_cache_alias-->find_mergeable:检查是否可以合并

```c
<mm/slab_common.c>

struct kmem_cache *find_mergeable(size_t size, size_t align,
		unsigned long flags, const char *name, void (*ctor)(void *))
{
	struct kmem_cache *s;

	if (slab_nomerge || (flags & SLAB_NEVER_MERGE))
		return NULL;

	if (ctor)
		return NULL;

	size = ALIGN(size, sizeof(void *));
	align = calculate_alignment(flags, align, size);
	size = ALIGN(size, align);
	flags = kmem_cache_flags(size, flags, name, NULL);

	list_for_each_entry_reverse(s, &slab_caches, list) {
		if (slab_unmergeable(s))//该slab是否可以合并
			continue;

		if (size > s->size)//大小检查
			continue;

		if ((flags & SLAB_MERGE_SAME) != (s->flags & SLAB_MERGE_SAME))//标志检测
			continue;
		/*
		 * Check if alignment is compatible.
		 * Courtesy of Adrian Drzewiecki
		 */
		if ((s->size & ~(align - 1)) != s->size)//对齐检查
			continue;

		if (s->size - size >= sizeof(void *))
			continue;

		if (IS_ENABLED(CONFIG_SLAB) && align &&
			(align > s->align || s->align % align))
			continue;

		return s;
	}
	return NULL;
}
```

do_kmem_cache_create(创建 struct kmem_cache结构) --> __kmem_cache_create（初始化struct kmem_cache结构，位于mm/slub中）:

__kmem_cache_create --> kmem_cache_open:

kmem_cache_open --> calculate_sizes:计算分配slab的页介数，以及一个slab中的对象数。

kmem_cache_open --> init_kmem_cache_nodes:分配并初始化kmem_cache_node节点

kmem_cache_open --> alloc_kmem_cache_cpus:分配并初始化kmem_cache_cpu

# 分配

自底向上

alloc_slab_page:分配一个slab(也就是page 结构,从伙伴系统中分配)。slub分配器重用page结构作为slab描述符。

allocate_slab:调用alloc_slab_page分配一个slab，并对slab进行初始化（将page结构中的objects设置为一个slab中具有的对象个数）。

new_slab调用allocate_slab：并进一步对分配的slab进行初始化。将page结构的slab_cache指向相应的kmem_cache结构，设置page标志，利用page中的空闲对象，构造一个空闲对象单链表，将page->freelist指向第一个空闲对象。设置page->inuse为slab中的对象个数。

kmem_cache_alloc --> slab_alloc --> slab_alloc_node

slab_alloc_node:在当前kmem_cache_cpu中没有空闲对象，或则当前slab的节点不匹配的情况下，调用__slab_alloc，否则该函数返回获得的对象。

分配过程：

首先尝试从CPU slab中分配，如果分配失败，尝试从CPU partial slab中分配，如果失败则从node partial slab中分配，如果失败，申请新的slab。

# 释放过程

kmem_cache_free --> slab_free:如果当前对象属于当前CPU slab，则直接释放。否则调用 __slab_free。(参考资料3)

# 销毁

kmem_cache_destroy --> __kmem_cache_shutdown --> kmem_cache_close

# 资料

0.Linux SLUB 分配器详解

https://www.ibm.com/developerworks/cn/linux/l-cn-slub/index.html

1.【linux内存源码分析】slub分配算法（1）

https://www.jeanleo.com/2018/09/07/%e3%80%90linux%e5%86%85%e5%ad%98%e6%ba%90%e7%a0%81%e5%88%86%e6%9e%90%e3%80%91slub%e5%88%86%e9%85%8d%e7%ae%97%e6%b3%95%ef%bc%881%ef%bc%89/

2.slub分配器

http://www.wowotech.net/memory_management/247.html

3.图解slub算法过程

https://blog.csdn.net/lukuen/article/details/6935068

4.图解slub内存分配器

https://my.oschina.net/fileoptions/blog/1630346