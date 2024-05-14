# kmalloc

```c
#include <linux/slab.h>

void *kmalloc(size_t size,int flags);

void kfree(void *addr);
```

flags:

```c
GFP_ATOMIC:
    Used to allocate memory from interrupt handlers and other code outside of a process context.Never sleeps

GFP_KERNEL：
    Normal allocation of kernel memory,May sleep.
    
GFP_USER
    Used to allocate memory for user-space pages; it may sleep.
GFP_HIGHUSER
    Like GFP_USER,  but  allocates  from  high  memory,  if  any.  High  memory  is described in the next subsection.
GFP_NOIO
GFP_NOFS
    These flags function like GFP_KERNEL, but they add restrictions on what the ker-nel can do to satisfy the request. A GFP_NOFS allocation is not allowed to perform 

The allocation flags listed above can be augmented by an ORing in any of the follow-ing flags, which change how the allocation is carried out:

__GFP_DMA
    This flag requests allocation to happen in the DMA-capable memory zone. The exact meaning is platform-dependent and is explained in the following section.
__GFP_HIGHMEM 
    This flag indicates that the allocated memory may be located in high memory.
__GFP_COLD
    Normally, the memory allocator tries to return “cache warm” pages—pages that are likely to be found in the processor cache. Instead, this flag requests a “cold” page, which has not been used in some time. It is useful for allocating pages for DMA reads, where presence in the processor cache is not useful. See the section“Direct Memory Access” in Chapter 1 for a full discussion of how to allocate DMA buffers.
__GFP_NOWARN
    This  rarely  used  flag  prevents  the  kernel  from  issuing  warnings  (with printk)when an allocation cannot be satisfied
__GFP_HIGH
    This flag marks a high-priority request, which is allowed to consume even thelast pages of memory set aside by the kernel for emergencies.
__GFP_REPEAT
__GFP_NOFAIL
__GFP_NORETRY
    These flags modify how the allocator behaves when it has difficulty satisfying anallocation.__GFP_REPEAT means “try a little harder” by repeating the attempt—but the allocation can still fail. The__GFP_NOFAIL flag tells the allocator never to fail; it works as hard as needed to satisfy the request. Use of__GFP_NOFAILis very strongly discouraged; there will probably never be a valid reason to use it in adevice driver. Finally,__GFP_NORETRY tells the allocator to give up immediately ifthe requested memory is not available.
```

#### Memory zones

The Linux kernel knows about a minimum of three memory zones: DMA-capable memory,normal memory,and high memory.

ZONE_DMA:是低内存的一块区域，用于DMA

ZONE_NORMAL:属于该区域的内存，被内核直接映射到线性地址

ZONE_HIGHMEM:是系统中剩下的可用内存，但是因为内核地址空间有限，这部分内存不能直接映射到内核。

links:http://www.ilinuxkernel.com/files/Linux_Physical_Memory_Description.pdf

#### The Size Argument

the smallest allocation that kmalloc can handle is as big as 32 or 64 bytes,depending on the page size used by the system's architecture.

If your code is to be completely portable,it cannot count on being able to allocate anything larger than 128KB.

# Lookaside Caches

```c
#include <linux/slab.h>

kmem_cache *kmem_cache_create(const char *name,size_t size,size_t offset,unsigned long flags,void (*ctor)(void*));

void *kmem_cache_alloc(kmem_cache *cache,int flags);

void kmem_cache_free(kmem_cache *cache,const void *obj);

void kmem_cache_destroy(kmem_cache *cache);
```

# Memory pools

There are place in the kernel where memory allocations cannot be allowd to fail.

```c
#include <linux/mempool.h>

typedef void *(mempool_alloc_t)(int gfp_mask,void *pool_data);

typedef void *(mempool_free_t)(void *element,void *pool_data);

mempool_t *mempool_create(int min_nr,mempool_alloc_t *alloc_fn,mempool_free_t *free_fn,void *pool_data);

void *mempool_alloc(mempool_t *pool,int gfp_mask);
void mempool_free(void *element,mempool_t *pool);

int mempool_resize(mempool_t *pool,int new_min_nr,int gfp_mask);
void mempool_destroy(mempool_t* pool);
```

eg:

```c
cache = kmem_cache_create(...);
pool = mempool_create(20,mempool_alloc_slab,mempool_free_slab,cache);
```

# get_free_page and Friends

If a module needs to allocate big chunks of memory,it is usually better to use a page-oriented technique.

```c

#include <linux/gfp.h>

get_zeroed_page(unsigned int flags);

__get_free_page(unsigned int flags);

__get_free_pages(unsined int flags,unsigned int order);

void free_page(unsigned long addr);
void free_pages(unsigned long,unsigned long order);
```

order is the base-two logarithm of the number of pages you are requesting or freeing.For example,order is 0 if you want one page and 3 if you want request eight pages.

# The alloc_pages Interface

The real core of the Linux page allocator is a function called alloc_pages_node:

struct page *alloc_pages_node(int nid,unsigned int flags,unsigned int order);

This function also has two variants;

```c
struct page *alloc_pages(unsigned int flags,unsigned int order);

struct page *alloc_page(unsigned int flags);

void __free_page(struct page *page);
void __free_pages(struct page *page,unsigned int order);
void free_hot_page(struct page *page);
void free_cold_page(struct page *page);
```

# vmalloc and Friends

The(virtual) address range used by kmalloc and __get_free_pages features a one-to-one mapping to physical memory,possibly shifted by a constant PAGE_OFFSET value.

allocates a contiguous memory region in the virtual address space.Although the pages are not consecutive in physical memory(each page is retrieved with a separate call to alloc_page),the kernel sees them as a contiguous range of addresses.

```c
#include <linux/vmalloc.h>

void *vmalloc(unsigned long size);
void vfree(void *addr);
void *ioremap(unsigned long offset,unsigned long size);
void iounmap(void *addr);
```

# Per-CPU Variables

```
#include <linux/percpu.h>

DEFINE_PER_CPU(type,name);

per_cpu(variable,int cpu_id);

get_cpu_var(sockets_in_use)++;
put_cpu_var(sockets_in_use);
```

The call to get_cpu_var returns an lvalue for the current processor's version of the variable and disables preemption.

Dynamically allocated per-CPU variable are also possible.

```c
void *alloc_percpu(type);
void *__alloc_percpu(size_t size,size_t align);

per_cpu_ptr(void *per_cpu_var,int cpu_id);

void free_percpu(void *);
```

you need to use get_cpu to block preemption while working with the variabel.

eg:

```c
int cpu;
cpu = get_cpu();
ptr = per_cpu_ptr(per_cpu_var,cpu);
/*work with ptr*/
put_cpu();
```

Export Per-CPU variables:

```c
EXPORT_PER_CPU_SYMBOL(per_cpu_var);
EXPORT_PER_CPU_SYMBOL_GPL(per_cpu_var);
```

To access such a variable within a module,declare it with:
```c
DECLARE_PER_CPU(type, name);
```

The use of DECLARE_PER_CPU(instead ofDEFINE_PER_CPU)   tells the compiler that an external reference is being made

# Acquiring a Dedicated Buffer at Boot Time

Needless to say,a module can't allocate memory at boot time;only drivers directly linked to the kernel can do that;

When the kernel is booted,it gains access to all the physical memory available in the system.It then initializes each of its subsystems by calling that subsystem's initialization function,allowing initialization code to allocate a memory buffer for private use by reducing the amount of RAM left for normal system operation.

```c
#include <linux/bootmem.h>

void *alloc_bootmem(unsigned long size);
void *alloc_bootmem_low(unsigned long size);
void *alloc_bootmem_pages(unsigned long size);
void *alloc_bootmem_low_pages(unsigned long size);

void free_bootmem(unsigned long addr,unsigned long size);
```