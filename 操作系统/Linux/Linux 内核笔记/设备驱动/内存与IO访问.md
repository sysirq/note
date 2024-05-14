高性能处理器一般会提供一个内存管理单元（MMU），该单元辅助操作系统进行内存管理，提供虚拟地址到物理地址的转换、内存访问权限保护和cache缓存控制等硬件支持。

对于内核物理内存映射区的虚拟内存，使用virt_to_phys()可以实现内核虚拟地址转换为物理地址，与之对应的函数为phys_to_virt()，它将物理地址转换为内核虚拟地址

# 内核空间内存动态申请

kmalloc、kfree

__get_free_pages、free_pages

vmalloc、vfree（适合分配大量内存，不能用在原子上下文中，因为它的内部实现使用了标志为GFP_KERNEL的kmalloc）

GFP_KERNEL

GFP_ATOMIC

GFP_DMA

GFP_HIGHMEM

### slab

eg:

```c
static kmem_cache_t *xxx_cachep;
xxx_cachep = kmem_cache_create("xxx",sizeof(struct xxx),0,SLAB_HWCACHE_ALIGN,NULL,NULL);

struct xxx * ctx;
ctx = kmem_cache_alloc(xxx_cachep,GFP_KERNEL);
....
kmem_cache_free(xxx_cachep,ctx);
kmem_cache_destroy(xxx_cachep);
```

### mmap

驱动程序中mmap()的实现机制是建立页表映射关系（remap_pfn_range），并填充VMA结构体中vm_operations_struct指针。

```c
int remap_pfn_range(struct vm_area_struct *vma, unsigned long virt_addr, unsigned long pfn, unsigned long size, pgprot_t prot);
```

### mmap 中的 fault函数（缺页时调用的函数）

eg:

```c
static int xxx_fault(struct vm_area_struct *vma,struct vm_fault *vmf)
{
    unsigned long paddr;
    unsigned long pfn;
    pgoff_t index = vmf->pgoff;
    
    struct vm_data *vdata = vma->vm_private_data;
    
    ...
    
    pfn = paddr >> PAGE_SHIFT;
    
    vm_insert_pfn(vma,(unsigned long)vmf->virtual_address,pfn);
    
    return VM_FAULT_NOPAGE;
}
```