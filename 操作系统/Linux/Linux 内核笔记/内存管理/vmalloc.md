# 申请

vmalloc --> ... --> __vmalloc_node_range --> __get_vm_area_node(分配代表虚拟空间的结构vm_struct与vmap_area),__vmalloc_area_node(分配实际的物理页面，并与相应的虚拟空间建立映射关系)

alloc_vmap_area:查找连续虚拟内存空间,并返回代表该段空间的vmap_area结构。

__vmalloc_area_node：完成实际物理页面的申请，并将物理页面映射到虚拟内存空间。

# 释放

vfree

vfree --> __vunmap --> remove_vm_area: 删除相应虚拟内存映射关系。

vfree --> __vunmap: 释放掉物理内存页面与申请的一些结构体

# 资料

1.【Linux内存源码分析】vmalloc不连续内存管理（1）

https://www.jeanleo.com/2018/09/09/%e3%80%90linux%e5%86%85%e5%ad%98%e6%ba%90%e7%a0%81%e5%88%86%e6%9e%90%e3%80%91vmalloc%e4%b8%8d%e8%bf%9e%e7%bb%ad%e5%86%85%e5%ad%98%e7%ae%a1%e7%90%86%ef%bc%881%ef%bc%89/