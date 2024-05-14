the object-based reverse-mapping VM

# 文件映射页的反向映射

在创建文件映射时，在__vma_link_file中调用vma_interval_tree_insert(vma, &mapping->i_mmap)，将vma与文件区间关联起来，从而创建从page 到 pte的映射。

解除映射使用的是unlink_file_vma

# 资料

1.Linux中匿名页的反向映射

http://liujunming.top/2017/09/03/Linux%E4%B8%AD%E5%8C%BF%E5%90%8D%E9%A1%B5%E7%9A%84%E5%8F%8D%E5%90%91%E6%98%A0%E5%B0%84/

2.逆向映射的演进

http://www.wowotech.net/memory_management/reverse_mapping.html

3.Linux内核剖析之回收页框

http://www.it165.net/os/html/201411/9928.html

4.PST优先搜索树原理及在Linux内核中的应用

https://www.docin.com/p-1360679176.html