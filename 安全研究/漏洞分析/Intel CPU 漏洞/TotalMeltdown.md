# 环境

windows 7 x64 + KB4056897(问题补丁)

# 分析

#define TMD_VA_PML4                 0xFFFFF6FB7DBED000

#define TMD_VA_PML4_SELFREF         0xFFFFF6FB7DBEDF68


# 原理 

四级分页结构:
PML4、PDPT、PD、PT

由于PML4自引用的权限位为可读可写

所以利用自引用，黑客可以任意修改PML4、PDPT、PD、PT中的任意数据

正常虚拟地址到物理地址的映射:

PML4-----PDPT-----PD-------PT----PAGE-----PAddr

利用自引用访问受保护的数据:

第一步修改页保护位(假设地址对应的PML4、PDPT、PD、PT对该用户来说都是可读可写（如果不，原理跟此一样）),首先想办法获得与该页对应的PTE（利用自引用）地址：

方法:
PML4-----PML4----PDPT------PD-----PT-------PTE

修改保护位为可读可写。

第二步：直接修改数据（由于第一部已经修改权限位，所以不会引发异常）



所以黑客可以修改任意页权限位为可读、可写、可执行。然后利用指针进行数据读写

# 参考质料
1.http://blog.frizk.net/2018/03/total-meltdown.html

2.https://mp.weixin.qq.com/s/Ykh-F4btn0tCKPxv5s2YHg