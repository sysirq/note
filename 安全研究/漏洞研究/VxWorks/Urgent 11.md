# CVE-2019-12256

栈溢出漏洞

影响 VxWorks 6.9.3 以及更高版本.

ipnet_icmp4_copyopts中的代码使用SRR—Pointer字段作为SRR选项中最终路由条目的偏移量，并将所有路由条目复制到分配在ipnet_icmp4_send函数堆栈上的传出数据包的选项中。每个LSRR选项都有3字节长，但它会生成一个43字节的复制选项(3字节报头、36字节路由条目、当前路由的4字节新路由条目)。由于没有验证(在此上下文中)畸形数据包不包含一个以上的SSRR\LSRR选项，发送多个这种类型的选项将导致opts溢出，opts是堆栈上分配的40字节数组。

由于使用了无效IP选项，只能在局域网发起攻击。因为如果其中包含无效IP选项的话，通过第一个路由器就会将该包给丢弃掉。

# TCP紧急指针RCE漏洞

# 参考资料

https://armis.com/urgent11/

https://mp.weixin.qq.com/s/pqOC2bT9KEE-HZPt11aDUA