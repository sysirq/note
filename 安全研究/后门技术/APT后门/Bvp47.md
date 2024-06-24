# Bvp技术细节

- 内核模块防检测

通过修改内核模块 elf 文件的前四个字节，达到躲避内存搜索 elf 的目的

- BPF SYNKnock

BPF(Berkeley Packet Filter)是 Linux 内核中用来过滤自定义格式数据包的内核引擎，它可以提供一套规定的语言供用户层的普通进程来过滤指定数据包。

利用 BPF 的这个特性作为隐蔽信道环节中在 Linux 内核层面的高级技巧，避免直接的内核网络协议栈 hook 被追踪者检测出来。

# 参考资料

https://www.pangulab.cn/files/The_Bvp47_a_top-tier_backdoor_of_us_nsa_equation_group.en.pdf

“电幕行动”（Bvp47）技术细节报告（二）——关键组件深度揭秘

https://www.qianxin.com/news/detail?news_id=6484