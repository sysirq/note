ip_v4的接收函数为ip_rcv

ip包发送给本地的函数为ip_local_deliver，转发为ip_forward

dst_output --> ip_output

IP内核栈的核心功能：

![image](http://www.embeddedlinux.org.cn/linux_net/0596002556/images/understandlni_1801.jpg)

# 传输

L3层中发送数据包的核心函数是dst_output（ip_queue_xmit和ip_push_pending_fames、ip_append_data、ip_append_page最终都调用他）

ip_qeueu_xmit：L4层的协议已经将数据划分为大小合适的块(主要由TCP调用)，该函数仅仅设置路由信息和构建IP头

ip_push_pending_frames：L4层的协议没要考虑数据的分段(When the L4 protocol needs to flush the output queue created with ip_append_data, the protocol invokes ip_push_pending_frames, which in turn does any necessary fragmentation and pushes the resulting packets down to dst_output.)（主要由UDP调用）

# 内存分配与buffer组织

sk_buff中的frags是用于Scatter Gather IO的。他是独立于IP分段的，只是让代码和硬件在不相邻的内存区域上进行操作，就像它们是相邻的。这意味着，即使页面大小大于PMTU，当sk_buff中的数据(由skb->data指向)加上frags引用的数据到达PMTU时，也会创建一个新的sk buff。

skb_is_nonlinear：skb->data_len != NULL;frags中有数据

skb_headlen：skb->len - skb->data_len; skb->data - skb->tail之间的长度

skb_pagelen：（skb->data - skb->tail之间的长度） + （frags中的数据）

# IP数据发送关键函数

ip_append_data、ip_append_page：将要发送的数据buffer，转换为sk_buff（如果buffer长度超过MTU的大小，则会创建多个sk_buff），并将创建的buffer加入到sk->sk_write_queue中（FIFO队列）

ip_push_pending_frames：为sk->sk_write_queue中的第一个sk_buff创建IP头，并将其他的sk_buff通过sk_buff->next字段连接起来，然后第一个通过sk_buff->frag_list连接他们（__ip_make_skb完成）。然后调用ip_send_skb发送（dst_output）

udp_sendmsg：调用ip_make_skb，将用户输入的数据buffer 转换为 sk_buff，然后调用udp_send_skb添加udp头，在发送

# IP分段

ip_fragment：分为快速路径和慢速路径。快速路径：由ip_append_data、ip_append_page将buffer已经分成多个合适的fragment，此时只需要添加IP头并修改分段信息字段就可以发送。慢速路径：此时是一个大的sk_buff，其大小已经超过MTU的大小，需要在这里进行分段，然后在发送。

# IP重组

IP分段被组织进hash表中的struct ipq元素中。然后进行重组。（ip_defrag）

IP包经过重组之后，其多余分段的数据组织到第一个sk_buff中的skb_shinfo(sk_buff)->frags中去，如果frags满了，则添加到frag_list中去。

# L4协议注册

inet_add_protocol 

inet_del_protocol