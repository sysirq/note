swtich：是一个多端口的bridge

bridge/switch具有地址学习功能，能够自动知道该frame需不需要转发到其他port

用bridge连接LAN时，需要解决Frame flood 问题，通过Spanning Tree Protocol解决


Linux网桥初始化代码：br_init、br_deint

网桥的ioctl控制代码：br_ioctl_deviceless_stub

虚拟网桥通过br_add_bridge和br_del_bridge创建

向虚拟网桥添加或删除端口的方法为：br_add_if、br_del_if

实际接收由硬件设备完成，最终通过netif_receive_skb函数提交给上层，而在该函数中会处理bridge这类特殊设备（br_handle_frame），对于网桥会调用br_handle_frame函数。

# tap/tun

tap网络设备创建过程：通过ioctl的TUNSETIFF创建

tap设备的net_device中的netdev_ops为tap_netdev_ops，其中的发送函数为tun_net_xmit，该函数只是简单的将要发生的skb放入socket的接收队列中，然后在该tap设备对应的文件描述符上就可以接收到：

```c
skb_queue_tail(&tfile->socket.sk->sk_receive_queue, skb);
```


tap文件写tun_chr_write_iter：将写入的数据用sk_buff封装，然后注入到协议栈(调用netif_rx_ni)

ta文件读tun_chr_read_iter：从tfile->socket.sk->sk_receive_queue中读取数据

# 虚拟机数据包走向

虚拟机构造要发送到外网的数据包--》TAP设备写--》netif_rx_ni--》br_handle_frame--》br_forward--》dev_queue_xmit(eth0,连接外网的网卡)

外网发送的到虚拟机的数据包--》netif_receive_skb（eth0网卡，连接外网的网卡）--》br_handle_frame--》br_forward--》tun_net_xmit--》TAP设备读--》虚拟机

# 参考资料

Linux内核TUN/TAP设备驱动

https://blog.csdn.net/sinat_20184565/article/details/83415106

linux network net bridge技术分析

https://cloud.tencent.com/developer/article/1087504

Linux下的虚拟Bridge实现

https://www.cnblogs.com/zmkeil/archive/2013/04/21/3034733.html