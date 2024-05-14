vhost_net的启动命令是-netdev tap,..中指定vhost=on启动的。

vhost的核心是ioeventfd与irqfd

通过KVM_IOEVENTFD ioctl命令设置ioeventfd,将虚拟机写一段pio或mmio转换为对文件描述符的读写操作（poll）

通过KVM_IRQFD ioctl命令设置irqfd，通过该设置后，能使得对文件描述符的操作变成生成中断

# 资料

virtio spec

https://docs.oasis-open.org/virtio/virtio/

Introduction to virtio-networking and vhost-net

https://www.redhat.com/en/blog/introduction-virtio-networking-and-vhost-net

Deep dive into Virtio-networking and vhost-net

https://www.redhat.com/en/blog/deep-dive-virtio-networking-and-vhost-net

Hands on vhost-net: Do. Or do not. There is no try

https://www.redhat.com/en/blog/hands-vhost-net-do-or-do-not-there-no-try?source=bloglisting&page=1&f%5B0%5D=post_tags%3AVirtualization&search=vhost

Vhost Architecture

https://luohao-brian.gitbooks.io/interrupt-virtualization/vhost-architecture.html

virtIO之VHOST工作原理简析

https://www.cnblogs.com/ck1020/p/7204769.html