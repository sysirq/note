# virtio-net-pci

```
TYPE_OBJECT                     Object                          ObjectClass    
    
TYPE_DEVICE                     DeviceState                     DeviceClass                        

TYPE_PCI_DEVICE                 PCIDevice                       PCIDeviceClass                                                                     
TYPE_VIRTIO_PCI                 VirtIOPCIProxy                  VirtioPCIClass                  virtio_pci_info       

virtio-net-pci                  VirtIONetPCI                    VirtioPCIClass                  
```

VirtioPCIClass中的realize函数指针，指向具体的virtio设备初始化函数。

# 前端

通过virtqueue_add 将要发送的 scatter-gather 列表，转换成desc ，加入到vring中，并更新avail vring数组对应项为desc的头

通过virtqueue_get_buf，从virtqueue中提取后端传入的数据（used vring）

# vring

由三部分组成：descriptors table，avail ring，used ring。

A VRing descriptor is not very different from the e1000 TX or RX ones.It contains:

- The physical address and length of a buffer
- a next field for descriptor chaining
- flags

descriptor table 中对应的 descriptor对应的内存是在客户机中申请分配的。

该结构是前后端共享的

初始化过程(客户机中)：

```c
static inline void vring_init(struct vring *vr, unsigned int num, void *p,
			      unsigned long align)
{
	vr->num = num;
	vr->desc = p;
	vr->avail = p + num*sizeof(struct vring_desc);
	vr->used = (void *)(((unsigned long)&vr->avail->ring[num] + sizeof(__virtio16)
		+ align-1) & ~(align - 1));
}
```



# 后端

virtqueue_pop：从aval vring中提取数据前端

virtqueue_fill：写used vring，写入已经使用了的descs

virtqueue_flush：更新used vring的idx

# 通知机制

guest：virtqueue_kick

qemu：virtio_notify

VirtIO为VQ kick抑制定义了可选的高级功能，代替了基于标志的抑制，称为event-idx。


VirtIO defines an optional advanced feature for VQ kick suppression, replacing the flag-based suppression, referred to as event-idx. At the end of the used ring, the consumer stores an avail-event-idx field, to indicate when the next kick is desired. The producer should kick when avail-idx goes beyond avail-event-idx from the last time kick was invoked, which means that the producer has just filled the avail slot at index avail-event-idx

Why is event-idx useful? The avail-event-idx may be used by the consumer to ask for kicks as soon as there is more to consume, by setting avail-event-idx to the current value of avail-idx*. By doing this, we obtain the very same behaviour of of flag-based suppression, with the advantage that the consumer does not have to reset the flag in the VQ kick callback

However, event-idx may be used to ask for delayed notifications. If the consumer sets avail-event-idx = avail-idx + 20, the producer will kick only when 21 more SGs will have been produced. In this way, the notification cost is amortized over 21 requests

# 资料

virtio spec

https://docs.oasis-open.org/virtio/virtio/

半虚拟化 I/O 框架 virtio

https://abelsu7.top/2019/09/02/virtio-in-kvm/

IO虚拟化 - virtio介绍及代码分析

https://blog.csdn.net/xidianjiapei001/article/details/89293914

Deep dive into Virtio-networking and vhost-net

https://www.redhat.com/en/blog/deep-dive-virtio-networking-and-vhost-net

Linux设备模型

https://blog.csdn.net/hsly_support/article/details/7358941

virtio后端驱动详解

https://www.cnblogs.com/ck1020/p/5939777.html

Virtio网络发包过程分析

http://lihanlu.cn/virtio-net-xmit/

virtio前端通知机制分析

http://lihanlu.cn/virtio-frontend-kick/

virtIO前后端notify机制详解

https://www.cnblogs.com/ck1020/p/6066007.html