# Layout 字段

unsigned int len：缓冲区中的数据大小，包括主缓存中的(由 head指向)和分段（fragment）中的。这个值在数据穿越协议栈各层中会改变，比如从L2到L3会丢弃L2的头部，造成该字段变小

unsigned int data_len：只包含fragment中的数据大小

atomic_t users：引用sk_buff的计数，通过函数skb_get和kfree_skb操纵。实际(data buffer)数据区的引用计数由dataref(skb_shared_info中)表示

unsigned int truesize：在alloc_skb被设置为len+sizeof(skb_shared_info)

sk_buff_data_t	tail

sk_buff_data_t	end

unsigned char		*head,*data：head和end指向为缓冲区分配的空间的开始和结束，data和tail指向实际数据的开始与结束。head与data之间的数据区被称为headroom 用于添加新的协议头，tail与end之间的数据区称为tailroom 用于添加新的数据。

# General 字段

struct net_device *dev：表示用于接受或用于发送的网络设备

char cb[40]：用于保存每个协议层执行时的私有信息；比如tcp_skb_cb

unsigned char cloned：当设置的时候，表示当前skb是其他skb的克隆

unsigned char pkt_type：该字段通过L2的目标地址对帧的类型进行了分类（PACKET_HOST、PACKET_MULTICAST等），对于以太网设备，这个参数是由eth_type_trans函数初始化的

unsigned short protocol：是从L2的设备驱动程序的角度来看，下一层使用的协议（IP、ARP）。

# Management 函数

### skb分配函数：alloc_skb与dev_alloc_skb函数

包含两次内存分配：一次是data buffer，一次是sk_buff

dev_alloc_skb主要是设备驱动使用，且可以在中断上下文中使用

### skb释放函数：kfree_skb与dev_kfree_skb

当 skb->users 为 1 的时候释放掉。

### 数据保留与对齐

skb_reserve：在buffer的头部保留一些空间，通常用于允许插入头部或强制数据对其。这个函数移动data和tail指针。通常在alloc_skb之后调用（此时data与tail一样）

skb_push：用于将数据添加到buffer头部（通过减小data指针，增大len实现）

skb_put：用于将数据添加到尾部（通过增大tail指针，增大len实现）

skb_pull：用于将数据从buffer头部移除（通过增大data指针，减少len实现）

### skb_shared_info 结构与skb_shinfo 函数

skb_shared_info位于data buffer中，由sk_buff中的end指向

```c
#define skb_shinfo(SKB)    ((struct skb_shared_info *)((SKB)->end))
```

### cloning and copying buffers

skb_clone：当一个buffer需要被多个函数处理时，可以通过这个函数进行克隆，该函数只会分配sk_buff结构，指向相同的data buffer。因此不能修改data buffer中的数据。

pskb_copy：分配一个新的sk_buff，然后拷贝一份新的sk_buff -> data 到 tail之间的数据

skb_copy：全拷贝，包括fragment中的数据。

### 列表管理函数

skb_queue_head_init：初始化一个sk_buff_head

skb_queue_head, skb_queue_tail：向sk_buff_head添加sk_buff

skb_dequeue, skb_dequeue_tail

skb_queue_purge：清空sk_buff_head中的所有sk_buff

skb_queue_walk：依次对sk_buff_head中的每个元素运行循环。

# 总结

其实sk_buff就像一个数据区描述符，指向data buffer，data buffer中又包含了skb_shared_info用于管理fragment