The structure has changed many times in the history of the kernel,both to add new options and to reorganize existing fields into a cleaner layout.Its fields can be classified roughly into the following categories:

- Layout
- General
- Feature-specific
- Management functions

# Layout Fields

Interesting fields of sk_buff:

- struct sock *sk:This is a pointer to a sock data structure of the socket that owns this buffer.
- unsigned int len:This is the size of the block of data in the buffer.This length include both the data in the main buffer and the data in the fragments.
- unsigned int data_len:Unlike len,data_len accounts only for the size of the data in the fragments.
- unsigned int mac_len:This is the size of the MAC header
- atomic_t users:This is the reference count.
- unsigned int truesize:This field represent the total size of the buffer,including the sk_buff structure itself.
- unsigned char *head,*end,*data,*tail:head and end point to the beginning and end of the space allocated to the buffer,and data and tail point to the beginning and end of the actual data.

# General Fields

- struct timeval stamp:This is usually meaningful only for a received packet.It is a timestamp that represents when a packet was received or when one is scheduled for transmission.
- struce net_device * dev:describes a network device.
- struct dst_entry dst:This is used by the routing subsystem.
- char cb[40]:This is a "control buffer",or storage for private information,maintained by each layer for internal use
- unsigned char clone:indicates that this structure is a clone of another sk_buff buffer.
- unsigned char pkt_type:This field classifies the type of frame based on its L2 destination address.
- unsigned short protocol:This is the protocol used at the next-higher layer from the perspective of the device driver at L2.

# Feature-Specific Fields

The Linux kernel is modular.allowing you to select what to include and waht to leave out.Thus some fields are included in the sk_buff data structure only if the kernel is compiled with support for particular features such as firewalling or QoS

- struct nf_conntrack *nfct
- struct nf_bridge_info *nf_bridge;
- u8 nfctinfo
- u8 nf_trace
    
    These parameters are used by Netfilter

- u16 tc_index
- u16 tc_verd

    These parameters are used by the Traffic Control

- struct sec_path *sp
    
    This is used by the IPsec protocol suite to keep track of transformations

# Management Functions

Before and After:(a)skb_put,(b)skb_push,(c)skb_pull,(d)skb_reserve

![image](./images/Figure%202-4.Before%20and%20Afterskb_put,skb_push,skb_pull,skb_reserve.jpg)

### Allocating memory:alloc_skb and dev_alloc_skb

creating a single buffer involves two allocations of memory(one for the buffer and one for the sk_buff struct)

### The skb_shared_info structure and the skb_shinfo function

skb_shared_info at the end of the data buffer that keeps additional information about the data block(Fragment).

Note that there is no field inside sk_buff structure pointing at the skb_shared_info data structure.To access that structure,functions need to use the skb_shinfo macro,which simply returns the end pointer.

### List management functions

skb_queue_head_init: initializes an sk_buff_head with an empty queue of elements.

skb_queue_head,skb_queue_tail:Adds one buffer to the head or to the tail of a queue,respectively

skb_dequeue,skb_dequeue_tail:Dequeues an element from the head or from the tail.

skb_queue_purge:Empties a queue.

skb_queue_walk:Runs a loop on each element of a queue in turn.