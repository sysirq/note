该函数其实是进入内核协议栈的入口,位于 /net/core/dev.c

```c
static int __netif_receive_skb_core(struct sk_buff *skb, bool pfmemalloc)
{
    struct packet_type *ptype, *pt_prev;
.......................................................
	list_for_each_entry_rcu(ptype, &ptype_all, list) {
		if (pt_prev)
			ret = deliver_skb(skb, pt_prev, orig_dev);
		pt_prev = ptype;
	}

	list_for_each_entry_rcu(ptype, &skb->dev->ptype_all, list) {
		if (pt_prev)
			ret = deliver_skb(skb, pt_prev, orig_dev);
		pt_prev = ptype;
	}

......................................................
	if (likely(!deliver_exact)) {
		deliver_ptype_list_skb(skb, &pt_prev, orig_dev, type,
				       &ptype_base[ntohs(type) &
						   PTYPE_HASH_MASK]);
	}
......................................................
}
```

struct packet_type 结构:
```c
struct packet_type {
	__be16			type;	/* This is really htons(ether_type). */
	struct net_device	*dev;	/* NULL is wildcarded here	     */
	int			(*func) (struct sk_buff *,
					 struct net_device *,
					 struct packet_type *,
					 struct net_device *);
	bool			(*id_match)(struct packet_type *ptype,
					    struct sock *sk);
	void			*af_packet_priv;
	struct list_head	list;
};
```

其中__netif_receive_skb_core函数，主要涉及到两部分，其他涉及到vlan数据包的处理，就没去了解了

第一部分是调用ptype_all链表上的sniffer函数,libcap实现貌似就是通过向ptype_all函数注册sniffer函数实现的.

第二部分就是调用（ptype_base）特定协议的handler函数，比如ip_rcv、arp_rcv