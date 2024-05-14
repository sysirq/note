通知链 链表的元素为notifier_block

```c
struct notifier_block {
	notifier_fn_t notifier_call;
	struct notifier_block __rcu *next;
	int priority;
};
```

在通知链上注册的函数为：notifier_chain_register

常用通知链：inetaddr_chain（本地端口地址改变）（register_inetaddr_notifier、unregister_inetaddr_notifier）、inet6addr_chain（register_inet6addr_notifier）、netdev_chain（网络设备）（register_netdevice_notifier）

notifier_call_chain

注意，可能同时在不同CPU上对同一个通知链调用notifier_call_chain。因此回调函数需要注意互斥和串行性。
