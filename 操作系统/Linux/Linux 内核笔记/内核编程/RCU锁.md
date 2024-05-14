RCU主要应用在那种，读线程多，而写线程唯一的情况，同时需要保证数据一致性。


读端的使用：

```
	rcu_read_lock();
	do_vmclear_operation = rcu_dereference(crash_vmclear_loaded_vmcss);
	rcu_read_unlock();
```

写端的使用:

```
rcu_assign_pointer(ioc->icq_hint, NULL);
call_rcu(&icq->__rcu_head, icq_free_icq_rcu)
```

# 参考资料

Linux内核中的RCU

https://zhuanlan.zhihu.com/p/67520807