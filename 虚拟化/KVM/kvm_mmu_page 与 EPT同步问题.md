```
Huaitong Han
上午10:45 (7小时前)
发送至 我

1ng0 r <r1ng0hacking@gmail.com> 于2020年7月24日周五 下午6:10写道：
>
> 您好，打扰了，最近小弟在看KVM的代码！发现两个个问题实在没搞懂怎么弄的，所以想请教一下~~~
>
> 程序通过调用KVM_SET_USER_MEMORY_REGION删除它的内存时，是怎么通知EPT去清除对应的映射呢，小弟代码看了半天，也没发现是怎么搞的（CPU 具有VPID特性）
mr delete后清除了所有ept，参考kvm_mmu_invalidate_zap_pages_in_memslot
>
>
> 还有一个问题就是：我自己写的一个程序，通过mmap申请内存，然后 KVM_SET_USER_MEMORY_REGION向KVM注册内存，最后通过一个线程运行NON-ROOT模式下的代码访问 mmap 申请的那段内存，然后在开一个线程过5秒，munmap那段内存，会导致NON-ROOT模式的代码推出，这又是怎么进行EPT同步，让EPT知道指向的内存被munmap掉的呢？
可以清除所有ept，也可以定向清理对应的sp
>
> 打扰了~~~~~~~~~
```

对于第一个问题：会调用kvm_arch_flush_shadow_memslot函数，最终调用kvm_mmu_invalidate_zap_pages_in_memslot进行响应的处理

对于第二个问题：在kvm结构体初始化的时候会调用kvm_init_mmu_notifier函数，对munmap的事件进行监听，调用kvm_unmap_hva_range，取消EPT表中的映射