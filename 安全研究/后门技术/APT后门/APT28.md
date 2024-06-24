# Linux内核模块持久化

内核模块可以使用Linux内置的在引导时加载内核模块的功能进行持久化。

在基于Red Hat的发行版中，这可能包括(但不限于)在/etc/sysconfig/modules/中放置一个.modules可执行脚本，在/etc/modules.conf中添加内核模块，或者在/etc/modules-load.d/中放置一个.conf文件。

在基于Debian的发行版中，这可能包括但不限于将内核模块添加到/etc/modules中，或者在/etc/modules-load.d/中放置一个.conf文件。

内核模块通常位于/lib/modules/<KERNEL_RELEASE>/ Kernel /drivers/中，其中<KERNEL_RELEASE>是目标机器的Linux内核版本。

# Linux内核hook

### 进程隐藏

hook:

- find_pid_ns
- find_pid
- find_task_by_pid_type
- d_lookup
- do_fork()：实现对子进程的隐藏 

### Netfilter Hiding

hook掉nf_register_hook函数（用于注册Netfilter hook）。首先调用原始的nf_register_hook，允许新的Netfilter hook 被添加。然后卸载我们恶意模块的在该hook number 的Netfilter hook（nf_unregister_hook），然后重新注册，这样能保证我们的恶意模块netfilter hook始终是第一个处理网络数据包的hook。

当我们恶意模块的netfilter hook被调用时，当是触发包时，我们可以通过返回NF_STOP，阻止接下来的netfilter 处理

# 资料

Russian GRU 85th GTsSS Deploys Previously Undisclosed Drovorub Malware