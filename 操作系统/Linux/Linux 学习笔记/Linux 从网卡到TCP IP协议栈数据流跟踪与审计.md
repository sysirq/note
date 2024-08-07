# 前沿

在学代码审计，然后最近做Linux协议栈的审计，发现Linux不愧是一个久经考验的系统，本来以为可以找到个DoS的,结果发现其在TCP/IP协议栈的链路层实现，利用了各种技术，用来提高性能与安全性。

# 工具

在跟踪数据从网卡到TCP/IP协议栈的过程中，使用4.10.0内核，利用understand查看代码，以及flawfinder来配合进行安全性的检查。以intel e1000 驱动为列。

# 分析

#### NAPI

首先，为了效率，Linux使用了NAPI机制。所谓NAPI机制，其就是当数据到来时，采用中断加轮询的方式，接受数据包。

如果Linux使用中断的方式，接受数据包的话，每次数据包的到来，就会产生中断，这样，当有大量数据包到来的话，其中断开销就比较大，如果CPU是单核，且频率较低的话，就有可能够造成DoS攻击。

如果只是使用轮询的话，那么当没有数据包到来时，会造成CPU浪费在无用功上。

所有Linux内核黑客发明了NAPI机制，中断与轮询相互结合的方式。

当数据到来时，会产生中断，设备首先会关闭自身中断，然后将该网卡设备，加入到轮询表中，然后进而触发软中断，使用轮询接受数据包，然后当该设备上没有数据时，打开该设备的中断。

其内核实现路径为:

数据到来，触发中断，调用网卡中断函数e1000_intr(/drivers/net/ethernet/intel/e1000/e1000_main.c)，其会将该设备加入到轮询表中（struct softnet_data中的poll_list，其中softnet_data是每个CPU所独有的），然后触发软中断NET_RX_SOFTIRQ。软中断会进一步回调设备注册的轮询函数，e1000设备驱动是e1000_clean。然后调用e1000_clean_rx_irq轮询接受数据包。

#### GRO

GRO，其实就是Generic receive offload。通过在进入到Linux 内核TCP IP协议栈处理之前，将多个数据流合并成一个，减少内核协议栈处理，提高系统性能。

感觉这玩意涉及到数据包的合并，必然涉及到很多内存上面的操作，容易发生一些漏洞什么的，，但是通过结合flawfinder，加人工审计，并没有发现。也可能由于我对skb_buff结构不是很了解，它已经看到了我，我没有看到它。这块到跟进协议栈后，熟悉skb_buff结构体之后，回过来再次看一看。

其实现函数为:napi_gro_receive.就是从底层跟踪到高层协议，查看是否能合并，比如mac 地址相同，就看ip地址是否相同，。。。。

分析发现，其会将不能合并的加入到一个链表中，然后我就想，我是否可以够造恶意数据，让耗尽其内存，然后分析发现too young,too simple。其实现中，会限制链表大小，当超过限制，会强制发送到协议栈中。

#### RPS RFS

如果没有NAPI机制的话，就有可能耗尽多核中的一个CPU的运算量，但是RPS的出现，让其变得不可能。

RPS RFS 其全称分别是：Receive Packet Steering 与 Receive Flow Steering。顾名思义，其就是让数据处理均衡到每个CPU上。

RPS:用户通过 /sys/class/net/eth0/queues/rx-0/rps_cpus 设置参加负载均衡的CPU。当数据包到来时，会根据相关字段，如ip建立一个hash，然后用来选择一个CPU。

RFS：RFS其实是，RPS的补丁，想象一下，当用户进程等待在另一个CPU上，准备接受数据包时，但是RPS给其分配到了一个不相同的CPU上，这时，当数据包处理完后，该数据包到用户进程所在CPU进一步处理，这样会造成缓存失效，从而降低系统性能。RFS的出现就是为了解决该问题的。

内核函数：get_rps_cpu 选择一个CPU，然后enqueue_to_backlog加入到一个CPU的等待队列