# 小技巧

通过在交互式的python解释器下，可以通过help()函数查看函数或模块的用途。

dir() 函数不带参数时，返回当前范围内的变量、方法和定义的类型列表；带参数时，返回参数的属性、方法列表

ls(),查看选项,如  ls(ARP)

# 安装

python3，Ubuntu 18.04环境

```python
sudo apt install python3-pip

pip3 install scapy
```

# 导入

```python
from scapy.all import *
```

# 构造包

scapy通过重载'/'符号，能够一层一层的构造包，比如构造一个ARP请求包

```python
arpPkt = Ether(dst="FF:FF:FF:FF:FF:FF")/ARP(pdst="172.16.128.85")
```

# 发送 与 接受

send 与 sendp，都只发送，且send 只能发送三层协议，而sendp才能发送二层协议。

```python
send(IP())
sendp(Ether()/IP())
```

sr与srp，发送并接受，且sr不能发送二层协议，srp才能。

两个的返回值为 响应与没收到响应元组。

```python
>>> ans,unans = srp(Ether(dst="FF:FF:FF:FF:FF:FF")/ARP(pdst="172.16.85.128"),iface="vmnet8")
Begin emission:
Finished sending 1 packets.
*
Received 1 packets, got 1 answers, remaining 0 packets
>>> type(ans)
<class 'scapy.plist.SndRcvList'>

>>> type(ans[0])
<class 'tuple'>
>>> ans[0]
(<Ether  dst=FF:FF:FF:FF:FF:FF type=0x806 |<ARP  pdst=172.16.85.128 |>>, <Ether  dst=00:50:56:c0:00:08 src=00:0c:29:90:8d:a1 type=0x806 |<ARP  hwtype=0x1 ptype=0x800 hwlen=6 plen=4 op=is-at hwsrc=00:0c:29:90:8d:a1 psrc=172.16.85.128 hwdst=00:50:56:c0:00:08 pdst=172.16.85.1 |<Padding  load='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' |>>>)

>>> type(ans[0][0])
<class 'scapy.layers.l2.Ether'>
>>> type(ans[0][1])
<class 'scapy.layers.l2.Ether'>

>>> ans[0][0].dst
'FF:FF:FF:FF:FF:FF'
>>> ans[0][0].src
'00:50:56:c0:00:08'
>>> ans[0][1].dst
'00:50:56:c0:00:08'
>>> ans[0][1].src
'00:0c:29:90:8d:a1'

>>> ans[0][1][1].show()
###[ ARP ]### 
  hwtype    = 0x1
  ptype     = 0x800
  hwlen     = 6
  plen      = 4
  op        = is-at
  hwsrc     = 00:0c:29:90:8d:a1
  psrc      = 172.16.85.128
  hwdst     = 00:50:56:c0:00:08
  pdst      = 172.16.85.1
###[ Padding ]### 
     load      = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

>>> ans[0][1][1].psrc
'172.16.85.128'

```

通过以上分析，可以知道，ans为一个发送与接受的列表，其包含发送与接受的元组。元组中下标为0为发送的数据，下标为1为接受到的数据。且返回数据包中，可以通过下标提取固定的协议数据

sr1,srp1 是 sr，srp的简化版本

```python
>>> ans= srp1(Ether(dst="FF:FF:FF:FF:FF:FF")/ARP(pdst="172.16.85.128"),iface="vmnet8")
Begin emission:
Finished sending 1 packets.
*
Received 1 packets, got 1 answers, remaining 0 packets
>>> type(ans)
<class 'scapy.layers.l2.Ether'>
>>> ans.pdst
'172.16.85.1'
```

发送并只接受第一个返回的数据包.返回值为接受到的第一个数据包,没有收到数据时，返回None

# 抓包

通过sniff抓取数据包

eg:

```python
>>> packets = sniff(iface="wlp58s0",count=20)
>>> type(packets)
<class 'scapy.plist.PacketList'>
>>> type(packets[0])
<class 'scapy.layers.l2.Ether'>
```

# 局域网ARP扫描器
```python
#!/usr/bin/python3

from scapy.all import *

if __name__ == "__main__":
    netif = "vmnet8"  #net iface
    ip_prefix = "172.16.85."
    
    live_host = {}; 

    for i in range(1,255):
        ip_str = ip_prefix + str(i)
        print("ip:",ip_str)
        arp_req_pkt = Ether(dst="FF:FF:FF:FF:FF:FF")/ARP(pdst=ip_str)
        arp_rsp_pkt = srp1(arp_req_pkt,iface=netif,timeout=0.01)

        if arp_rsp_pkt != None:
            live_host[arp_rsp_pkt.psrc] = arp_rsp_pkt.hwsrc

    for key,value in live_host.items():
        print(key,value)
    

```
# Links

https://scapy.readthedocs.io/en/latest/introduction.html#about-scapy