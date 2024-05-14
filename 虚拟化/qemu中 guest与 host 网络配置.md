# 在主机中执行

```shell
# root @ john-machine in /home/john [16:46:43] 
$ ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens32: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:0c:29:1c:ef:96 brd ff:ff:ff:ff:ff:ff
    inet 192.168.220.168/24 brd 192.168.220.255 scope global dynamic noprefixroute ens32
       valid_lft 1722sec preferred_lft 1722sec
    inet6 fe80::18ab:4d6b:734:68f1/64 scope link noprefixroute 
       valid_lft forever preferred_lft forever

# root @ john-machine in /home/john [16:46:44] 
$ ip link add br0 type bridge

# root @ john-machine in /home/john [16:47:00] 
$ ip addr flush ens32 

# root @ john-machine in /home/john [16:47:12] 
$ ip addr add 192.168.220.168/24 dev br0

# root @ john-machine in /home/john [16:48:12]
$ ip link set ens32 master br0

# root @ john-machine in /home/john [16:47:28] 
$ ip link set br0 up

# root @ john-machine in /home/john [16:47:41] 
$ ip route add default via 192.168.220.2 dev br0    # 默认路由设置

# root @ john-machine in /home/john [16:48:44] 
$ ping 114.114.114.114        
PING 114.114.114.114 (114.114.114.114) 56(84) bytes of data.
64 bytes from 114.114.114.114: icmp_seq=1 ttl=128 time=31.1 ms
64 bytes from 114.114.114.114: icmp_seq=2 ttl=128 time=40.9 ms
^C
--- 114.114.114.114 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1002ms
rtt min/avg/max/mdev = 31.103/36.049/40.995/4.946 ms
```

可能需要设置DNS地址，在/etc/resolv.conf中设置。

# 虚拟机设置

通过

```shell
qemu-system-x86_64 -hda Linux -enable-kvm -m 2048 -smp 2 -machine q35 -netdev tap,script=no,downscript=no,vhost=on,id=mynet -device virtio-net-pci,netdev=mynet
```

启动虚拟机。

此时会在宿主机中创建一个tap网卡。

在宿主机中运行：

```shell
# root @ john-machine in /home/john [16:53:04] 
$ ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens32: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel master br0 state UP group default qlen 1000
    link/ether 00:0c:29:1c:ef:96 brd ff:ff:ff:ff:ff:ff
5: br0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 00:0c:29:1c:ef:96 brd ff:ff:ff:ff:ff:ff
    inet 192.168.220.168/24 scope global br0
       valid_lft forever preferred_lft forever
    inet6 fe80::3c6a:8aff:fe6c:1b70/64 scope link 
       valid_lft forever preferred_lft forever
6: tap0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether 3a:bf:c5:1c:82:d2 brd ff:ff:ff:ff:ff:ff

# root @ john-machine in /home/john [16:53:06] 
$ ip link set tap0 master br0

# root @ john-machine in /home/john [16:53:16] 
$ ip link set tap0 up
```

在虚拟机中运行：

```shell
ip addr add 192.168.220.180/24 dev enp0s2
ip route add default via 192.168.220.2 dev enp0s2 # 默认路由设置
```

可能需要设置DNS地址，在/etc/resolv.conf中设置

即可完成上网。