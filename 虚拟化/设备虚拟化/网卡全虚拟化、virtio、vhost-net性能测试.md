# 全虚拟化

虚拟机启动参数：

```shell
qemu-system-x86_64 -hda Linux -enable-kvm -m 2048 -smp 2 -machine q35 -netdev tap,script=no,downscript=no,id=mynet -device e1000e,netdev=mynet
```

虚拟机中运行:

```shell
iperf3 -s
```

宿主机中运行：

```shell
$ iperf3 -c 192.168.220.180
Connecting to host 192.168.220.180, port 5201
[  4] local 192.168.220.168 port 53048 connected to 192.168.220.180 port 5201
[ ID] Interval           Transfer     Bandwidth       Retr  Cwnd
[  4]   0.00-1.00   sec   121 MBytes  1.02 Gbits/sec   85   1.31 MBytes       
[  4]   1.00-2.00   sec   126 MBytes  1.06 Gbits/sec    0   1.44 MBytes       
[  4]   2.00-3.00   sec   126 MBytes  1.06 Gbits/sec    0   1.53 MBytes       
[  4]   3.00-4.00   sec   125 MBytes  1.05 Gbits/sec    3   1.15 MBytes       
[  4]   4.00-5.00   sec   127 MBytes  1.07 Gbits/sec    0   1.23 MBytes       
[  4]   5.00-6.00   sec   126 MBytes  1.06 Gbits/sec    0   1.30 MBytes       
[  4]   6.00-7.00   sec   126 MBytes  1.06 Gbits/sec    0   1.37 MBytes       
[  4]   7.00-8.00   sec   127 MBytes  1.06 Gbits/sec    0   1.44 MBytes       
[  4]   8.00-9.00   sec   127 MBytes  1.07 Gbits/sec    0   1.50 MBytes       
[  4]   9.00-10.00  sec   121 MBytes  1.01 Gbits/sec   61   1.14 MBytes       
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bandwidth       Retr
[  4]   0.00-10.00  sec  1.22 GBytes  1.05 Gbits/sec  149             sender
[  4]   0.00-10.00  sec  1.22 GBytes  1.05 Gbits/sec                  receiver

iperf Done.
```

# virtio

虚拟机启动参数:

```shell
qemu-system-x86_64 -hda Linux -enable-kvm -m 2048 -smp 2 -machine q35 -netdev tap,script=no,downscript=no,id=mynet -device virtio-net-pci,netdev=mynet
```

虚拟机中运行:

```shell
iperf3 -s
```

宿主机中运行：

```shell
$ iperf3 -c 192.168.220.180
Connecting to host 192.168.220.180, port 5201
[  4] local 192.168.220.168 port 53086 connected to 192.168.220.180 port 5201
[ ID] Interval           Transfer     Bandwidth       Retr  Cwnd
[  4]   0.00-1.00   sec  1.80 GBytes  15.5 Gbits/sec    0   3.05 MBytes       
[  4]   1.00-2.00   sec  1.84 GBytes  15.8 Gbits/sec    0   3.05 MBytes       
[  4]   2.00-3.00   sec  1.73 GBytes  14.9 Gbits/sec    0   3.05 MBytes       
[  4]   3.00-4.00   sec  1.84 GBytes  15.8 Gbits/sec    0   3.05 MBytes       
[  4]   4.00-5.00   sec  1.84 GBytes  15.8 Gbits/sec    0   3.05 MBytes       
[  4]   5.00-6.00   sec  1.84 GBytes  15.8 Gbits/sec    0   3.05 MBytes       
[  4]   6.00-7.00   sec  1.79 GBytes  15.4 Gbits/sec    0   3.05 MBytes       
[  4]   7.00-8.00   sec  1.68 GBytes  14.4 Gbits/sec    0   3.05 MBytes       
[  4]   8.00-9.00   sec  1.84 GBytes  15.8 Gbits/sec    0   3.05 MBytes       
[  4]   9.00-10.00  sec  1.82 GBytes  15.6 Gbits/sec    0   3.05 MBytes       
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bandwidth       Retr
[  4]   0.00-10.00  sec  18.0 GBytes  15.5 Gbits/sec    0             sender
[  4]   0.00-10.00  sec  18.0 GBytes  15.5 Gbits/sec                  receiver

iperf Done.
```

# vhost-net

虚拟机启动参数：

```shell
qemu-system-x86_64 -hda Linux -enable-kvm -m 2048 -smp 2 -machine q35 -netdev tap,script=no,downscript=no,vhost=on,id=mynet -device virtio-net-pci,netdev=mynet
```

虚拟机中运行:

```shell
iperf3 -s
```

宿主机中运行：

```shell
$ iperf3 -c 192.168.220.180
Connecting to host 192.168.220.180, port 5201
[  4] local 192.168.220.168 port 53124 connected to 192.168.220.180 port 5201
[ ID] Interval           Transfer     Bandwidth       Retr  Cwnd
[  4]   0.00-1.00   sec  2.29 GBytes  19.7 Gbits/sec    0   3.14 MBytes       
[  4]   1.00-2.00   sec  2.40 GBytes  20.7 Gbits/sec    0   3.14 MBytes       
[  4]   2.00-3.00   sec  3.46 GBytes  29.7 Gbits/sec    0   3.14 MBytes       
[  4]   3.00-4.00   sec  2.35 GBytes  20.2 Gbits/sec    0   3.14 MBytes       
[  4]   4.00-5.00   sec  2.37 GBytes  20.3 Gbits/sec    0   3.14 MBytes       
[  4]   5.00-6.00   sec  2.37 GBytes  20.4 Gbits/sec    0   3.14 MBytes       
[  4]   6.00-7.00   sec  2.41 GBytes  20.7 Gbits/sec    0   3.14 MBytes       
[  4]   7.00-8.00   sec  2.23 GBytes  19.2 Gbits/sec    0   3.14 MBytes       
[  4]   8.00-9.00   sec  2.95 GBytes  25.3 Gbits/sec    0   3.14 MBytes       
[  4]   9.00-10.00  sec  2.64 GBytes  22.7 Gbits/sec    0   3.14 MBytes       
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bandwidth       Retr
[  4]   0.00-10.00  sec  25.5 GBytes  21.9 Gbits/sec    0             sender
[  4]   0.00-10.00  sec  25.5 GBytes  21.9 Gbits/sec                  receiver

iperf Done.
```