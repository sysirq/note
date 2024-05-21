# Storage

The most explicit way to describe disks is to use a combination of **-device** to specify the hardware device and **-blockdev** to describe the backend. **The device defines what the  guest  sees  and  the backend describes how QEMU handles the data**. **It is the only guaranteed stable interface for describing block devices** and as such is recommended for management tools and scripting.



Eg:



```sh
qemu-system-x86_64 --accel kvm \
										-m 4G \
										-smp 4 \
										--blockdev driver=qcow2,node-name=mydisk,file.driver=file,file.filename=hd.qcow2  \
										-device virtio-blk,drive=mydisk \
										-cdrom ../iso/CentOS-7-x86_64-Minimal-2009.iso \
										-vnc :1
```



Or:



```sh
qemu-system-x86_64 --accel kvm  \
										-m 4G \
										-smp 4 \
										-blockdev driver=file,node-name=my_file,filename=hd.qcow2  \
										-blockdev driver=qcow2,node-name=hda,file=my_file \
										-device virtio-blk,drive=hda \
										-vnc :1
```



```
 drive=<str>            - Node name or ID of a block device to use as a backend
```







# Network

Create a network backend like this:

```sh
-netdev TYPE,id=NAME,
```

```
sysirq@sysirq-machine:~$ qemu-system-x86_64 -device virtio-net,help | grep netdev
  netdev=<str>           - ID of a netdev to use as a backend
  mac=<str>              - Ethernet 6-byte MAC Address, example: 52:54:00:12:34:56
```

### user

```
qemu-system-x86_64 -netdev user,id=nc1 -device virtio-net,netdev=nc1,mac=52:54:00:21:34:56
```

### tap

```
qemu-system-x86_64 -netdev tap,id=nc0,ifname=tap0,script=no,downscript=no -device virtio-net,netdev=nc0,mac=52:54:00:21:34:56
```

- nat

  add a net bridge name br0

  ```sh
  ip link add br0 type bridge
  ip addr add 192.168.182.1/24 dev br0
  ip link set br0 up
  ```

  Add tap interface for VM

  ```sh
  ip tuntap add mode tap tap0
  ip link set tap0 up
  ```
  
  connect tun/tap interfaces with bridge
  
  ```sh
  ip link set tap0 master br0
  ```
  
  enable ip_forward
  
  ```sh
  sysctl -w net.ipv4.ip_forward=1
  # -o takes as argument the interface you want to use for routing, in this example enp2s0
  iptables -t nat -A POSTROUTING -o enp2s0 -j MASQUERADE
  ```
  
  vm seting
  
  ````sh
  ip link set eth0 down
  ip addr add 192.168.182.130/24 dev eth0
  ip link set eth0 up
  ip route add default via 192.168.182.1 dev eth0
  ````
  
# display

```sh
-device virtio-vga 
```

# IO

```sh
-device virtio-mouse
-device virtio-keyboard
```

# 完整命令

```sh
qemu-system-x86_64 -accel kvm \
										-m 16G -smp 8 \
										-blockdev driver=file,node-name=file,filename=hd.qcow2 \
										-blockdev driver=qcow2,file=file,node-name=hd \
										-device virtio-blk,drive=hd \
										-device virtio-vga \
										-device virtio-mouse \
										-device virtio-keyboard \
										-netdev user,id=nc0 \
										-device virtio-net,netdev=nc0,mac=52:54:00:21:34:56 \
										-vnc 10.4.21.2:1
```

# 资料

Manual page qemu

Network bridges and tun/tap interfaces in Linux

https://krackout.wordpress.com/2020/03/08/network-bridges-and-tun-tap-interfaces-in-linux/
