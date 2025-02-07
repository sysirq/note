
# mips 全模拟搭建

宿主机网络配置：

```
ip link add br0 type bridge
ip addr add 192.168.128.1/24 dev br0

ip tuntap add dev tap0 mode tap
ip link set tap0 master br0

ip link set br0 up
ip link set tap0 up

sysctl -w net.ipv4.ip_forward=1


```

客户机启动(密码、账号全为root)：

```
wget https://people.debian.org/~aurel32/qemu/mips/debian_squeeze_mips_standard.qcow2
wget https://people.debian.org/~aurel32/qemu/mips/vmlinux-2.6.32-5-5kc-malta
qemu-system-mips64 -M malta -kernel vmlinux-2.6.32-5-5kc-malta -hda debian_squeeze_mips_standard.qcow2 -append "root=/dev/sda1 console=tty0" -net nic -net tap,ifname=tap0,script=no,downscript=no -nographic
```

客户机网络配置：

```
ifconfig eth0 192.168.128.100/24
route add default gw 192.168.128.1
```


# 资料

mips架构逆向那些事

https://forum.butian.net/share/1502