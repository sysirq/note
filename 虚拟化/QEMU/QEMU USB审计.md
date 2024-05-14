# 设备模拟的关键

通过捕获对MMIO 和 IO端口 的访问 ，进行模拟设备对应操作。

相应的函数有：

注册一段MMIO或IO空间的操作函数:

```c
memory_region_init_io
```

从qemu读取/写入guest os中的内存：

```c
pci_dma_read

pci_dma_write
```


# 资料

USB 协议分析

https://blog.csdn.net/zhoutaopower/article/details/82083043

USN-3261-1: QEMU vulnerabilities

https://usn.ubuntu.com/3261-1/

linux内核之USB驱动分析

https://www.cnblogs.com/gzqblogs/p/10159417.html

几种USB控制器类型：OHCI，UHCI，EHCI，XHCI

http://smilejay.com/2012/10/usb_controller_xhci/

5.5 USB虚拟化

https://blog.csdn.net/wanthelping/article/details/48395751