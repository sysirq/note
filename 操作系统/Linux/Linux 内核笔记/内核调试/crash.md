```
yum install kexec-tools

systemctl start kdump
systemctl enable kdump

yum install crash

wget http://debuginfo.centos.org/7/x86_64/kernel-debuginfo-common-x86_64-`uname -r`.rpm
wget http://debuginfo.centos.org/7/x86_64/kernel-debuginfo-`uname -r`.rpm

rpm -ivh *.rpm
```

使用crash来调试vmcore，至少需要两个参数：

NAMELIST：未压缩的内核映像文件vmlinux，默认位于/usr/lib/debug/lib/modules/XXX/vmlinux，由内核调试信息包提供。

MEMORY-IMAGE：内存转储文件vmcore，默认位于/var/crash/%HOST-%DATE/vmcore，由kdump生成。

```
crash /usr/lib/debug/lib/modules/3.10.0-693.el7.x86_64/vmlinux vmcore
```