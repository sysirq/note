# 内核版本判断

```c
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
static long minor_ioctl(struct file *filp,unsigned int cmd,unsigned long arg)
#else
static int minor_ioctl(struct inode *inode,struct file *filp,unsigned long arg)
#endif
```

# 参考资料

awesome-linux-rootkits

https://github.com/milabs/awesome-linux-rootkits

kunkillable (kunkillable is an LKM (loadable kernel module) that makes userland processes unkillable.)

https://github.com/spiderpig1297/kunkillable

kprochide (kprochide is an LKM for hiding processes from the userland. The module is able to hide multiple processes and is able to dynamically receive new processes to hide.)

https://github.com/spiderpig1297/kprochide