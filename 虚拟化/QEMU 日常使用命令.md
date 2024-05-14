# 磁盘创建

```shell
qemu-img create -f qcow2 test.qcow2 512M
```

-f 指定格式 有 raw格式 和 qcow2格式等

其中 qcow2支持快照等功能。

# 磁盘信息查看

```shell
qemu-img info test.qcow2 
```

# 磁盘格式转换

```shell
qemu-img convert -f raw -O qcow2 test.raw test.qcow2
```

-f 指定转换前的格式，-O指定转换后的格式

# 快照

```shell
qemu-img snapshot -c snapshot01 test.qcow2  //创建
qemu-img snapshot -l test.qcow2             //查看
qemu-img snapshot -a snapshot01 test.qcow2  //revert到快照点
qemu-img snapshot -d snapshot01 test.qcow2  //删除
```

