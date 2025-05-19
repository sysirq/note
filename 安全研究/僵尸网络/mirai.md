# 单一实例

通过端口来实现

```c
addr.sin_port = htons(SINGLE_INSTANCE_PORT);
```

如果发现已经存在，通过遍历 /proc/net/tcp 文件，获取到文件inode，然后遍历/proc/pids/fds，找到文件中是否存在该inode，如果找到就直接kill掉该进程


# 资料

Mirai-Source-Code

https://github.com/jgamblin/Mirai-Source-Code