# 版本

ivanti connect security 22.7r2.3

# web

./home/config/web.cfg

```sh
bash-4.2# ls -hl /home/bin/web80
-rwxr-xr-x. 1 root root 79K Oct  6  2024 /home/bin/web80
bash-4.2# ls -hl /home/bin/web  
-rwxr-xr-x. 1 root root 1.5M Oct  6  2024 /home/bin/web
```

从./home/config/web.cfg读取端口，创建一个端口复用的socket

```c
setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)) < 0);
```

然后根据环境变量DSNUMWEBS或者CPU个数fork对应数量的children，来对到来的web 请求进行处理，内核自动根据负载把连接分配到不同子进程上。



DSWSAcceptor --> 