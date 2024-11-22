# Linux 进程之间传递文件描述符

通过Linux 内核中的辅助消息（Ancillary Message）机制，辅助消息（Ancillary Message）是 Linux 套接字子系统的一种扩展机制，允许通过套接字发送除普通数据之外的元信息。例如，文件描述符传递和进程身份信息（PID、UID、GID）传递就是通过辅助消息实现的。

eg:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>

// 发送文件描述符的函数
void send_fd(int socket, int fd_to_send) {
    struct msghdr msg = {0};
    struct cmsghdr *cmsg;
    char buf[CMSG_SPACE(sizeof(fd_to_send))];
    memset(buf, '\0', sizeof(buf));

    struct iovec io = { .iov_base = (void*)"FD", .iov_len = 2 };
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;

    msg.msg_control = buf;
    msg.msg_controllen = CMSG_SPACE(sizeof(fd_to_send));

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(fd_to_send));

    *((int *) CMSG_DATA(cmsg)) = fd_to_send;

    if (sendmsg(socket, &msg, 0) < 0)
        perror("sendmsg");
}

// 接收文件描述符的函数
int recv_fd(int socket) {
    struct msghdr msg = {0};

    char m_buffer[256];
    struct iovec io = { .iov_base = m_buffer, .iov_len = sizeof(m_buffer) };
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;

    char cmsg_buffer[CMSG_SPACE(sizeof(int))];
    msg.msg_control = cmsg_buffer;
    msg.msg_controllen = sizeof(cmsg_buffer);

    if (recvmsg(socket, &msg, 0) < 0)
        perror("recvmsg");

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

    int fd = -1;
    if (cmsg && cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
        fd = *((int *) CMSG_DATA(cmsg));
    }

    return fd;
}

int main() {
    int sv[2]; // 套接字对
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
        perror("socketpair");
        exit(1);
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(1);
    }

    if (pid == 0) { // 子进程
        close(sv[0]); // 关闭父进程端
        int fd = recv_fd(sv[1]);
        if (fd < 0) {
            perror("recv_fd");
        } else {
            write(fd, "Hello from child\n", 17);
            close(fd);
        }
        close(sv[1]);
    } else { // 父进程
        close(sv[1]); // 关闭子进程端
        int fd = open("example.txt", O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd < 0) {
            perror("open");
            exit(1);
        }
        send_fd(sv[0], fd);
        close(fd);
        close(sv[0]);
        wait(NULL);
    }

    return 0;
}
```

# SSL VPN  文件描述符传递

首先，SSL VPN 会起一个 端口监听用户的连接，当有用户请求时，会将accept的fd通过unix域套接字传递给子进程进行处理。如：

```
/ # busybox ps -eo pid,ppid,comm | busybox grep sslvpn
 3449     1 sslvpnd
 4364  3449 sslvpnd
 4374  3449 sslvpnd
 4381  3449 sslvpnd
```

其中3449是父进程，通过netstat 可以看到只有3449接受网络连接:

```
/ # busybox netstat -tpna | busybox grep sslvpn
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      3449/sslvpnd
tcp        0      0 0.0.0.0:8443            0.0.0.0:*               LISTEN      3449/sslvpnd
tcp        0      0 :::80                   :::*                    LISTEN      3449/sslvpnd
tcp        0      0 :::8443                 :::*                    LISTEN      3449/sslvpnd
```

通过openssl s_client命令：

```
openssl s_client 192.168.182.188:8443
```

我们可以发现，最终处理请求的是其子进程：

```
/ # busybox netstat -tpna | busybox grep sslvpn
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      3449/sslvpnd
tcp        0      0 0.0.0.0:8443            0.0.0.0:*               LISTEN      3449/sslvpnd
tcp        0      0 192.168.182.188:8443    192.168.182.1:57590     ESTABLISHED 4374/sslvpnd
tcp        0      0 :::80                   :::*                    LISTEN      3449/sslvpnd
tcp        0      0 :::8443                 :::*                    LISTEN      3449/sslvpnd
```



