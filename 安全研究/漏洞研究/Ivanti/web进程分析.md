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

其代码类似：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/wait.h>

#define PORT 8090
#define BACKLOG 128
#define CHILD_NUM 4

void handle_client(int client_fd) {
    char buffer[1024] = {0};
    int n = read(client_fd, buffer, sizeof(buffer)-1);
    if (n > 0) {
        printf("Received: %s\n", buffer);
        send(client_fd, "Hello from server!\n", 19, 0);
    }
    close(client_fd);
}

void server_loop(int listen_fd) {
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            perror("accept failed");
            continue;
        }

        printf("Process %d accepted connection\n", getpid());
        handle_client(client_fd);
    }
}

int main() {
    int listen_fd;
    struct sockaddr_in addr;
    int opt = 1;

    // 创建 socket
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // 开启 SO_REUSEADDR 和 SO_REUSEPORT
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }

    // 绑定地址和端口
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(listen_fd, BACKLOG) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Listening on port %d...\n", PORT);

    // fork子进程
    for (int i = 0; i < CHILD_NUM; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            // 子进程
            server_loop(listen_fd);
            exit(0);
        } else if (pid < 0) {
            perror("fork failed");
        }
        // 父进程继续循环
    }

    // 父进程等子进程
    while (1) {
        wait(NULL);
    }

    close(listen_fd);
    return 0;
}

```



DSWSAcceptor --> 