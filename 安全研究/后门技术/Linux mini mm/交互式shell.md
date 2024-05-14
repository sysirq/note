```c
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <pty.h>
#include <sys/wait.h>
#include <sys/select.h>

void read_from_child(int fd) {
    char buffer[4096];
    ssize_t nbytes;

    while ((nbytes = read(fd, buffer, sizeof(buffer))) > 0) {
        write(STDOUT_FILENO, buffer, nbytes);
    }
}

void interact_with_shell(int master_fd) {
    fd_set read_fds;
    char buffer[4096];
    ssize_t nbytes;

    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(STDIN_FILENO, &read_fds);
        FD_SET(master_fd, &read_fds);

        if (select(master_fd + 1, &read_fds, NULL, NULL, NULL) == -1) {
            perror("select");
            exit(EXIT_FAILURE);
        }

        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
            nbytes = read(STDIN_FILENO, buffer, sizeof(buffer));
            if (nbytes <= 0) {
                break;
            }
            write(master_fd, buffer, nbytes);
        }

        if (FD_ISSET(master_fd, &read_fds)) {
            nbytes = read(master_fd, buffer, sizeof(buffer));
            if (nbytes <= 0) {
                break;
            }
            write(STDOUT_FILENO, buffer, nbytes);
        }
    }
}

int main() {
    int master_fd, slave_fd;
    pid_t pid;
    int old=open("/dev/tty",O_RDWR);  //打开当前控制终端
    ioctl(old, TIOCNOTTY);  //放弃当前控制终端

    // 创建伪终端
    if (openpty(&master_fd, &slave_fd, NULL, NULL, NULL) == -1) {
        perror("openpty");
        exit(EXIT_FAILURE);
    }

    // 创建子进程
    pid = fork();

    if (pid == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    if (pid == 0) { // 子进程
        setsid();  //子进程成为会话组长
        // 关闭主设备
        close(master_fd);

        // 将从设备设置为子进程的标准输入、输出和错误
        dup2(slave_fd, STDIN_FILENO);
        dup2(slave_fd, STDOUT_FILENO);
        dup2(slave_fd, STDERR_FILENO);

        // 执行shell
        execlp("/bin/bash", "/bin/bash", NULL);

        // 如果 execlp() 失败
        perror("execlp");
        exit(EXIT_FAILURE);
    } else { // 父进程
        // 关闭从设备
        close(slave_fd);

        // 与子进程进行交互
        interact_with_shell(master_fd);

        // 等待子进程退出
        waitpid(pid, NULL, 0);

        // 关闭主设备
        close(master_fd);

        exit(EXIT_SUCCESS);
    }
}

```

