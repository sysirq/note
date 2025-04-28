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

sub_30CC0 --> DSWSAcceptor: 添加accept的fd到事件循环中，对应的类为（）

# 有哪些文件

```c
.rodata:00122950	0000000D	C	logopt.pb.cc
.rodata:00122A0E	0000000A	C	accept.cc
.rodata:00122C86	0000000A	C	agentd.cc
.rodata:00126812	0000000A	C	buffer.cc
.rodata:00126886	00000007	C	cgi.cc
.rodata:00127494	0000000A	C	client.cc
.rodata:001283CA	0000000E	C	connection.cc
.rodata:00128EA6	0000000C	C	connwait.cc
.rodata:00129013	00000007	C	eap.cc
.rodata:00129373	00000009	C	files.cc
.rodata:00129855	00000009	C	java2.cc
.rodata:0012AA28	0000000D	C	jsamproxy.cc
.rodata:0012AA50	00000014	C	jsamproxyhandler.cc
.rodata:0012EF42	0000000A	C	linger.cc
.rodata:0012EFAF	00000008	C	main.cc
.rodata:0012F654	0000000B	C	request.cc
.rodata:00134D35	0000000B	C	rewrite.cc
.rodata:00135551	00000008	C	util.cc
.rodata:00135AA7	0000000C	C	compress.cc
.rodata:00135B3F	0000000A	C	radius.cc
.rodata:001362E3	00000008	C	saml.cc
.rodata:0013647D	00000007	C	ivs.cc
.rodata:00136537	00000008	C	soap.cc
.rodata:00136B49	0000000D	C	nameduser.cc
.rodata:00137782	00000010	C	tnctransport.cc
.rodata:00138B04	00000009	C	proxy.cc
.rodata:0013952A	0000000A	C	config.cc
.rodata:001398C1	0000000C	C	html5acc.cc
.rodata:00139BD9	00000007	C	ssl.cc
.rodata:0013A2B9	00000012	C	html5bsslProxy.cc
.rodata:0013AC87	00000011	C	pyresthandler.cc
.rodata:0013B3D1	00000015	C	metricresthandler.cc
.rodata:0013BBA5	00000016	C	hawkAuthentication.cc
.rodata:0013BBF0	00000013	C	TncsClientState.cc
.rodata:0013CEC7	00000011	C	TncsAsyncImpl.cc
.rodata:0013D64F	00000012	C	TncsConnection.cc
```

# 请求处理流程分析

```c
virtual void DSWSAcceptor::ioReady(int);//accept 客户端请求
virtual DSWSSsl::Status DSWSSsl::readBytes(char*, int*);//read 接受客户端的数据
virtual DSWSSsl::Status DSWSSsl::writeBytes(const char*, int*)//write 发送到客户端的数据
```

# 状态转换

DSWSClientSslNegotiator

# 如何调试

```python
import http.client
import ssl
import socket
import re
import time
import urllib.parse

HOST = "192.168.31.182"
PORT = 443  
DSNUMWEBS = 8

REQ_POST = """\
POST %s HTTP/1.1\r
Host: %s:%d\r
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0\r
Content-Type: text/plain;charset=UTF-8\r
Connection: keep-alive\r
Content-Length: %d\r
\r
%s
"""

REQ_GET = """\
GET %s HTTP/1.1\r
Host: %s:%d\r
Connection: keep-alive\r
\r
"""

CIPHERS = "AES256-GCM-SHA384"
context = ssl.create_default_context()
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.set_ciphers(CIPHERS)
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

def create_ssl_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    ssl_sock = context.wrap_socket(sock)
    return ssl_sock

def send_get(sock, path: str) -> bytes:
    """Sends a GET request, returns the response."""
    request = REQ_GET % (
            path,
            HOST,
            PORT,
    )
    sock.sendall(request.encode())
    return try_read_response(sock)

def try_read_response(sock) -> bytes:
    """Try to read the response header and contents. If the read() call
    returns an empty byte array, `RuntimeError` is raised. This generally
    indicates that the socket died.
    """

    def read_or_raise(n):
        read = sock.read(n)
        if not read:
            raise RuntimeError(f"Unable to read response headers: {headers}")
        return read

    count = 0
    max_count = 10
    while not (headers := sock.read(1)):
        count += 1
        time.sleep(0.1)
        if count == max_count:
            raise RuntimeError(f"Unable to read response headers: {headers}")

    while b"\r\n\r\n" not in headers:
        headers += read_or_raise(100)

    # TOP tier HTTP parser
    if b"Content-Length: " in headers:
        length = int(re.search(rb"Content-Length: ([0-9]+)", headers).group(1))
        data = headers[headers.index(b"\r\n\r\n") + 4 :]
        while len(data) < length:
            data += read_or_raise(length - len(data))
    elif b"Transfer-Encoding: chunked" in headers:
        data = headers[headers.index(b"\r\n\r\n") + 4 :]
        while not data.endswith(b"\r\n0\r\n\r\n"):
            data += read_or_raise(100)
    else:
        raise RuntimeError(
            f"No Content-Length / Transfer-Encoding headers: {headers}"
        )
    # print(headers.decode())
    return data

def send_post(sock, path: str, data: dict) -> bytes:
    """Sends a POST request, returns the response."""
    data = urllib.parse.urlencode(data)
    if len(data) > 0x10000:
        failure(f"POST data too big: {hex(len(data))}")
    request = REQ_POST % (path, HOST, PORT, len(data), data)
    # msg_print(request[:-0x1000])
    sock.sendall(request.encode())
    return try_read_response(sock)

input("Press Enter to send the HTTP request...")
socks = []
for i in range(DSNUMWEBS):
    ssl_socket = create_ssl_socket()
    socks.append(ssl_socket)

while True:
    time.sleep(4)
```

