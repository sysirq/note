# Linux 进程之间通过UNIX 域套接字传递文件描述符

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

# 如何进行调试

首先建立ssl连接，然后在FGT上获取处理该ssl连接的pid附加上去，最后在发送数据：

```python
import http.client
import ssl
import socket
import re
import urllib.parse

HOST = "192.168.182.188"
PORT = 8443  

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

CIPHERS = "ECDHE-RSA-AES256-SHA@SECLEVEL=0"
context = ssl.create_default_context()
context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
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

ssl_socket = create_ssl_socket()
input("Press Enter to send the HTTP request...")

ret = send_get(ssl_socket,"/remote/info")
print(ret)
```

# SSL VPN module

通过字符串"DYNAMIC_MODULE_LIMIT and recompile"，定位到FGT 自己实现的ap_add_module函数

通过字符串我们可以看到SSL VPN有哪些模块：

```
.rodata:00000000030B2378	00000038	C	/code/FortiOS/fortinet/daemon/sslvpnd/http/apache_ssl.c
.rodata:00000000030B32B8	00000037	C	/code/FortiOS/fortinet/daemon/sslvpnd/http/http_core.c
.rodata:00000000030B59C8	00000036	C	/code/FortiOS/fortinet/daemon/sslvpnd/modules/error.c
.rodata:00000000030B7218	0000003D	C	/code/FortiOS/fortinet/daemon/sslvpnd/modules/logindisable.c
.rodata:00000000030B7340	00000038	C	/code/FortiOS/fortinet/daemon/sslvpnd/modules/message.c
.rodata:00000000030B7378	00000038	C	/code/FortiOS/fortinet/daemon/sslvpnd/modules/mod_dir.c
.rodata:00000000030B7440	0000003A	C	/code/FortiOS/fortinet/daemon/sslvpnd/modules/mod_image.c
.rodata:00000000030B7480	00000039	C	/code/FortiOS/fortinet/daemon/sslvpnd/modules/mod_mime.c
.rodata:00000000030B7788	0000003A	C	/code/FortiOS/fortinet/daemon/sslvpnd/modules/mod_proxy.c
.rodata:00000000030B77C8	00000040	C	/code/FortiOS/fortinet/daemon/sslvpnd/modules/mod_zip_archive.c
.rodata:00000000030BC490	0000003A	C	/code/FortiOS/fortinet/daemon/sslvpnd/modules/rmt_login.c
.rodata:00000000030C6890	0000003B	C	/code/FortiOS/fortinet/daemon/sslvpnd/modules/rmt_tunnel.c
.rodata:00000000030C6970	0000003C	C	/code/FortiOS/fortinet/daemon/sslvpnd/modules/rmt_tunnel2.c
.rodata:00000000030C69B0	0000003B	C	/code/FortiOS/fortinet/daemon/sslvpnd/modules/rmt_webcgi.c
.rodata:00000000030C7FE8	00000039	C	/code/FortiOS/fortinet/daemon/sslvpnd/proxy/proxy_html.c
.rodata:00000000030CA400	00000039	C	/code/FortiOS/fortinet/daemon/sslvpnd/state/http_state.c
.rodata:00000000030CCBD0	0000003C	C	/code/FortiOS/fortinet/daemon/sslvpnd/libtelnet/libtelnet.c
```

通过脚本找到所有的SSL VPN注册的模块（magic 为：19990320 、18 ）

```
import idc
import idaapi
import idautils

def get_string_at(ea):
    i = 0
    byte_array = bytearray()
    while True:
        b = idaapi.get_byte(ea+i)
        if b == 0:
            break
        byte_array.append(b)
        i = i + 1
    
    if i == 0:
        return ""
    return byte_array.decode('utf-8')
 

def find_all_sequences(data, sequence):
    sequence_length = len(sequence)
    data_length = len(data)
    indices = []
    
    position = 0
    
    while position < data_length:
        position = data.find(sequence, position)
        if position == -1:
            break
        indices.append(position)
        position += 1
    return indices

start_addr = 0x0000000000400000
end_addr   = 0x000000000F4D2EC8

number_major = 19990320
number_minor = 18

number_major_bytes = number_major.to_bytes(4, byteorder='little', signed=False)
number_minor_bytes = number_minor.to_bytes(4, byteorder='little', signed=False)

search_bytes = number_major_bytes + number_minor_bytes

img_data = idaapi.get_bytes(start_addr, end_addr - start_addr)
address = find_all_sequences(img_data,search_bytes)

for addr in address:
    addr += start_addr
    
    module_name_addr_addr = addr + 0x10
    module_name_addr = int.from_bytes(ida_bytes.get_bytes(module_name_addr_addr, 8),'little')
    module_name = get_string_at(module_name_addr)
    
    print("module addr: ",hex(addr))
    print("name: ",module_name)
```

output：

```
module addr:  0x42bfe00
name:  /code/FortiOS/fortinet/daemon/sslvpnd/http/apache_ssl.c
module addr:  0x42bff40
name:  /code/FortiOS/fortinet/daemon/sslvpnd/http/http_core.c
module addr:  0x42c0ac0
name:  /code/FortiOS/fortinet/daemon/sslvpnd/modules/error.c
module addr:  0x42c0c20
name:  /code/FortiOS/fortinet/daemon/sslvpnd/modules/logindisable.c
module addr:  0x42c0d20
name:  /code/FortiOS/fortinet/daemon/sslvpnd/modules/message.c
module addr:  0x42c0e00
name:  /code/FortiOS/fortinet/daemon/sslvpnd/modules/mod_dir.c
module addr:  0x42c0f00
name:  /code/FortiOS/fortinet/daemon/sslvpnd/modules/mod_image.c
module addr:  0x42c1000
name:  /code/FortiOS/fortinet/daemon/sslvpnd/modules/mod_mime.c
module addr:  0x42c1120
name:  /code/FortiOS/fortinet/daemon/sslvpnd/modules/mod_proxy.c
module addr:  0x42c1200
name:  /code/FortiOS/fortinet/daemon/sslvpnd/modules/mod_zip_archive.c
module addr:  0x42c1820
name:  /code/FortiOS/fortinet/daemon/sslvpnd/modules/rmt_tunnel.c
module addr:  0x42c1920
name:  /code/FortiOS/fortinet/daemon/sslvpnd/modules/rmt_tunnel2.c
module addr:  0x42c1a20
name:  /code/FortiOS/fortinet/daemon/sslvpnd/modules/rmt_webcgi.c
```

# SSL VPN /remote/info bt

```
(gdb) bt
#0  0x00000000016476b0 in ?? ()
#1  0x00000000015fd118 in ?? ()   # sub_15FD0A0    ap_invoke_handler
#2  0x0000000001608e62 in ?? ()   # sub_1608D50    ap_process_request_internal
#3  0x00000000017114fd in ?? ()   # sub_17113A0    ap_read_request
#4  0x0000000001713ad5 in ?? ()   # ap_process_http?
#5  0x00000000017152a0 in ?? ()
#6  0x000000000171537e in ?? ()
#7  0x0000000001715b91 in ?? ()
#8  0x0000000001716f42 in ?? ()
#9  0x0000000001717236 in ?? ()
#10 0x0000000001717919 in ?? ()
#11 0x000000000044c88f in ?? ()
#12 0x00000000004554ca in ?? ()
#13 0x000000000045212c in ?? ()
#14 0x0000000000454738 in ?? ()
#15 0x0000000000455061 in ?? ()
#16 0x00007f0715b89deb in __libc_start_main () from /usr/lib/x86_64-linux-gnu/libc.so.6
#17 0x0000000000447daa in ?? ()
```

