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

请求 https://192.168.182.188:8443/remote/info ，到响应生成的流程

```
(gdb) bt
#0  0x00000000016476b0 in ?? ()
#1  0x00000000015fd118 in ?? ()   # sub_15FD0A0    ap_invoke_handler
#2  0x0000000001608e62 in ?? ()   # sub_1608D50    ap_process_request_internal
#3  0x00000000017114fd in ?? ()   # sub_17113A0    ap_read_request
#4  0x0000000001713ad5 in ?? ()   # ap_process_http?
#5  0x00000000017152a0 in ?? ()
#6  0x000000000171537e in ?? ()
#7  0x0000000001715b91 in ?? ()   # sub_1715A60 ，  疑似SSL相关、fgt ssl vpn 决定相关
#8  0x0000000001716f42 in ?? ()   # sub_17169B0 ，  疑似通过unix 域套节字传递 连接信息 ，然后进行后续处理
#9  0x0000000001717236 in ?? ()		# sub_1717000 ，  疑似通过unix 域套节字传递 连接信息 ，然后进行后续处理
#10 0x0000000001717919 in ?? ()		# sub_17175E0 ， ssl vpn main 函数
#11 0x000000000044c88f in ?? ()
#12 0x00000000004554ca in ?? ()
#13 0x000000000045212c in ?? ()
#14 0x0000000000454738 in ?? ()
#15 0x0000000000455061 in ?? ()
#16 0x00007f0715b89deb in __libc_start_main () from /usr/lib/x86_64-linux-gnu/libc.so.6
#17 0x0000000000447daa in ?? ()
```

# SSL VPN CGI 处理流程

通过sslvpnd/modules/rmt_webcgi.c，我们可以定位到所有的CGI接口：

```
.data:00000000042C1A20 dword_42C1A20   dd 1310730h             ; DATA XREF: .data:00000000042C1330↑o
.data:00000000042C1A20                                         ; .data:00000000042C13B0↑o
.data:00000000042C1A24                 dd 12h
.data:00000000042C1A28                 dq 0FFFFFFFFh
.data:00000000042C1A30                 dq offset aCodeFortiosFor_602 ; "/code/FortiOS/fortinet/daemon/sslvpnd/m"...
.data:00000000042C1A38                 dq 0
.data:00000000042C1A40                 dq 0
.data:00000000042C1A48                 dq 41503133h
.data:00000000042C1A50                 dq 0
.data:00000000042C1A58                 dq 0
.data:00000000042C1A60                 dq 0
.data:00000000042C1A68                 dq 0
.data:00000000042C1A70                 dq 0
.data:00000000042C1A78                 dq 0
.data:00000000042C1A80                 dq offset off_42C1A00   ; "rmt-webcgi-handler"
```

```
.data:00000000042C1A00 off_42C1A00     dq offset aRmtWebcgiHandl
.data:00000000042C1A00                                         ; DATA XREF: .data:00000000042C1A80↓o
.data:00000000042C1A00                                         ; "rmt-webcgi-handler"
.data:00000000042C1A08                 dq offset sub_1663390
```

根据sub_1663390函数，可以找到url对应的处理函数：

```
.rodata:000000000306DD60 off_306DD60     dq offset key           ; DATA XREF: sub_16432F0+4A↑r
.rodata:000000000306DD60                                         ; sub_16432F0+51↑o
.rodata:000000000306DD68                 align 10h
.rodata:000000000306DD70                 dq offset key
.rodata:000000000306DD78                 align 20h
.rodata:000000000306DD80                 dq offset key
.rodata:000000000306DD88                 align 10h
.rodata:000000000306DD90                 dq offset key
.rodata:000000000306DD98                 align 20h
.rodata:000000000306DDA0                 dq offset aInfo         ; "info"
.rodata:000000000306DDA8                 dq offset sub_16476B0
.rodata:000000000306DDB0                 dq offset aLogin_2      ; "login"
.rodata:000000000306DDB8                 dq offset sub_1649700
.rodata:000000000306DDC0                 dq offset aTool         ; "tool"
.rodata:000000000306DDC8                 dq offset sub_16621F0
.rodata:000000000306DDD0                 dq offset aPortal       ; "portal"
.rodata:000000000306DDD8                 dq offset sub_165E340
.rodata:000000000306DDE0                 dq offset aLogout_0     ; "logout"
.rodata:000000000306DDE8                 dq offset sub_164F870
.rodata:000000000306DDF0                 dq offset aNetwork      ; "network"
.rodata:000000000306DDF8                 dq offset sub_1658140
.rodata:000000000306DE00                 dq offset aRemoteLogoutok+8 ; "logoutok"
.rodata:000000000306DE08                 dq offset sub_164FD50
.rodata:000000000306DE10                 dq offset aRemoteNetworkD+8 ; "network/del"
.rodata:000000000306DE18                 dq offset sub_1650610
.rodata:000000000306DE20                 dq offset aFabricLoginche+8 ; "logincheck"
.rodata:000000000306DE28                 dq offset sub_164DFA0
.rodata:000000000306DE30                 dq offset aNetworkLogin ; "network/login"
.rodata:000000000306DE38                 dq offset sub_1651FD0
.rodata:000000000306DE40                 dq offset aLicensecheck ; "licensecheck"
.rodata:000000000306DE48                 dq offset sub_1647CC0
.rodata:000000000306DE50                 dq offset aRemoteSamlLogi+8 ; "saml/login"
.rodata:000000000306DE58                 dq offset sub_161D260
.rodata:000000000306DE60                 dq offset aRemoteNetworkL+8 ; "network/logout"
.rodata:000000000306DE68                 dq offset sub_1652850
.rodata:000000000306DE70                 dq offset aSamlStart    ; "saml/start"
.rodata:000000000306DE78                 dq offset sub_161EA00
.rodata:000000000306DE80                 dq offset aSamlLogout+1 ; "saml/logout"
.rodata:000000000306DE88                 dq offset sub_161E700
.rodata:000000000306DE90                 dq offset aMaxForwards+9 ; "rds"
.rodata:000000000306DE98                 dq offset sub_165FD40
.rodata:000000000306DEA0                 dq offset aRmtEmpty     ; "rmt_empty"
.rodata:000000000306DEA8                 dq offset sub_1638580
.rodata:000000000306DEB0                 dq offset aLoginredir   ; "loginredir"
.rodata:000000000306DEB8                 dq offset sub_164F550
.rodata:000000000306DEC0                 dq offset aPortalBookmark_0 ; "portal/bookmarks"
.rodata:000000000306DEC8                 dq offset sub_16377B0
.rodata:000000000306DED0                 dq offset aSslvpnSsoJs  ; "sslvpn_sso.js"
.rodata:000000000306DED8                 dq offset sub_16612F0
.rodata:000000000306DEE0                 dq offset aRemoteNetworkM+8 ; "network/mkdir"
.rodata:000000000306DEE8                 dq offset sub_1653170
.rodata:000000000306DEF0                 dq offset aLoginexpire  ; "loginexpire"
.rodata:000000000306DEF8                 dq offset sub_164EFE0
.rodata:000000000306DF00                 dq offset aLogindisable+1 ; "logindisable"
.rodata:000000000306DF08                 dq offset sub_164EA50
.rodata:000000000306DF10                 dq offset aRemoteSslvpnSu+8 ; "sslvpn_support.js"
.rodata:000000000306DF18                 dq offset sub_16619C0
.rodata:000000000306DF20                 dq offset aRemoteNetworkR+8 ; "network/rename"
.rodata:000000000306DF28                 dq offset sub_1653CB0
.rodata:000000000306DF30                 dq offset aFortisslvpn  ; "fortisslvpn"
.rodata:000000000306DF38                 dq offset sub_163CB60
.rodata:000000000306DF40                 dq offset aError_1      ; "error"
.rodata:000000000306DF48                 dq offset sub_1639100
.rodata:000000000306DF50                 dq offset aRemoteHostchec_0+8 ; "hostcheck_install"
.rodata:000000000306DF58                 dq offset sub_1644150
.rodata:000000000306DF60                 dq offset aRemoteNetworkU+8 ; "network/upload"
.rodata:000000000306DF68                 dq offset sub_1654C20
.rodata:000000000306DF70                 dq offset aFortisslvpnXml ; "fortisslvpn_xml"
.rodata:000000000306DF78                 dq offset sub_163E1E0
.rodata:000000000306DF80                 dq offset aNetworkDownloa ; "network/download"
.rodata:000000000306DF88                 dq offset sub_1651040
.rodata:000000000306DF90                 dq offset aSamlAuthId   ; "saml/auth_id"
.rodata:000000000306DF98                 dq offset sub_161CD50
.rodata:000000000306DFA0                 dq offset aHttpsSSamlLogi+0Bh ; "saml/login/"
.rodata:000000000306DFA8                 dq offset sub_161D260
.rodata:000000000306DFB0                 dq offset aSamlLogout_1 ; "saml/logout/"
.rodata:000000000306DFB8                 dq offset sub_161E700
.rodata:000000000306DFC0                 dq offset aSamlAuthId_0 ; "saml/auth_id/"
.rodata:000000000306DFC8                 dq offset sub_161CD50
.rodata:000000000306DFD0                 dq offset aWebService   ; "web_service"
.rodata:000000000306DFD8                 dq offset sub_16645E0
.rodata:000000000306DFE0                 dq offset aHostcheckSw  ; "hostcheck_sw"
.rodata:000000000306DFE8                 dq offset sub_1645590
.rodata:000000000306DFF0                 dq offset aSIsNotFoundInC+13h ; "cookie"
.rodata:000000000306DFF8                 dq offset sub_16382B0
.rodata:000000000306E000                 dq offset aRemoteLogincon+8 ; "loginconfirm"
.rodata:000000000306E008                 dq offset sub_1649CB0
.rodata:000000000306E010                 dq offset aFgtLang      ; "fgt_lang"
.rodata:000000000306E018                 dq offset sub_16399B0
.rodata:000000000306E020                 dq offset key
.rodata:000000000306E028                 align 10h
.rodata:000000000306E030                 dq offset key
.rodata:000000000306E038                 align 20h
.rodata:000000000306E040                 dq offset aRemoteHostchec_1+8 ; "hostcheck_validate"
.rodata:000000000306E048                 dq offset sub_1646A90
.rodata:000000000306E050                 dq offset key
.rodata:000000000306E058                 align 20h
.rodata:000000000306E060                 dq offset key
.rodata:000000000306E068                 align 10h
.rodata:000000000306E070                 dq offset key
.rodata:000000000306E078                 align 20h
.rodata:000000000306E080                 dq offset key
.rodata:000000000306E088                 align 10h
.rodata:000000000306E090                 dq offset key
.rodata:000000000306E098                 align 20h
.rodata:000000000306E0A0                 dq offset key
.rodata:000000000306E0A8                 align 10h
.rodata:000000000306E0B0                 dq offset aHostcheckPerio ; "hostcheck_periodic"
.rodata:000000000306E0B8                 dq offset sub_1646A90
.rodata:000000000306E0C0                 dq offset key
.rodata:000000000306E0C8                 align 10h
.rodata:000000000306E0D0                 dq offset key
.rodata:000000000306E0D8                 align 20h
.rodata:000000000306E0E0                 dq offset key
.rodata:000000000306E0E8                 align 10h
.rodata:000000000306E0F0                 dq offset aFortisslvpnSsl ; "fortisslvpn/sslvpn_installer"
.rodata:000000000306E0F8                 dq offset sub_1642F70
```

通过动态调试ap_invoke_handler函数，发现request的handler也为rmt-webcgi-handler

```
(gdb) x /s *(long*)($rdi+328)    
0x7f0710ba43b0:	"rmt-webcgi-handler"
```

# request_rec 的handler是什么时候设置的呢

