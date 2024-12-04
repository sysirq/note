# 版本

以下分析基于:FGT 7.2.0 VM 版本

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

```
#0  0x000000000162410a in ?? ()   #apache find_ct function
#1  0x00000000015fccb5 in ?? ()   #apache ap_run_type_checker
#2  0x0000000001608e46 in ?? ()		#apache ap_process_request_internal
#3  0x00000000017114fd in ?? ()
#4  0x0000000001713ad5 in ?? ()
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
```

# ssl vpn module 的 command_struct 

```
.rodata:000000000306C040 off_306C040     dq offset aAddtype      ; DATA XREF: .data:00000000042C1058↓o
.rodata:000000000306C040                                         ; "AddType"
.rodata:000000000306C048                 dq offset sub_1623270
.rodata:000000000306C050                 dq 0
.rodata:000000000306C058                 dd 4
.rodata:000000000306C05C                 dd 4
.rodata:000000000306C060                 dq offset aAMimeTypeFollo ; "a mime type followed by one or more fil"...
.rodata:000000000306C068                 dq offset aAddencoding  ; "AddEncoding"
.rodata:000000000306C070                 dq offset sub_16232C0
.rodata:000000000306C078                 dq 0
.rodata:000000000306C080                 dd 4
.rodata:000000000306C084                 dd 4
.rodata:000000000306C088                 dq offset aAnEncodingEGGz ; "an encoding (e.g., gzip), followed by o"...
.rodata:000000000306C090                 dq offset aAddcharset   ; "AddCharset"
.rodata:000000000306C098                 dq offset sub_1623310
.rodata:000000000306C0A0                 dq 0
.rodata:000000000306C0A8                 dd 4
.rodata:000000000306C0AC                 dd 4
.rodata:000000000306C0B0                 dq offset aACharsetEGIso2 ; "a charset (e.g., iso-2022-jp), followed"...
.rodata:000000000306C0B8                 dq offset aAddlanguage  ; "AddLanguage"
.rodata:000000000306C0C0                 dq offset sub_1623360
.rodata:000000000306C0C8                 dq 0
.rodata:000000000306C0D0                 dd 4
.rodata:000000000306C0D4                 dd 4
.rodata:000000000306C0D8                 dq offset aALanguageEGFrF ; "a language (e.g., fr), followed by one "...
.rodata:000000000306C0E0                 dq offset aAddhandler   ; "AddHandler"
.rodata:000000000306C0E8                 dq offset sub_16233B0
.rodata:000000000306C0F0                 dq 0
.rodata:000000000306C0F8                 dd 4
.rodata:000000000306C0FC                 dd 4
.rodata:000000000306C100                 dq offset aAHandlerNameFo ; "a handler name followed by one or more "...
.rodata:000000000306C108                 dq offset aForcetype    ; "ForceType"
.rodata:000000000306C110                 dq offset sub_15FE090
.rodata:000000000306C118                 dq 40h
.rodata:000000000306C120                 dd 4
.rodata:000000000306C124                 dd 1
.rodata:000000000306C128                 dq offset aAMediaType   ; "a media type"
.rodata:000000000306C130                 dq offset aRemovehandler ; "RemoveHandler"
.rodata:000000000306C138                 dq offset sub_1623400
.rodata:000000000306C140                 dq 0
.rodata:000000000306C148                 dd 4
.rodata:000000000306C14C                 dd 3
.rodata:000000000306C150                 dq offset aOneOrMoreFileE ; "one or more file extensions"
.rodata:000000000306C158                 dq offset aRemoveencoding ; "RemoveEncoding"
.rodata:000000000306C160                 dq offset sub_1623450
.rodata:000000000306C168                 dq 0
.rodata:000000000306C170                 dd 4
.rodata:000000000306C174                 dd 3
.rodata:000000000306C178                 dq offset aOneOrMoreFileE ; "one or more file extensions"
.rodata:000000000306C180                 dq offset aRemovetype   ; "RemoveType"
.rodata:000000000306C188                 dq offset sub_16234A0
.rodata:000000000306C190                 dq 0
.rodata:000000000306C198                 dd 4
.rodata:000000000306C19C                 dd 3
.rodata:000000000306C1A0                 dq offset aOneOrMoreFileE ; "one or more file extensions"
.rodata:000000000306C1A8                 dq offset aSethandler   ; "SetHandler"
.rodata:000000000306C1B0                 dq offset sub_15FE090
.rodata:000000000306C1B8                 dq 48h
.rodata:000000000306C1C0                 dd 4
.rodata:000000000306C1C4                 dd 1
.rodata:000000000306C1C8                 dq offset aAHandlerName ; "a handler name"
.rodata:000000000306C1D0                 dq offset aTypesconfig  ; "TypesConfig"
.rodata:000000000306C1D8                 dq offset sub_16234F0
.rodata:000000000306C1E0                 dq 0
.rodata:000000000306C1E8                 dd 80h
.rodata:000000000306C1EC                 dd 1
.rodata:000000000306C1F0                 dq offset aTheMimeTypesCo ; "the MIME types config file"
.rodata:000000000306C1F8                 dq offset aDefaultlanguag ; "DefaultLanguage"
.rodata:000000000306C200                 dq offset sub_15FE080
.rodata:000000000306C208                 dq 50h
.rodata:000000000306C210                 dd 4
.rodata:000000000306C214                 dd 1
.rodata:000000000306C218                 dq offset aLanguageToUseF ; "language to use for documents with no o"...
```

# 疑似处理SSL 连接过程中的状态转换的代码

通过字符串“read_client_block”的引用的引用可以找到sub_1724B60函数:

```c
void sub_1724B60()
{
  dword_BBA8128 = 0;
  qword_BBA8130 = (__int64)sub_1705070;
  dword_BBA8170 = 8;
  qword_BBA8178 = (__int64)sub_1705410;
  dword_BBA81D0 = 4;
  qword_BBA81D8 = (__int64)sub_1706410;
  qword_BBA81E0 = (__int64)sub_1706480;
  dword_BBA8230 = 15;
  qword_BBA8238 = (__int64)sub_172C240;
  qword_BBA8240 = (__int64)sub_172C310;
  dword_BBA8248 = 16;
  qword_BBA8250 = (__int64)sub_1728EE0;
  qword_BBA8258 = (__int64)sub_1728FE0;
  dword_BBA8188 = 6;
  qword_BBA8190 = (__int64)sub_1712020;
  dword_BBA81A0 = 7;
  qword_BBA81A8 = (__int64)sub_1712F30;
  dword_BBA8218 = 13;
  qword_BBA8220 = (__int64)sub_1675820;
  qword_BBA8228 = (__int64)sub_1675940;
  dword_BBA8158 = 9;
  qword_BBA8160 = (__int64)sub_171A6F0;
  dword_BBA81B8 = 11;
  qword_BBA81C0 = (__int64)sub_16A0130;
  qword_BBA81C8 = (__int64)sub_16A01D0;
  dword_BBA81E8 = 5;
  qword_BBA81F0 = (__int64)sub_172E4D0;
  dword_BBA8200 = 12;
  qword_BBA8208 = (__int64)sub_1697F00;
  qword_BBA8210 = (__int64)sub_16983A0;
  dword_BBA8140 = 3;
  qword_BBA8148 = (__int64)sub_170CC00;
  qword_BBA8150 = (__int64)sub_170CCB0;
  dword_BBA8260 = 17;
  qword_BBA8268 = (__int64)sub_171A1A0;
  qword_BBA8270 = (__int64)sub_171A200;
  dword_BBA8278 = 18;
  qword_BBA8280 = (__int64)sub_17354F0;
  qword_BBA8288 = (__int64)sub_1735560;
  dword_BBA8290 = 19;
  qword_BBA8298 = (__int64)sub_170D1A0;
  dword_BBA82A8 = 20;
  qword_BBA82B0 = (__int64)sub_17387A0;
  qword_BBA82B8 = (__int64)sub_1738890;
  dword_BBA82C0 = 21;
  qword_BBA82C8 = (__int64)sub_170EC00;
  qword_BBA82D0 = (__int64)sub_170ECA0;
}
```



在sub_1715180函数中，疑似通过连接是否可读或者写，通过指定的参数调用sub_1713A40函数（可以看到代码通过测试，用不同的参数对sub_1713A40进行了调用，分别对应读和写的情况），进行连接处理。

```c
__int64 __fastcall sub_1715180(__int64 a1, char a2)
{
  __int64 v2; // rax
  __int64 result; // rax
  int v4; // er14
  __int64 v5; // r12
  __int64 v6; // rbx
  __int64 v7; // rsi
  __int64 v8; // rdx
  __int64 (__fastcall *v9)(__int64); // rax
  __int64 v10; // rax

  v2 = qword_BBA80C0;
  if ( qword_BBA80C0 - 1000 - *(_QWORD *)(a1 + 984) >= 0 )
  {
    sub_166BB70();
    v2 = qword_BBA80C0;
  }
  if ( v2 - (unsigned int)(*(_DWORD *)(a1 + 912) + 1000) >= 0 )
  {
    sub_166BE70(a1);
    v2 = qword_BBA80C0;
  }
  if ( v2 - (unsigned int)(*(_DWORD *)(a1 + 936) + 12000) >= 0 )
    sub_162B390(a1);
  if ( !a2 || (result = sub_162AA90(a1), (int)result >= 0) )
  {
    v4 = 0;
    result = sub_1722770(a1);
    do
    {
      v5 = a1 + 32 * (v4 + 6LL);
      if ( (*(_BYTE *)(v5 + 16) & 2) != 0 )
      {
        result = sub_1713A40(a1, v4, 1u);    // 喵喵喵喵 ，重点函数
        if ( (_DWORD)result )
          goto LABEL_23;
        *(_BYTE *)(v5 + 16) &= 0xFDu;
      }
      v6 = a1 + 32 * (v4 + 6LL);
      if ( (*(_BYTE *)(v6 + 16) & 4) != 0 )
      {
        result = sub_1713A40(a1, v4, 0);    // 喵喵喵喵 ，重点函数
        if ( (_DWORD)result )
        {
LABEL_23:
          v10 = *(_QWORD *)(a1 + 664);
          if ( v10 )
          {
            v9 = *(__int64 (__fastcall **)(__int64))(v10 + 136);
            if ( v9 )
              return v9(a1);
          }
          return sub_1713E80(a1);
        }
        *(_BYTE *)(v6 + 16) &= 0xFBu;
      }
      ++v4;
    }
    while ( v4 != 5 );
    v7 = *(_QWORD *)(a1 + 664);
    if ( v7 )
    {
      v8 = *(_QWORD *)(v7 + 112);
      if ( v8 )
      {
        result = v7 + 96;
        if ( v8 != v7 + 96 )
        {
          v9 = *(__int64 (__fastcall **)(__int64))(v8 + 200);
          if ( v9 )
            return v9(a1);
          result = sub_1713400(a1, v7, v8);
        }
      }
    }
  }
  return result;
}
```

sub_1713A40 函数，通过

```
    v11 = *(__int64 (__fastcall **)(__int64))(32LL * a2 + v27 + 32);
    if ( !v11 )
```

调用sub_1724B60注册的函数，如：

```
  sub_1724730((__int64 *)a2, "send_expect_100", 0, 4, (__int64)sub_171A4B0);
  sub_1724730((__int64 *)a2, "read_post_data", 0, 1, (__int64)sub_171A510);
```

```
2326: 2024-12-01 22:56:53 <00223> [0x0171a602] => /bin/sslvpnd  
2327: 2024-12-01 22:56:53 <00223> [0x01713ad5] => /bin/sslvpnd  
```

实现对read_post_data 函数的调用



```c
__int64 __fastcall sub_1713A40(__int64 a1, int a2, unsigned int a3)
{
  char v4; // al
  __int64 v5; // r13
  __int64 v6; // rsi
  __int64 v7; // rcx
  __int64 v8; // r14
  unsigned int v9; // ebx
  __int64 v10; // rdx
  __int64 (__fastcall *v11)(__int64); // rax
  char v12; // al
  __int64 result; // rax
  __int64 (__fastcall *v14)(__int64, __int64, __int64, __int64); // rax
  __int64 v15; // rcx
  __int64 j; // rax
  __int64 *v17; // rax
  __int64 v18; // rcx
  __int64 i; // rax
  __int64 v20; // rcx
  __int64 k; // rax
  __int64 *v22; // rax
  __int64 v23; // rcx
  __int64 l; // rax
  __int64 v25; // rcx
  __int64 m; // rax
  __int64 v27; // [rsp+8h] [rbp-38h]

  v4 = *(_BYTE *)(a1 + 1143);
  v5 = *(_QWORD *)(a1 + 664);
  v6 = v4 & 0x20;
  if ( !v5 || (v7 = *(_QWORD *)(v5 + 112)) == 0 || (v8 = v5 + 96, v5 + 96 == v7) )
  {
    if ( !(_BYTE)v6 )
    {
      if ( (v4 & 0x40) == 0 )
      {
LABEL_19:
        if ( (int)sub_17136C0(a1, v5) < 0 )
        {
          if ( !sub_17050F0(a1) )
          {
            sub_17050D0(a1);
            return 1LL;
          }
        }
        else if ( !sub_17050F0(a1) )
        {
          return sub_1713720(a1);
        }
        return 1LL;
      }
      return sub_1713720(a1);
    }
    goto LABEL_66;
  }
  v9 = a3;
  if ( a2 < 0 )
  {
    if ( !(_BYTE)v6 )
    {
      v12 = v4 & 0x40;
      goto LABEL_15;
    }
LABEL_66:
    *(_BYTE *)(a1 + 1140) |= 0x80u;
    return 0xFFFFFFFFLL;
  }
  if ( (_BYTE)v6 )
    goto LABEL_66;
  v27 = *(_QWORD *)(v5 + 112);
  sub_2902A70(a3);
  if ( v9 )
  {
    v11 = *(__int64 (__fastcall **)(__int64))(32LL * a2 + v27 + 32);  // 喵喵喵喵 ，重点函数
    if ( !v11 )
      return 0xFFFFFFFFLL;
    v9 = v11(a1);
    v12 = *(_BYTE *)(a1 + 1143) & 0x40;
    if ( !v9 )
    {
      if ( v12 )
        goto LABEL_10;
      *(_DWORD *)(v27 + 32LL * a2 + 16) = sub_1713990(a1, (unsigned int)a2, 1LL);
      if ( (*(_BYTE *)(a1 + 1143) & 0x40) != 0 )
        return sub_1713720(a1);
      return 0LL;
    }
  }
  else
  {
    v14 = *(__int64 (__fastcall **)(__int64, __int64, __int64, __int64))(32LL * a2 + v27 + 40); // 喵喵喵喵 ，重点函数
    if ( !v14 )
      return 0xFFFFFFFFLL;
    v9 = v14(a1, v6, v10, v27);
    v12 = *(_BYTE *)(a1 + 1143) & 0x40;
    if ( v12 )
    {
LABEL_10:
      if ( v9 == 7 )
        return 0xFFFFFFFFLL;
      return sub_1713720(a1);
    }
    if ( !v9 )
    {
      *(_DWORD *)(v27 + 32LL * a2 + 20) = sub_1713990(a1, (unsigned int)a2, 0LL);
      if ( (*(_BYTE *)(a1 + 1143) & 0x40) != 0 )
        return sub_1713720(a1);
      return 0LL;
    }
  }
LABEL_15:
  if ( v12 )
    goto LABEL_10;
  switch ( v9 )
  {
    case 0u:
      return v9;
    case 1u:
      v18 = *(_QWORD *)(*(_QWORD *)(v5 + 112) + 8LL);
      if ( v18 == v8 )
        return 0xFFFFFFFFLL;
      for ( i = 0LL; i != 40; i += 8LL )
      {
        if ( *(_QWORD *)(a1 + i + 616) )
        {
          *(_DWORD *)(v18 + 4 * i + 16) = *(_DWORD *)(v18 + 4 * i + 24);
          *(_DWORD *)(v18 + 4 * i + 20) = *(_DWORD *)(v18 + 4 * i + 28);
        }
      }
      *(_QWORD *)(v5 + 112) = *(_QWORD *)(*(_QWORD *)(v5 + 112) + 8LL);
      return 0LL;
    case 2u:
      v22 = *(__int64 **)(v5 + 112);
      goto LABEL_46;
    case 3u:
      v17 = *(__int64 **)(v5 + 112);
      goto LABEL_40;
    case 4u:
      v15 = **(_QWORD **)(v5 + 112);
      if ( v15 == v8 )
        goto LABEL_19;
      for ( j = 0LL; j != 40; j += 8LL )
      {
        if ( *(_QWORD *)(a1 + j + 616) )
        {
          *(_DWORD *)(v15 + 4 * j + 16) = *(_DWORD *)(v15 + 4 * j + 24);
          *(_DWORD *)(v15 + 4 * j + 20) = *(_DWORD *)(v15 + 4 * j + 28);
        }
      }
      v17 = **(__int64 ***)(v5 + 112);
      *(_QWORD *)(v5 + 112) = v17;
LABEL_40:
      v20 = *v17;
      if ( *v17 == v8 )
        goto LABEL_19;
      for ( k = 0LL; k != 40; k += 8LL )
      {
        if ( *(_QWORD *)(a1 + k + 616) )
        {
          *(_DWORD *)(v20 + 4 * k + 16) = *(_DWORD *)(v20 + 4 * k + 24);
          *(_DWORD *)(v20 + 4 * k + 20) = *(_DWORD *)(v20 + 4 * k + 28);
        }
      }
      v22 = **(__int64 ***)(v5 + 112);
      *(_QWORD *)(v5 + 112) = v22;
LABEL_46:
      v23 = *v22;
      if ( *v22 == v8 )
        goto LABEL_19;
      for ( l = 0LL; l != 40; l += 8LL )
      {
        if ( *(_QWORD *)(a1 + l + 616) )
        {
          *(_DWORD *)(v23 + 4 * l + 16) = *(_DWORD *)(v23 + 4 * l + 24);
          *(_DWORD *)(v23 + 4 * l + 20) = *(_DWORD *)(v23 + 4 * l + 28);
        }
      }
      *(_QWORD *)(v5 + 112) = **(_QWORD **)(v5 + 112);
      result = 0LL;
      break;
    case 5u:
      v25 = *(_QWORD *)(v5 + 112);
      if ( v25 && v8 == v25 )
        v25 = 0LL;
      for ( m = 0LL; m != 40; m += 8LL )
      {
        if ( *(_QWORD *)(a1 + m + 616) )
        {
          *(_DWORD *)(v25 + 4 * m + 16) = *(_DWORD *)(v25 + 4 * m + 24);
          *(_DWORD *)(v25 + 4 * m + 20) = *(_DWORD *)(v25 + 4 * m + 28);
        }
      }
      return 0LL;
    case 6u:
      goto LABEL_19;
    default:
      return 0xFFFFFFFFLL;
  }
  return result;
}
```

# 连接处理相关流程分析

sslvpnd中，存在自己的事件循环处理机制，也存在自己的用来管理连接的结构体：

根据“allocSSLConn”字符串 ， 可以找到sub_1722890 函数

```c
__int64 __fastcall sub_1722890(unsigned int a1, const __m128i *a2, __int64 a3, char a4, int a5)
{
  __int64 v7; // rax
  __int64 v8; // r12
  __int64 v9; // rcx
  __int64 *v10; // rax
  __int64 v11; // rdi
  __m128i v12; // xmm0
  __m128i v13; // xmm1
  __m128i v14; // xmm2
  __m128i v15; // xmm3
  __m128i v16; // xmm4
  __m128i v17; // xmm5
  __m128i v18; // xmm6
  __m128i v19; // xmm7
  __int64 v20; // rdi
  __int64 v21; // rax
  unsigned int v22; // edx
  int v23; // eax
  unsigned __int64 v24; // rax
  bool v25; // al
  char v26; // al
  __int64 v28; // rdi
  __int64 v29; // rax
  int *v30; // rax
  char *v31; // rax
  __int64 v32; // rdi

  v7 = je_calloc(1LL, a5 + 1152LL);
  v8 = v7;
  if ( !v7 )
    return v8;
  if ( a3 )
  {
    *(_DWORD *)(v7 + 144) = *(_DWORD *)(a3 + 200);
    *(_BYTE *)(v7 + 148) = *(_BYTE *)(a3 + 204);
  }
  else if ( (int)sub_2846F50(a1, v7 + 144, v7 + 148) < 0 )
  {
    v30 = __errno_location();
    v31 = strerror(*v30);
    sub_166F020(0LL, 8LL, (__int64)"%s:%d get_ervf_vrf_id() failed: %s\n", "allocSSLConn", 214LL, v31);
    v32 = v8;
    v8 = 0LL;
    je_free(v32);
    return v8;
  }
  v9 = v8 + 40;
  *(_DWORD *)(v8 + 184) = a1;
  *(_QWORD *)(v8 + 8) = v8 + 8;
  *(_QWORD *)(v8 + 16) = v8 + 8;
  *(_QWORD *)(v8 + 24) = v8 + 24;
  *(_QWORD *)(v8 + 32) = v8 + 24;
  *(_QWORD *)(v8 + 680) = v8 + 680;
  *(_QWORD *)(v8 + 688) = v8 + 680;
  *(_QWORD *)(v8 + 72) = v8 + 72;
  *(_QWORD *)(v8 + 80) = v8 + 72;
  *(_DWORD *)(v8 + 216) = -1;
  *(_DWORD *)(v8 + 248) = -1;
  *(_DWORD *)(v8 + 280) = -1;
  *(_DWORD *)(v8 + 312) = -1;
  *(_QWORD *)(v8 + 192) = sub_17143B0;
  *(_QWORD *)(v8 + 224) = sub_17143B0;
  *(_QWORD *)(v8 + 256) = sub_17143B0;
  *(_QWORD *)(v8 + 288) = sub_17143B0;
  *(_QWORD *)(v8 + 320) = sub_17143B0;
  *(_QWORD *)(v8 + 40) = v8 + 40;
  *(_QWORD *)(v8 + 48) = v8 + 40;
  *(_QWORD *)(v8 + 88) = v8 + 88;
  *(_QWORD *)(v8 + 96) = v8 + 88;
  *(_QWORD *)(v8 + 752) = 0LL;
  *(_QWORD *)(v8 + 760) = 1LL;
  *(_QWORD *)(v8 + 112) = 0LL;
  *(_QWORD *)(v8 + 120) = 1LL;
  *(_QWORD *)(v8 + 128) = 0LL;
  *(_QWORD *)(v8 + 136) = 1LL;
  *(_QWORD *)(v8 + 792) = 0LL;
  *(_QWORD *)(v8 + 800) = 1LL;
  if ( a4 )
  {
    *(_BYTE *)(v8 + 1144) |= 2u;
    *(_QWORD *)(v8 + 1032) = 0LL;
    *(_QWORD *)(v8 + 1040) = 1LL;
  }
  else
  {
    sub_1704600((__int64 *)v8, a1, (__int64)a2);
    *(_QWORD *)(v8 + 616) = *(_QWORD *)(v8 + 720);
    sub_1713030(v8);
    v9 = v8 + 40;
  }
  v10 = (__int64 *)qword_BBA80F0;
  qword_BBA80F0 = v9;
  *(_QWORD *)(v8 + 40) = &qword_BBA80E8;
  *(_QWORD *)(v8 + 48) = v10;
  *v10 = v9;
  v11 = *(unsigned int *)(v8 + 144);
  ++dword_BBA80F8;
  sub_27D82A0(v11);
  v12 = _mm_loadu_si128(a2);
  v13 = _mm_loadu_si128(a2 + 1);
  v14 = _mm_loadu_si128(a2 + 2);
  v15 = _mm_loadu_si128(a2 + 3);
  *(_DWORD *)(v8 + 820) = -1;
  v16 = _mm_loadu_si128(a2 + 4);
  v17 = _mm_loadu_si128(a2 + 5);
  *(__m128i *)(v8 + 344) = v12;
  v18 = _mm_loadu_si128(a2 + 6);
  v19 = _mm_loadu_si128(a2 + 7);
  *(__m128i *)(v8 + 360) = v13;
  v20 = *(unsigned int *)(v8 + 144);
  *(__m128i *)(v8 + 376) = v14;
  *(__m128i *)(v8 + 392) = v15;
  *(__m128i *)(v8 + 408) = v16;
  *(__m128i *)(v8 + 424) = v17;
  *(__m128i *)(v8 + 440) = v18;
  *(__m128i *)(v8 + 456) = v19;
  sub_17226D0(v20, v8 + 149, 32LL);
  v21 = sub_17200F0(*(_DWORD *)(v8 + 144));
  if ( !v21 )
    goto LABEL_31;
  if ( (*(_BYTE *)(v21 + 36) & 4) != 0 )
    *(_BYTE *)(v8 + 1141) |= 8u;
  if ( a2->m128i_i16[0] == 10 )
    *(_BYTE *)(v8 + 1143) |= 2u;
  v22 = ++dword_42C2234;
  if ( byte_BBAF688 )
    goto LABEL_15;
  v23 = 0;
LABEL_13:
  if ( !v22 )
  {
    byte_BBAF688 = 1;
    v22 = 1;
    dword_42C2234 = 1;
    if ( v23 == 1 )
    {
LABEL_30:
      sub_166F020(v8, 128LL, (__int64)"%s:%d run out of connection index.\n", "allocSSLConn", 276LL);
LABEL_31:
      v28 = v8;
      v8 = 0LL;
      sub_17222B0(v28);
      return v8;
    }
LABEL_15:
    v24 = qword_BBA80C8;
    if ( qword_BBA80C8 )
    {
      while ( *(_DWORD *)(v24 + 104) != v22 )
      {
        if ( *(_DWORD *)(v24 + 104) > v22 )
          v24 = *(_QWORD *)(v24 + 128);
        else
          v24 = *(_QWORD *)(v24 + 136) & 0xFFFFFFFFFFFFFFFELL;
        if ( !v24 )
        {
          v23 = 1;
          goto LABEL_13;
        }
      }
      dword_42C2234 = v22 + 1;
      goto LABEL_30;
    }
    byte_BBAF688 = 0;
    v22 = 1;
    dword_42C2234 = 1;
  }
  *(_DWORD *)(v8 + 104) = v22;
  sub_1720980(&qword_BBA80D0, v8);
  sub_1721600(&qword_BBA80C8, v8);
  sub_166F020(
    v8,
    128LL,
    (__int64)"%s:%d sconn %p (%d:%s)\n",
    "allocSSLConn",
    303LL,
    (const void *)v8,
    *(unsigned int *)(v8 + 144),
    (const char *)(v8 + 149));
  if ( (unsigned int)sub_2060A60(135, 128LL) || (v29 = sub_21258E0(*(_QWORD *)(qword_EF84C80 + 1080))) == 0 )
    v25 = 0;
  else
    v25 = *(_BYTE *)(v29 + 8) == 1;
  v26 = (8 * v25) | *(_BYTE *)(v8 + 1144) & 0xF7;
  if ( a3 )
    v26 |= 0x80u;
  *(_BYTE *)(v8 + 1144) = v26;
  return v8;
}
```

该函数为FGT自己用来申请管理连接的结构体的函数，通过对该函数下断点，然后访问sslvpnd，可以得到下面的bt：

```
Breakpoint 3, 0x0000000001722890 in ?? ()
(gdb) bt
#0  0x0000000001722890 in ?? () #申请SSL vpn自己的，用来管理连接的结构体
#1  0x00000000017150cc in ?? () #sub_1714EF0
#2  0x0000000001715d47 in ?? ()
#3  0x0000000001716f42 in ?? ()
#4  0x0000000001717236 in ?? ()
#5  0x0000000001717919 in ?? ()
#6  0x000000000044c88f in ?? ()
#7  0x00000000004554ca in ?? ()
#8  0x000000000045212c in ?? ()
#9  0x0000000000454738 in ?? ()
#10 0x0000000000455061 in ?? ()
#11 0x00007fad5ad07deb in __libc_start_main () from /usr/lib/x86_64-linux-gnu/libc.so.6
#12 0x0000000000447daa in ?? ()
```

sub_1714EF0 为通过Unix域套节字机制，获取父进程accpet的fd

```c
__int64 __fastcall sub_1714EF0(int fd, unsigned int a2)
{
  int v2; // eax
  __int64 v4; // rbx
  int v5; // er12
  unsigned int v6; // er13
  int v7; // edi
  __int64 v8; // r12
  unsigned int v9; // eax
  int *v10; // rax
  socklen_t v11; // [rsp-124h] [rbp-12Ch] BYREF
  __int128 v12; // [rsp-120h] [rbp-128h] BYREF
  struct msghdr v13; // [rsp-110h] [rbp-118h] BYREF
  _QWORD v14[2]; // [rsp-D0h] [rbp-D8h] BYREF
  struct sockaddr v15[8]; // [rsp-C0h] [rbp-C8h] BYREF
  _QWORD v16[9]; // [rsp-40h] [rbp-48h] BYREF

  v16[3] = __readfsqword(0x28u);
  v12 = 0LL;
  v13.msg_control = v16;
  v14[0] = &v12;
  *(_QWORD *)&v13.msg_flags = 0LL;
  v13.msg_controllen = 24LL;
  v14[1] = 16LL;
  v13.msg_iov = (iovec *)v14;
  v13.msg_iovlen = 1LL;
  *(_OWORD *)&v13.msg_name = 0LL;
  if ( (a2 & 0x18) != 0 )
  {
    sub_166F020(0LL, 8LL, (__int64)"parent fd error! close child %x.\n", a2);
    exit(1);
  }
  while ( recvmsg(fd, &v13, 0) <= 0 )
  {
    v2 = *__errno_location();
    if ( v2 != 4 && v2 != 11 )
      return 4294967294LL;
  }
  v4 = (unsigned int)v12;
  if ( (_DWORD)v12 == 1 )
  {
    if ( v13.msg_controllen <= 0xF
      || !v13.msg_control
      || *(_QWORD *)v13.msg_control != 20LL
      || *((_QWORD *)v13.msg_control + 1) != 0x100000001LL )
    {
      return 0xFFFFFFFFLL;
    }
    v6 = *((_DWORD *)v13.msg_control + 4);
    if ( dword_BBA80F8 < dword_BBA8124 )
    {
      v11 = 128;
      if ( getpeername(v6, v15, &v11) >= 0 )
      {
        v7 = v6;
        v8 = sub_1722890(v6, (const __m128i *)v15, 0LL, 0, 0);//调用sub_1722890创建连接管理结构体，v6为父进程accept 的fd，通过Unix域套节字传递过来的，v15为客户端的地址
        if ( v8 )
        {
          sub_1722230(v6);
          sub_1714800(v8);//设置结构体中的函数指针表，以及进行状态转换
          return 0LL;
        }
        goto LABEL_25;
      }
      v10 = __errno_location();
      sub_166F020(0LL, 8LL, (__int64)"failed to get peer name %d\n", (unsigned int)*v10);
    }
    v7 = v6;
LABEL_25:
    close(v7);
    return 0xFFFFFFFFLL;
  }
  if ( (_DWORD)v12 == 2 )
  {
    if ( v13.msg_controllen > 0xF
      && v13.msg_control
      && *(_QWORD *)v13.msg_control == 20LL
      && *((_QWORD *)v13.msg_control + 1) == 0x100000001LL )
    {
      v5 = *((_DWORD *)v13.msg_control + 4);
      sub_1714A00(v5);
      close(v5);
      return 0LL;
    }
    return 0xFFFFFFFFLL;
  }
  v9 = getpid();
  sub_166F020(0LL, 524296LL, (__int64)"[%d] %s:%d unknown cmd %d\n", v9, "sslvpn_listenPassingFdHandler", 887LL, v4);
  return 0xFFFFFFFFLL;
}
```



sub_1714EF0 会调用sub_1714800



sub_1714800 会调用sub_1713720，对sconn结构体中的函数指针表进行初始化，这里刚好与（疑似处理SSL 连接过程中的状态转换的代码）这一节说到的sub_1724B60函数对上了

```c
__int64 __fastcall sub_1713720(__int64 a1)
{
  _QWORD *v1; // r14
  __int64 *v2; // rax
  __int64 v3; // rcx
  _QWORD *v4; // rdx
  __int64 *v5; // rbx
  unsigned int v6; // er14
  unsigned int (__fastcall *v7)(__int64, __int64 *); // rax
  __int64 *v8; // rax
  __int64 (__fastcall *v9)(__int64, __int64 *); // rdx
  int v10; // eax
  int *v12; // rax
  __int64 i; // rdx

  while ( 1 )
  {
    v1 = *(_QWORD **)(a1 + 664);
    sub_1722770(a1);
    *(_BYTE *)(a1 + 208) &= 0xF9u;
    *(_BYTE *)(a1 + 240) &= 0xF9u;
    *(_BYTE *)(a1 + 272) &= 0xF9u;
    *(_BYTE *)(a1 + 304) &= 0xF9u;
    *(_BYTE *)(a1 + 336) &= 0xF9u;
    sub_17243F0((_QWORD *)a1);
    if ( v1 )
    {
      sub_1724800(a1, v1);
      change_sconn_function_table(a1, 0LL);
    }
    v2 = *(__int64 **)(a1 + 680);
    *(_BYTE *)(a1 + 1143) &= 0xBFu;
    if ( v2 == (__int64 *)(a1 + 680) )
    {
      v6 = 1;
      v5 = sub_17245D0(a1, (__int64)&dword_BBA8188, 0);
    }
    else
    {
      v3 = *v2;
      v4 = (_QWORD *)v2[1];
      v5 = v2 - 1;
      if ( *v2 )
        *(_QWORD *)(v3 + 8) = v4;
      if ( v4 )
        *v4 = v3;
      *v2 = (__int64)v2;
      v6 = 0;
      v2[1] = (__int64)v2;
    }
    change_sconn_function_table(a1, (__int64)v5);
    v5[6] = qword_BBA80C0;
    if ( (unsigned int)sub_1724860((__int64)v5) )
      break;
    sub_1724870((__int64)v5);
    v7 = *(unsigned int (__fastcall **)(__int64, __int64 *))(v5[7] + 8);
    if ( v7 && v7(a1, v5) )
    {
      sub_166F020(a1, 8LL, (__int64)"sslStateInit error\n");
      return 0xFFFFFFFFLL;
    }
    v8 = (__int64 *)v5[12];
    if ( v8 == v5 + 12 )
    {
      sub_166F020(a1, 8LL, (__int64)"task empty\n");
      return 0xFFFFFFFFLL;
    }
    v9 = (__int64 (__fastcall *)(__int64, __int64 *))v5[11];
    v5[14] = (__int64)v8;
    if ( !v9 )
      goto LABEL_27;
    v10 = v9(a1, v5);
    if ( v10 == 7 )
    {
      sub_166F020(a1, 8LL, (__int64)"enter() returned task error.\n");
      return 0xFFFFFFFFLL;
    }
    if ( v10 == 6 )
    {
      if ( (int)sub_17136C0(a1, (__int64)v5) < 0 )
      {
        sub_166F020(a1, 8LL, (__int64)"sslStateDoFinish error\n");
        return 0xFFFFFFFFLL;
      }
      v12 = (int *)v5[7];
      if ( v6 || v12 == &dword_BBA8128 )
      {
        sub_166F020(
          a1,
          8LL,
          (__int64)"%s:%d error (last state: %d, closeOp: %d)\n",
          "sslConnGotoNextState",
          311LL,
          v6,
          v12 == &dword_BBA8128);
        return 0xFFFFFFFFLL;
      }
    }
    else
    {
      if ( (*(_BYTE *)(a1 + 1143) & 0x40) == 0 )
        break;
      if ( v6 )
      {
        sub_166F020(a1, 8LL, (__int64)"http request enter error!.\n");
        return 0xFFFFFFFFLL;
      }
    }
  }
  v8 = (__int64 *)v5[14];
LABEL_27:
  for ( i = 0LL; i != 20; i += 4LL )
  {
    if ( *(_QWORD *)(a1 + i * 2 + 616) )
    {
      LODWORD(v8[i + 2]) = v8[i + 3];
      HIDWORD(v8[i + 2]) = HIDWORD(v8[i + 3]);
    }
  }
  return 0LL;
}
```





FGT用于管理连接的结构体的结构：

```
*(_DWORD *)(v8 + 184) = a1; //client的fd
```

