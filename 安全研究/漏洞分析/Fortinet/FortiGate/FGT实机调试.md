网线连接FGT设备的MGMT端口端口，然后访问：

https://192.168.1.99

### Getting Root Access to the 100D

To get a root shell on the 100D and to install GDB, Frida server, etc. we created a local root exploit for another FortiGate bug ([CVE-2021-44168](https://www.fortiguard.com/psirt/FG-IR-21-201)). Interestingly, much like CVE-2022-42475, CVE-2021-44168 was discovered during the investigation of a compromised FortiGate firewall.

# CVE-2021-44168

### 安全提取（移除路径前缀）

使用 --strip-components 忽略文件路径中的危险部分，只保留文件名或较短的路径。例如，假设路径为 ../../../../../data2/bfbin/mkswap：

```
tar --strip-components=6 -xf archive.tar -C /safe/output/directory
```

### Build a malicious tarball on Linux

```
tar Pcf file.tar ./../../../../path/to/file
```

# 实机数据结构以及CPU个数

### 100D_6_2_5

cpu：4
sconn大小：1072 ，在jemalloc 中，会被分配到1280字节的内存
SSL 结构体大小：6224 , 在jemalloc 中，会被分配到8kb内存

##### 内存分配函数

je_calloc:

```c
__int64 __fastcall sub_13993F0(__int64 a1)
{
  __int64 result; // rax

  result = sub_E24A70(a1);
  ++dword_13659CC0;
  return result;
}
```

je_malloc:

```c
_QWORD *__fastcall sub_12C3CD0(int a1)
{
  _QWORD *result; // rax

  result = (_QWORD *)sub_E24A70(a1 + 24);
  if ( !result )
  {
    fwrite("Ouch!  je_malloc failed in malloc_block()\n", 1uLL, 0x2AuLL, stderr);
    exit(1);
  }
  result[1] = 0LL;
  result[2] = result + 3;
  *result = (char *)result + a1 + 24;
  return result;
}
```

##### 有用的脚本

```
set pagination off
handle SIGPIPE nostop

b *SSL_free
commands
	silent
	printf "ssl struct free  addr:%p\n",$rdi
	continue
end

b *SSL_new+0x33
commands
	silent
	printf "ssl struct alloc addr:%p\n",$rax
	continue
end

set pagination off
hb *0x0000000000E15920 if (($rsi > 6144)&&($rsi<=8192))
commands
  silent
	printf "alloc size:0x%x\n",$rsi
	bt
	continue
end

set pagination off
hb *0x00000000012CAC6F
commands
  silent
	printf "buf alloc addr:       %p\n",$rax
	continue
end
```

##### 事件循环

```
#2  0x0000000001396e2d in ?? ()
#3  0x0000000001397f90 in ?? ()
```

# TFTP PYTHON CODE

```python
import os
import socket

# TFTP 默认端口
TFTP_PORT = 69
BUFFER_SIZE = 516  # 512 字节数据 + 4 字节头
TFTP_ROOT = "./tftp_root"  # 文件存储的根目录

# 创建根目录（如果不存在）
os.makedirs(TFTP_ROOT, exist_ok=True)

def handle_client(data, addr, server_socket):
    """处理客户端请求"""
    opcode = int.from_bytes(data[:2], byteorder="big")
    
    if opcode == 1:  # 读取请求 (RRQ)
        filename = data[2:].split(b'\0')[0].decode()
        filepath = os.path.join(TFTP_ROOT, filename)

        if not os.path.exists(filepath):
            print(f"文件未找到: {filename}")
            send_error(server_socket, addr, 1, "文件未找到。")
            return

        print(f"发送文件: {filename}")
        with open(filepath, "rb") as file:
            block = 1
            while True:
                data = file.read(512)
                packet = b'\x00\x03' + block.to_bytes(2, byteorder="big") + data
                server_socket.sendto(packet, addr)

                # 等待 ACK
                ack, _ = server_socket.recvfrom(BUFFER_SIZE)
                ack_block = int.from_bytes(ack[2:4], byteorder="big")
                if ack_block != block:
                    print(f"ACK 错误: {ack_block} != {block}")
                    break

                if len(data) < 512:  # 文件结束
                    print(f"文件 {filename} 发送完成")
                    break
                block += 1

    elif opcode == 2:  # 写入请求 (WRQ)
        filename = data[2:].split(b'\0')[0].decode()
        filepath = os.path.join(TFTP_ROOT, filename)

        print(f"接收文件: {filename}")
        with open(filepath, "wb") as file:
            block = 0
            while True:
                # 发送 ACK
                ack_packet = b'\x00\x04' + block.to_bytes(2, byteorder="big")
                server_socket.sendto(ack_packet, addr)

                # 接收数据
                packet, _ = server_socket.recvfrom(BUFFER_SIZE)
                opcode = int.from_bytes(packet[:2], byteorder="big")
                block_num = int.from_bytes(packet[2:4], byteorder="big")

                if opcode != 3 or block_num != block + 1:
                    print("错误：收到无效数据包")
                    break

                file.write(packet[4:])
                if len(packet[4:]) < 512:  # 文件结束
                    print(f"文件 {filename} 接收完成")
                    break
                block += 1
    else:
        print("不支持的操作")
        send_error(server_socket, addr, 4, "不支持的操作")

def send_error(sock, addr, code, message):
    """发送错误包"""
    packet = b'\x00\x05' + code.to_bytes(2, byteorder="big") + message.encode() + b'\x00'
    sock.sendto(packet, addr)

def start_tftp_server():
    """启动 TFTP 服务器"""
    print("启动 TFTP 服务器...")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
        server_socket.bind(("0.0.0.0", TFTP_PORT))
        print(f"TFTP 服务器运行在端口 {TFTP_PORT}")

        while True:
            data, addr = server_socket.recvfrom(BUFFER_SIZE)
            print(f"收到来自 {addr} 的请求")
            handle_client(data, addr, server_socket)

if __name__ == "__main__":
    start_tftp_server()
```

# 资料

恢复出厂

https://handbook.fortinet.com.cn/系统管理/固件与配置管理/配置管理/恢复出厂.html

Breaking Fortinet Firmware Encryption

https://bishopfox.com/blog/breaking-fortinet-firmware-encryption

固件切换

https://handbook.fortinet.com.cn/系统管理/固件与配置管理/固件版本管理/固件切换.html

MASTERING FORTIOS EXPLOITATION - NO DIRECT DEBUGGING REQUIRED

https://occamsec.com/mastering-fortios-exploitation-no-direct-debugging-required/

CVE-2021-44168

https://github.com/0xhaggis/CVE-2021-44168

Technical Tip: Installing firmware from system reboot

https://community.fortinet.com/t5/FortiGate/Technical-Tip-Installing-firmware-from-system-reboot/ta-p/190793

Technical Tip: How to connect to the FortiGate and FortiAP console port

https://community.fortinet.com/t5/FortiGate/Technical-Tip-How-to-connect-to-the-FortiGate-and-FortiAP/ta-p/214839

Technical Tip: Formatting and loading FortiGate firmware image using TFTP

https://community.fortinet.com/t5/FortiGate/Technical-Tip-Formatting-and-loading-FortiGate-firmware-image/ta-p/197617/redirect_from_archived_page/true

Mac终端自带screen连接串口终端

https://blog.csdn.net/fzxhub/article/details/118539712