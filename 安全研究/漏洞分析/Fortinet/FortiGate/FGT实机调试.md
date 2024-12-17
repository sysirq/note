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
handle SIGPIPE nostop

b *SSL_free
commands
	printf "ssl struct free  addr:%p\n",$rdi
	continue
end

b *SSL_new+0x33
commands
	printf "ssl struct alloc addr:%p\n",$rax
	continue
end
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