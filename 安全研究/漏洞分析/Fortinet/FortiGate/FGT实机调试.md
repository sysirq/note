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
SSL 结构体大小：6224 , 在jemalloc 中，会被分配到7kb内存

### 有用的脚本

```
handle SIGPIPE nostop
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