网线连接FGT设备的MGMT端口端口，然后访问：

https://192.168.1.99

### Getting Root Access to the 100D

To get a root shell on the 100D and to install GDB, Frida server, etc. we created a local root exploit for another FortiGate bug ([CVE-2021-44168](https://www.fortiguard.com/psirt/FG-IR-21-201)). Interestingly, much like CVE-2022-42475, CVE-2021-44168 was discovered during the investigation of a compromised FortiGate firewall.

# 资料

恢复出厂

https://handbook.fortinet.com.cn/系统管理/固件与配置管理/配置管理/恢复出厂.html

Breaking Fortinet Firmware Encryption

https://bishopfox.com/blog/breaking-fortinet-firmware-encryption

固件切换

https://handbook.fortinet.com.cn/系统管理/固件与配置管理/固件版本管理/固件切换.html

MASTERING FORTIOS EXPLOITATION - NO DIRECT DEBUGGING REQUIRED

https://occamsec.com/mastering-fortios-exploitation-no-direct-debugging-required/