#  固件下载

 ATP100_5.20 : https://www.dropbox.com/s/yb8q0fqrdrnay9r/ATP100_5.20.zip?dl=1

# 系统架构

```
sysirq@debian:~/Work/iot/CVE-2022-30525/_520ABPS0C0.ri.extracted/_240.extracted/root/compress.img/_compress.img.extracted/squashfs-root/bin$ readelf -h ./zysh
ELF Header:
  Magic:   7f 45 4c 46 01 02 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF32
  Data:                              2's complement, big endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           MIPS R3000
  Version:                           0x1
  Entry point address:               0x1000bc00
  Start of program headers:          52 (bytes into file)
  Start of section headers:          25363248 (bytes into file)
  Flags:                             0x808e0025, noreorder, cpic, abi2, octeon3, mips64r2
  Size of this header:               52 (bytes)
  Size of program headers:           32 (bytes)
  Number of program headers:         8
  Size of section headers:           40 (bytes)
  Number of section headers:         36
  Section header string table index: 35
```

# bin目录

```
sysirq@debian:~/Work/iot/CVE-2022-30525/_520ABPS0C0.ri.extracted/_240.extracted/root/compress.img/_compress.img.extracted/squashfs-root/bin$ ls -hl
total 54M
-rwxr-xr-x 1 sysirq sysirq 8.5K Jan  4  2022 applypwd.suid
-rwxr-xr-x 1 sysirq sysirq  20K Jan  4  2022 applyservice.suid
lrwxrwxrwx 1 sysirq sysirq   15 Jan  4  2022 awk -> ../usr/bin/gawk
-rwxr-xr-x 1 sysirq sysirq 1.4M Jan  4  2022 bash
-rwxr-xr-x 1 sysirq sysirq  42K Jan  4  2022 cat
-rwxr-xr-x 1 sysirq sysirq  65K Jan  4  2022 chgrp
-rwxr-xr-x 1 sysirq sysirq  61K Jan  4  2022 chmod
-rwxr-xr-x 1 sysirq sysirq  67K Jan  4  2022 chown
-rwxr-xr-x 1 sysirq sysirq 106K Jan  4  2022 cp
-rwxr-xr-x 1 sysirq sysirq 1.7K Jan  4  2022 csoap-config
-rwxr-xr-x 1 sysirq sysirq 209K Jan  4  2022 curl
-rwxr-xr-x 1 sysirq sysirq  58K Jan  4  2022 date
-rwxr-xr-x 1 sysirq sysirq  85K Jan  4  2022 df
-rwxr-xr-x 1 sysirq sysirq 122K Jan  4  2022 dir
-rwxr-xr-x 1 sysirq sysirq  20K Jan  4  2022 dmesg
-rwxr-xr-x 1 sysirq sysirq  24K Jan  4  2022 echo
lrwxrwxrwx 1 sysirq sysirq   16 Jan  4  2022 egrep -> ../usr/bin/egrep
-rwxr-xr-x 1 sysirq sysirq  55K Jan  4  2022 event_rpcgen.py
-rwxr-xr-x 1 sysirq sysirq  22K Jan  4  2022 false
lrwxrwxrwx 1 sysirq sysirq   16 Jan  4  2022 fuser -> ../usr/bin/fuser
lrwxrwxrwx 1 sysirq sysirq   15 Jan  4  2022 gawk -> ../usr/bin/gawk
lrwxrwxrwx 1 sysirq sysirq   15 Jan  4  2022 grep -> ../usr/bin/grep
lrwxrwxrwx 1 sysirq sysirq   15 Jan  4  2022 gzip -> ../usr/bin/gzip
-rwxr-xr-x 1 sysirq sysirq  27K Jan  4  2022 hostname
-rwxr-xr-x 1 sysirq sysirq  29K Jan  4  2022 iconv
-rwxr-xr-x 1 sysirq sysirq  47K Jan  4  2022 idn
lrwxrwxrwx 1 sysirq sysirq   21 Jan  4  2022 iptables-xml -> ../sbin/xtables-multi
-rwxr-xr-x 1 sysirq sysirq  41K Jan  4  2022 join
-rwxr-xr-x 1 sysirq sysirq  31K Jan  4  2022 kill
lrwxrwxrwx 1 sysirq sysirq   10 Jan  4  2022 ldapadd -> ldapmodify
-rwxr-xr-x 1 sysirq sysirq  56K Jan  4  2022 ldapcompare
-rwxr-xr-x 1 sysirq sysirq  58K Jan  4  2022 ldapdelete
-rwxr-xr-x 1 sysirq sysirq  56K Jan  4  2022 ldapexop
-rwxr-xr-x 1 sysirq sysirq  66K Jan  4  2022 ldapmodify
-rwxr-xr-x 1 sysirq sysirq  56K Jan  4  2022 ldapmodrdn
-rwxr-xr-x 1 sysirq sysirq  57K Jan  4  2022 ldappasswd
-rwxr-xr-x 1 sysirq sysirq  80K Jan  4  2022 ldapsearch
-rwxr-xr-x 1 sysirq sysirq  19K Jan  4  2022 ldapurl
-rwxr-xr-x 1 sysirq sysirq  54K Jan  4  2022 ldapwhoami
-rwxr-xr-x 1 sysirq sysirq  64K Jan  4  2022 ln
-rwxr-xr-x 1 sysirq sysirq  33K Jan  4  2022 login
-rwxr-xr-x 1 sysirq sysirq 122K Jan  4  2022 ls
lrwxrwxrwx 1 sysirq sysirq   15 Jan  4  2022 lsmod -> ../usr/bin/kmod
-rwxr-xr-x 1 sysirq sysirq  37K Jan  4  2022 mkdir
-rwxr-xr-x 1 sysirq sysirq  33K Jan  4  2022 mknod
-rwxr-xr-x 1 sysirq sysirq  31K Jan  4  2022 more
-rwxr-xr-x 1 sysirq sysirq  71K Jan  4  2022 mount
-rwxr-xr-x 1 sysirq sysirq 104K Jan  4  2022 mv
-rwxr-xr-x 1 sysirq sysirq  12K Jan  4  2022 netopeer-manager
-rwxr-xr-x 1 sysirq sysirq 122K Jan  4  2022 netopeer-server
-rwxr-xr-x 1 sysirq sysirq 121K Jan  4  2022 netstat
-rwxr-xr-x 1 sysirq sysirq 7.0K Jan  4  2022 pfc
lrwxrwxrwx 1 sysirq sysirq   16 Jan  4  2022 pidof -> ../sbin/killall5
-rwxr-xr-x 1 sysirq sysirq  39K Jan  4  2022 ping
-rwxr-xr-x 1 sysirq sysirq  11K Jan  4  2022 post_fwupgrade
-r-xr-xr-x 1 sysirq sysirq  70K Jan  4  2022 ps
-rwxr-xr-x 1 sysirq sysirq  38K Jan  4  2022 pwd
-rwxr-xr-x 1 sysirq sysirq 8.0K Jan  4  2022 reset_zyshd
-rwxr-xr-x 1 sysirq sysirq  65K Jan  4  2022 rm
-rwxr-xr-x 1 sysirq sysirq  29K Jan  4  2022 rmdir
-rwxr-xr-x 1 sysirq sysirq 110K Jan  4  2022 sed
lrwxrwxrwx 1 sysirq sysirq    4 Jan  4  2022 sh -> bash
-rwxr-xr-x 1 sysirq sysirq  33K Jan  4  2022 sleep
-rwxr-xr-x 1 sysirq sysirq  12K Jan  4  2022 soapclient
-rwxr-xr-x 1 sysirq sysirq  49K Jan  4  2022 stty
-rwxr-xr-x 1 sysirq sysirq  27K Jan  4  2022 sync
lrwxrwxrwx 1 sysirq sysirq   14 Jan  4  2022 tar -> ../usr/bin/tar
-rwxr-xr-x 1 sysirq sysirq  59K Jan  4  2022 touch
-rwxr-xr-x 1 sysirq sysirq  22K Jan  4  2022 true
-rwxr-xr-x 1 sysirq sysirq  49K Jan  4  2022 umount
-rwxr-xr-x 1 sysirq sysirq  29K Jan  4  2022 uname
lrwxrwxrwx 1 sysirq sysirq   21 Jan  4  2022 uncompress -> ../usr/bin/uncompress
-rwxr-xr-x 1 sysirq sysirq 6.0K Jan  4  2022 usleep
-rwxr-xr-x 1 sysirq sysirq  32K Jan  4  2022 web-console-login
-rwxr-xr-x 1 sysirq sysirq 4.5K Jan  4  2022 write_daas
-rwxr-xr-x 1 sysirq sysirq 4.5K Jan  4  2022 write_enable_debug
-rwxr-xr-x 1 sysirq sysirq  30K Jan  4  2022 xsltproc
-rwxr-xr-x 1 sysirq sysirq 8.7K Jan  4  2022 zylogin.login
-rwxr-xr-x 1 sysirq sysirq  25M Jan  4  2022 zysh
-rwxr-xr-x 1 sysirq sysirq  25M Jan  4  2022 zyshd
-rwxr-xr-x 1 sysirq sysirq  17K Jan  4  2022 zyshd_wd
-rwxr-xr-x 1 sysirq sysirq 9.1K Jan  4  2022 zysudo.suid
```

# 固件提取

提取镜像恢复文件。

```
binwalk -Me 520ABPS0C0.ri 
cd _520ABPS0C0.ri.extracted/_240.extracted/
```

通过分析init进程(zyinit)，发现其会通过zld_fsextract解压固件
```c
sub_10039970(
    (int)"/zyinit/zld_fsextract",
    (int)"/zyinit/zld_fsextract",
    (int)"/tmp/Firmware",
    (int)"/zyinit/unzip",
    (int)"-s",
    (int)"list",
0LL);
......................
sub_10039970(
    (int)"/zyinit/zld_fsextract",
    (int)"/zyinit/zld_fsextract",
    v6,
    (int)"/zyinit/unzip",
    (int)"-s",
    (int)"extract",
    (int)"-e",
    (int)"db",
0);
......................
sub_10039970(
    (int)"/zyinit/zld_fsextract",
    (int)"/zyinit/zld_fsextract",
    (int)"/tmp/Firmware",
    (int)"/zyinit/unzip",
    (int)"-s",
    (int)"extract",
    (int)"-e",
    (int)"code",
0);
......................
sub_10039970(
    (int)"/zyinit/zld_fsextract",
    (int)"/zyinit/zld_fsextract",
    (int)"/tmp/Firmware",
    (int)"/zyinit/unzip",
    (int)"-s",
    (int)"extract",
    (int)"-e",
    (int)"kernel",
0);
......................
```

```
sysirq@debian:~/Work/iot/CVE-2022-30525/_520ABPS0C0.ri.extracted/_240.extracted$ qemu-mipsn32-static ./zld_fsextract 520ABPS0C0.bin ./unzip -s list
name                :kernel
scope               :-f kernelatp100.bin -f kernelchecksum -D /
nc_scope            :-f kernelatp100.bin
version             :3.10.87
build_date          :2022-01-04 14:11:50
checksum            :59071cba760b4da39b41ff1d55275f1d
core_checksum       :663bc8652acaaa0b11f7db263ec9c48f

name                :code
scope               :-f bmatp100.bin -f bmchecksum -f kernelatp100.bin -f kernelchecksum -d wtp_image -d db -i -D /rw
scope               :-d db/etc/zyxel/ftp/conf -D /
nc_scope            :-f fwversion -f filechecksum -f wtpinfo
version             :5.20(ABPS.0)
build_date          :2022-01-04 14:47:42
checksum            :d8c6dff8d4a1cf5085057dfdaa50d9a2
core_checksum       :02725d2d6f985c9abf3553f9294b2f16

name                :WTP_wtp_image/nwa5120
scope               :-f wtp_image/nwa5120 -D /db
nc_scope            :
version             :5.10(###.10)
build_date          :2021-01-21 10:04:56
checksum            :
core_checksum       :

name                :WTP_wtp_image/wax650
scope               :-f wtp_image/wax650 -D /db
nc_scope            :
version             :6.25(###.1)
build_date          :2021-10-04 03:22:31
checksum            :
core_checksum       :

name                :WTP_wtp_image/wac6500
scope               :-f wtp_image/wac6500 -D /db
nc_scope            :
version             :6.25(###.0)
build_date          :2021-09-17 03:42:10
checksum            :
core_checksum       :

name                :WTP_wtp_image/nwa5301
scope               :-f wtp_image/nwa5301 -D /db
nc_scope            :
version             :5.10(###.10)
build_date          :2021-01-21 10:27:30
checksum            :
core_checksum       :

name                :WTP_wtp_image/nwa5123-ac
scope               :-f wtp_image/nwa5123-ac -D /db
nc_scope            :
version             :6.10(###.10)
build_date          :2021-01-21 15:20:56
checksum            :
core_checksum       :

name                :WTP_wtp_image/wax630
scope               :-f wtp_image/wax630 -D /db
nc_scope            :
version             :6.25(###.1)
build_date          :2021-10-04 02:31:32
checksum            :
core_checksum       :

name                :WTP_wtp_image/nwa5kcn50
scope               :-f wtp_image/nwa5kcn50 -D /db
nc_scope            :
version             :5.10(###.3)
build_date          :2018-01-23 11:28:31
checksum            :
core_checksum       :

name                :WTP_wtp_image/wac500h
scope               :-f wtp_image/wac500h -D /db
nc_scope            :
version             :6.25(###.0)
build_date          :2021-09-17 08:01:37
checksum            :
core_checksum       :

name                :WTP_wtp_image/wac500
scope               :-f wtp_image/wac500 -D /db
nc_scope            :
version             :6.25(###.0)
build_date          :2021-09-17 07:16:39
checksum            :
core_checksum       :

name                :WTP_wtp_image/wac6100
scope               :-f wtp_image/wac6100 -D /db
nc_scope            :
version             :6.25(###.0)
build_date          :2021-09-17 04:16:53
checksum            :
core_checksum       :

name                :WTP_wtp_image/wax610
scope               :-f wtp_image/wax610 -D /db
nc_scope            :
version             :6.25(###.1)
build_date          :2021-10-04 01:41:11
checksum            :
core_checksum       :

name                :WTP_wtp_image/wac6300
scope               :-f wtp_image/wac6300 -D /db
nc_scope            :
version             :6.25(###.0)
build_date          :2021-09-17 03:13:45
checksum            :
core_checksum       :

name                :WTP_wtp_image/wac5300v2
scope               :-f wtp_image/wac5300v2 -D /db
nc_scope            :
version             :6.25(###.0)
build_date          :2021-09-17 08:28:21
checksum            :
core_checksum       :

name                :WTP_wtp_image/wax510
scope               :-f wtp_image/wax510 -D /db
nc_scope            :
version             :6.25(###.1)
build_date          :2021-10-04 04:12:21
checksum            :
core_checksum       :

name                :WTP_wtp_image/wac5300
scope               :-f wtp_image/wac5300 -D /db
nc_scope            :
version             :6.10(###.10)
build_date          :2021-01-21 12:16:54
checksum            :
core_checksum       :

name                :WTP_wtp_image/nwa5123-ac-hd
scope               :-f wtp_image/nwa5123-ac-hd -D /db
nc_scope            :
version             :6.25(###.0)
build_date          :2021-09-17 04:43:21
checksum            :
core_checksum       :
```

ZIP密码（./unzip 的 -P选项 7D8B/LWW0PPjd0z0uh1rQIXyoX/Xtx90AJDBgmjiB9RrBQt58xzaFWZ43adyXo.）：

```
sysirq@debian:~/Work/iot/CVE-2022-30525/_520ABPS0C0.ri.extracted/_240.extracted$ strace -f -s 199 qemu-mipsn32-static ./zld_fsextract 520ABPS0C0.bin ./unzip -s extract -e code
............................................................
[pid 70967] execve("./unzip", ["./unzip", "-o", "-q", "-P", "7D8B/LWW0PPjd0z0uh1rQIXyoX/Xtx90AJDBgmjiB9RrBQt58xzaFWZ43adyXo.", "520ABPS0C0.bin", "-d", "/rw", "compress.img", "etc_writable/", "etc_writable/ModemManager/", "etc_writable/ModemManager/libmm-plugin-altair-lte.so", "etc_writable/ModemManager/libmm-plugin-anydata.so", "etc_writable/ModemManager/libmm-plugin-cinterion.so", "etc_writable/ModemManager/libmm-plugin-generic.so", "etc_writable/ModemManager/libmm-plugin-gobi.so", "etc_writable/ModemManager/libmm-plugin-hso.so", "etc_writable/ModemManager/libmm-plugin-huawei.so", "etc_writable/ModemManager/libmm-plugin-iridium.so", "etc_writable/ModemManager/libmm-plugin-linktop.so", "etc_writable/ModemManager/libmm-plugin-longcheer.so", "etc_writable/ModemManager/libmm-plugin-mbm.so", "etc_writable/ModemManager/libmm-plugin-motorola.so", "etc_writable/ModemManager/libmm-plugin-mtk.so", "etc_writable/ModemManager/libmm-plugin-nokia-icera.so", "etc_writable/ModemManager/libmm-plugin-nokia.so", "etc_writable/ModemManager/libmm-plugin-novatel-lte.so", "etc_writable/ModemManager/libmm-plugin-novatel.so", "etc_writable/ModemManager/libmm-plugin-option.so", "etc_writable/ModemManager/libmm-plugin-pantech.so", "etc_writable/ModemManager/libmm-plugin-samsung.so", "etc_writable/ModemManager/libmm-plugin-sierra.so", "etc_writable/ModemManager/libmm-plugin-simtech.so", "etc_writable/ModemManager/libmm-plugin-telit.so", "etc_writable/ModemManager/libmm-plugin-via.so", "etc_writable/ModemManager/libmm-plugin-wavecom.so", "etc_writable/ModemManager/libmm-plugin-x22x.so", "etc_writable/ModemManager/libmm-plugin-zte.so", "etc_writable/budget/", "etc_writable/budget/budget.conf", "etc_writable/cloud-upgraded", "
............................................................
```

固件提取：

```
 qemu-mipsn32-static ./unzip -o -q -P "7D8B/LWW0PPjd0z0uh1rQIXyoX/Xtx90AJDBgmjiB9RrBQt58xzaFWZ43adyXo." 520ABPS0C0.bin -d root/compress.img
```

```
sysirq@debian:~/Work/iot/CVE-2022-30525/_520ABPS0C0.ri.extracted/_240.extracted/root/compress.img$ binwalk compress.img 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             Squashfs filesystem, little endian, version 4.0, compression:xz, size: 95667665 bytes, 8170 inodes, blocksize: 131072 bytes, created: 2022-01-04 06:11:09
```

# 环境配置




# 资料

CVE-2022-30525 (FIXED): Zyxel Firewall Unauthenticated Remote Command Injection

https://www.rapid7.com/blog/post/2022/05/12/cve-2022-30525-fixed-zyxel-firewall-unauthenticated-remote-command-injection/

Security Products - Firmware Overview and History Downloads for FLEX, ATP, USG, VPN, ZYWALL

https://support.zyxel.eu/hc/en-us/articles/360013941859-Security-Products-Firmware-Overview-and-History-Downloads-for-FLEX-ATP-USG-VPN-ZYWALL

原创 Paper | 探秘 Zyxel 设备：固件提取分析

https://cloud.tencent.com/developer/article/2407135

Zyxel firmware extraction and password analysis

https://security.humanativaspa.it/zyxel-firmware-extraction-and-password-analysis/