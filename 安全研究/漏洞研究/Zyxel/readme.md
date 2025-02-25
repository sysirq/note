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
sysirq@debian:~/Work/iot/CVE-2022-30525/_520ABPS0C0.ri.extracted/_240.extracted/root/compress.img$ binwalk compress.img 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             Squashfs filesystem, little endian, version 4.0, compression:xz, size: 95667665 bytes, 8170 inodes, blocksize: 131072 bytes, created: 2022-01-04 06:11:09
```

# 参考资料

Zyxel firmware extraction and password analysis

https://security.humanativaspa.it/zyxel-firmware-extraction-and-password-analysis/