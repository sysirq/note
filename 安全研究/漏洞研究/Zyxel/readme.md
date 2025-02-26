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



```
sysirq@debian:~/Work/Firmware/Zyxel/ATP100_5.38/root$ binwalk -Me compress.img

Scan Time:     2025-02-26 11:22:45
Target File:   /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/compress.img
MD5 Checksum:  6394950b22cba034d31e45d72a5ac42b
Signatures:    411

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/msmtprc -> /var/zyxel/msmtprc; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/mtab -> /proc/31067/mounts; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/services -> /var/zyxel/services; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/ftpuser -> /var/zyxel/ftpusers; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/net-snmp -> /var/zyxel/net-snmp; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/localtime -> /var/zyxel/MyZone; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/miniupnp -> /var/zyxel/miniupnp; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/passwd -> /var/zyxel/passwd; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/resolv.conf.prev -> /var/zyxel/resolv.conf.prev; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/snmpd.conf -> /var/zyxel/snmpd.conf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/issue -> /var/zyxel/issue; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/pam.d -> /var/zyxel/pam.d; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/crontab -> /var/zyxel/crontab; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/ftp.conf -> /var/zyxel/ftp.conf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/hostname -> /var/zyxel/hostname; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/resolv.conf -> /var/zyxel/resolv.conf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/adjtime -> /var/zyxel/adjtime; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/shadow -> /var/zyxel/shadow; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/hosts -> /var/zyxel/hosts; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/rc.d/rc3.d/S10syslog -> /etc/init.d/syslog; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/rc.d/rc3.d/S11zwd -> /etc/init.d/zwd.sh; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/rc.d/rc3.d/S15uam -> /etc/init.d/uam; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/rc.d/rc3.d/S28myzyxel -> /etc/init.d/myzyxel_init; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/rc.d/rc3.d/S09ZLD_sfp_detect -> /etc/init.d/ZLD_sfp_detect.sh; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/rc.d/rc3.d/S393G_update -> /etc/init.d/3G_init.sh; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/rc.d/rc3.d/S99rmnologin -> /etc/init.d/rmnologin; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/rc.d/rcS.d/S68ZLD_post-reboot -> /etc/init.d/ZLD_post-reboot.sh; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/rc.d/rcS.d/S09ZLD_sfp_detect -> /etc/init.d/ZLD_sfp_detect.sh; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/rc.d/rcS.d/S66ZLD_timezone -> /etc/init.d/ZLD_timezone.sh; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/rc.d/rc4.d/S10syslog -> /etc/init.d/syslog; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/rc.d/rc4.d/S61lionic -> /etc/init.d/lc23xx_loopback_init.sh; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/rc.d/rc4.d/S11zwd -> /etc/init.d/zwd.sh; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/rc.d/rc4.d/S16app -> /etc/init.d/app; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/rc.d/rc4.d/S15uam -> /etc/init.d/uam; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/rc.d/rc4.d/S09ZLD_sfp_detect -> /etc/init.d/ZLD_sfp_detect.sh; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/rc.d/rc4.d/S63HTMconfig -> /etc/zyxel/conf/HTMconfig; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/ppp/peers -> /var/zyxel/ppp/peers; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/ppp/pap-secrets -> /var/zyxel/ppp/pap-secrets; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/ppp/chap-secrets -> /var/zyxel/ppp/chap-secrets; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/ppp/options.pptp -> /var/zyxel/ppp/options.pptp; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/sandbox/magic.mgc -> /db/etc/sandbox/magic.mgc; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/sandbox/config.lastline -> /db/etc/sandbox/config.lastline; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/sandbox/config.null -> /db/etc/sandbox/config.null; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/sandbox/config.zyxel -> /db/etc/sandbox/config.zyxel; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/sandbox/config -> /db/etc/sandbox/config; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/app_patrol/app-fullname.rules -> /db/etc/app_patrol/app-fullname.rules; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/app_patrol/app.rules -> /db/etc/app_patrol/app.rules; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/app_patrol/category.txt -> /db/etc/app_patrol/category.txt; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/app_patrol/libqmbundle.so.1.510.1-22 -> /db/etc/app_patrol/libqmbundle.so.1.510.1-22; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/app_patrol/libqmbundle.so -> /db/etc/app_patrol/libqmbundle.so; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/app_patrol/app_meta_beh.txt -> /db/etc/app_patrol/app_meta_beh.txt; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/app_patrol/tag.txt -> /db/etc/app_patrol/tag.txt; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/app_patrol/sig-version.txt -> /db/etc/app_patrol/sig-version.txt; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/app_patrol/sig_info.txt -> /db/etc/app_patrol/sig_info.txt; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/app_patrol/app.rules.29 -> /db/etc/app_patrol/app.rules.29; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/app_patrol/USGFLEX_BWM_APP_LIST.csv -> /db/etc/app_patrol/USGFLEX_BWM_APP_LIST.csv; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/app_patrol/app-fullname.rules.29 -> /db/etc/app_patrol/app-fullname.rules.29; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/reputation-ebl/last_sync_time -> /db/etc/reputation-ebl/last_sync_time; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/cloud_query/config.lastline -> /db/etc/cloud_query/config.lastline; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/cloud_query/config.null -> /db/etc/cloud_query/config.null; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/cloud_query/config.zyxel -> /db/etc/cloud_query/config.zyxel; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/cloud_query/config -> /db/etc/cloud_query/config; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/idp/dmz.conf -> /db/etc/idp/dmz.conf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/idp/attributes.txt -> /db/etc/idp/attributes.txt; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/idp/threshold.config -> /db/etc/idp/threshold.config; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/idp/classification.config -> /db/etc/idp/classification.config; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/idp/none.conf -> /db/etc/idp/none.conf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/idp/detectonly.conf -> /db/etc/idp/detectonly.conf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/idp/device.conf -> /db/etc/idp/device.conf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/idp/wan.conf -> /db/etc/idp/wan.conf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/idp/reference.config -> /db/etc/idp/reference.config; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/idp/lan.conf -> /db/etc/idp/lan.conf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/idp/all.conf -> /db/etc/idp/all.conf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/idp/sysprotect.conf -> /db/etc/idp/sysprotect.conf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/idp/suricata.yaml -> /db/etc/idp/suricata.yaml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/idp/zyxel.rules -> /db/etc/idp/zyxel.rules; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/idp/self.rules -> /db/etc/idp/self.rules; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/idp/magic -> /db/etc/idp/magic; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/idp/idp-sig-version.txt -> /db/etc/idp/idp-sig-version.txt; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/ssl/certs/cacert.pem -> /share/cacert.pem; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/ssh/sshd_config -> /var/zyxel/sshd_config; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/anti-botnet/zabsig -> /db/etc/anti-botnet/zabsig; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/ip-reputation/zirsig -> /db/etc/ip-reputation/zirsig; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/zyxel/ftp -> /db/etc/zyxel/ftp; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/zyxel/sys/dhcpd.conf -> /var/zyxel/dhcpd.conf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/zyxel/sys/rndc.conf -> /var/zyxel/rndc.conf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/zyxel/sys/named -> /var/zyxel/named; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/etc/zyxel/sys/named.conf -> /var/zyxel/named.conf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/usr/lib/terminfo -> /usr/share/terminfo; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/usr/local/cdr_blockpage/htdocs/libcdr_cloud_blockpage.html -> /tmp/cdr/libcdr_cloud_blockpage.html; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/usr/local/zyxel-gui/cgi-twofa/ext-js -> /usr/local/zyxel-gui/htdocs/ext-js; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/usr/local/zyxel-gui/cgi-twofa/images -> /usr/local/zyxel-gui/htdocs/images; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/usr/local/zyxel-gui/cgi-twofa/lib -> /usr/local/zyxel-gui/htdocs/lib; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/usr/local/zyxel-gui/cgi-twofa/css -> /usr/local/zyxel-gui/htdocs/css; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/usr/local/zyxel-gui/htdocs/speedtest.json -> /tmp/speedtest; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/usr/local/zyxel-gui/htdocs/privacy_statement_secureporter.pdf -> /etc/zyxel/ftp/.myzyxel/pdf/privacy_statement_secureporter.pdf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/usr/local/zyxel-gui/htdocs/privacy_statement_sandbox.pdf -> /etc/zyxel/ftp/.myzyxel/pdf/privacy_statement_sandbox.pdf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/usr/local/zyxel-gui/htdocs/terms_of_service.html -> /var/zyxel/terms_of_service.html; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/usr/local/zyxel-gui/htdocs/fw_zyxel_1_fw_news.pdf -> /db/etc/zyxel/ftp/.myzyxel/fetchurl/fw_zyxel_1_fw_news.pdf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/usr/local/zyxel-gui/htdocs/atp.json -> /tmp/utm_dashboard_data; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/usr/local/zyxel-gui/htdocs/fw_zyxel_1_fw_note.pdf -> /db/etc/zyxel/ftp/.myzyxel/fetchurl/fw_zyxel_1_fw_note.pdf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/usr/local/zyxel-gui/htdocs/securpt_api_status.json -> /tmp/securpt_api_status.json; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/usr/local/zyxel-gui/htdocs/multi-portal -> /var/zyxel/.multi-portal; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/usr/local/zyxel-gui/htdocs/customize -> /var/zyxel/.ua_customize; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/usr/local/zyxel-gui/htdocs/securpt_claim_device.json -> /tmp/securpt_claim_device.json; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/usr/local/zyxel-gui/htdocs/claim_status.json -> /share/securpt/claim_status.json; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/usr/local/zyxel-gui/htdocs/fw_zyxel_2_fw_note.pdf -> /db/etc/zyxel/ftp/.myzyxel/fetchurl/fw_zyxel_2_fw_note.pdf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/usr/local/zyxel-gui/htdocs/fw_zyxel_1_fw_message.html -> /db/etc/zyxel/ftp/.myzyxel/fetchurl/fw_zyxel_1_fw_message.html; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/usr/local/zyxel-gui/htdocs/fw_zyxel_2_fw_news.pdf -> /db/etc/zyxel/ftp/.myzyxel/fetchurl/fw_zyxel_2_fw_news.pdf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/usr/local/zyxel-gui/htdocs/fw_zyxel_2_fw_message.html -> /db/etc/zyxel/ftp/.myzyxel/fetchurl/fw_zyxel_2_fw_message.html; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/usr/local/zyxel-gui/htdocs/sdwan_intro_video.html -> /usr/local/zyxel-gui/templates/sdwan_intro_video.html; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/usr/local/zyxel-gui/htdocs/privacy_statement_general.pdf -> /etc/zyxel/ftp/.myzyxel/pdf/privacy_statement_general.pdf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/usr/local/zyxel-gui/htdocs/sdwan_intro.html -> /usr/local/zyxel-gui/templates/sdwan_intro.html; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/usr/local/zyxel-gui/htdocs/ext-js/images/usg/others/country-flags -> /etc/geoip/country-flags; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/usr/local/zyxel-gui/htdocs/ext-js/app/view/portal/secuextender -> /etc_writable/zyxel/secuextender; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/usr/local/zyxel-gui/htdocs/ext-js/app/view/object/authmeth/twoFA/2FA-msg-default.txt -> /var/zyxel/2FA-msg-default.txt; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/usr/local/zyxel-gui/htdocs/ext-js/app/view/authpolicy/ua.zip -> /var/zyxel/ua.zip; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/usr/local/zyxel-gui/htdocs/ext-js/app/view/authpolicy/customize/ua.zip -> /db/etc/customize_zip/ua.zip; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/usr/local/zyxel-gui/htdocs/ext-js/app/common/multi-lang/language -> /share/language; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/usr/local/zyxel-gui/htdocs/lib/mode_ana -> /tmp/mode_ana; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/sbin/ip6tables-save -> /usr/sbin/zyiptables; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/sbin/iptables -> /usr/sbin/zyiptables; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/sbin/iptables.original -> /usr/sbin/xtables-multi; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/sbin/iptables-restore.original -> /usr/sbin/xtables-multi; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/sbin/ip6tables-xml -> /usr/sbin/zyiptables; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/sbin/ip6tables -> /usr/sbin/zyiptables; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/sbin/iptables-xml -> /usr/sbin/zyiptables; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/sbin/ip6tables.original -> /usr/sbin/xtables-multi; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/sbin/ip6tables-restore -> /usr/sbin/zyiptables; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/sbin/ip6tables-xml.original -> /usr/sbin/xtables-multi; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/sbin/iptables-save -> /usr/sbin/zyiptables; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/sbin/iptables-xml.original -> /usr/sbin/xtables-multi; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/sbin/ip6tables-restore.original -> /usr/sbin/xtables-multi; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/sbin/ip6tables-save.original -> /usr/sbin/xtables-multi; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/sbin/iptables-restore -> /usr/sbin/zyiptables; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/sbin/iptables-save.original -> /usr/sbin/xtables-multi; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-cdr/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-cdr-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-route/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-route-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-ospf/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-ospf-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-monitoring/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-monitoring-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-idp/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-idp-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cfgnetopeer/datastore-server.xml -> /share/ztp/sdwan-ctrl/datastore-server.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-bgp/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-bgp-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-anti-botnet/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-anti-botnet-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-anti-malware/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-anti-malware-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-vpn-client-certificate/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-vpn-client-certificate-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-dns-filter/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-dns-filter-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-debug-restart/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-debug-restart-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/ca-cert/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/ca-cert-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/periodical-port-usage/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/periodical-port-usage-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-traceroute/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-traceroute-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-debug-runcmd/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-debug-runcmd-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-path-measure/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-path-measure-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-secumanager/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-secumanager-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-common-types/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-common-types-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-auth-service/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-auth-service-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-alg/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-alg-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-device-ha/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-device-ha-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-reverse-ssh/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-reverse-ssh-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-ddns/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-ddns-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-system/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-system-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-monitor-mode-config/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-monitor-mode-config-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-walled-garden/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-walled-garden-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-path/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-path-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-ping/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-ping-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/sta-mgnt/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/sta-mgnt-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-org2org/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-org2org-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-sandbox/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-sandbox-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-users/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-users-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-bpolicy/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-bpolicy-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-usb/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-usb-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-client/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-client-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-license/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-license-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-vpn/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-vpn-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-ip-reputation/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-ip-reputation-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-wifi/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-wifi-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-pcap/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-pcap-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-snmp/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-snmp-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-services-group/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-services-group-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/common-info/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/common-info-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-lldp-mib/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-lldp-mib-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-syslog-server/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-syslog-server-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-firewall/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-firewall-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-dns/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-dns-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-debug-tun/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-debug-tun-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-arp/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-arp-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-time/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-time-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-secureporter/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-secureporter-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-wifi-radio-info/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-wifi-radio-info-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-diag-flows/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-diag-flows-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-debug-factorydefault/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-debug-factorydefault-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-tunnel-ssid/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-tunnel-ssid-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-diag-usb/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-diag-usb-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/nebula-status/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/nebula-status-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-interfaces/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-interfaces-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-rtable/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-rtable-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-diag-dnsdhcp/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-diag-dnsdhcp-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/cubs-ip-exception/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-ip-exception-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/periodical-client-usage/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/periodical-client-usage-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/netopeer/netopeer/periodical-application-usage-per-ip/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/periodical-application-usage-per-ip-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/zyxel/ua.zip -> /usr/local/zyxel-gui/htdocs/ext-js/app/view/authpolicy/english/ua.zip; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/zyxel/raddb/certs/random -> /dev/urandom; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/zyxel/.multi-portal/wp -> /db/etc/.multi-portal/wp; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/zyxel/.multi-portal/ua -> /db/etc/.multi-portal/ua; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root/var/zyxel/.multi-portal/customize -> /var/zyxel/.multi-portal/html; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/msmtprc -> /var/zyxel/msmtprc; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/mtab -> /proc/31067/mounts; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/services -> /var/zyxel/services; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/ftpuser -> /var/zyxel/ftpusers; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/net-snmp -> /var/zyxel/net-snmp; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/localtime -> /var/zyxel/MyZone; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/miniupnp -> /var/zyxel/miniupnp; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/passwd -> /var/zyxel/passwd; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/resolv.conf.prev -> /var/zyxel/resolv.conf.prev; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/snmpd.conf -> /var/zyxel/snmpd.conf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/issue -> /var/zyxel/issue; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/pam.d -> /var/zyxel/pam.d; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/crontab -> /var/zyxel/crontab; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/ftp.conf -> /var/zyxel/ftp.conf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/hostname -> /var/zyxel/hostname; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/resolv.conf -> /var/zyxel/resolv.conf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/adjtime -> /var/zyxel/adjtime; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/shadow -> /var/zyxel/shadow; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/hosts -> /var/zyxel/hosts; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/rc.d/rc3.d/S10syslog -> /etc/init.d/syslog; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/rc.d/rc3.d/S11zwd -> /etc/init.d/zwd.sh; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/rc.d/rc3.d/S15uam -> /etc/init.d/uam; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/rc.d/rc3.d/S28myzyxel -> /etc/init.d/myzyxel_init; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/rc.d/rc3.d/S09ZLD_sfp_detect -> /etc/init.d/ZLD_sfp_detect.sh; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/rc.d/rc3.d/S393G_update -> /etc/init.d/3G_init.sh; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/rc.d/rc3.d/S99rmnologin -> /etc/init.d/rmnologin; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/rc.d/rcS.d/S68ZLD_post-reboot -> /etc/init.d/ZLD_post-reboot.sh; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/rc.d/rcS.d/S09ZLD_sfp_detect -> /etc/init.d/ZLD_sfp_detect.sh; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/rc.d/rcS.d/S66ZLD_timezone -> /etc/init.d/ZLD_timezone.sh; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/rc.d/rc4.d/S10syslog -> /etc/init.d/syslog; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/rc.d/rc4.d/S61lionic -> /etc/init.d/lc23xx_loopback_init.sh; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/rc.d/rc4.d/S11zwd -> /etc/init.d/zwd.sh; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/rc.d/rc4.d/S16app -> /etc/init.d/app; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/rc.d/rc4.d/S15uam -> /etc/init.d/uam; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/rc.d/rc4.d/S09ZLD_sfp_detect -> /etc/init.d/ZLD_sfp_detect.sh; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/rc.d/rc4.d/S63HTMconfig -> /etc/zyxel/conf/HTMconfig; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/ppp/peers -> /var/zyxel/ppp/peers; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/ppp/pap-secrets -> /var/zyxel/ppp/pap-secrets; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/ppp/chap-secrets -> /var/zyxel/ppp/chap-secrets; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/ppp/options.pptp -> /var/zyxel/ppp/options.pptp; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/sandbox/magic.mgc -> /db/etc/sandbox/magic.mgc; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/sandbox/config.lastline -> /db/etc/sandbox/config.lastline; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/sandbox/config.null -> /db/etc/sandbox/config.null; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/sandbox/config.zyxel -> /db/etc/sandbox/config.zyxel; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/sandbox/config -> /db/etc/sandbox/config; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/app_patrol/app-fullname.rules -> /db/etc/app_patrol/app-fullname.rules; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/app_patrol/app.rules -> /db/etc/app_patrol/app.rules; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/app_patrol/category.txt -> /db/etc/app_patrol/category.txt; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/app_patrol/libqmbundle.so.1.510.1-22 -> /db/etc/app_patrol/libqmbundle.so.1.510.1-22; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/app_patrol/libqmbundle.so -> /db/etc/app_patrol/libqmbundle.so; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/app_patrol/app_meta_beh.txt -> /db/etc/app_patrol/app_meta_beh.txt; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/app_patrol/tag.txt -> /db/etc/app_patrol/tag.txt; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/app_patrol/sig-version.txt -> /db/etc/app_patrol/sig-version.txt; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/app_patrol/sig_info.txt -> /db/etc/app_patrol/sig_info.txt; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/app_patrol/app.rules.29 -> /db/etc/app_patrol/app.rules.29; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/app_patrol/USGFLEX_BWM_APP_LIST.csv -> /db/etc/app_patrol/USGFLEX_BWM_APP_LIST.csv; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/app_patrol/app-fullname.rules.29 -> /db/etc/app_patrol/app-fullname.rules.29; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/reputation-ebl/last_sync_time -> /db/etc/reputation-ebl/last_sync_time; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/cloud_query/config.lastline -> /db/etc/cloud_query/config.lastline; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/cloud_query/config.null -> /db/etc/cloud_query/config.null; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/cloud_query/config.zyxel -> /db/etc/cloud_query/config.zyxel; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/cloud_query/config -> /db/etc/cloud_query/config; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/idp/dmz.conf -> /db/etc/idp/dmz.conf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/idp/attributes.txt -> /db/etc/idp/attributes.txt; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/idp/threshold.config -> /db/etc/idp/threshold.config; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/idp/classification.config -> /db/etc/idp/classification.config; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/idp/none.conf -> /db/etc/idp/none.conf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/idp/detectonly.conf -> /db/etc/idp/detectonly.conf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/idp/device.conf -> /db/etc/idp/device.conf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/idp/wan.conf -> /db/etc/idp/wan.conf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/idp/reference.config -> /db/etc/idp/reference.config; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/idp/lan.conf -> /db/etc/idp/lan.conf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/idp/all.conf -> /db/etc/idp/all.conf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/idp/sysprotect.conf -> /db/etc/idp/sysprotect.conf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/idp/suricata.yaml -> /db/etc/idp/suricata.yaml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/idp/zyxel.rules -> /db/etc/idp/zyxel.rules; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/idp/self.rules -> /db/etc/idp/self.rules; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/idp/magic -> /db/etc/idp/magic; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/idp/idp-sig-version.txt -> /db/etc/idp/idp-sig-version.txt; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/ssl/certs/cacert.pem -> /share/cacert.pem; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/ssh/sshd_config -> /var/zyxel/sshd_config; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/anti-botnet/zabsig -> /db/etc/anti-botnet/zabsig; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/ip-reputation/zirsig -> /db/etc/ip-reputation/zirsig; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/zyxel/ftp -> /db/etc/zyxel/ftp; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/zyxel/sys/dhcpd.conf -> /var/zyxel/dhcpd.conf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/zyxel/sys/rndc.conf -> /var/zyxel/rndc.conf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/zyxel/sys/named -> /var/zyxel/named; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/etc/zyxel/sys/named.conf -> /var/zyxel/named.conf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/usr/lib/terminfo -> /usr/share/terminfo; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/usr/local/cdr_blockpage/htdocs/libcdr_cloud_blockpage.html -> /tmp/cdr/libcdr_cloud_blockpage.html; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/usr/local/zyxel-gui/cgi-twofa/ext-js -> /usr/local/zyxel-gui/htdocs/ext-js; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/usr/local/zyxel-gui/cgi-twofa/images -> /usr/local/zyxel-gui/htdocs/images; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/usr/local/zyxel-gui/cgi-twofa/lib -> /usr/local/zyxel-gui/htdocs/lib; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/usr/local/zyxel-gui/cgi-twofa/css -> /usr/local/zyxel-gui/htdocs/css; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/usr/local/zyxel-gui/htdocs/speedtest.json -> /tmp/speedtest; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/usr/local/zyxel-gui/htdocs/privacy_statement_secureporter.pdf -> /etc/zyxel/ftp/.myzyxel/pdf/privacy_statement_secureporter.pdf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/usr/local/zyxel-gui/htdocs/privacy_statement_sandbox.pdf -> /etc/zyxel/ftp/.myzyxel/pdf/privacy_statement_sandbox.pdf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/usr/local/zyxel-gui/htdocs/terms_of_service.html -> /var/zyxel/terms_of_service.html; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/usr/local/zyxel-gui/htdocs/fw_zyxel_1_fw_news.pdf -> /db/etc/zyxel/ftp/.myzyxel/fetchurl/fw_zyxel_1_fw_news.pdf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/usr/local/zyxel-gui/htdocs/atp.json -> /tmp/utm_dashboard_data; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/usr/local/zyxel-gui/htdocs/fw_zyxel_1_fw_note.pdf -> /db/etc/zyxel/ftp/.myzyxel/fetchurl/fw_zyxel_1_fw_note.pdf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/usr/local/zyxel-gui/htdocs/securpt_api_status.json -> /tmp/securpt_api_status.json; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/usr/local/zyxel-gui/htdocs/multi-portal -> /var/zyxel/.multi-portal; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/usr/local/zyxel-gui/htdocs/customize -> /var/zyxel/.ua_customize; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/usr/local/zyxel-gui/htdocs/securpt_claim_device.json -> /tmp/securpt_claim_device.json; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/usr/local/zyxel-gui/htdocs/claim_status.json -> /share/securpt/claim_status.json; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/usr/local/zyxel-gui/htdocs/fw_zyxel_2_fw_note.pdf -> /db/etc/zyxel/ftp/.myzyxel/fetchurl/fw_zyxel_2_fw_note.pdf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/usr/local/zyxel-gui/htdocs/fw_zyxel_1_fw_message.html -> /db/etc/zyxel/ftp/.myzyxel/fetchurl/fw_zyxel_1_fw_message.html; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/usr/local/zyxel-gui/htdocs/fw_zyxel_2_fw_news.pdf -> /db/etc/zyxel/ftp/.myzyxel/fetchurl/fw_zyxel_2_fw_news.pdf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/usr/local/zyxel-gui/htdocs/fw_zyxel_2_fw_message.html -> /db/etc/zyxel/ftp/.myzyxel/fetchurl/fw_zyxel_2_fw_message.html; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/usr/local/zyxel-gui/htdocs/sdwan_intro_video.html -> /usr/local/zyxel-gui/templates/sdwan_intro_video.html; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/usr/local/zyxel-gui/htdocs/privacy_statement_general.pdf -> /etc/zyxel/ftp/.myzyxel/pdf/privacy_statement_general.pdf; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/usr/local/zyxel-gui/htdocs/sdwan_intro.html -> /usr/local/zyxel-gui/templates/sdwan_intro.html; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/usr/local/zyxel-gui/htdocs/ext-js/images/usg/others/country-flags -> /etc/geoip/country-flags; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/usr/local/zyxel-gui/htdocs/ext-js/app/view/portal/secuextender -> /etc_writable/zyxel/secuextender; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/usr/local/zyxel-gui/htdocs/ext-js/app/view/object/authmeth/twoFA/2FA-msg-default.txt -> /var/zyxel/2FA-msg-default.txt; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/usr/local/zyxel-gui/htdocs/ext-js/app/view/authpolicy/ua.zip -> /var/zyxel/ua.zip; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/usr/local/zyxel-gui/htdocs/ext-js/app/view/authpolicy/customize/ua.zip -> /db/etc/customize_zip/ua.zip; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/usr/local/zyxel-gui/htdocs/ext-js/app/common/multi-lang/language -> /share/language; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/usr/local/zyxel-gui/htdocs/lib/mode_ana -> /tmp/mode_ana; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/sbin/ip6tables-save -> /usr/sbin/zyiptables; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/sbin/iptables -> /usr/sbin/zyiptables; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/sbin/iptables.original -> /usr/sbin/xtables-multi; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/sbin/iptables-restore.original -> /usr/sbin/xtables-multi; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/sbin/ip6tables-xml -> /usr/sbin/zyiptables; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/sbin/ip6tables -> /usr/sbin/zyiptables; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/sbin/iptables-xml -> /usr/sbin/zyiptables; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/sbin/ip6tables.original -> /usr/sbin/xtables-multi; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/sbin/ip6tables-restore -> /usr/sbin/zyiptables; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/sbin/ip6tables-xml.original -> /usr/sbin/xtables-multi; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/sbin/iptables-save -> /usr/sbin/zyiptables; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/sbin/iptables-xml.original -> /usr/sbin/xtables-multi; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/sbin/ip6tables-restore.original -> /usr/sbin/xtables-multi; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/sbin/ip6tables-save.original -> /usr/sbin/xtables-multi; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/sbin/iptables-restore -> /usr/sbin/zyiptables; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/sbin/iptables-save.original -> /usr/sbin/xtables-multi; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-cdr/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-cdr-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-route/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-route-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-ospf/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-ospf-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-monitoring/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-monitoring-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-idp/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-idp-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cfgnetopeer/datastore-server.xml -> /share/ztp/sdwan-ctrl/datastore-server.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-bgp/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-bgp-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-anti-botnet/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-anti-botnet-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-anti-malware/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-anti-malware-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-vpn-client-certificate/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-vpn-client-certificate-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-dns-filter/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-dns-filter-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-debug-restart/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-debug-restart-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/ca-cert/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/ca-cert-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/periodical-port-usage/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/periodical-port-usage-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-traceroute/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-traceroute-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-debug-runcmd/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-debug-runcmd-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-path-measure/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-path-measure-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-secumanager/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-secumanager-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-common-types/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-common-types-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-auth-service/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-auth-service-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-alg/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-alg-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-device-ha/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-device-ha-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-reverse-ssh/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-reverse-ssh-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-ddns/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-ddns-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-system/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-system-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-monitor-mode-config/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-monitor-mode-config-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-walled-garden/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-walled-garden-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-path/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-path-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-ping/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-ping-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/sta-mgnt/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/sta-mgnt-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-org2org/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-org2org-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-sandbox/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-sandbox-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-users/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-users-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-bpolicy/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-bpolicy-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-usb/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-usb-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-client/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-client-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-license/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-license-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-vpn/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-vpn-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-ip-reputation/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-ip-reputation-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-wifi/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-wifi-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-pcap/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-pcap-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-snmp/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-snmp-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-services-group/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-services-group-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/common-info/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/common-info-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-lldp-mib/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-lldp-mib-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-syslog-server/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-syslog-server-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-firewall/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-firewall-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-dns/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-dns-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-debug-tun/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-debug-tun-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-arp/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-arp-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-time/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-time-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-secureporter/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-secureporter-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-wifi-radio-info/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-wifi-radio-info-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-diag-flows/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-diag-flows-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-debug-factorydefault/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-debug-factorydefault-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-tunnel-ssid/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-tunnel-ssid-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-diag-usb/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-diag-usb-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/nebula-status/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/nebula-status-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-interfaces/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-interfaces-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-rtable/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-rtable-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-diag-dnsdhcp/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-diag-dnsdhcp-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/cubs-ip-exception/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/cubs-ip-exception-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/periodical-client-usage/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/periodical-client-usage-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/netopeer/netopeer/periodical-application-usage-per-ip/datastore.xml -> /share/ztp/sdwan-ctrl/datastores/periodical-application-usage-per-ip-datastore.xml; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/zyxel/ua.zip -> /usr/local/zyxel-gui/htdocs/ext-js/app/view/authpolicy/english/ua.zip; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/zyxel/raddb/certs/random -> /dev/urandom; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/zyxel/.multi-portal/wp -> /db/etc/.multi-portal/wp; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/zyxel/.multi-portal/ua -> /db/etc/.multi-portal/ua; changing link target to /dev/null for security purposes.

WARNING: Symlink points outside of the extraction directory: /home/sysirq/Work/Firmware/Zyxel/ATP100_5.38/root/_compress.img.extracted/squashfs-root-0/var/zyxel/.multi-portal/customize -> /var/zyxel/.multi-portal/html; changing link target to /dev/null for security purposes.
0             0x0             Squashfs filesystem, little endian, version 4.0, compression:xz, size: 97218409 bytes, 8304 inodes, blocksize: 131072 bytes, created: 2024-03-27 20:53:31

```

# 环境配置

提取 usr/local/zyxel-gui/htdocs/ztp 所有文件内容到 /var/www/ztp 中

```
sysirq@debian:/var/www/ztp$ ls
activation_fail.html     apply_fail.html  fonts           twoFAsms.html           ztp_enabled.html
activationfail.html      cgi-bin          images          verification_fail.html  ztp_reg.html
activation_success.html  css              twoFAapps.html  zld_enabled.html
```


配置apache服务器，

```
sudo apt install apache2
sudo a2enmod cgi
```

```
sudo vim /etc/apache2/apache2.conf
```

将以下内容添加到文件的末尾：

```
#########     Adding capaility to run CGI-scripts #################
ServerName localhost
ScriptAlias /ztp/cgi-bin/ /var/www/ztp/cgi-bin/
Options +ExecCGI
AddHandler cgi-script .cgi .pl .py
```

sudo vim /etc/apache2/conf-available/serve-cgi-bin.conf，修改文件内容：

```
ScriptAlias /cgi-bin/ /usr/lib/cgi-bin/
<Directory "/usr/lib/cgi-bin">
    AllowOverride None
    Options +ExecCGI -MultiViews +SymLinksIfOwnerMatch
    Require all granted
</Directory>   
```

为：

```
ScriptAlias /ztp/cgi-bin/ /var/www/ztp/cgi-bin/
<Directory "/var/www/ztp/cgi-bin">
		AllowOverride None
		Options +ExecCGI -MultiViews +SymLinksIfOwnerMatch
		Require all granted
</Directory>
```

编写一个测试文件/var/www/ztp/cgi-bin/first.py：

```python
#!/usr/bin/env python3
import cgitb

cgitb.enable()

print("Content-Type: text/html;charset=utf-8")
print ("Content-type:text/html\r\n")
print("<H1> Hello, From python server :) </H1>")
```


```
sudo service apache2 restart
```

测试：

```
sysirq@debian:/var/www/ztp/cgi-bin$ curl http://localhost/ztp/cgi-bin/first.py
<H1> Hello, From python server :) </H1>
```



目标版本的python版为2.7

```
sysirq@debian:~/Work/iot/CVE-2022-30525/_520ABPS0C0.ri.extracted/_240.extracted/root/compress.img/_compress.img.extracted/squashfs-root$ ls usr/bin/python
usr/bin/python
sysirq@debian:~/Work/iot/CVE-2022-30525/_520ABPS0C0.ri.extracted/_240.extracted/root/compress.img/_compress.img.extracted/squashfs-root$ ls usr/bin/python -hl
lrwxrwxrwx 1 sysirq sysirq 7 Jan  4  2022 usr/bin/python -> python2
sysirq@debian:~/Work/iot/CVE-2022-30525/_520ABPS0C0.ri.extracted/_240.extracted/root/compress.img/_compress.img.extracted/squashfs-root$ ls usr/bin/python2 -hl
lrwxrwxrwx 1 sysirq sysirq 9 Jan  4  2022 usr/bin/python2 -> python2.7
```



```
sysirq@debian:/var/www/ztp/cgi-bin$ cat handler.py | head -n 30
#!/usr/bin/python

import sys
import cgi
import json
import subprocess
import os
import threading
import select
import signal
import time
import base64
import logging
import re
import subprocess
from xml.dom import minidom
import socket
import datetime

import lib_cmd_interface
import lib_wan_setting
import lib_cmd_devinfo
import lib_usb_setting
import lib_cmd_pcap
import lib_remote_assist
import lib_cmd_language
from ztpinclude import ZTPSTATUS as ZTP_STATUS_PATH
```

- debian12 安装 python2.7


It is still possible, firstly open /etc/apt/sources.list

and add this new line, which adds Debian 9 software to apt-get sources:

```
deb http://archive.debian.org/debian/ stretch contrib main non-free
```

then in bash type the following command:

```
sudo apt-get update

sudo apt-get install python2.7
```

Now you should be able to use python2.7 in Debian12.

Don't forget to remove that new line in /etc/apt/sources.list,otherwise it may affect your future apt-get

- debian12 安装 pip2

```
curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py
sudo python2.7 get-pip.py
pip2 --version
```

- python2.7 模块安装

根据cat  /var/log/apache2/error.log  信息，我们需要全局安装 requests模块

```
sudo pip2 install requests
```

- 需要创建命令程序/usr/sbin/sdwan_iface_ipc 用于模拟

```
--- RUN CMD: setWanPortSt ---
command: setWanPortSt
{u'proto': u'dhcp', u'vlan_tagged': u'1', u'vlanid': u'5', u'mtu': u'; touch /tmp/hack;', u'command': u'setWanPortSt', u'data': u'hi', u'port': u'4'}
cmdLine = /usr/sbin/sdwan_iface_ipc 11 WAN3 4 ; touch /tmp/hack; 5 >/dev/null 2>&1
sh: 1: /usr/sbin/sdwan_iface_ipc: not found
32512
cmd thread return error
Internal err=500
err=Unknown Error[503]
Ret {'message': 'Internal Server Error', 'code': 10001, 'result': ''}
```

```
root@debian:/etc/apache2# cat /usr/sbin/sdwan_iface_ipc
#!/bin/bash


root@debian:/etc/apache2# chmod +x /usr/sbin/sdwan_iface_ipc
```

**Tips**

如果出现500错误，可以直接在 handler.py 第一行直接指定 python 版本为 2.7
```
#!/usr/bin/python2.7

import sys
import cgi
import json
import subprocess
import os
...
```

# ATP100分析

入口：

```
squashfs-root/usr/local/zyxel-gui
```

配置文件分析：

```
AcceptPathInfo Off
DirectoryIndex weblogin.cgi
AuthZyxelRedirect /
AuthZyxelSkipPattern /images/ /lib/ /mobile/ /weblogin.cgi /admin.cgi /login.cgi /error.cgi /redirect.cgi /I18N.js /language /logo/ /ext-js/web-pages/login/no_granted.html /ssltun.jar /sslapp.jar /VncViewer.jar /Forwarder.jar /eps.jar /css/ /sdwan_intro.html /sdwan_intro_video.html /videos/ /webauth_error.cgi /webauth_relogin.cgi /SSHTermApplet-jdk1.3.1-dependencies-signed.jar /SSHTermApplet-jdkbug-workaround-signed.jar /SSHTermApplet-signed.jar /commons-logging.properties /org.apache.commons.logging.LogFactory /fetch_ap_info.cgi /agree.cgi /walled_garden.cgi /payment_transaction.cgi /paypal_pdt.cgi /redirect_pdt.cgi /securepay.cgi /authorize_dot_net.cgi /payment_failed.cgi /customize/ /multi-portal/ /free_time.cgi /free_time_redirect.cgi /free_time_transaction.cgi /free_time_failed.cgi /js/ /terms_of_service.html /dynamic_script.cgi /ext-js/ext/ext-all.js /ext-js/ext/adapter/ext/ext-base.js /ext-js/ext/resources/css/ext-all.css /ext-js/app/common/zyFunction.js /ext-js/app/common/zld_product_spec.js /cf_hdf_blockpage.cgi \
/libcdr_blockpage.cgi \
/libcdr_blockpage.html \
/libcdr_cloud_blockpage.html \
/2FA-access.cgi \
/webauth_ga.cgi \
/ztp/cgi-bin/ztp_reg.py /ztp/ztp_enabled.html /ztp/css /ztp/images /ztp/fonts \
/change-expired-password.html /chg_exp_pwd.cgi ext-js/web-pages/login/chgpw_expired.html /ext-all.css /ext-all.js /appLite.js zld_product_spec.js /showCLI.js /zyVType.js /persist-min.js /zyExtend.js /zyFunction.js /zyComponent.js /language_panel.js /ext-lang-en.js /language.js /login.css /custmiz_page.js /chgpw_expired.js /retrieveData.js /MultiSelect.js /ItemSelector.js /cmdStore.js /favicon.ico /PagingStore.js /zyform.js /ext-theme-classic-all.css /content_line.gif /content_bg.jpg /login_img.gif /login_bg.jpg /advance_bg.gif /reset.css \

AuthZyxelSkipUserPattern 127.0.0.1:10443 127.0.0.1:10444 /images/ /I18N.js /language /weblogin.cgi /admin.cgi /login.cgi /redirect.cgi /welcome.cgi /access.cgi /setuser.cgi /grant_access.html /eps_grant_access.html /eps.jar /user/ /cgi-bin/ /EPS_INIT /EPS_RESULT /RevProxy/ /Exchange/ /exchweb/ /public/ /Socks/ /CnfSocks/ /cifs/ /uploadcifs/ /epc/ /frame_access.html /eps_frame_access.html /dummy.html /dummy_eps.html /access_eps.html /logo/ /ext-js/ /fetch_ap_info.cgi /agree.cgi /walled_garden.cgi /payment_transaction.cgi /paypal_pdt.cgi /redirect_pdt.cgi /securepay.cgi /authorize_dot_net.cgi /payment_failed.cgi /free_time.cgi /free_time_redirect.cgi /free_time_transaction.cgi /free_time_failed.cgi /cf_hdf_blockpage.cgi \
/libcdr_blockpage.cgi \
/cdr_cloud_block_page.html \
/2FA-access.cgi \
/webauth_ga.cgi \
/ztp/cgi-bin/ztp_reg.py /ztp/ztp_enabled.html /ztp/css /ztp/images /ztp/fonts \
/change-expired-password.html /chg_exp_pwd.cgi ext-js/web-pages/login/chgpw_expired.html /ext-all.css /ext-all.js /appLite.js zld_product_spec.js /showCLI.js /zyVType.js /persist-min.js /zyExtend.js /zyFunction.js /zyComponent.js /language_panel.js /ext-lang-en.js /language.js /login.css /custmiz_page.js /chgpw_expired.js /retrieveData.js /MultiSelect.js /ItemSelector.js /cmdStore.js /favicon.ico /PagingStore.js /zyform.js /ext-theme-classic-all.css /content_line.gif /content_bg.jpg /login_img.gif /login_bg.jpg /advance_bg.gif /reset.css \

AuthZyxelSkipTwoFaPattern /ext-js/app/view/object/authmeth/twoFA/2FAVerify.html /ext-js/ext/ux/grid/FiltersFeature.js /ext-js/app/view/object/authmeth/twoFA/2FAVerify.js /ext-js/ext/ux/form/field/BoxSelect/BoxSelect.js /ext-js/ext/ux/toggleslide/ToggleSlide.js /ext-js/ext/ux/toggleslide/Thumb.js /ext-js/ext/ux/grid/menu/ListMenu.js /ext-js/ext/ux/grid/menu/RangeMenu.js /ext-js/ext/ux/grid/filter/DateFilter.js /ext-js/ext/ux/grid/filter/BooleanFilter.js /ext-js/ext/ux/grid/filter/DateTimeFilter.js /ext-js/ext/ux/grid/filter/ListFilter.js /ext-js/ext/ux/grid/filter/NumericFilter.js /ext-js/ext/ux/grid/filter/StringFilter.js /ext-js/ext/ux/grid/filter/Filter.js /ext-js/ext/src/zy2FAVerifyForm.js /cgi-bin/zysh-cgi \

ScriptAlias /cgi-bin/ "/usr/local/apache/cgi-bin/"

AddHandler cgi-script .cgi .py
```

# 版本探测

```
"/ext-js/app/common/zld_product_spec.js"
```

```python
import argparse
import base64
import random
import requests

# ignore ssl certification
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def version_print(host,port,isHttps):
    url = ""
    if isHttps:
        url = f"https://{host}:{port}/ext-js/app/common/zld_product_spec.js"
    else:
        url = f"http://{host}:{port}/ext-js/app/common/zld_product_spec.js"

    try:
        version = ""
        title = ""

        response = requests.get(url, timeout=10,verify=False)
        if "ZLDSYSPARM_PRODUCT_NAME1=" in response.text:
            title = response.text.split('ZLDSYSPARM_PRODUCT_NAME1="')[1].split('"')[0]
        if "ZLDCONFIG_CLOUD_HELP_VERSION=" in response.text:
            version = response.text.split("ZLDCONFIG_CLOUD_HELP_VERSION=")[1].split(";")[0]
            
        print(f"    title   = {title}")
        print(f"    version = {version}")
    except Exception as e:
        print(e)
        print("get version error")
    return

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Zyxel version check")
    parser.add_argument("host", type=str, help="target host")
    parser.add_argument("--port", type=str, help="port", default="443")
    parser.add_argument("--no-https", dest="no_https", action="store_true")
    
    args = parser.parse_args()
    https = not args.no_https
    host = args.host
    port = args.port

    version_print(host,port,https)
```

# 参考资料

Zyxel firmware extraction and password analysis

https://security.humanativaspa.it/zyxel-firmware-extraction-and-password-analysis/

ZYXEL VPN SERIES PRE-AUTH REMOTE COMMAND EXECUTION

https://ssd-disclosure.com/ssd-advisory-zyxel-vpn-series-pre-auth-remote-command-execution/