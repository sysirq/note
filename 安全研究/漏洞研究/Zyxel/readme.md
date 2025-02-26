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