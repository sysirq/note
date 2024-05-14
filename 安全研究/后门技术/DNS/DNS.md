# 防火墙关闭


centos

```
systemctl status firewalld
systemctl stop   firewalld
```

# 搭建

### 安装DNS服务

```shell
yum install bind bind-utils
```

### 修改主配置文件

```
# vim /etc/named.conf               //修改监听端口，允许别的计算机访问

listen-on port 53 { any; };         # 服务器上的所有IP地址均可提供DNS域名解析服务

allow-query { any; };               # 允许所有人对本服务器发送DNS查询请求
```

DNS-Bind日志详述(https://www.cnblogs.com/sunnydou/p/15067571.html)

eg

```c
logging {
    channel query {    # DNS查询记录的配置信息
        file "/var/log/bind/query" versions 5 size 10M; # 保存路径
        print-time yes;
        severity info; # 记录级别为info
    };

    category queries { query; };
};

```

### 检查配置文件语法是否正确

```
#  named-checkconf /etc/named.conf
```

### 修改其区域文件，添加需要解析的域名，末尾添加

```
#  vim /etc/named.rfc1912.zones
```

```
//正向区域配置
zone "dnps.com" IN {
        type master;
        file "dnps.com.zone";
        allow-update { none; };
};
```

### 修改正向解析区域文件(正向解析：根据域名查找对应的ip地址)

```shell
# cd  /var/named

# cp -p named.localhost dnps.com.zone       //编辑正向区域数据配置文件，注意复制配置文件时，要保持源文件权限
# vim /var/named/dnps.com.zone           //编辑正向区域数据配置文件内容
```

```

$TTL 1D
@	IN SOA	@ rname.invalid. (
					0	; serial
					1D	; refresh
					1H	; retry
					1W	; expire
					3H )	; minimum
	NS	@
	A	172.20.32.232
www	IN A	172.20.32.232
ftp	IN A	172.20.32.232
	AAAA	::1
```

### 检查zone区域配置文件：

```
# named-checkzone www.dnps.com /var/named/dnps.com.zone
```

### 启动DNS服务器

```
# chkconfig named on        //设置开机自启动

# service named restart     // 重启

# service named start        // 开启命令

# service named stop        //关闭服务命令

# service named status
```

DNS采用的UDP协议，监听53号端口，进一步检验named工作是否正常

```
# netstat -an|grep :53
```

启动异常时查看日志：

```
# tail -n 30 /var/log/messages 
```

# 泛解析

当同一个IP地址的服务器对应有相同域内大量不同域名时 （如IDC的虚拟主机服务器，提供个人站点的空间服务器等），可以通过DNS区域数据库文件使用泛域名解析，只需要添加一条主机地址为“*”的A记录即可（作用类似于通配符），如：

```
$TTL 1D
@   IN SOA  @ rname.invalid. (
                    0   ; serial
                    1D  ; refresh
                    1H  ; retry
                    1W  ; expire
                    3H )    ; minimum
        NS      @   
        A       192.168.182.133
*       IN A    110.110.110.110
*.xtt       IN A    111.111.111.111
*.back  IN A    112.112.112.112
www     IN A    113.113.113.113
        AAAA    ::1 

```

# 测试

修改一台机器上的 /etc/resolv.conf，添加新的DNS nameserver

eg

```
nameserver 192.168.182.133
```

# 资料

Linux搭建DNS服务器

https://blog.csdn.net/finghting321/article/details/107537022

DNS服务配置与管理

https://www.yunweipai.com/33973.html

用C语言实现DNS

https://www.cnblogs.com/qrxqrx/articles/8034781.html

红队工具研究篇 - Sliver C2 通信流量分析

https://forum.butian.net/share/2252

构建域名服务器--DNS

https://xstarcd.github.io/wiki/sysadmin/named.html