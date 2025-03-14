# 编译

### APR

```
git clone https://github.com/apache/apr.git
sudo apt install libtool-bin
./buildconf
./configure --prefix=/usr/local/apr
make -j 4
sudo make install
```

### APR-Util

```
git clone https://github.com/apache/apr-util.git
./buildconf
./configure --prefix=/usr/local/apr-util --with-apr=/usr/local/apr/bin/apr-2-config
make -j 4
sudo make install
```

### pcre

```
sudo apt install -y libpcre3 libpcre3-dev
which pcre-config
```

### httpd

```
./buildconf
./configure --prefix=/usr/local/httpd \
						--with-apr=/usr/local/apr/bin/apr-2-config \
						--with-apr-util=/usr/local/apr-util/bin/apu-1-config \
						--with-pcre=/usr/bin/pcre-config \
						--enable-modules=all \
						--with-mpm=prefork
make -j 4
sudo make install
```
配置文件位置为 ./configure 指定 prefix 时下的 conf/httpd.conf。eg:
```
/usr/local/httpd/conf/httpd.conf
```

启动服务：
```
PREFIX/bin/apachectl -k start
```

指定conf 文件:

```
apachectl -f 
```

一个简单的httpd.conf 配置文件

```
LoadModule mime_module modules/mod_mime.so
LoadModule dir_module modules/mod_dir.so
LoadModule log_config_module modules/mod_log_config.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule unixd_module modules/mod_unixd.so

Listen 80

DocumentRoot "/home/sysirq/Work/apache2/www/htdocs"
<Directory "/home/sysirq/Work/apache2/www/htdocs">
    AllowOverride None
    Require all granted
</Directory>


DirectoryIndex index.html
```

如果启动出错，可以到log文件中查看启动失败原因（PREFIX/logs）

# 资料

CVE-2024-40725-CVE-2024-40898

https://github.com/TAM-K592/CVE-2024-40725-CVE-2024-40898