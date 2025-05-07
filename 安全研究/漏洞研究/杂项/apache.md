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

# CVE-2024-38475

The root cause of this vulnerability has been excellently explained by Orange Tsai. However, to quickly recap: the issue occurs during the truncation phase, **due to the fact that r->filename is treated as a URL path rather than a filesystem path**.

**This Filename Confusion vulnerability allows the abuse of the question mark (%3F) symbol to truncate the final constructed path.**

To illustrate, let us use one of Orange’s examples. Consider the following RewriteRule statement for Apache’s mod_rewrite module:

```conf
RewriteEngine On
RewriteRule "^/user/(.+)$" "/var/user/$1/profile.yml"
```

The above mod_rewrite rule is simple: if an HTTP request is made to the url http://server/user/orange, the file /var/user/orange/profile.yml is retrieved and returned to the user as per below:

```sh
$ curl http://server/user/orange

# the output of file `/var/user/orange/profile.yml`
```

As you can see, we have a suffix where /profile.yml is concatenated to our path.

Due to the Filename Confusion vulnerability in the mod_rewrite module of Apache, although this rule is performing substitution against a filesystem path, it mistakenly treats the final path as a URL path.

This means that if we include a URL-encoded question mark in our requested path, the server will truncate the final filesystem path.

As a result, the appended /profile.yml is dropped, allowing us to retrieve the /secret.yml file instead, as demonstrated below:

```sh
$ curl http://server/user/orange%2Fsecret.yml%3F
 # the output of file `/var/user/orange/secret.yml`
```
.......

# 资料

CVE-2024-40725-CVE-2024-40898

https://github.com/TAM-K592/CVE-2024-40725-CVE-2024-40898

HTTP 请求走私详解

https://www.freebuf.com/articles/web/321907.html

HTTP Desync Attacks: Smashing into the Cell Next Door

https://www.blackhat.com/us-19/briefings/schedule/#http-desync-attacks-smashing-into-the-cell-next-door-15153

CVE 2023 25690 - Proof of Concept

https://github.com/dhmosfunk/CVE-2023-25690-POC

Confusion Attacks: Exploiting Hidden Semantic Ambiguity in Apache HTTP Server!

https://blog.orange.tw/posts/2024-08-confusion-attacks-en/

CVE-2024-38473 Nuclei Template

https://github.com/juanschallibaum/CVE-2024-38473-Nuclei-Template

SonicBoom, From Stolen Tokens to Remote Shells - SonicWall SMA (CVE-2023-44221, CVE-2024-38475)

https://labs.watchtowr.com/sonicboom-from-stolen-tokens-to-remote-shells-sonicwall-sma100-cve-2023-44221-cve-2024-38475/