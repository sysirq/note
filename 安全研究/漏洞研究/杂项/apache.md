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



配置文件位置为 ./configure 指定 prefix 时下的 conf/httpd.conf。

```
/usr/local/httpd/conf/httpd.conf
```

# 资料

CVE-2024-40725-CVE-2024-40898

https://github.com/TAM-K592/CVE-2024-40725-CVE-2024-40898