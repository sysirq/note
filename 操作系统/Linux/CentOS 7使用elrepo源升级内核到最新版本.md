# 安装特定内核版本

从 http://mirrors.coreix.net/elrepo-archive-archive/kernel/el7/x86_64/RPMS/ 下载对对应的包，eg：



```
wget http://mirrors.coreix.net/elrepo-archive-archive/kernel/el7/x86_64/RPMS/kernel-ml-6.5.5-1.el7.elrepo.x86_64.rpm

wget http://mirrors.coreix.net/elrepo-archive-archive/kernel/el7/x86_64/RPMS/kernel-ml-devel-6.5.5-1.el7.elrepo.x86_64.rpm

wget http://mirrors.coreix.net/elrepo-archive-archive/kernel/el7/x86_64/RPMS/kernel-ml-headers-6.5.5-1.el7.elrepo.x86_64.rpm
```



然后使用rpm安装



- 查看已经安装的内核：

```sh
[root@centos ~]# rpm -qa | grep kernel
kernel-tools-libs-3.10.0-1160.118.1.el7.x86_64
kernel-3.10.0-1160.el7.x86_64
kernel-3.10.0-1160.118.1.el7.x86_64
kernel-headers-3.10.0-1160.118.1.el7.x86_64
kernel-ml-devel-6.5.5-1.el7.elrepo.x86_64
kernel-tools-3.10.0-1160.118.1.el7.x86_64
kernel-ml-6.5.5-1.el7.elrepo.x86_64
```

- 查看系统可用内核并更换

```sh
[root@centos ~]# awk -F\' '$1=="menuentry "{print $2}' /etc/grub2.cfg 
CentOS Linux (6.5.5-1.el7.elrepo.x86_64) 7 (Core)
CentOS Linux (3.10.0-1160.118.1.el7.x86_64) 7 (Core)
CentOS Linux (3.10.0-1160.el7.x86_64) 7 (Core)
CentOS Linux (0-rescue-6844a80ca4504d13ba5edc40e11787a7) 7 (Core)
```
从上往下是0开始数

我们这里选择6.5.5-1，所以是0

```
[root@centos ~]# grub2-set-default 0
```

- 重启并验证

```
[sysirq@centos ~]$ uname -r
6.5.5-1.el7.elrepo.x86_64
```

# CentOS 安装GCC 9.3.1 

```sh
yum -y install centos-release-scl
yum -y install devtoolset-9-gcc devtoolset-9-gcc-c++ devtoolset-9-binutils
scl enable devtoolset-9 bash
```

scl 命令启用只是临时的，退出shell或重启将会恢复原系统gcc版本

如果要长期使用gcc9.3的话：

```c
echo "source /opt/rh/devtoolset-9/enable" >> /etc/profile
```

# 资料

Centos7.X内核升级

https://www.hebye.com/docs/c7/c7-1f4rgf8a8rn1e

Centos7.x升级内核

https://blog.csdn.net/weixin_67405599/article/details/127862829