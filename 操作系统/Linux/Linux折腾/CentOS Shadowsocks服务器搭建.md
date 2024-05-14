# 安装ssserver
```shell
# yum install python-setuptools && easy_install pip

# pip install shadowsocks
```

# 配置服务器

```
# cat /etc/shadowsocks.json
{
  "server": "0.0.0.0",
  "server_port": 8080,
  "password": "填写密码",
  "method": "aes-256-cfb"
}
```

# 开机启动设置

```shell
# cat /etc/systemd/system/shadowsocks.service
[Unit]
Description=Shadowsocks

[Service]
TimeoutStartSec=0
ExecStart=/usr/bin/ssserver -c /etc/shadowsocks.json

[Install]
WantedBy=multi-user.target

# systemctl enable shadowsocks

# systemctl start shadowsocks

# systemctl status shadowsocks -l
```