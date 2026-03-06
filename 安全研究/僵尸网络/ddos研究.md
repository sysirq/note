# udp

# tcp

# ssl

# http(s)

### Slowloris 攻击

通过大量“未完成的 HTTP 请求”占满服务器连接资源。

不发送完整 Header

```
GET / HTTP/1.1
Host: example.com
User-Agent: test
X-a: 1
```

然后 每隔几十秒再发送一个 header

```
X-b: 2
X-c: 3
X-d: 4
```

服务器会认为：HTTP header 还没有结束

于是：

```
连接保持
线程保持
内存保持
```

- 资料

Slowloris DDoS 攻击解析

https://www.akamai.com/zh/glossary/what-is-a-slowloris-ddos-attack

# 参考资料

DHCPDiscover Reflection/Amplification DDoS Attack Mitigation Recommendations

https://www.netscout.com/blog/asert/dhcpdiscover-reflectionamplification-ddos-attack-mitigation

DDOS-RootSec

https://github.com/R00tS3c/DDOS-RootSec

qbot

https://github.com/geniosa/qbot/blob/master/client.c#L1295

Botnet

https://github.com/NoSpacesFlies/Botnet

Mirai-Source-Code

https://github.com/jgamblin/Mirai-Source-Code/tree/master

MHDDoS

https://github.com/MatrixTM/MHDDoS