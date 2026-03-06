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

### HTTP Flood 异常字符 URI 、 Host 

但如果 URI 包含异常字符，例如：

```
GET /%FF%FE%AA%00%81 HTTP/1.1
```

很多 Web 服务器必须执行额外步骤：

```
URL decode
↓
UTF-8 校验
↓
路径规范化 (normalize)
↓
安全过滤
↓
路由匹配
```

这些步骤都会增加 CPU 开销。

很多服务器在处理Host字段时：

```
Host header
```

也会额外消耗 CPU：split host、解析

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