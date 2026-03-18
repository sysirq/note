# udp

# tcp

### syn flood

攻击者不断发送syn 包，导致SYN backlog 队列被占满

### ack flood

攻击者不断发送ack包，触发协议栈 查找连接，从而消耗目标资源

### tcp stomp

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

# 一些有用的知识


### 反缓存 HTTP 洪水攻击

反缓存 HTTP 洪水攻击 (Anti-cache HTTP Flood Attack)，也常被称为缓存穿透攻击 (Cache-Busting Attack) 或缓存绕过攻击 (Cache Bypass
  Attack)，是一种专门设计用来击穿目标网站的缓存防御体系（如 CDN、反向代理缓存等），直接打击后端真实服务器（源站）的 DDoS 攻击手法

反缓存攻击的核心原理：让每一次请求都“独一无二”

- 随机查询字符串
- 随机子域名(Host字段)


# ddos 分析

### 流量监控

```sh
tcpdump -i eth0 udp -n -w - | pv -br > /dev/null 
```

```
1. tcpdump -i eth0 udp -n -w -:
    * -i eth0: 指定监听名为 eth0 的网卡。
    * udp: 仅过滤并抓取 UDP 协议的数据包。
    * -n: 不进行域名解析（直接显示 IP 地址和端口），提高效率。
    * -w -: 将抓到的原始报文写入到标准输出（stdout）而非保存到文件。


2. | pv -br:
    * |: 管道，将前一个命令抓取的原始数据流传给 pv。
    * pv: (Pipe Viewer) 用于监控数据通过管道的进度。
    * -b: (bytes) 显示累计传输的数据量。
    * -r: (rate) 显示当前的传输速率（带宽）。


3. > /dev/null:
    * 将 pv 处理后的数据丢弃到“黑洞” /dev/null，因为你只想看速率统计，并不需要保存报文内容。
```


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

check-host

https://check-host.net/

dstat

https://www.vedbex.com/dstat