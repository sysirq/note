# 传播手段

### 弱口令爆破

爆破活动逐渐从 Botnet 的爆破功能中独立出来，由专项爆破家族实施。eg：GoBrut

### 远程代码执行漏洞

鱼叉钓鱼（邮件）

### 钓鱼

### 免费软件留后门

- Android：电视盒子，二次打包
- 免费或廉价的满足用户的视听需求，即诱使用户安装免费的视频APP，或固件刷机安装廉价的影像娱乐平台，这些APP/平台都带有后门组件，一旦安装设备就成了黑产团伙私建流媒体平台中的一个业务流量节点
- 在各种STB，DVB，IPTV论坛传播后门化的固件感染基于Android或eCos系统的机顶盒设备


机顶盒

```
1. Sat Universe

🔗 地址: https://www.sat-universe.com/
📌 简介: 老牌卫星电视和机顶盒论坛，讨论 Enigma2、Dreambox、Vu+、OpenATV、IPTV 线路、EMU 等。
📚 内容: 图像固件、插件、卡共享（Cardsharing）、EMU、IPTV、破解讨论等。
2. TechKings

🔗 地址: https://www.techkings.org/
📌 简介: IPTV、DVB 和 Kodi 插件为主的社区，也有关于 STB 和 IPTV box 的资源分享。
📚 内容: IPTV 列表、配置指南、Mag Box / Zgemma 等 STB 设置、Cardsharing、测试线路。
3. Linux Sat Support Community

🔗 地址: https://www.linuxsat-support.com/
📌 简介: 涉及 Enigma2 盒子、OpenPLi / OpenATV 系统以及 IPTV 支持。
📚 内容: 固件刷机、插件安装、EPG 电子节目指南、软卡（softcam）设置等。
4. Satpimps

🔗 地址: http://www.satpimps.co.uk/
📌 简介: 英国老牌 STB 社区，集中讨论 DVB 接收卡、IPTV、CS、E2、固件等。
📚 内容: 最新固件、IPTV 行业新闻、STB 使用教程、破解资讯。
5. Digital Kaos

🔗 地址: https://www.digital-kaos.co.uk/
📌 简介: 广泛涵盖汽车诊断、游戏机破解和 STB / IPTV。
📚 内容: Dreambox/Vu+、Enigma2、CCcam、KODI、IPTV 列表等。
6. Forum Team-CZ

🔗 地址: https://www.ab-forum.info/ (捷克站，内容较为硬核)
📌 简介: 欧洲 DVB 协议和 STB 用户交流，支持多语种，技术性强。
📚 内容: Broadcom 芯片机型、软卡技术、固件更新。
```

路由器：



# 技术思路

代理服务器与 C&C 通信

# botnet

- Gafgyt
- Mirai
- IoT Reaper 
- mozi

# 挖矿

- WatchBog

# 挖矿

- Kerberods


# 木马

开源木马 DcRAT：集成了勒索、DDoS 和远程控制等多种功能

# 跨平台编译时的一些坑

- 通过readelf -h 与目标编译时一致时，但是还是运行有问题，可以尝试通过 cat /proc/cpuinfo 来定位处理器的类型，最后在网上找到对应的编译工具

- 注意区分硬件浮点数的支持，有些比较老旧的处理器压根就不支持硬件浮点数，eg：mips-linux-musl 编译出来的程序， 默认是会使用硬件浮点数，而mips-linux-muslsf则不会

- 同一个架构，厂家也可能会定制指令集，需要找到厂家提供的sdk

# 参考资料


Gayfemboy：一个利用四信工业路由0DAY传播的僵尸网络

https://blog.xlab.qianxin.com/gayfemboy/

MIRAI源码分析报告

https://blog.nsfocus.net/mirai-source-analysis-report/

P2P技术原理浅析

https://keenjin.github.io/2021/04/p2p/#4-p2p下载技术原理

网络协议 15 - P2P 协议

https://zhuanlan.zhihu.com/p/87327257

Distributed Hash Tables with Kademlia

https://codethechange.stanford.edu/guides/guide_kademlia.html

BitTorrent.org

https://www.bittorrent.org/beps/bep_0000.html

风云再起：全球160万电视被Vo1d僵尸网络操控，潜在危害令人担忧

https://blog.xlab.qianxin.com/long_live_the_botnet_vo1d_is_back_cn/

2019 BOTNET 趋势报告

https://blog.nsfocus.net/wp-content/uploads/2019/12/2019-Botnet-Trend-Report.pdf

2020 BOTNET 趋势报告

https://blog.nsfocus.net/wp-content/uploads/2021/01/2020-BOTNET.pdf

Botnet趋势报告（2025版）

https://www.nsfocus.com.cn/html/2025/92_0409/228.html

GoBrut: A new GoLang Botnet

https://yoroi.company/research/gobrut-a-new-golang-botnet/

[原创] 猫鼠游戏：在不引起安全社区注意的情况下快速制造大规模僵尸网络

https://bbs.kanxue.com/thread-281983.htm

一个藏在我们身边的巨型僵尸网络 Pink

https://blog.netlab.360.com/pinkbot/

Understanding Everything About GoBrut

https://thecentexitguy.com/understanding-everything-about-gobrut/

使用动态种子的 DGA 家族：DNS 流量中的意外行为

https://www.akamai.com/zh/blog/security-research/dga-dynamic-unexpected-behavior-in-dns

DGA家族Orchard持续变化，新版本用比特币交易信息生成DGA域名

https://blog.netlab.360.com/orchard-dga/

笼罩在机顶盒上空的阴影：揭开隐蔽8年黑灰产团伙Bigpanzi的神秘面纱

https://blog.xlab.qianxin.com/unveiling-the-mystery-of-bigpanzi/

Android BadBox 2.0 Malware

https://www.ncsc.gov.ie/pdfs/AndroidBadbox2-0.pdf

Satori Threat Intelligence Disruption: BADBOX 2.0 Targets Consumer Devices with Multiple Fraud Schemes

https://www.humansecurity.com/learn/blog/satori-threat-intelligence-disruption-badbox-2-0/

URLhaus(URLhaus is a platform from abuse.ch and Spamhaus dedicated to sharing malicious URLs that are being used for malware distribution.)

https://urlhaus.abuse.ch

Mirai, BrickerBot, Hajime Attack a Common IoT Weakness

https://www.mcafee.com/blogs/other-blogs/mcafee-labs/mirai-brickerbot-hajime-attack-common-iot-weakness/

PeerBlight Linux Backdoor Exploits React2Shell CVE-2025-55182

https://www.huntress.com/blog/peerblight-linux-backdoor-exploits-react2shell