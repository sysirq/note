# dht实现代码分析

https://github.com/jech/dht

### 消息类型（dht_periodic）

- PING：探测目标节点是否在线
- FIND_NODE：查找接近某个节点ID的其他节点
- GET_PEERS：请求一个info_hash对应的peer列表或邻近节点
- ANNOUNCE_PEER：告诉目标节点：“我拥有这个 info_hash 的资源”；

# 资料

Gossip是什么

https://www.cnblogs.com/charlieroro/articles/12655967.html

Gossip 协议详解

https://javaguide.cn/distributed-system/protocol/gossip-protocl.html

深入理解 Redis cluster GOSSIP 协议

https://www.cyningsun.com/07-04-2023/redis-cluster-gossip.html

【超详细】分布式一致性协议 - Paxos

https://cloud.tencent.com/developer/article/1702057

Study of P2P Botnet

https://www.iosrjournals.org/iosr-jce/papers/Vol16-issue4/Version-4/F016443542.pdf

BitTorrent协议规范之Bencode

https://blog.csdn.net/gxllang83/article/details/2838093

DHT Protocol

https://www.bittorrent.org/beps/bep_0005.html

dht

https://github.com/jech/dht

Kademlia、DHT、KRPC、BitTorrent 协议、DHT Sniffer

https://www.cnblogs.com/LittleHann/p/6180296.html