# dht实现代码分析

https://github.com/jech/dht

### 消息类型（dht_periodic）

- PING：探测目标节点是否在线
- FIND_NODE：查找接近某个节点ID的其他节点
- GET_PEERS：请求一个info_hash对应的peer列表或邻近节点
- ANNOUNCE_PEER：告诉目标节点：“我拥有这个 info_hash 的资源”；

# 一些启示

### 0x00

Kademlia 算法在不同的项目中会有不同的实现，区别主要在于 kbucket 数据结构及其相关方法。

比如，常见的 Kademlia 实现（如 BitTorrent）是，先根据 ID 空间预先分配 kbucket 数量的空间（比如 160 位，就分配 160 个 buckets 空间，256 位就直接分配 256 个 buckets 空间，这样，后续计算 distance 的时候可以直接 distance 作为 bucket 索引），还有就是 IPFS 这种，也是原始 Kademlia 论文中提到的，动态分配 buckets，如果节点少的时候，就只有一个 bucket，当节点不断增加之后，原 bucket 不断分裂，具体就是，每次满了 k 个元素，原 bucket 就分裂成 2 个。这样的话，对于内存空间是一个优化。而以太坊中的实现又略有不同，它使用固定数量的 buckets，但是却限定在 17 个，而不是 256 个，它通过一个 log 映射表来把新节点均匀分布在各个 buckets 中。

### 0x01

在 Kad 网络中，所有节点都被当作一颗二叉树的叶子，并且每一个节点的位置都由其 ID 值的最短前缀唯一的确定，每个节点都有一个160bit的ID值作为标志符。 整个网络节点状态可以使用二叉树表示。

规则如下：

ID值以二进制形式表示；二进制的第 n 个 bit 就对应了二叉树的第 n 层；如果该位是 1，进入左子树，是 0 则进入右子树；最后二叉树上的叶子节点对应某个节点。

每个节点是160位的二进制表示，所以最多有160层，而实际并没有这么多层，因为采用最短唯一前缀，所以叶子节点会在任意层数出现。

### 0x02

Kademlia 协议依靠路由表和其它节点通信，下面介绍一下路由表的建立过程。

前面我们提到网络中的节点都可以放到同一个二进制二叉树中，而**路由表的制作过程实际上就是二叉树的拆分过程**。我们假设节点 ID 为 11（二进制），看看二叉树的拆分过程。

首先将不包含自身的最大子树取出。



```
+--------------+
|             *|
|           /  | \
|          /   |  \
|      0  /    |   \  1
|        /     |    \
|       /      |     \
|      *       |       *
|    /  \      |     /  \
| 0 /    \ 1   |  0 /    \ 1
|  /      \    |   /      \
| O        O   |  O        O
+--------------+
```

重复上述步骤，直到剩余的部分只有自己这一个节点。本例中只需要拆分两次。

```
+--------------+
|            * |
|           /  | \
|          /   |  \
|      0  /    |   \  1
|        /     |    \
|       /      |     \
|              | +-------+
|      *       | |      *|
|    /  \      | |    /  |\
| 0 /    \ 1   | | 0 /   | \ 1
|  /      \    | |  /    |  \
| O        O   | | O     |  O
+--------------+ +-------+
```

此时我们从左到右一共有了三颗子树，其中第三颗子树只有我们自己。此时**三颗子树就对应了三个 K-桶（K-Bucket）**。


### 0x03

Kademlia网络提供四种Potocol(RPC)

- PING 测试是否节点存在
- STORE存储通知的资料
- FIND_NODE 通知其他节点帮助寻找node
- FIND_VALUE 通知其他节点帮助寻找Value

# mozi

通过引导节点：

```
dht.transmissionbt.com:6881
router.bittorrent.com:6881
router.utorrent.com:6881
bttracker.debian.org:6881
212.129.33.59:6881
82.221.103.244:6881
130.239.18.159:6881
87.98.162.88:6881
```

加入到Mainline DHT（主线DHT）


# Pink

### P2P over UDP 123

向四个B段地址（"114.25.0.0/16"，"36.227.0.0/16"，"59.115.0.0/16"，"1.224.0.0/16"）发起 Peer 探测请求

# krpc 消息格式

组成部分：

- t:  事务 ID，用于标识请求和响应的匹配。
- y: 消息类型（q 表示请求，r 表示响应，e 表示错误）。
- q: 请求方法名（如 ping、find_node、get_peers 等）。
- r: 响应的数据。
- e: 错误代码和错误信息。
- a: 请求的参数。
- v: 版本信息（should be included in every message with a client version string，The string should be a two character client identifier registered in BEP 20 [3] followed by a two character version identifier. Not all implementations include a "v" key so clients should not assume its presence.）

所有查询都有一个“id”键和包含查询节点 node ID的值。所有响应都有一个“id”键，其值包含响应节点的node ID。

### error

```python
generic error = {"t":"aa", "y":"e", "e":[201, "A Generic Error Ocurred"]}
bencoded = d1:eli201e23:A Generic Error Ocurrede1:t2:aa1:y1:ee
```

### ping

```python
ping Query = {"t":"aa", "y":"q", "q":"ping", "a":{"id":"abcdefghij0123456789"}}
bencoded = d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe

Response = {"t":"aa", "y":"r", "r": {"id":"mnopqrstuvwxyz123456"}}
bencoded = d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re
```

### find_node

```python
find_node Query = {"t":"aa", "y":"q", "q":"find_node", "a": {"id":"abcdefghij0123456789", "target":"mnopqrstuvwxyz123456"}}
# "id" containing the node ID of the querying node, and "target" containing the ID of the node sought by the queryer. 
bencoded = d1:ad2:id20:abcdefghij01234567896:target20:mnopqrstuvwxyz123456e1:q9:find_node1:t2:aa1:y1:qe

Response = {"t":"aa", "y":"r", "r": {"id":"0123456789abcdefghij", "nodes": "def456..."}}
bencoded = d1:rd2:id20:0123456789abcdefghij5:nodes9:def456...e1:t2:aa1:y1:re
```

### get_peers

```python
get_peers Query = {"t":"aa", "y":"q", "q":"get_peers", "a": {"id":"abcdefghij0123456789", "info_hash":"mnopqrstuvwxyz123456"}}
bencoded = d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe

Response with peers = {"t":"aa", "y":"r", "r": {"id":"abcdefghij0123456789", "token":"aoeusnth", "values": ["axje.u", "idhtnm"]}}
bencoded = d1:rd2:id20:abcdefghij01234567895:token8:aoeusnth6:valuesl6:axje.u6:idhtnmee1:t2:aa1:y1:re

Response with closest nodes = {"t":"aa", "y":"r", "r": {"id":"abcdefghij0123456789", "token":"aoeusnth", "nodes": "def456..."}}
bencoded = d1:rd2:id20:abcdefghij01234567895:nodes9:def456...5:token8:aoeusnthe1:t2:aa1:y1:re
```

### announce_peer

```python
announce_peers Query = {"t":"aa", "y":"q", "q":"announce_peer", "a": {"id":"abcdefghij0123456789", "implied_port": 1, "info_hash":"mnopqrstuvwxyz123456", "port": 6881, "token": "aoeusnth"}}
bencoded = d1:ad2:id20:abcdefghij01234567899:info_hash20:<br />
mnopqrstuvwxyz1234564:porti6881e5:token8:aoeusnthe1:q13:announce_peer1:t2:aa1:y1:qe

Response = {"t":"aa", "y":"r", "r": {"id":"mnopqrstuvwxyz123456"}}
bencoded = d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re
```

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

死磕以太坊源码分析之Kademlia算法

https://www.cnblogs.com/1314xf/p/14019453.html

P2P 网络核心技术：Kademlia 协议

https://zhuanlan.zhihu.com/p/40286711

分布式哈希表DHT和Kademlia算法详解

https://blog.csdn.net/happyblreay/article/details/140993392

分布式散列表协议 —— Kademlia 详解

https://www.addesp.com/archives/5338

Kademlia详解&&细说 Kademlia 【FreeXploiT整理文】

http://www.cppblog.com/tommyyan/articles/82057.html

P2P僵尸网络深度追踪——Mozi（二）二叉树吃瓜记

https://www.anquanke.com/post/id/245500

Mozi恶意样本分析报告

https://mp.weixin.qq.com/s?__biz=MzUzNDYxOTA1NA==&mid=2247491557&idx=1&sn=ea07addfc5babd260198767dccedc2bf&scene=21&poc_token=HOC0tmijfcOoFqgqWuQ-gCZXd1O573LIEh4tB9BX

A new botnet attack just mozied into town

https://www.ibm.com/think/x-force/botnet-attack-mozi-mozied-into-town

Uncleanable and Unkillable: The Evolution of IoT Botnets Through P2P Networking

https://documents.trendmicro.com/assets/pdf/Technical_Brief_Uncleanable_and_Unkillable_The_Evolution_of_IoT_Botnets_Through_P2P_Networking.pdf

FritzFrog: A New Generation of Peer-to-Peer Botnets

https://www.akamai.com/blog/security/fritzfrog-a-new-generation-of-peer-to-peer-botnets

bootstrap-dht

https://github.com/bittorrent/bootstrap-dht

DHT bootstrap node

https://blog.libtorrent.org/2016/09/dht-bootstrap-node/