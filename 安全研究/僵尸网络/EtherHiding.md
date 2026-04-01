https://app.ens.domains



```shell
$curl https://api.ensideas.com/ens/resolve/pawsatyou.eth
{"address":"0xde569B825877c47fE637913eCE5216C644dE081F","name":"pawsatyou.eth","displayName":"pawsatyou.eth","avatar":"https://metadata.ens.domains/mainnet/avatar/pawsatyou.eth"}
```



### kimwolf

- pawsatyou.eth
- re6ce.eth
- byniggasforniggas.eth

```
from web3 import Web3
from ens import ENS

w3 = Web3(Web3.HTTPProvider("https://eth.llamarpc.com"))

ns = ENS.from_web3(w3)

print(ns.get_text("byniggasforniggas.eth", "n2"))
```

output:

```
[1a3f:7c9b:de42:e8d0:7b2f:4c8d:c086:cec1]:25001,[1a3f:7c9b:de42:e8d0:7b2f:4c8d:f662:ad4b]:25001,[1a3f:7c9b:de42:e8d0:7b2f:4c8d:fb9d:d7de]:25001,[1a3f:7c9b:de42:e8d0:7b2f:4c8d:fb03:c621]:25001,[1a3f:7c9b:de42:e8d0:7b2f:4c8d:c080:c307]:25001,[1a3f:7c9b:de42:e8d0:7b2f:4c8d:f929:536a]:25001,[1a3f:7c9b:de42:e8d0:7b2f:4c8d:fcf7:14dd]:25001,[1a3f:7c9b:de42:e8d0:7b2f:4c8d:d65c:a521]:25001,[1a3f:7c9b:de42:e8d0:7b2f:4c8d:c39b:936d]:25001,[1a3f:7c9b:de42:e8d0:7b2f:4c8d:d65c:a341]:25001,[1a3f:7c9b:de42:e8d0:7b2f:4c8d:c834:d8a5]:25001,[1a3f:7c9b:de42:e8d0:7b2f:4c8d:c834:d8f7]:25001,[1a3f:7c9b:de42:e8d0:7b2f:4c8d:c834:cf9f]:25001,[1a3f:7c9b:de42:e8d0:7b2f:4c8d:c834:d85a]:25001,[1a3f:7c9b:de42:e8d0:7b2f:4c8d:c834:d938]:25001,[1a3f:7c9b:de42:e8d0:7b2f:4c8d:c834:d007]:25001,[1a3f:7c9b:de42:e8d0:7b2f:4c8d:c834:d85b]:25001,[1a3f:7c9b:de42:e8d0:7b2f:4c8d:c834:cfcb]:25001,[1a3f:7c9b:de42:e8d0:7b2f:4c8d:c834:cf46]:25001,[1a3f:7c9b:de42:e8d0:7b2f:4c8d:c834:d8de]:25001
```

# 可用公共RPC节点

```
https://eth.llamarpc.com
https://rpc.mevblocker.io
https://rpc.payload.de
https://eth.drpc.org
https://ethereum.publicnode.com
```





# 参考资料

DPRK Adopts EtherHiding: Nation-State Malware Hiding on Blockchains

https://cloud.google.com/blog/topics/threat-intelligence/dprk-adopts-etherhiding/

EtherHiding: How Web3 Infrastructure Enables Stealthy Malware Distribution

https://www.picussecurity.com/resource/blog/etherhiding-how-web3-infrastructure-enables-stealthy-malware-distribution

Simulating EtherHiding: Blockchain as a Malware 

https://cymulate.com/blog/simulating-etherhiding-blockchain-as-a-malware/