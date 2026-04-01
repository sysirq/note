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