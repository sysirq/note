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

# 手工构造查询

```python
import json, requests
from eth_hash.auto import keccak  # pip install eth-hash[pysha3]

RPC = "https://eth.llamarpc.com"

# ─── 1. namehash ──────────────────────────────────────────────────────────────
def namehash(name: str) -> bytes:
    node = b"\x00" * 32
    if name:
        for label in reversed(name.split(".")):
            label_hash = keccak(label.encode("utf-8"))
            node = keccak(node + label_hash)
    return node

# ─── 2. ABI 手动编码工具 ───────────────────────────────────────────────────────
def encode_call_resolver(node: bytes) -> str:
    """Registry.resolver(bytes32 node)  selector = 0x0178b8bf"""
    selector = bytes.fromhex("0178b8bf")
    return "0x" + (selector + node).hex()

def encode_call_text(node: bytes, key: str) -> str:
    """Resolver.text(bytes32 node, string key)  selector = 0x59d1d43c"""
    selector   = bytes.fromhex("59d1d43c")
    # slot 0: node (bytes32，直接放)
    arg0       = node                              # 32 bytes
    # slot 1: string 的偏移量 = 0x40（两个槽之后才是字符串数据）
    arg1_offset = (64).to_bytes(32, "big")         # 0x0000...0040
    # 字符串编码：长度 + 内容（右填充到 32 的倍数）
    key_bytes  = key.encode("utf-8")
    key_len    = len(key_bytes).to_bytes(32, "big")
    key_padded = key_bytes.ljust((len(key_bytes) + 31) // 32 * 32, b"\x00")
    payload    = selector + arg0 + arg1_offset + key_len + key_padded
    return "0x" + payload.hex()

# ─── 3. eth_call 封装 ──────────────────────────────────────────────────────────
def eth_call(to: str, data: str) -> str:
    resp = requests.post(RPC,
        json={
            "jsonrpc": "2.0", "id": 1, "method": "eth_call",
            "params": [{"to": to, "data": data}, "latest"]
        },
        headers={
            "Content-Type": "application/json",
            "User-Agent": "python-requests/2.28.0",  # 加上 UA
        },
        timeout=10
    )
    # 调试：先打印原始响应
    print(f"  HTTP {resp.status_code}: {resp.text[:200]}")
    result = resp.json()
    if "error" in result:
        raise RuntimeError(result["error"])
    return result["result"]

# ─── 4. 解码 address（低 20 字节）─────────────────────────────────────────────
def decode_address(hex_result: str) -> str:
    raw = bytes.fromhex(hex_result.removeprefix("0x"))
    return "0x" + raw[-20:].hex()

# ─── 5. 解码 ABI string 返回值 ─────────────────────────────────────────────────
def decode_string(hex_result: str) -> str:
    raw = bytes.fromhex(hex_result.removeprefix("0x"))
    if len(raw) < 64:
        return ""
    # raw[0:32]  = offset（固定 0x20）
    # raw[32:64] = 字符串字节长度
    str_len = int.from_bytes(raw[32:64], "big")
    return raw[64: 64 + str_len].decode("utf-8", errors="replace")

# ─── 6. 主流程 ────────────────────────────────────────────────────────────────
ENS_REGISTRY = "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e"
DOMAIN       = "byniggasforniggas.eth"
KEYS         = ["n2"]

node = namehash(DOMAIN)
print(f"namehash : 0x{node.hex()}")

# Step 2: 取 resolver 地址
resolver_data = encode_call_resolver(node)
print(f"\n[eth_call] Registry.resolver()")
print(f"  to   : {ENS_REGISTRY}")
print(f"  data : {resolver_data}")
raw_resolver = eth_call(ENS_REGISTRY, resolver_data)
resolver_addr = decode_address(raw_resolver)
print(f"  → resolver: {resolver_addr}")

# Step 3: 逐个查询 text record
print(f"\n=== {DOMAIN} Text Records ===")
for key in KEYS:
    text_data = encode_call_text(node, key)
    try:
        raw = eth_call(resolver_addr, text_data)
        value = decode_string(raw) or "(未设置)"
    except Exception as e:
        value = f"出错: {e}"
    print(f"  {key:20s} → {value}")
```



# 参考资料

DPRK Adopts EtherHiding: Nation-State Malware Hiding on Blockchains

https://cloud.google.com/blog/topics/threat-intelligence/dprk-adopts-etherhiding/

EtherHiding: How Web3 Infrastructure Enables Stealthy Malware Distribution

https://www.picussecurity.com/resource/blog/etherhiding-how-web3-infrastructure-enables-stealthy-malware-distribution

Simulating EtherHiding: Blockchain as a Malware 

https://cymulate.com/blog/simulating-etherhiding-blockchain-as-a-malware/