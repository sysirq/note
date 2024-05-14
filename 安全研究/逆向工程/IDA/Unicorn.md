# eg

```python
from unicorn import *
from unicorn.x86_const import *

BASE_ADDR = 0x400000
STACK_ADDR = 0x0
MEM_SIZE = 1024*1024

instructions_skip_list = [0x00000000004004EF,0x00000000004004F6,0x0000000000400502,0x000000000040054F]

def read(name):
    with open(name,'rb') as f:
        return f.read()

def hook_code(mu,address,size,user_data):
    #print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size))
    if address in instructions_skip_list:
        mu.reg_write(UC_X86_REG_RIP, address+size)
    if address == 0x0000000000400560:
        c = mu.reg_read(UC_X86_REG_EDI)
        print(chr(c))
        mu.reg_write(UC_X86_REG_RIP, address+size)

mu = Uc(UC_ARCH_X86,UC_MODE_64)
mu.mem_map(BASE_ADDR,MEM_SIZE)
mu.mem_map(STACK_ADDR,MEM_SIZE)

mu.mem_write(BASE_ADDR,read("fibonacci"))

mu.reg_write(UC_X86_REG_RSP,STACK_ADDR+MEM_SIZE-1)

mu.hook_add(UC_HOOK_CODE, hook_code) # call hook_code function before emulation of each instruction

mu.emu_start(0x00000000004004E0, 0x0000000000400575)
```

# 资料

1.Unicorn Engine tutorial

http://eternal.red/2018/unicorn-engine-tutorial/