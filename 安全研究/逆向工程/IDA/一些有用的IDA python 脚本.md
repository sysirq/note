```python
import idaapi
import sys

def callstack(start_addr,target_func_start_addr,target_func_end_addr,stack):
    stack.append(start_addr)
    if (target_func_start_addr <= start_addr) and (start_addr <= target_func_end_addr):
        print(stack)
        stack.pop()
        return
    addr = idaapi.get_first_cref_to(start_addr)
    
    while addr != idaapi.BADADDR:
        callstack(addr,target_func_start_addr,target_func_end_addr,stack)   
        addr =  idaapi.get_next_cref_to(start_addr,addr) 
    stack.pop()
    return

listen_addr = 0x446D40
sslvpnd_handler_start_addr = 0x001858B00
sslvpnd_handler_end_addr =  0x001859843
stack = []
sys.setrecursionlimit(999999999)
callstack(0x446D40,sslvpnd_handler_start_addr,sslvpnd_handler_end_addr,stack)
```

