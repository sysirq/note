```python
# 查找调用lua_dostring的函数
import idaapi
import ida_idc
import idautils
import idc

func_name = "lua_dostring"
func_addr = get_name_ea_simple(func_name)
caller = {}

if(func_addr == idc.BADADDR):
    print("not found %s function"%(func_name))
    exit() 

for xref in XrefsTo(func_addr, 0):
    name = idc.get_func_name(xref.frm)
    if name not in caller:
        caller[name] = []
    caller[name].append(xref.frm)

for name in caller:
    print("func name: %s call count: %d"%(name,len(caller[name])))
```