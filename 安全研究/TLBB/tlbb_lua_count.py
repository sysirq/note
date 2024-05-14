# When luaplus.lua_dostring call lua_dobuffer,breakpoint in ,count lua script
# lua_count:1340

from x64dbgpy.pluginsdk._scriptapi import *

lua_count = 0
ret_addr = 0
ret_addrs = {}

for i in range(0,5500):
    debug.Run()
    debug.Wait()

    lua_byte_count = memory.ReadDword(register.GetESP()+8)
    if lua_byte_count > 100:
        lua_count = lua_count + 1
        ret_addr = memory.ReadDword(register.GetEBP()+4)
        
        if ret_addr not in ret_addrs:
            ret_addrs[ret_addr] = 0
        ret_addrs[ret_addr] = ret_addrs[ret_addr] + 1

print("lua_count:%d ret_addrs count:%d"%(lua_count,len(ret_addrs)))

for addr in ret_addrs:
    print("ret addr:%X,count:%d,base:%X,off:%X"%(addr,ret_addrs[addr],module.BaseFromAddr(addr),addr - module.BaseFromAddr(addr)))