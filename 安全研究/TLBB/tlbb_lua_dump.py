# after get information from tlbb_lua_count.py
# break at 'call lua_dostring' key point
# ret addr:92DDEA,count:1112,base:4C0000,off:46DDEA
# ret addr:92DDA7,count:228 ,base:4C0000,off:46DDA7

from x64dbgpy.pluginsdk._scriptapi import *
import string


filespath = "F:\\Data\\tlbb_lua\\"
for i in range(0,1340):
    debug.Run()
    debug.Wait()

    lua_content_addr = memory.ReadPtr(register.GetESP()+4)
    if(module.GetMainModuleBase() + 0x46DDA7) < register.GetEIP():
        lua_name_addr = memory.ReadPtr(register.GetESP()+0x8)
    else:
        lua_name_addr = memory.ReadPtr(register.GetESP()+0xC)
    lua_name = ""
    lua_content = ""
    lua_namec = 0
    lua_contentc = 0

    print("content_addr:%x,name_addr:%x"%(lua_content_addr,lua_name_addr))

    while memory.IsValidPtr(lua_name_addr):
        lua_namec = memory.ReadByte(lua_name_addr)
        if chr(lua_namec) in string.printable:
            lua_name = lua_name + chr(lua_namec)
            lua_name_addr = lua_name_addr+1
        else:
            break

    if len(lua_name)!=0:
        while(1):
            lua_contentc = memory.ReadByte(lua_content_addr)
            if(lua_contentc == 0):
                break
            lua_content = lua_content + chr(lua_contentc)
            lua_content_addr = lua_content_addr + 1

        lua_name = lua_name.replace("/","--")
        filepath = filespath+lua_name
        print('lua_name:%s,lua_content_len:%d'%(lua_name,len(lua_content)))
        f = open(filepath,'w')
        f.write(lua_content)
        f.close()