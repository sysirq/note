# N way 组关联

假设cache 的大小为 S，cache line 的大小为 K

就是将cache分成N份，每份有 （S/N）/K 个cache line。

N份中，相同 index 的cache line，称为一个组


valid bit | tag | index | offset



# 资料

浅谈Cache Memory

http://www.wowotech.net/memory_management/458.html?from=timeline