# 基础

ea 表示地址

```python
idc.get_screen_ea() # 获取当前光标位置

idc.MinEA() #获取IDA数据库中最小地址

idc.MaxEA() #获取IDA数据库中最大地址

idc.get_segm_name(ea) # 获取ea地址的段名

idc.GetDisasm(ea) # 获取某行的反汇编代码
```

# Segments

遍历程序段

```py
segs = idautils.Segments()

for s in segs:
    print("%s %X %X"%(idc.get_segm_name(s),idc.get_segm_start(s),idc.get_segm_end(s)))
```

# Functions

打印函数列表

```py
funcs = idautils.Functions()

for f in funcs:
    print("%s %X"%(idc.get_func_name(f),f))
```