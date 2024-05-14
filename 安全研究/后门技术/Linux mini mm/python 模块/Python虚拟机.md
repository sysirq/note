# pythonvm-rust

```
git clone https://github.com/progval/pythonvm-rust.git
cd pythonvm-rust
python3 -m compileall -b pythonlib examples
cargo run pythonlib/ examples/helloworld.pyc
```

# 源代码编译成字节码

```
>>> import dis
>>> dis.dis('a=2')
  1           0 LOAD_CONST               0 (2)
              2 STORE_NAME               0 (a)
              4 LOAD_CONST               1 (None)
              6 RETURN_VALUE
>>>

```

# 函数创建 字节码实现

```python
#Listing 2
s='''a = 1
b = 2
def f(x):
    global b
    b = 3
    y = x + 1
    return y 
f(4)
print(a)
'''
c=compile(s, "", "exec")
disassemble(c)
```

```bytecode
1         0 LOAD_CONST               0 (1)
          2 STORE_NAME               0 (a)

2         4 LOAD_CONST               1 (2)
          6 STORE_GLOBAL             1 (b)

3         8 LOAD_CONST               2 (<code object f at 0x00000218C2E758A0, file "", line 3>)
         10 LOAD_CONST               3 ('f')
         12 MAKE_FUNCTION            0 
         14 STORE_NAME               2 (f)

8        16 LOAD_NAME                2 (f)
         18 LOAD_CONST               4 (4)
         20 CALL_FUNCTION            1 
         22 POP_TOP                    

9        24 LOAD_NAME                3 (print)
         26 LOAD_NAME                0 (a)
         28 CALL_FUNCTION            1 
         30 POP_TOP                    
         32 LOAD_CONST               5 (None)
         34 RETURN_VALUE               

Disassembly of<code object f at 0x00000218C2E758A0, file "", line 3>:

5         0 LOAD_CONST               1 (3)
          2 STORE_GLOBAL             0 (b)

6         4 LOAD_FAST                0 (x)
          6 LOAD_CONST               2 (1)
          8 BINARY_ADD                 
         10 STORE_FAST               1 (y)

7        12 LOAD_FAST                1 (y)
         14 RETURN_VALUE
```


```python
def f(x=5):
    global b
    b = 3
    y = x + 1
    return y
```

```bytecode
2         4 LOAD_CONST               5 ((5,))
          6 LOAD_CONST               1 (<code object f at 0x00000218C2E75AE0, file "", line 2>)
          8 LOAD_CONST               2 ('f')
         10 MAKE_FUNCTION            1
```

# 函数调用 字节码实现

```python
s='''a=0
while a<10:
    print(a)
    a += 1
'''
c=compile(s, "", "exec")
disassemble(c)
```

```bytecode
1         0 LOAD_CONST               0 (0)
          2 STORE_NAME               0 (a)

2         4 SETUP_LOOP              28 (to 34)
    >>    6 LOAD_NAME                0 (a)
          8 LOAD_CONST               1 (10)
         10 COMPARE_OP               0 (<)
         12 POP_JUMP_IF_FALSE       32 

3        14 LOAD_NAME                1 (print)
         16 LOAD_NAME                0 (a)
         18 CALL_FUNCTION            1 
         20 POP_TOP                    

4        22 LOAD_NAME                0 (a)
         24 LOAD_CONST               2 (1)
         26 INPLACE_ADD                
         28 STORE_NAME               0 (a)
         30 JUMP_ABSOLUTE            6 
    >>   32 POP_BLOCK                  
    >>   34 LOAD_CONST               3 (None)
         36 RETURN_VALUE
```

# 资料

Understanding Python Bytecode

https://towardsdatascience.com/understanding-python-bytecode-e7edaae8734d

Read Inside The Python Virtual Machine

https://leanpub.com/insidethepythonvirtualmachine/read

<https://nanguage.gitbook.io/inside-python-vm-cn/1.-jian-jie>


https://github.com/progval/pythonvm-rust

深入理解 python 虚拟机：pyc 文件结构

https://mp.weixin.qq.com/s?__biz=Mzg3ODgyNDgwNg==&mid=2247488040&idx=1&sn=665b5b6080d5ec7910f586b252281bcf&chksm=cf0c8e21f87b073748c82af61a5c7c9d73bca95e5b6558d50d1d5b1cc97e50c4a93d9daffcfa&token=1257007364&lang=zh_CN#rd

Python逆向（二）—— pyc文件结构分析

https://www.cnblogs.com/blili/p/11799483.html

PYC文件格式分析

https://kdr2.com/tech/python/pyc-format.html