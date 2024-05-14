# 语料蒸馏(corpus distillation)

在模糊处理中，重要的是消除输入语料库中的大部分冗余语料

# 符号执行(symbolic execution)

符号执行 （Symbolic Execution）是一种程序分析技术，它可以通过分析程序来得到让特定代码区域执行的输入。顾名思义，使用符号执行分析一个程序时，该程序会使用符号值作为输入，而非一般执行程序时使用的具体值。在达到目标代码时，分析器可以得到相应的路径约束，然后通过约束求解器来得到可以触发目标代码的具体值。、

# AFL的算法

- 1.将用户输入的基本测试用例加入到队列当中
- 2.从队列中选择测试用例
- 3.精简测试用例（把不影响程序行为的部分给去除掉）
- 4.变异测试用例
- 5.如果变异导致新的状态转变，则将测试用例添加到队列中
- 6.转到第2步

# 插桩

```shell

# CC=/path/to/afl/afl-gcc ./configure

# make clean all

```

测试库文件时，最好将库静态连接到程序中

``` shell
# CC=/path/to/afl/afl-gcc ./configure --disable-shared

```

在调用“ make”时设置AFL_HARDEN = 1将使CC包装器自动启用代码强化选项，从而使检测简单的内存错误更加容易.

# 二进制文件插桩

利用qemu实现

# 选择初始测试用例

为了正确操作，fuzzer需要一个或多个正常的测试用例。测试用例的原则如下：

- 保持文件足够小
- 测试用例是能测试不同功能的集合（强调差异）

# Fuzzing程序

fuzzing过程本身是由afl-fuzz工具执行的。该工具需要的参数有：一个包含初始测试用例的目录、一个包含发现的目录、要测试的二进制文件。

对于从标准输入中接受数据的程序，用法如下:

```shell
$ ./afl-fuzz -i testcase_dir -o findings_dir /path/to/program [...params...]
```

对于从文件中接受输入的程序，使用 ‘@@’ 去标识文件名应该出现在命令中的位置：

```shell
$ ./afl-fuzz -i testcase_dir -o findings_dir /path/to/program @@
```

# 解释输出

参考status_screen.txt

在输出目录下会创建三种子目录：

- queue : 每个代码路径对应的测试用例加上用户提供的测试用例
- crashes : 导致程序收到致命信号的测试用例（SIGSEGV、SIGILL、SIGABRT）
- hangs : 导致程序超时的测试用例

# 资料

README

https://github.com/google/AFL

status screen

https://github.com/google/AFL/blob/master/docs/status_screen.txt

AFL 漏洞挖掘技术漫谈(一)

https://paper.seebug.org/841/

AFL 漏洞挖掘技术漫谈(二)

https://paper.seebug.org/842/

AFL内部实现细节小记

http://rk700.github.io/2017/12/28/afl-internals/

AFL(American Fuzzy Lop)实现细节与文件变异

https://paper.seebug.org/496/