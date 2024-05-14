SystemTap的基本思想是命名事件（events），并为他们提供处理程序（handlers）。

这里有几种事件：进入/退出函数，定时器，对话终止。

# 结构

SystemTap的工作过程：

*   检查脚本
*   转化为C代码，并将其编译为内核模块
*   SystemTap加载模块，并启动内核probe
*   一旦对应的event发生，则执行相应的handler
*   退出清理工作

# SytemTap脚本

SystemTap脚本由两个部件组成\:events and handler。（An event and its corresponding handler is collectively called a probe.）他们一起叫做probe

### 格式

SystemTap脚本使用.stp文件后缀。格式为

```stp
probe event {statements}
```

SystemTap支持多个events对应一个probe；多个events用，分割。每个语句之间的分隔符并不需要

SystemTap允许编写函数，使其在多个probes中使用。

```stp
function function_name(arguments){statements}
probe event {function_name(arguments)}
```

### Event

SystemTap的events被分成两种类别：同步的和异步的

#### 同步Events

当任何进程在内核代码的特定位置执行一条指令时，都会发生同步事件。这为其他事件提供了一个参考点，可以从中获得更多上下文数据。

##### syscall.sysctem\_call

eg:

    syscall.close

    syscall.close.return

##### vfs.file\_operation

    vfs.vfs_read
    vfs.vfs_read.return

##### kernel.function("function")

    kernel.function("sys_open")
    kernel.function("sys_open").return

    kernel.function("*@kernel/fork.c:1598")

##### kernel.trace("tracepoint")

静态探测点

##### module("module").function("function")

Allows you to probe functions within modules.

    probe module("ext3").function("*"){}
    probe module("ext3").function("*").return{}

##### netdev

probe netdev.transmit

#### 异步Events

并不关联到特殊的函数和指令

##### begin

开始执行SystemTap时执行

##### end

同上

##### timer events

    probe timer.s(4)
    probe timer.ms(milliseconds)
    probe timer.us(microseconds)
    probe timer.ns(nanoseconds)
    probe timer.hz(hertn)
    probe timer.jiffies(jiffies)

当与其他收集信息的probe一起使用的时候，timer events允许你周期打印收集到的信息

# SystemTap Handler Body

### SystemTap 函数

print\_backtrace():打印函数调用栈

symname():得到指定地址的符号

execname():进程的名称

pid()：进程的pid

tid()：tid

uid()

cpu():当前cpu号

gettimeofday\_s():从1970，1，1到当前的秒数

ctime()\:Convert number of seconds since UNIX epoch to date.

pp()\:A string describing the probe point currently being handled

thread\_indent(int):接受一个整数，加到thread相关的变量中，表示缩进的空格，该函数返回到第一次调用thread\_indent经过的时间，进程名，进程id，缩进空格字符串

name:与跟踪系统调用的event一起使用，输出当前跟踪的系统调用名称。（syscall.system\_call）

target():与stap一起使用，通过 -x 选项指定一个整数，target()就返回该整数

exit():退出脚本

# 基本的SystemTap Handler 构造

### 变量

SystemTap能够根据赋值给变量的值，自动推断出变量的类型（string or integer）。

```stp
global count_jiffies, count_ms   #定义probes之间可以共享的变量
probe timer.jiffies(100) { count_jiffies ++ }
probe timer.ms(100) { count_ms ++ }
probe timer.ms(12345)
{
  hz=(1000*count_jiffies) / count_ms # 定义只能在probe内使用的变量
  printf ("jiffies:ms ratio %d:%d => CONFIG_HZ=%d\n",
    count_jiffies, count_ms, hz)
  exit ()
}
```

### 目标变量

映射到代码中实际位置的探测事件(例如，kernel.function(“function”)和kernel.statement(“statement”))允许使用目标变量来获得在代码中该位置可见的变量的值。

可以使用-L选项来获得可用的目标变量:

    stap -L 'kernel.function("vfs_read")'

    会得到以下信息：

    kernel.function("vfs_read@/build/linux-IWbocJ/linux-4.15.0/fs/read_write.c:432") $file:struct file* $buf:char* $count:size_t $pos:loff_t* $ret:ssize_t

    可以使用@var("varname@src/file.c")引用全局变量

    可以使用 var->fied 来引用字段，var可以是结构体也可以是指针

可以通过内存地址来获得该地址的值：

    kernel_char(address)

    kernel_short(address)

    kernel_int(address)

    kernel_long(address)

    kernel_string(address)

    kernel_string_n(address,n)

### 更简单的打印目标变量

SystemTap脚本通常用于观察代码中正在发生的事情。 在许多情况下，仅打印各种上下文变量的值就足够了。 SystemTap提供了一些变量，这些运算可以为目标变量生成可打印的字符串

```

$$locals:Expands to a subset of $$vars contaning only the local variables

$$params:Expands to a subset of $$vars containing only the function parameters

$$return:Is available in return probes only. It expands to a string that is equivalent to sprintf("return=%x",  $return) if the probed function has a return value, or else an empty string.

$$vars、$$locals、$$params、$$return可以加（多个）$，表示展开指针（结构）
```

### 类型转换

```c
function task_state:long (task:long)
{
    return @cast(task,"task_struct","kernel<linux/sched.h>")->state   
}
```
### 检查变量的可用性

随着代码的发展，可用的变量可能会改变。可以使用$define查看变量是否可用。eg:@defined($flags)

# 条件语句

### if/else statements

```stp
if(condition)
    statement1
else
    statement2
```

### While Loops

```stp
while(condition)
    statement
```

### For Loops

```c
for(initialization;conditional;increment)
    statement
```

### 命令行参数

SystemTap脚本也可以接受命令行参数，通常是$或@后接数字（从1开始），$开头表示参数是整形，@开头表示参数是字符串

```c
probe kernel.function(@1){}
probe kernel.function(@1).return{}
```

参数传递的方法:

```
stap test.stp kernel function
```

# SystemTap中的关联数组操作

### 赋值

```
array_name[index_expression]=value

foo[tid()] = gettimeofday_s()
```

由于关联数组通常在多个probe中使用，因此应在SystemTap脚本中将它们声明为全局变量。

您最多可以在一个数组语句中指定九个索引表达式

```stap
global arr 

probe begin {
        arr["hanhan","boy"] = 25
        arr["dundun","girl"] = 24
        printf("hanhan age:%d\n",arr["hanhan","girl"])
        exit()
}
```

### 从数组中读取数据

```
array_name[index_expression]

delta = gettimeofday_s() - foo[tid()]
```

当index_expression 不存在时，返回0(NULL)

### 数组遍历

```stap
global arr

probe begin {
        arr["hanhan","boy"] = 25
        arr["dundun","girl"] = 24

        foreach( [name,sex] in arr){
                printf("%s,%s\n",name,sex);
        }

        exit()
}
```

```stap
global reads
probe vfs.read
{
    reads[execname()]++
}

probe timer.s(3)
{
    foreach(count in reads)
        printf("%s:%d\n",count,reads[count]);
}
```

遍历时，也可以指定value的排序方式，+ 升序，-降序，以及遍历的个数:limit

```
foreach(count in reads+ limit 5)
```

### 删除数组中的元素 或 清空数组

```
delete reads # 清空数组reads
delete reads[ls] # 清空"ls"数组元素
```

### 在条件语句中使用数组

```
if([index_expression] in array_name) statement
```

检查index_expression key 是否在数组中

### 数据汇总

```
global reads

probe vfs.read
{
    reads[execname()] <<< $count
}
```

the operator <<< $count stores the amount returned by $count to the associated value of the corresponding execname() in the reads array. Remember, these values are stored; they are not added to the associated values of each unique key, nor are they used to replace the current associated values. In a manner of speaking, think of it as having each unique key (execname()) having multiple associated values, accumulating with each probe handler run.

使用@extractor(variable/array index express)来提取统计值。extractor可以是

- count
- sum
- min
- max
- avg

当使用数值统计的时候，你也可以这样使用数组(Multiple array index)

```
global reads

probe vfs.read
{
    reads[execname(),pid()] <<< 1
}

probe timer.s(3)
{
    foreach([var1,var2] in reads)
        printf("%s (%d): %d\n",var1,var2,@count(reads[var1,var2]));
}
```

# tapset

tapset 类似于C语言中的库文件。

标准tapset位于：/usr/share/systemtap/tapset
````

