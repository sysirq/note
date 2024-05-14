内核中已经加载的模块信息也存放在/sys/module目录下。

# 模块加载函数

Linux内核模块加载函数一般以__init标识声明，典型的模块加载函数的形式如下:

```c
static init __init initialization_function(void)
{
    ....
}

module_init(initialization_function);
```

初始化成功，返回0。初始化失败时，返回错误编码。在Linux内核里，错误编码是一个接近于0的负值，在<Linux/error.h>中定义，包括-ENODEV等

对于只是初始化阶段需要的数据,可以被定义为__initdata

```
static init hello_data __initdata = 1;
```

# 模块卸载函数

```c
static void __exit cleanup_function(void)
{
    ...
}

module_exit(cleanup_function);
```

对于只是退出阶段采用的数据可以使用__exitdata来形容。

# 模块参数

可以用module_param(参数名，参数类型，参数读/写权限)为模块定义一个参数。

参数类型:byte、short、ushort、int、uint、long、ulong、charp（字符指针）、bool

在装载内核模块时，用户可以向模块传递参数，形式为

```
insmod 模块名 参数名=参数值
```

模块也可以拥有参数数组，形式为"module_param_array(数组名，数组类型，数组长度，参数读写权限)"。运行insmod或modprobe命令时，应使用逗号分隔输入的数组元素


```c
static char *my_name="hanhan";
static int age = 24; 

module_param(my_name,charp,S_IRUGO);
module_param(age,int,S_IRUGO);
```

其中参数读写权限用于/sys/module/对应模块/parameters/age的权限设置.

# 导出符号

Linux的"/proc/kallsyms"文件对应着内核符号表，它记录了符号以及符号所在的内存地址。 

模块可以使用如下宏导出到内核符号表中:

```
EXPORT_SYMBOL(符号名)；
EXPORT_SYMBOL_GPL(符号名)；//只适用于包括GPL的模块使用
```

# 简单Makefile

```c
obj-m += import.o

EXTRA_CFLAGS = -g -O0 #Specify flags for the module compilation

all:
        make -C /home/john/Code/Linux/kernel/linux-4.0 M=$(shell pwd) modules
clean:
        make -C /home/john/Code/Linux/kernel/linux-4.0 M=$(shell pwd) clean
```

如果一个模块包括多个.c文件，则应该以如下方式编写Makefile

```
obj-m := modulename.o
modulename-objs := file1.o file2.o
```