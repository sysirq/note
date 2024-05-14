# 快速定位Android程序的关键代码

1.通过apktool反编译apk文件，得到AndroidManifest.xml文件,可以得到程序用到的组建、配置、以及主Activity

2.信息反馈法(特殊字符串)

3.特征函数法(Toast)

4.一行一行代码看

5.插桩法

6.查看调用栈

7.Method Profiling(记录每个函数的CPU时间，以及调用栈)

# smali文件格式
主要框架

.class <访问权限> [修饰关键字] <类名>

.super <父类名>

.source <源代码名称>

后面是具体的字段、方法、注解(下面 <xxx>表示必须要，[xxx]表示可选)
### 字段表示
静态字段：
    
    #static fields
    .field <访问权限> static [修饰关键字] <字段名>:<字段类型>
    
实例字段

    #instance fields
    .field <访问权限>  [修饰关键字] <字段名>:<字段类型>
    
### 方法表示

    .method <访问权限> [修饰关键字] <方法原型>
    .prologue
    具体代码
    .end method
    
### 接口
    
    .implements <接口名>
    
### 注解类

    .annotation [注解属性] <注解类名>
        [注解字段 = 值]
    .end annotation

# Android程序中的类
baksmali反编译dex文件时，会为每一个类都生成一个smali文件

### 内部类
如下
```java
class Outer{
    class Inner{}
}
```
baksmali反编译的时候会生成 Outer.smali文件 与 Outer$Inner.smali文件。其中内部内文件名形式为"[外部类]$[内部类].smali"。

我们打开Outer$Inner.smali文件会发现，存在一个this$0 的synthetic的字段(synthetic表示由编译器合成)，其指向父类，供内部类的其他方法调用（其中0表示第几层父类）

查看内部类的初始化函数，我们可以发现该类的初始化为：先保存外部类的引用，然后调用父类的构造函数，然后是自身的初始化

### 监听器
也就是匿名类，其形式与内部类差不多。文件名形式为"[外部类]$[数字].smali"

### 注解类
```smali
#annotations
.annotation system Ldalvik/annotation/Memberclasses;
    value = {
        Lcom/droider/crackme/MainActivity#SNChecker;
    }
.end annotation
``` 
MemberClasses为父类提供一个member classes 列表.通俗的将就是一个内部类列表

```smali
#annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = {
        Lcom/droider/crackme/MainActivity;->onCreate()V;
    }
.end annotation
``` 
EnclosingMehtod注解用来说明其作用范围,Method表示他作用于一个方法。value表示其作用的具体类中的函数.相应的还用EnclosingClass注解

```smali
#annotations
.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "SNChecker"
.end annotation
``` 
InnerClass注解表示类为一个内部类

### 自动生成的类
##### R类
每个工程下的res目录下的每个资源都会有一个id，其保存在R类中


# 阅读反汇编的smali代码
### 循环语句
- 迭代器(hasNext,next)
- 普通循环(x86反汇编形式差不多)

### switch 分支语句
- packed-switch（有规律的）
- sparse-switch (无规律的)

smali格式大概如下:
xxxxx-switch p0,switch_goto_table

switch_goto_table指向一个跳转表。

其中默认 default 分支 位于 xxxxx-switch p0,switch_goto_table 指令之后

### try-catch 语句
smali 代码中，try语句块使用 try_start_x ,try_end_x 包围 (其中 x为数字).

在 try_end_x下面是.catch 指令，指定处理的异常类型与处理代码的位置

在处理catch代码时，发现异常会调用外围catch

