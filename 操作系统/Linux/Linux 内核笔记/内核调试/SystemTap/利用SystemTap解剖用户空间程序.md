内核选项CONFIG_UPROBES必须启用

所有的用户空间probe event 以process开头，可以将process events指定到特定的进程（通过指定进程ID或可执行文件路径）

# User-Space Events

process("PATH").function("function")  也可以加.return   必须指定可执行文件路径（进程ID），因为需要调试符号 

process("PATH").statement("statement")  必须指定可执行文件路径(进程ID)，因为需要调试符号

process("PATH").mark("marker")  必须指定可执行文件路径(进程ID)，因为需要调试符号

process.begin   可以指定进程ID或可执行文件路径

process.thread.begin    可以指定进程ID或可执行文件路径

process.end 可以指定进程ID或可执行文件路径

process.thread.end  可以指定进程ID或可执行文件路径

process.syscall : $arg1...$arg6 , $return(.return后缀才可以使用),$syscall(int)系统调用号    可以指定进程ID或可执行文件路径

# 访问用户空间程序中的变量

```
user_char(address)

user_short(address)

user_int(address)

user_long(address)

user_string(address)

user_string_n(address,n)
```

也可以使用->，不用区分是否是指针还是结构体

# 打印用户空间堆栈

```
#!/usr/bin/stap

probe process("/root/systemtap/user_space/main").function("func")
{
	print_ubacktrace();
	exit();
}
```