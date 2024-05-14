# 命令选项

```
stap 脚本路径

stap -e '脚本'

stap -p4 -r kernel_version script -m module_name：生成跨电脑的stap module，可以通过staprun运行

stap -v : 输出详细过程

stap -o file_name：将标准输出定向到filename中

stap -S size,count： 指定输出到的文件的大小和个数

stap -x process_id: 在stap脚本中target()函数可以返回process_id

stap -F : use SystemTap's flight recorder mode and makes the script a background process


stap -F -o /tmp/pfaults.log -S 1,2  pfaults.stp : File Fight Recorder

stap -l probe ： 显示该探测点在源代码中的位置

stap -L probe ： 显示该探测点的变量等详细信息

stap -g : 启用专家模式，可以显示更多的探测点

```

# 资料

Linux 自检和 SystemTap

https://www.ibm.com/developerworks/cn/linux/l-systemtap/index.html

SystemTap Beginners Guide

https://sourceware.org/systemtap/SystemTap_Beginners_Guide/

SystemTap使用技巧

https://my.oschina.net/sherrywangzh/blog/1518223

systemtap 应用笔记

https://blog.csdn.net/yk_wing4/article/details/91038920