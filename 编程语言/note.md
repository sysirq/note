# 在Visual studio中，定义一个可执行数据段的方法

1.virtualprotect

2.pragma section

```c
#pragma section( "mydata" ,read,write,execute )

__declspec(allocate("mydata"))
```

https://docs.microsoft.com/en-us/cpp/preprocessor/section?view=vs-2019


或者使用CFF  修改PE文件 

https://blog.csdn.net/apollon_krj/article/details/77095776