# 一些有用的函数

###  获取函数的返回地址

GCC提供了内建函数__builtin_return_address()，用于获取函数的返回地址，适用于多种架构。它的使用更加简单，且与平台无关：

```
#include <stdio.h>

void test() {
    void* ret = __builtin_return_address(0);
    printf("Return address: %p\n", ret);
}

int main() {
    test();
    return 0;
}
```

解释：
- __builtin_return_address(0)：0表示获取当前函数的返回地址，如果传递1，则可以获取调用者的返回地址。

# 资料

交叉平台编译

https://getting-started-with-llvm-core-libraries-zh-cn.readthedocs.io/zh-cn/latest/ch08.html