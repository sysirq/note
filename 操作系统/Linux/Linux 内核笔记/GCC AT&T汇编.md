# AT\&T格式汇编

*   寄存器名要加上%作为前缀
*   指令的源操作数在前，目的操作数在后
*   操作大小由操作码名称的最后一个字母决定。b表示一个字节，w表示2个字节，l表示4个字节，q表示8个字节
*   直接操作数要加上`$,如:“push $`50”
*   绝对转移或调用指令jump/call的操作数要加上\*。
*   远程的转移指令和子程序调用指令的操作码名称为ljmp和lcall
*   间接寻址的格式为disp(base,index,scale)。用于在数组中访问特定元素中的一个特定字段，base为起始地址，index为元素下标，scale为元素大小，disp为元素中的偏移(-4（%ebp）)

# GCC内联汇编

一般形式：

指令部:输出部:输入部:损坏部

表明约束条件有：

"m","v","o":表示内存单元

"r"： 表示任何寄存器

"q":表示寄存器eax，ebx,ecx,edx之一

"i"和"h"：表示直接操作数

"E"和"F"：表示浮点数

"g"：表示任意

"a","b","c","d":分别表示寄存器eax,ebx,ecx,edx

"S","D":分别表示寄存器esi，edi

"I":表示常数

## eg

```c
#include <stdio.h>

int main(void)
{
    int arr[10] = {0};
    int i;
    int arr_len = sizeof(arr)/sizeof(int);

    for(i = 0;i<arr_len;i++){
        arr[i] = i;
    }   
    
    __asm__ __volatile__(
        "movq $0,%%rax\n\t"
        "1:\n\t"
        "cmp %%eax,%1\n\t"
        "je 1f\n\t"
        "movq (%0,%%rax,4),%%rbx\n\t"
        "addq $1000,%%rbx\n\t"
        "movq %%rbx,(%0,%%rax,4)\n\t"
        "inc %%rax\n\t"
        "jmp 1b\n\t"
        "1:\n\t"
        :
        :"S"(arr),"D"(arr_len)
        :"%rax","%rbx"
    );  

    for(i = 0;i<arr_len;i++){
        printf("arr[%d] = %d\n",i,arr[i]);;
    }   

    return 0;
}
```

