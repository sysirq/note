# 特性

```
uint8_t func(){
    uint32_t len;
    uint32_t len2;
}
len为栈顶部的元素
len2为栈底部的元素:ebp所指向的
数组中高索引为栈底，靠近ebp的


uint8_t func(uint32_t test1,uint32_t test2){
    ......
}

其中

```
```c
enum OPCODES
{
	MOV = 0xb0,
	SUB = 0xb1,
	ADD = 0xb2,
	PUSH = 0xb3,
	POP = 0xb4,
	EXIT = 0x00,
};

enum REGISTERS
{
	EAX = 0x10,
	EBX = 0x11,
	ECX = 0x12,
	EDX = 0x13,
	ESI = 0x14,
	EDI = 0x15,
	EBP = 0x16,
	ESP = 0x17,
	EIP = 0x18,
};

enum OP_SIZE {
	BYTE = 0x21,
	WORD = 0x22,
	DWORD = 0x24
};

enum TYPE {
	REG_REG = 0x11,
	REG_ADR = 0x12,
	REG_INT = 0x13,
	ADR_REG = 0x14
};
```
# 内存布局



# 寄存器编码

```c
	EAX = 0x10,
	EBX = 0x11,
	ECX = 0x12,
	EDX = 0x13,
	ESI = 0x14,
	EDI = 0x15,
	EBP = 0x16,
	ESP = 0x17,
	EIP = 0x18,
```



# mov

```

mov dst,src

第一个字节0xb0 代表mov指令
第二个字节代表,代表目标地址和源地址的类型:
	0x11:都是寄存器
	0x12:目标是寄存器，源是内存地址
	0x13:目标是寄存器，源是立即数
	0x14:目标是内存地址，源是寄存器
第三个字节代表操作大小：
    0x21:一个字节
    0x22:两个字节
    0x24:四个字节
第四个字段开始的N个字节是目标

第五个字段开始的N个字节是源


```

# sub 指令

```

sub dst,src

第一个字节0xb1 代表sub指令
第二个字节代表,代表目标地址和源地址的类型:
	0x11:都是寄存器
	0x12:目标是寄存器，源是内存地址
	0x13:目标是寄存器，源是立即数
	0x14:目标是内存地址，源是寄存器
第三个字节代表操作大小：
    0x21:一个字节
    0x22:两个字节
    0x24:四个字节
第四个字段开始的N个字节是目标

第五个字段开始的N个字节是源


```

# push指令

```
push 
```