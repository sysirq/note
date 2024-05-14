# 必须存在的Section

.text  = section number 0 

.data  = section number 1

.rdata = section number 2

.bss   = section number 3


# 数据格式 


OS types[1 byte] + OS arch[1 byte] + oep[8 byte] + .text size [8 byte] + .text data + .data size[8 byte] + .data data + .rdata size[8 byte] + .rdata data + .bss size[8 byte] + relocation data

# CS 中的 重定位信息

![image](https://storage.tttang.com/media/attachment/2022/10/25/a9972529-9435-4631-91bf-4884269026f1.png)

在getRelocations()函数中，会根据不同的段，插入不同的Magic Number。例如，如果是.rdata，则会插入1024，如果是.data，则会插入1025，如果是.text，则会插入1026，如果是DynamicFunction，则会插入1027，最后以插入1028结尾。
 
 
# 对于需要重定位的情况

- bof内部重定义
- 外部符号引用



- 外部符号还是内部符号
 
# 重定位格式

type: 重定位类型

Section : Number

offset : Section中需要重定位的偏移

offsetInSection ：目标地址在目标Section中的偏移