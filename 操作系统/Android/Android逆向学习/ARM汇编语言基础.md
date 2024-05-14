# ARM 与 Thumb 寄存器对应关系
- PC寄存器: ARM状态为R15,Thumb状态为PC
- LR寄存器: ARM状态为R14,Thumb状态为LR
- SP寄存器: ARM状态为R13,Thumb状态为SP
- IP寄存器: ARM状态为R12,Thumb状态为IP
- FP寄存器: ARM状态为R11,Thumb状态为FP

其他对应关系一一相同

# ARM 与 Thumb 指令集
指令格式:

<opcode>{<cond>}{S}{.W|.N} <Rd>,<Rn>{,<operand2>}

其中
- opcode为助记符
- cond为条件
- S指定其是否影响CPSR寄存器的值（也就是程序状态字）
- .W与.N指定指令宽带。(一个指定32，一个指定16)
- Rd 目的寄存器
- Rn 第一个操作数寄存器
- operand2为第二个操作数

### 跳转指令

####  B 跳转指令

格式：B{cond} label

####  BL带链接的跳转指令

格式：BL{cond} label

当条件满足时，会将当前指令的下一条指令保存到R14(LR)寄存器中，然后跳转到label中。这通常用于调用子程序，在子程序的尾部，通过 MOV PC,LR 返回

####  BX 带状态切换的跳转指令

格式：BX{cond} Rm

当执行BX指令时，如果条件cond满足，则处理器会检查Rm的为[0]是否为1，如果为1，这将CSPR寄存器的T置1，并将目标代码解释为Thumb代码来执行。为0的话，复位 CSPR寄存器的T。并将目标代码解释为ARM代码来执行。

eg:

```arm
.code 32
ADR R0,thumbcode+1 
BX R0 @跳转到thmbcode,并将处理器切换为thumb模式 
thumbcode:
.code 16
...
```

####  BLX带链接与状态切换的跳转指令

格式：BLX{cond} Rm

### 存储器访问指令

#### LDR

格式：
    
    LDR{type}{cond} Rd,label
    
    LDRD{cond} Rd,Rd2,label

type指定了操作的数据大小

用于从存储器中加载数据到寄存器。

LDRD 一次加载双字的数据，将数据加载到Rd,Rd2中

#### STR
格式：
    
    STR{type}{cond} Rd,label
    
    STRD{cond} Rd,Rd2,label

用于储存数据到指定的存储单元

#### LDM
格式:
    
    LDM{addr_mode}{cond} Rn{!},reglist

其中 ! 为可选，如果有，则将最终地址回写到Rn中

该指令从指定的存储单元，加载数据到寄存器列表中

eg:
```arm
LDMIA R0!,{R1-R3} @依次加载R0地址处的数据到R1,R2,R3寄存器中
```

#### STM
格式:
    
    STM{addr_mode}{cond} Rn{!},reglist

其中 ! 为可选，如果有，则将最终地址回写到Rn中

将寄存器列表中的数据存储到指定存储单元

#### PUSH

#### POP

#### SWP

格式:
 
    SWP{B}{cond} Rd,Rm,[Rn]
 
Rd:为要从存储器加载数据的寄存器
 
Rm:为写入数据到存储器的寄存器
 
Rn:为存储器地址
 
如果 Rd 与 Rm 相同，则可实现寄存器与存储器的交换

### 数据处理指令