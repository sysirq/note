# Introduction

### Architecture State and Instruction Set

Recall that a computer architecture is defined by its instruction set and architectural state.The architectural state fro the MIPS processor consists of the program counter and the 32 registers.Based on the current architectural state,the processor executes a particular instruction with a particular set of data to produce a new architectural state.  

handle only the following instructions:

- R-type arithmetic/logic instructions:add,sub,and,or,slt
- Memory instructions:lw,sw
- Branches:beq

### Design Process

A good way to design a complex system is to start with hardware containing the state elements.These elements include the memories and the architecutral state(register file).Then,add block of combinational logic between the state elements to compute the new state based on the current state.

![image](images/66BC6FB7137B4736B68060C154772FAAclipboard.png)

### MIPS Microarchitectures

![image](images/C376CD2C17884D3F93BD34F5E897E855clipboard.png)

# Performance Analysis

![image](images/7454557CEEE847B584A32697084C1CC2clipboard.png)