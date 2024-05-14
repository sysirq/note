We will be examining an implementation that includes a subset of the core RISC-V instruction set:

- The memory-reference instructions load doubleword and store doubleword
- The arithmetic-logical instructions add,sub,and,or
- The conditional branch instruction branch if equal.(beq)


![image](images/F6C9530301574CBA8442586D2DAE0C191599789568(1).png)

![image](images/BC1E11259E5C49C9B18226C689BE96781599791196(1).png)

![image](images/4C68CB59094248CA8F10D0CF88495E5D1599792904(1).png)

# 逻辑设计规范

The datapath elements in the RISC-V implementation consist of two different type of logic elements:elements that operate on data values and elements that contain state.

A state element has at least two inputs and one output.The required inputs are the data value to be written into the element and the clock,which determines when the data values is written.The output from a state element provides the value that was written in an earlier clock cycle.

The clock is used to determine when the state element should be written;a state element can be read at any time.

# 创建数据通路

In the RISC-V implementation,the datapath elements include the instruction and data memories,the register file,the ALU,and adders.

![image](images/70729A5E527842BD907AB2072C83C8781600048689(1).png)

![image](images/FFF26B2E87B14A8CAFB15C44234609991600048842(1).png)

register file:A state element that consists of a set of registers that can be read and written by supplying a register number to be accessed.

![image](images/E61355703DB24BAA9ECA6665FFECD99B1600049749(1).png)

![image](images/E2673394DABC4F0792DD8E11D98C4C091600050472(1).png)

![image](images/09E8B72D14B54C1E9E29EB5A99778EF41600051447(1).png)

### 创建单个数据通路

Now that we have examined the datapath components needed for the individual instruction classed,we can combine them into a single datapath and add the control to complete the implementation.This simplest datapath will attempt to execute all instructions in one clock cycle.This design means that no datapath resource can be used more than once per instruction,so any element needed more than once must be duplicated.

![image](images/F264B3B83F77456497EE2BEF2363AD741600053770.png)

Now we can combine all the pieces to make a simple datapath for the core RISC-V architecture by adding the datapath for instruction fecth(Figure 4.6),the datapath from R-type and memory instructions(Figura 4.10),and the datapath for branches(Figure 4.9).


![image](images/6FEA01A109DE498188C596BC557C2E081600054380(1).png)

# 一个简单的实现方案

![image](images/9241EA949CA54042A103C02A604FC2161600065220(1).png)


![image](images/D67EA77A25D3430F8C32249238DCE1031600066203(1).png)

![image](images/432DE7D95FFF4382A83A7284D701B8121600135761(1).png)

![image](images/F89C4C55E55F4A2287A31C9471FD041E1600135808(1).png)

![image](images/DC102F5FBAA24D0FA882EF1E025448B41600136104(1).png)

![image](images/CBBD2A6EBD0746ACBEAC8E9E4B92AF811600136722(1).png)

![image](images/00F25BB830E74FB89F6EF3CFEB2A6EB61600137469(1).png)

### 数据通路的操作

The operation of the datapath for an R-type instruction(add x1,x2,x3)

- The instruction is fetched,and the PC is incremented.
- Two registers,x2 and x3,are read from the register file;also,the main control unit computers the setting of the control lines during the step
- The ALU operates on the data read from the register file,using portions of the opcode to generate the ALU function
- The result from the ALU is written into the destination register(x1) in the register file.

![image](images/53590C6FD66D4D5EA5C48035CC2A59E61600139487(1).png)

The operation of the datapath for an load instruction(ld x1,offset(x2))

- An instruction is fetched from the instruction memory,and the PC is incremented
- A register(x2) values is read from the register file
- The ALU computes the sum of the value read from the register file and the sign-extended 12 bits of the instruction(offset)
- The sum from ALU is used as the address for the data memory
- The data from the memory unit is written into the register file(x1)

![image](images/61D878A9C50E417691BE0B9A8105AA451600139745(1).png)


The operation of the datapath for an branch instruction(beq x1,x2,offset)

- An instruction is fetched from the instruction memory,and the PC is incremented.
- Two registers,x1 and x2,are read from the register file.
- The ALU subtracts one data value from the other data value,both read from the register file.The value of PC is added to the sign-extended,12 bits of the instruction(offset) left shifted by one;the result is the branch target address.
- The Zero status information from the ALU is used to decide which adder result to store in the PC

![image](images/95E482690F0A4BC5B41912B83D3FEC2B1600140151(1).png)


![image](images/0602A7CEEDFF410A99D7232B5743C93D1600140780(1).png)

Although the single-cycle design will work correctly,it is too inefficient to be used in modern deisgn.To see why this is so,notice that the clock cycle must have the same length for every instruction in this single-cycle design.Of course,the longest possible path in the processor determines the clock cycle.