# Single-Cycle Datapath

lw instruction:

![image](images/3022BE8D538E4C7CA748A7F1504F69EDclipboard.png)

![image](images/46225F0BBFB945B0943F850720C559A1clipboard.png)

![image](images/FC18B434501C446DB149A8D8BC839E09clipboard.png)

![image](images/5EF7EDF2966D481BBC2BF81B46B22204clipboard.png)

![image](images/E76B21D85CA244B3B5B115AB904D3B4Eclipboard.png)

![image](images/71130410C14F4FBA850D4CBC78EC7C95clipboard.png)

sw instruction:

![image](images/4973BE8E918A4051A237777FF1F8C908clipboard.png)

R-type instruction:

![image](images/E091FE6FD669481893E7EDC5B7B2733Dclipboard.png)

beq instruction:

![image](images/DCC3EE507AFC4776BCE9FEBF4B57DE96clipboard.png)

# Single-Cycle Control

The control unit computes the control signals based on the opcode and funct fields of the instruction.

Most of the control information comes from the opcode,but R-type instructions also use the funct field to determine the ALU operation.Thus,we will simplify our design by factoring the control unit into two blocks of combinational logic.The main decoder computes most of the outputs from the opcode.It also determines a 2-bit ALUOp signal.The ALU decoder uses this ALUOp signal in conjunction with the funct field to compute ALUControl.

![image](images/21B0B59AEAA14C33A99EBC3DDA44F4EEclipboard.png)

![image](images/82B22DF048F744258C8D2E0381DAC92Fclipboard.png)

![image](images/48114F6749104F8B85E6721CCDD535BB1601608955(1).jpg)

![image](images/DABBD459EDE44E9C81119A55A5CA010D1601608961(1).jpg)

![image](images/E7DA5A4E30174BA2B7C23D226A0BEB3Eclipboard.png)

![image](images/22EBCBBA852B4C34AF919809D5DC478Dclipboard.png)

# Performance Analysis

![image](images/9F243591588341309167BEC9555BBA9Fclipboard.png)

# 资料

MIPS 指令集速查

https://www.cnblogs.com/mipscpu/archive/2013/03/22/2976316.html