pipelining: An implementation technique in which multiple instructions are overlapped in execution,much like an assembly line.

The speed-up due to pipelining is equal to the number of stages in the pipeline.

RISC-V instructions classically take five steps:

- Fetch instruction from memory
- Read registers and decode the instruction
- Execute the operation or calculate an address
- Access an operand in data memory(if necessary)
- Write the result into a register(if necessary)

All the pipeline stages take a single clock cycle,so the clock cycle must be long enough to accommodate(适应) the slowest operation.

![image](images/2E1861A0B88E49A68AB624413CA969841600224369(1).png)

Under ideal conditions and with a large number of instructions,the speed-up from pipelining is approximately equal to the number of pipe stages.

Pipelining improves performance by increasing instruction throughput,in contrast to decreasing the execution time of an individual instruction,but instruction throughput is the important metric because real programs execute billions of instructions.

### Designing Instruction Sets for Pipelining

- First,all RISC-V instructions are the same length.This restriction makes it much easier to fetch instructions in the first pipeling stage and to decode them in the second stage.
- Second,RISC-V has just a few instruction formats,with the source and destination register fields being located in the same place in each instruction.
- Third,memory operands only appear in loads or stores in RISC-V.This restriction means we can use the execute stage to calculate the memory address and then access memory in the following stage.

### Pipeline Hazards

There are situations in pipelining when the next instruction cannot execute in the following clock cycle.These events are called hazards,and there are three different types.

##### Structural Hazard

When a planned instruction cannot execute in the proper clock cycle because the hardware does not support the combination of instructions that are set to execute.(所需的硬件部件正在为之前的指令工作)

##### Data Hazards

When a planned instruction cannot execute in the proper clock cycle because data that are needed to execute the instruction are not yet available(等待之前的指令完成数据读写).

![image](images/25D16049C08D420BA9D9FCC0B26F6E201600236890(1).png)

load-use data hazard:A specific form of data hazard in which the data being loaded by a load instruction have not yet become available when they are needed by another instruction.

pipeline stall(流水线停顿):Also called bubble.A stall initiated in order to resolve a hazard

##### Control Hazards

The third type of hazard is called a control hazard,arising from the need to make a decision on the results of one instruction while others are executing.(如果现在要执行那条指令，是由之前指令的运行结果来决定的，而现在之前指令的结果还没有产生，就导致了控制冒险)

# Pipelined Datapath and Control

- 1.IF: Instruction fetch
- 2.ID: Instruction decode and register file read
- 3.EX: Execution or address calculation
- 4.MEM:Data memory access
- 5.WB: Write back

![image](images/0CBB85BD15584FCCB7C6D8152AB65CC71600308625(1).png)

We must place register wherever there are dividing lines between stages.

All instructions advance during each clock cycle from one pipeline register to the next.

![image](images/54DD3570A3CA45479ADBD3D13A147A8D1600310461(1).png)


Instruction ld pipe stage:

![image](images/D036AC503D9E44C3A2ED1DD8149F78101600312086(1).png)

![image](images/A6B446B0065E4F21A2A6C69716B418281600312159(1).png)

![image](images/57F62FA6948640608494D0315E61DA4B1600312201(1).png)

This walk-through of the load instruction shows that any information needed in a later pipe stage must be passed to that stage via a pipeline register.

Each logical component of the datapath - such as instruction memory,register read ports,ALU,data memory,and register write port - can be used only within a single pipeline stage.Otherwise,we would have a structural hazard.

### Pipelined Control

![image](images/175DA106A05343E4B41AACC1C27E84201600324335(1).png)

![image](images/793269376C0B48F89C267E315FF62C481600325354(1).png)

![image](images/A6FDF631F1A64CF285A8CABF1755033D1600325485(1).png)

![image](images/7F76EC31068C44EEA8B60FBD8B7DD33E1600325606(1).png)

![image](images/DA3ECD9147B04B31ABEF1A00E9938BA61600325926(1).png)

![image](images/EA1003272EE1443EBFD8EB6EDD64B3981600326025(1).png)

Implementing control means setting the seven control lines to these values in each stage for each instruction.

# Data Hazards: Forwarding versus Stalling

![image](images/F6A6AE986AAE4B73B0BD6C5ECBC138051600393998(1).png)

![image](images/E53EC62D6F1049F7A96F34E3BD92D5CA1600395275(1).png)

![image](images/B772EFE577784C1E85AB39792E6EB1051600396937(1).png)

![image](images/380A1A89A648488B88A083F0D4BF4A4F1600397623(1).png)

![image](images/C7B3788D3AC94530BCA2BFA1A91EF8181600397758(1).png)

![image](images/8772888DBF8D477B9CF60992D5E6AB291600399328(1).png)

![image](images/DBBA5076706F4DFEB53FD8C1AEB196661600399527(1).png)

![image](images/8C353AB2F0D548F2A26BE2E15802AA571600400608(1).png)

![image](images/1211E8785C9C4B19BB16FC5BE93C93501600401383(1).png)

### Data hazards and Stalls

One case where forwarding cannot save the day is when an instruction tries to read a register following a load instruction that writes the same register:

![image](images/8DEB5CBC09084E25B081A1DF84D4C1AD1600411761(1).png)

The data is still being read from memory in clock cycle 4 while the ALU is performing the operation for the following instruction.Something must stall the pipeline for the combination of load followed by an instruction that reads its result.

![image](images/CB8936FB6AD640ACA4BA4FB0F591D4B61600412238(1).png)

![image](images/93D1893BA4ED43C7AF56294F3D0D81991600414156(1).png)

![image](images/FB0933278E8B4B3E80D66C3A77B825CA1600414502(1).png)

As before,the forwarding unit controls the ALU multiplexors to replace the value from a general-purpose register with the value from the proper pipeline register.The hazard detection unit controls the writing of the PC and IF/ID registers plus the multiplexor that chooses between the real control values and all 0s.

# 资料

流水线的冒险

https://www.cnblogs.com/houhaibushihai/p/9736616.html