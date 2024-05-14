In contrast,Verilog continuous assignment statements are reevaluated anytime any of the inputs on the right hand side changes.Therefore,such code necessarily describes combinational logic.

always statements can be used to imply flip-flops,latch,or combinational logic,depending on the sensitivity list and statement.Because of this flexibility,it is easy to produce the wrong hardware inadvertently,SystemVerilog introduces always_ff,always_latch and always_comb to reduce the risk of common errors.always_ff behaves like always but is used exclusively to imply flip-flops and allows tools to produce a warning if anything else is implied.

Unless you know that your tool does support latches and you have a good reason to ues them,avoid them and use edge-triggered flip-flops instead.

A case statement implies combinational logic if all possible input combinations are defined;otherwise it implies sequential logic,because the output will keep its old value in the undefined cases.

# Blocking and nonblocking assignment guidelines

- 1.Use always_ff and nonblocking assignments to model synchronous sequential logic.
- 2.Use continuous assignments to model simple combinational logic
- 3.Use always_comb and blocking assignments to model more complicated combinational logic where the always statement is helpful.
- 4.Do not make assignments to the same signal in more than one always statement or continuous assignment statement.

# Finite State Machines

Recall that a finite state machine consists of a state register and two blocks of combinational logic to computer the next state and the output given the current state and the input.HDL descriptions of state machines are correspondingly divided into three parts to model the state reigster,the next state logic,and the output logic.

# SystemVerilog

In Verilog,if a signal appears on the left hand side of <= or = in an always block,it must be declared as reg.Hence,a reg signal might be the output of a flip-flop,a latch,or combinational logic,depending on the sensitivity list and statement of an always block.

# Testbench

a testbench is an HDL module that is used to test another module,called the device under test.The testbench contains statements to apply inputs to the DUT and ,ideally,to check that the correct outputs are produced.The input and desired output patterns are called test vectors.

![image](images/ADED241F867B4A31B6AF41F3E207D5FC1600420054(1).png)

![image](images/567EF4C08A9341D49CF85608E141DED61600420495(1).png)

![image](images/6A33B19D61A64A57BC063A17C92F86DA1600420994(1).png)

![image](images/82A93691E05749F1BB2B80F36A94C3A81600421010(1).png)

initial语句 在仿真开始时执行

always 语句 在仿真过程中是不断重复执行的

# Summary

The most important thing to remember when you are writing HDL code is that you are describing real hardware,not writing a computer program.The most common beginner's mistake is to write HDL code without thinking about the hardware you intend to produce.If you don't know what hardware you are implying,you are almost certain not to get what you want.Instead,begin by sketching a block diagram of you system,identifying which portions are combinational logic,which portions are sequential circuits or finite state machines,and so forth.Then wirte HDL code for each portion,using the correct idioms to imply the kind of hardware you need.

# 资料

Verilog语法之十：过程块（initial和always）

https://zhuanlan.zhihu.com/p/72078544