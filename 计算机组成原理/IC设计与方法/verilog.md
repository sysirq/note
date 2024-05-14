assign关键字表示连接

wire 用于定义线

# Data Types

wire - represent structural connections between components

registers - represent variables used to store data

# Numbers in Verilog

Syntex: <size>'<radix><value>

eg:2'b01

# vectors

vectors are used to group related signals using one name to make it more convenient to manipulate.For example , wire [7:0] w; declares an 8-bit vector named w that is functionally equivalent to having 8 separate wires;

vectors must be declared:
```
type [upper:lower] vector_name;
```

type specifies the datatype of the vector.This is usually wire or reg. If you are declaring a input or output port,the type can additionally include the port type as well.Some examples:

```
wire [7:0] w;         // 8-bit wire
reg  [4:1] x;         // 4-bit reg
output reg [0:0] y;   // 1-bit reg that is also an output port (this is still a vector)
input wire [3:-2] z;  // 6-bit wire input (negative ranges are allowed)
output [3:0] a;       // 4-bit output wire. Type is 'wire' unless specified otherwise.
wire [0:7] b;         // 8-bit wire where b[0] is the most-significant bit.
```

The endianness(字节序) (or, informally, "direction") of a vector is whether the the least（最低） significant bit has a lower index (little-endian, e.g., [3:0]) or a higher index (big-endian, e.g., [0:3]). In Verilog, once a vector is declared with a particular endianness, it must always be used the same way. e.g., writing vec[0:3] when vec is declared wire [3:0] vec; is illegal. Being consistent with endianness is good practice, as weird bugs occur if vectors of different endianness are assigned or used together.

You may have noticed that in declarations, the vector indices are written before the vector name. This declares the "packed" dimensions of the array, where the bits are "packed" together into a blob (this is relevant in a simulator, but not in hardware). The unpacked dimensions are declared after the name. They are generally used to declare memory arrays. Since ECE253 didn't cover memory arrays, we have not used packed arrays in this course. See http://www.asic-world.com/systemverilog/data_types10.html for more details.

```
reg [7:0] mem [255:0];   // 256 unpacked elements, each of which is a 8-bit packed vector of reg.
reg mem2 [28:0];         // 29 unpacked elements, each of which is a 1-bit reg.
```

Accessing an entire vector is done using the vector name. For example:

assign w = a;

takes the entire 4-bit vector a and assigns it to the entire 8-bit vector w (declarations are taken from above). If the lengths of the right and left sides don't match, it is zero-extended or truncated as appropriate.

The part-select operator can be used to access a portion of a vector:

```
w[3:0]      // Only the lower 4 bits of w
x[1]        // The lowest bit of x
x[1:1]      // ...also the lowest bit of x
z[-1:-2]    // Two lowest bits of z
b[3:0]      // Illegal. Vector part-select must match the direction of the declaration.
b[0:3]      // The *upper* 4 bits of b.
assign w[3:0] = b[0:3];    // Assign upper 4 bits of b to lower 4 bits of w. w[3]=b[0], w[2]=b[1], etc.
```

Part selection was used to select portions of a vector. The concatenation operator {a,b,c} is used to create larger vectors by concatenating smaller portions of a vector together.

Part selection 时，[]中不能有变量，如果有则必须使用 [a+:4]形势，a+ 表示大端，4表示联系得4个字节

```
{3'b111, 3'b000} => 6'b111000
{1'b1, 1'b0, 3'b101} => 5'b10101
{4'ha, 4'd10} => 8'b10101010     // 4'ha and 4'd10 are both 4'b1010 in binary
```

vector的定义：

```verilog
# type [upper:lower] vector_name;

wire [7:8]w;
```

可以选择vector的部分内容：

```verilog
wire [7:8]w;
w2 = w[2:0]; //只需要w的最低3位
```

可以通过vector concatenation operator连接vector（大小必须已知）构造更大的vector

```verilog
wire [4:0] w1,w2,w3;
wire [7:0] w4;
w3 = {2'b10,2'b11}; //构造 w3 = 1011 vector
w4 = {w1,w2};
```

可以通过replication operator构建重复的vector

```verilog
//{num{vector}};
w = {num{4'b1011}};
```

向量部分选择:

```verilog
module top_module( 
    input [1023:0] in,
    input [7:0] sel,
    output [3:0] out );
	assign out = in[sel * 4 +: 4];
endmodule
```

如果sel等于0，in[sel * 4 +: 4]代表从0开始向上数4位，即in[3:0]

# module

模块定义:

```verilog
module module_name(input w1,output w2);
    module1 mudule11(.w1(w1)); #使用模块
endmodule
```

# Procedural Blocks

There are two types of procedural blocks in verilog:

- initial:execute only once at time zero
- always:execute over and over again

### Procedural Assignment Groups

If a procedure block contains more than one statement, those statements must be enclosed within:

- Sequential begin - end block
- Parallel fork - join block

# Always blocks

For synthesizing hardware,two types of always blocks are relevant:

- Combinational: always @(*)
- Clocked:always @(posedge clk)

Combinational always blocks are equivalent to assign statements, thus there is always a way to express a combinational circuit both ways. 

The left-hand-side of an assign statement must be a net type (e.g., wire), while the left-hand-side of a procedural assignment (in an always block) must be a variable type (e.g., reg). 

# Blocking vs. Non-Blocking Assignment

There are three types of assignments in Verilog:

- Continuous assignments (assign x = y;). Can only be used when not inside a procedure ("always block").
- Procedural blocking assignment: (x = y;). Can only be used inside a procedure.
- Procedural non-blocking assignment: (x <= y;). Can only be used inside a procedure.

In a combinational always block, use blocking assignments. In a clocked always block, use non-blocking assignments

在always语句中，阻塞赋值等号左端的参数如果参与该模块的其他运算，则按照赋值后的结果参与运算，而非阻塞赋值等号左端的参数依旧按照未赋值前的结果参与运算。

# if

An if statement usually creates a 2-to-1 multiplexer,selecting one input if the condition is true,and the other input if the condition is false.

```
wire w1;
if(w1)
    xxxxx;
else
    xxxxx;
```

However, the procedural if statement provides a new way to make mistakes. The circuit is combinational only if out is always assigned a value.

# case 

Case statements in Verilog are nearly equivalent to a sequence of if-elseif-else that compares one expression to a list of others.

```
case(xxx)
4'b00:xxxxx;
4'b01:xxxxx;
endcase
```

# casez 
```
always @(*) begin
    casez (in[3:0])
        4'bzzz1: out = 0;   // in[3:1] can be anything
        4'bzz1z: out = 1;
        4'bz1zz: out = 2;
        4'b1zzz: out = 3;
        default: out = 0;
    endcase
end
```
可以用z来表示某一位可以被忽略。

Notice how there are certain inputs (e.g., 4'b1111) that will match more than one case item. The first match is chosen (so 4'b1111 matches the first item, out = 0, but not any of the later ones).

# reduction

可以对vector中的所有位执行 AND OR XOR，并产生1位输出。

The reduction operators can do AND, OR, and XOR of the bits of a vector, producing one bit of output:

```
& a[3:0]     // AND: a[3]&a[2]&a[1]&a[0]. Equivalent to (a[3:0] == 4'hf)
| b[3:0]     // OR:  b[3]|b[2]|b[1]|b[0]. Equivalent to (b[3:0] != 4'h0)
^ c[2:0]     // XOR: c[2]^c[1]^c[0]
```

These are unary operators that have only one operand (similar to the NOT operators ! and ~). You can also invert the outputs of these to create NAND, NOR, and XNOR gates, e.g., (~& d[7:0]).

# for

在verilog中使用for语句，往往是为了减少并行代码段的重复长度：

```
out[0]  <=  y[0]   ^ x[0] ;

out[1]  <=  y[2]   ^ x[1] ;

out[2]  <=  y[4]   ^ x[2] ;

......

out[31] <= y[62] ^ x[31] ;

always @ (posedge clk)

for ( i=0; i<32; i=i+1 ) out[i] = y[i*2] ^ x[i] ;
```

# generate

自动生成多个模块实例的电路

```
generate
begin
    genvar i;
    for(i = 0; i<10;i++)begin:adder
        add aaa(xxxx);
    end
end
endgenerate
```

会生成10个add模块的实例

# Latches and Flip-Flops

D flip-flops are created by the logic synthesizer when a clocked always block is used .

# task and Function

eg:

```verilog
module simple_task();
    task convert;
        input [7:0] temp_in;
        output [7:0] temp_out;
        begin
          temp_out = (9/5) *( temp_in + 32)
        end
    endtask
endmodule
```


# System Task and Function

There are tasks and functions that are used to generate input and output during simulation.Their names begin with a dollar sign($).The synthesis tools parse and ignore system functions,and hence can be included event in synthesizable moodels.

### $display,$monitor

$monitor displays every time one of its parameters changes,$display display once every time they are executed.

- $display ("format_string", par_1, par_2, ... );
- $monitor ("format_string", par_1, par_2, ... );

### $time

These return the current simulation time as a 64-bit integer

### $fopen,$fwrite

# 资料

HDLBits: 在线学习 Verilog 

https://zhuanlan.zhihu.com/p/56646479

https://hdlbits.01xz.net/wiki/Wire4

什么是有限状态机？

https://www.pythonf.cn/read/78479