//------------------------------------------------
// topmulti.sv
// David_Harris@hmc.edu 9 November 2005
// Update to SystemVerilog 17 Nov 2010 DMH
// Top level system including multicycle MIPS 
// and unified memory
//------------------------------------------------

module top(input  logic        clk, reset, 
           output logic [31:0] writedata, adr, 
           output logic        memwrite);

  logic [31:0] readdata;
  
  // microprocessor (control & datapath)
  mips mips(clk, reset, adr, writedata, memwrite, readdata);

  // memory 
  mem mem(clk, memwrite, adr, writedata, readdata);

endmodule
