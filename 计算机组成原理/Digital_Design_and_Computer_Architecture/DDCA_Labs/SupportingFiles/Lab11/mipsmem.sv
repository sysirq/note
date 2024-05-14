//------------------------------------------------
// mipsmem.sv
// Sarah_Harris@hmc.edu 27 May 2007
// Update to SystemVerilog 17 Nov 2010 DMH
// External unified memory used by MIPS multicycle
// processor.
//------------------------------------------------

module mem(input  logic        clk, we,
           input  logic [31:0] a, wd,
           output logic [31:0] rd);

  logic  [31:0] RAM[63:0];

  // initialize memory with instructions
  initial
    begin
      $readmemh("memfile.dat",RAM);  // "memfile.dat" contains your instructions in hex
                                     // you must create this file
    end

  assign rd = RAM[a[31:2]]; // word aligned

  always_ff @(posedge clk)
    if (we)
      RAM[a[31:2]] <= wd;
endmodule
