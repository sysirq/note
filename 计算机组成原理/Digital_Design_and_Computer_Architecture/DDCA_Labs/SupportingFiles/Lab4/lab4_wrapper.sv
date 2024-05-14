// lab4_wrappers.sv
// David_Harris@hmc.edu 16 September 2010
// rename signals to match LEDs and switches on DE2 board

module lab4_wrapper(input  logic [2:0] SW,
                    input  logic [0:0]   KEY,
                    output logic [2:0] LEDR,
                    output logic [7:5] LEDG);
          
  // Use Key0 for clk
  // switches for inputs
  // red and green LEDs for output
          
  lab4_dh lab4_dh(.clk(KEY[0]), .reset(SW[0]), .left(SW[2]), .right(SW[1]),
                  .la(LEDR[0]), .lb(LEDR[1]), .lc(LEDR[2]), 
                  .ra(LEDG[7]), .rb(LEDG[6]), .rc(LEDG[5]));
endmodule