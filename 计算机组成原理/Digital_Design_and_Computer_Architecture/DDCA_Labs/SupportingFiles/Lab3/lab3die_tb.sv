// lab3die_tb.sv
// David_Harris@hmc.edu 15 September 2010
//
// This test bench plays the E85 Lab 3 adventure game
// and dies a hideous death in the Dragon's Den for want
// of a vorpal sword.

module testbench();
  
  logic clk, n, s, e, w, reset;
  logic win, d, s6, s5, s4, s3, s2, s1, s0;
  
  // rename lab3_dh to the name of your top level module
  // if you used different signal names, it will not work
  lab3_dh adventuregame(.clk, .reset, .n, .s, .e, .w, 
                        .win, .d, .s6, .s5, .s4, .s3, .s2, .s1, .s0);

  // generate clock with 100 ns period
  initial
    forever begin
      clk = 0; #50; clk = 1; #50;
    end  
    
  // apply inputs
  initial begin 
    #10; // wait a bit so transitions don't occur on the clock edge
  
    // cycle 0: reset to Cave of Cacophony
    reset = 1;
    n = 0; s = 0; e = 0; w = 0;
    #100;
  
    // cycle 1: east to Twisty Tunnel
    reset = 0;
    e = 1;
    #100;
  
    // cycle 2: south to Rapid River
    e = 0;
    s = 1;
    #100;
  
    // cycle 3: east to Dragon's Den
    s = 0;
    e = 1;
    #100;
  
    // cycle 4: eaten by dragon
    s = 0;
    #100;
  end
    
    
endmodule
  
