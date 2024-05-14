# Lab 8: Floating Point Addition
# Your name / date here

# The numbers below are loaded into memory (the Data Segment)
# before your program runs.  You can use a lw instruction to
# load these numbers into a register for use by your code.

        .data
atest1: .word 0x3F800000 # 1.0
btest1: .word 0x3F800000 # 1.0
                         # add more test vectors here
atest2: .word  # 2.0
btest2: .word  # 1.0
atest3: .word  # 2.0
btest3: .word  # 3.5
atest4: .word  # 0.50390625
btest4: .word  # 65535.6875

fmask:  .word 0x007FFFFF # mask for masking the fraction bits
emask:  .word 0x7F800000 # mask for masking the exponent
ibit:   .word 0x00800000 # mask for the implicit leading one
obit:   .word 0x01000000 # mask for the overflow bit
        .text

.global main			# define main as a global label
.set noreorder			# don't let the assembler reorder instructions
    
# Test the floating point add

main:	
		lw $a0, atest1	# first operand
		lw $a1, btest1	# second operand
		jal flpadd		# do the addition, look for result in $v0
		nop				# branch delay slot

						# insert more tests here
		lw $a0, atest2	# first operand
		lw $a1, btest2	# second operand
		jal flpadd		# do the addition, look for result in $v0
		nop				# branch delay slot
		lw $a0, atest3	# first operand
		lw $a1, btest3	# second operand
		jal flpadd		# do the addition, look for result in $v0
		nop				# branch delay slot
		lw $a0, atest4	# first operand
		lw $a1, btest4	# second operand
		jal flpadd		# do the addition, look for result in $v0
		nop				# branch delay slot

infiniteloop:
		j infiniteloop	# wait forever
		nop				# branch delay slot
		
# Here is the procedure that performs floating point addition of
# single-precision numbers.  IT SHOULD NOT USE ANY OF THE MIPS
# BUILT-IN FLOATING POINT INSTRUCTIONS.  Also, don't use any of
# the registers $s0-$s7, or any floating point registers (because
# these registers are used by the main program). Finally, don't
# forget to add comments to each line of code that you write.
#
# Remember the single precision format:
#          bit 31 = sign (1 bit)
#      bits 30-23 = exponent (8 bits)
#       bits 22-0 = fraction (23 bits)
#

# Describe your register usage here

# YOUR CODE GOES BELOW

