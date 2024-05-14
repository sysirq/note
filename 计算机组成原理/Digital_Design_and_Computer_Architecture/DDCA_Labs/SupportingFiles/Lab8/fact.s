/* fact.s
   8 November 2010 David_Harris@hmc.edu
   Compute factorial
   Assembly language tutorial based on following C code:

   	void main(void)
	{
		int f;

		f = factorial(4);

		while (1) {} // infinite loop
	}

	int factorial(int n)
	{
		if (n <= 1) return 1;
		else return (n * factorial(n-1));
	}
*/

.global main			# define main as a global label
.set noreorder			# don't let the assembler reorder instructions

main:					# assume f in $s0
	addi $a0, $0, 4		# $a0 = 4
	jal factorial		# call factorial(4)
	nop					# branch delay slot
	add	$s0, $v0, $0	# put return result in $s0
infiniteloop:
	j infiniteloop		# wait forever
	nop					# branch delay slot

factorial:
	addi $t0, $0, 2		
	slt $t0, $a0, $t0	# a <= 1?
	beq $t0, $0, else	# no: go to else
	nop					# branch delay slot
	addi $v0, $0, 1		# yes: return 1
	jr $ra				# and go back to caller
	nop					# branch delay slot
else:
	addi $sp, $sp, -8	# make room on stack for two registers
	sw $a0, 4($sp)		# store $a0
	sw $ra, 0($sp)		# store $ra
	addi $a0, $a0, -1	# argument of n-1
	jal factorial		# call factorial(n-1)
	nop					# branch delay slot
	lw $ra, 0($sp)		# restore $ra
	lw $a0, 4($sp)		# restore $a0
	addi $sp, $sp, 8	# restore stack pointer
	mul $v0, $a0, $v0	# return n * factorial(n-1)
	jr $ra				# and go back to caller
	nop					# branch delay slot
