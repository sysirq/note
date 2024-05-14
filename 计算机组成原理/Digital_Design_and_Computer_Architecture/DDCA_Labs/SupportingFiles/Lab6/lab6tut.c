/* lab6tut.c

	David_Harris@hmc.edu
	21 October 2010
	
	Demonstrate switches, LEDs, console I/O
*/


 

int main(void)
{
	int sw;
	int num;

	initIO();
	while(1) {
		sw = readSwitches(); // read 4-bit value from switches
		printf("Read %d from the switches\n", sw);
		printf("Please enter a number from 0-15: ");
		scanf("%d", &num);
		writeLEDs(sw | (num << 4)); // display 8 bits on LEDs
		delay(3000); // pause 3 seconds
	}
}

