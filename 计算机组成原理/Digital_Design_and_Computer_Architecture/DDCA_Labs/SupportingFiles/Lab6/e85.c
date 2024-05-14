/* e85.c
	David_Harris@hmc.edu 21 October 2010 

	Commonly used functions for E85:
		Set configuration bits to handle muMudd32 board
		Access LEDs and switches over PORT D
*/

// PIC libraries
#include <p32xxxx.h>
#include <plib.h>
#include <sys/appio.h>

// confguration bits
#pragma config FNOSC = PRI			// use primary clock
#pragma config POSCMOD = EC			// primary clock runs off external osc (40 MHz)
#pragma config FPBDIV = DIV_2		// peripherals operate at half freq (20 MHz)
#pragma config ICESEL = ICS_PGx1	// ICD communicates over PG1 pin

// prototypes
void initIO(void);
void writeLEDs(int);
int readSwitches(void);
void delay(int);
void writeE0(int);

// E85 I/O library functions

void initIO(void) {
	// digital ports
	TRISD = 0xFFFFFF00; // Set D7:0 to output to drive LEDs
                        //     D11:8 to input to read switches
	TRISE = 0xFFFFFFFE;	// Set E0 to output
	
	// analog port
	TRISB = 0xFFFFFFFF; // Set port B to input (for analog in)
	AD1PCFG = 0x0000;	// all pins analog
	AD1CON1 = 0x00E0;	// A/D converter setup to autoconvert
	AD1CON2 = 0x0000;	// A/D reference voltage (0 and 3.3V)
	AD1CON3 = 0x0F02;	// A/D converter clock
	AD1CHS  = 11 << 16; // A/D samples input in AN11 (RB11)
	AD1CSSL = 0x0000; 	// no input scanning
	AD1CON1bits.ADON = 1; // turn on A/D converter

	// console I/O
	DBINIT(); 			// initialize console I/O
}

void writeLEDs(int val) {
	LATD = val & 0x00FF; // LEDs driven by D7:0; mask these out
}

int readSwitches(void) {
	return (PORTD >> 8) & 0x000F; // switches connect to D11:8
}

void delay(int ms) {
	int time = ms * 625;	// 625 timer ticks per milisecond

	T2CONbits.ON = 0;		// turn timer off
	T2CONbits.T32 = 1;		// configure timers 2-3 as a 32-bit counter
	TMR2 = 0;				// reset timer to 0
	TMR3 = 0;
	T2CONbits.TCKPS = 5;	// prescale by 32 to clock counter at 20 MHz / 32 = 625 KHz
	T2CONbits.ON = 1;		// turn timer on
	

	while ((TMR2 | (TMR3 << 16)) < time); //wait until time has elapsed
}

void writeE0(int val)
{
	LATE = val & 0x0001; // mask off bottom bit
	if (val != 0 && val != 1) {
		printf("Illegal value %d written to E0; only 0 or 1 allowed\n");
	}
}

int analogReadB11(void)
{
	IFS1bits.AD1IF = 0;			// clear A/D interrupt flag
	AD1CON1bits.ASAM = 1;		// start conversion
	while (!IFS1bits.AD1IF);	// wait for conversion to complete 
	AD1CON1bits.ASAM = 0;		// stop conversion
	return ADC1BUF0;
}
