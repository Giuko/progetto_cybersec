#include "uart.h"

void UART_init( void ){
    UART0_BAUDDIV = 16;
    UART0_CTRL = 1;
}

void UART_printf(const char *s) {
    while(*s != '\0') {
        UART0_DATA = (unsigned int)(*s);
        s++;
    }
}

void UART_putc(const char c){
	while(UART0_FLAGREG & (1<<5)){
		//wait
	}
	UART0_DATA = c;
}
