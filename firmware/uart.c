#include "uart.h"

void UART_init( void ){
    UART0_BAUDDIV = 16;
    UART0_CTRL = 1;
}

void UART_putstr(const char *s) {
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

void UART_println(){
	while(UART0_FLAGREG & (1<<5)){
		//wait
	}
	UART0_DATA = '\n';
}

void UART_puthex(uint32_t value){

    const char hex_digits[] = "0123456789ABCDEF";

    for(int i = 7; i >= 0; i--){
        uint8_t trad = (value >> (i*4)) & 0xF;
        UART_putc(hex_digits[trad]);
    }
}

void UART_puthex_byte(uint8_t value){

    const char hex_digits[] = "0123456789ABCDEF";

    for(int i = 1; i >= 0; i--){
        uint8_t trad = (value >> (i*4)) & 0xF;
        UART_putc(hex_digits[trad]);
    }
}

void UART_puthex_2byte(uint16_t value){

    const char hex_digits[] = "0123456789ABCDEF";

    for(int i = 3; i >= 0; i--){
        uint8_t trad = (value >> (i*4)) & 0xF;
        UART_putc(hex_digits[trad]);
    }
}

void UART_putdigit(uint8_t digit){
    UART_putc(digit+48);
}
