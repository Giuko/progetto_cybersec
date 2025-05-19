#include "uart.h"
#include "tpm.h"

#include <string.h>
#include <stdio.h>

int main(void){
	UART_init();
    volatile uint8_t access = TPM_ACCESS;
	UART_putc(access+48);
    volatile uint32_t sts = TPM_STS;
	UART_putc(sts+48);
    //TPM_ACCESS = 5; 
    return 0;
}
