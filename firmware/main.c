#include "uart.h"
#include "tpm.h"

#include <string.h>
#include <stdio.h>

int main(void){
    int i = 5;
    UART_init();
    volatile uint8_t access = TPM_ACCESS;
    volatile uint32_t sts = TPM_STS;
    return 0;
}
