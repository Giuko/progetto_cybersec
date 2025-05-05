#include "uart.h"
int main(void){
    int i = 5;
    UART_init();
    UART_printf("Hello board\n");
    return 0;
}
