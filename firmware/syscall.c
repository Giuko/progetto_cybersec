#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

extern char _end; // provided by your linker script
static char *heap_end = 0;

void *_sbrk(ptrdiff_t incr) {
    if (heap_end == 0) heap_end = &_end;
    char *prev = heap_end;
    heap_end += incr;
    return (void *)prev;
}

int _write(int file, const void *ptr, size_t len) {
    // send to UART if available, or just discard
    return len;
}

int _read(int file, void *ptr, size_t len) {
    errno = ENOSYS;
    return -1;
}

int _close(int file) {
    errno = ENOSYS;
    return -1;
}

int _fstat(int file, struct stat *st) {
    st->st_mode = S_IFCHR;
    return 0;
}

int _lseek(int file, int ptr, int dir) {
    return 0;
}

int _isatty(int file) {
    return 1;
}

void _exit(int status) {
    while (1); // hang forever
}

