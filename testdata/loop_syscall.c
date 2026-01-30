#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
    uint64_t n = 10000ULL;

    for (uint64_t i = 0; i < n; i++) {
        volatile long v = getpid();
    }

    printf("iterations=%llu\n", (unsigned long long)n);

    return 0;
}
