#include <stdint.h>
#include <stdio.h>

int64_t add(uint64_t a, uint64_t b) {
    return a + b;
}

int main(void) {
    uint64_t n = 10000ULL;

    volatile uint64_t acc = 0;
    for (uint64_t i = 0; i < n; i++) {
        acc = add(acc, i);
    }

    printf("iterations=%llu acc=%llu\n",
           (unsigned long long)n,
           (unsigned long long)acc);

    return 0;
}
