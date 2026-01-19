#include <stdint.h>

volatile uint64_t watched_u64 = 0;

static int inner_function(int x) {
    return x + 1;
}

int main(void) {
    int acc = 0;
    for (int i = 0; i < 3; i++) {
        watched_u64 += (uint64_t)i;
        acc = inner_function(acc + i);
    }
    return 0;
}
