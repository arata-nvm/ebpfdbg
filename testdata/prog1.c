#include <stdio.h>

int add(int a, int b) {
  return a + b;
}

int main() {
  printf("3 + 4 = %d\n", add(3, 4));
  printf("10 + 20 = %d\n", add(10, 20));
  return 0;
}
