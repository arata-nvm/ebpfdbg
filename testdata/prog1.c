#include <stdio.h>

int fib(int n) {
  if (n <= 1) {
    return n;
  } else {
    return fib(n - 1) + fib(n - 2);
  }
}

int add(int a, int b) {
  return a + b;
}

int sub(int a, int b) {
  return a - b;
}

int main() {
  printf("3 + 4 = %d\n", add(3, 4));
  printf("10 + 20 = %d\n", add(10, 20));
  printf("10 - 4 = %d\n", sub(10, 4));
  printf("fib(3) = %d\n", fib(3));
  return 0;
}
