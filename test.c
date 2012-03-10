#include <stdio.h>
#include "test.h"

void
testFun1(void) {
  printf("Jestem w testFun1\n");
}

int
testFun2(int a, int b) {
  printf("Jestem w testFun2, a = %d, b = %d\n", a, b);
  return a + b;
}
