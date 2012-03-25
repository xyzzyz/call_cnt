#include "test.h"
#include "intercept.h"
#include <stdio.h>

void testLol() {
  printf("lol\n");
}

void testIntercept() {
  testFun1();
  testFun1();
  testFun1();
  testFun1();
  testLol();
  testFun2(2, 5);
  testFun2(2, 6);
  testFun2(2, 9);
}
