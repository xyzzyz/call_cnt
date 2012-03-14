#include "test.h"
#include "intercept.h"

void testIntercept() {
  testFun1();
  testFun1();
  testFun1();
  testFun1();
  testFun2(2, 5);
  testFun2(2, 6);
  testFun2(2, 9);
}
