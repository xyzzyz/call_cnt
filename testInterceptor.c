#include <stdio.h>
#include "intercept.h"
#include "call_cnt.h"

int
main(int argc, char **argv) {
  intercept(NULL, "libintercept.so.1");
  testIntercept();
  return 0;
}
