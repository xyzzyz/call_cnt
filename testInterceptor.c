#include <stdio.h>
#include "intercept.h"
#include "call_cnt.h"

int
main(int argc, char __attribute__((unused)) **argv) {
  struct call_cnt *c;
  if(argc == 1) {
    intercept(&c, "libintercept.so");
    testIntercept();
    stop_intercepting(c);
    release_stats(c);
  } else {
    testIntercept();
  }
  return 0;
}

