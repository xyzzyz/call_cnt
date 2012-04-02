#include <stdio.h>
#include "intercept.h"
#include "call_cnt.h"


int
main(int argc, char __attribute__((unused)) **argv) {
  struct call_cnt *c;
  if(argc == 1) {
    if(-1 == intercept(&c, "libintercept.so")) return -1;
    testIntercept();
    stop_intercepting(c);
    print_stats_to_stream(stdout, c);
    printf("internal: %zd, external: %zd\n",
           get_num_intern_calls(c),
           get_num_extern_calls(c));
    release_stats(c);
  } else {
    testIntercept();
  }
  return 0;
}

