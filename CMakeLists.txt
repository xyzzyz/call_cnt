cmake_minimum_required (VERSION 2.6)
project (call_cnt)
set(CMAKE_BUILD_TYPE Debug)

add_library(call_cnt SHARED call_cnt.c)
target_link_libraries(call_cnt m)

add_library(test SHARED test.c)

add_library(intercept SHARED intercept.c)

add_executable(testInterceptor testInterceptor.c)
target_link_libraries(testInterceptor intercept call_cnt test)

set(CMAKE_C_FLAGS_DEBUG "-g -DDEBUG -std=gnu99 -O0 -Wall -Wextra")
set(CMAKE_C_FLAGS_RELEASE "-std=gnu99 -O0 -Wall -Wextra")
