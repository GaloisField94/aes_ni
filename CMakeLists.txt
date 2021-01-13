cmake_minimum_required(VERSION 3.8)
project(aes_ni)

add_executable(aes_ni_fips197_test src/aes_ni_main.c src/aes_ni.c)
target_compile_options(aes_ni_fips197_test PUBLIC -msse2 -msse -maes -march=native)
target_include_directories(aes_ni_fips197_test PUBLIC inc)

