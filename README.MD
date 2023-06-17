# Falcon Signature API

This repo is used to generate falcon signatures test data.  
The `falcon_api_test.cpp` file is the entry point.

## Installation
- install [boost](https://www.boost.org)

## compilation
  - `cd build`
  - `cmake -S ..`
  - `make`

## execution
 - `./genfalcon --help` to see instructions, we use [program_options in boost](https://www.boost.org/doc/libs/1_81_0/doc/html/program_options/tutorial.html)
 - `--t` for test enabled, `--n=5` means generate 5 signatures
