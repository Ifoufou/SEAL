# Homomorphic Evaluation of AES using SEAL - FHE Project 2021

This repository is a fork of Microsoft SEAL, an Homomorphic Encryption Library.
It is used as a part of our project and it will contain our exercises and manipulations using this lib.

If you want to know more on Microsoft SEAL, please follow this link: https://github.com/microsoft/SEAL

# Build

In order to build the library with its extra components, you will need 3 softwares:
- git
- a C++ Compiler like gcc, clang...
- CMake

Once you're good with that, clone the repository using for example:
```git clone git@github.com:Ifoufou/SEAL.git```
Then, create a "build" repository in the main SEAL folder
```
cd SEAL
mkdir build
cd build
```
As always with CMake, let's generate the build files for the first time:
```cmake ..```
You can notice that this command print all the available options for the build: 
```
...
-- SEAL_BUILD_SEAL_C: OFF
-- SEAL_BUILD_EXAMPLES: OFF
-- SEAL_BUILD_KEYSWITCHING: OFF
-- SEAL_BUILD_TESTS: OFF
-- SEAL_BUILD_BENCH: OFF
...
```
You just have to configure them to the value "ON" if you want to build them !
```
cmake -DSEAL_BUILD_KEYSWITCHING="ON" ..
```
In this example, we build the AES key-switching executable containing a set of tests.
This will generate the Makefile allowing us to generate the project (depending on the generator used).
Finally, you just have to enter:
```
make -j4
```
and let the magic happen ! 

NOTE: you will find the generated executables in the folder SEAL/build/bin.
