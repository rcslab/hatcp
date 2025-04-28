#!/bin/sh
rm -rf build
mv CMakeLists.nosomig.txt CMakeLists.txt
cmake -B ./build/
cd build
make
