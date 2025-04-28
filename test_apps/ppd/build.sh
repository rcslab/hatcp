#!/bin/sh
rm -rf build
mv CMakeLists.smcp.txt CMakeLists.txt
cmake -B ./build/
cd build
make
