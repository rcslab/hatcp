#!/bin/sh
rm -rf build
mv CMakeLists.nosmcp.txt CMakeLists.txt
cmake -B ./build/
cd build
make
