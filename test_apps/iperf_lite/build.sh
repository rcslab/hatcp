#!/bin/sh
rm ./src/Makefile.in
./bootstrap.sh
./configure --disable-shared 
make 
