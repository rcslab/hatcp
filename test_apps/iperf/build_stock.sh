#!/bin/sh

./configure
make LDFLAGS=-lmemstat
