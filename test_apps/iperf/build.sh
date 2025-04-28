#!/bin/sh

./configure
make CFLAGS="-DSOMIGRATION -DSMCP" LDFLAGS="-lmemstat -lkvm"
