#!/bin/bash
set -e

cd jbd3
make clean
cd ..
make clean
cd jbd3
make
cp Module.symvers ../
cd ..
make

