#!/bin/bash

make
rm -rf lily3_10_2 /tmp/wdir

mkdir -p lily3_10_2
./elisabeth buildPolynomialBasisMatrix lily3_10_2

echo "[*] Generate the basis matrices"
./elisabeth buildBasisMatrices lily3_10_2

echo "[*] Generate an instance of the system to solve"
mkdir -p lily3_10_2/instance1
./elisabeth buildInstance lily3_10_2 lily3_10_2/instance1

echo "[*] Generate weight files"
cd lily3_10_2/instance1 && mf_scan2 /app/lily3_10_2/instance1/tA.bin

echo "[*] Generate balancing data"
mf_bal                                          \
	2x2                                           \
	mfile=/app/lily3_10_2/instance1/tA.bin        \
	reorder=columns                               \
	rwfile=/app/lily3_10_2/instance1/tA.rw.bin    \
	cwfile=/app/lily3_10_2/instance1/tA.cw.bin

echo "[*] Performing Block Wiedemann"
mkdir -p /tmp/wdir
bwc.pl :complete                            \
  wdir=/tmp/wdir                            \
  mn=64                                     \
  nullspace=left                            \
  matrix=/app/lily3_10_2/instance1/tA.bin   \
  thr=2x2                                   \
  balancing=$(find /app/lily3_10_2/instance1/ -name 'tA.2x2.*.bin')

echo "[*] Print the solution from the working directory"
cp /tmp/wdir/W .
cd ../..
./elisabeth printSolution lily3_10_2/instance1