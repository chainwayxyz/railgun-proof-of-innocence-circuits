#!/bin/bash -e

./buildCircuit.sh;

brotli ../artifacts/circuits/poi-transaction.wasm;
brotli ../artifacts/circuits/poi-transaction.zkey;

./buildCircuitVKey.sh;

