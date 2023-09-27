#!/bin/bash -e
POWERS_OF_TAU=17 # circuit will support max 2^POWERS_OF_TAU constraints
mkdir -p artifacts/circuits
if [ ! -f artifacts/circuits/ptau$POWERS_OF_TAU ]; then
  echo "Downloading powers of tau file"
  curl -L https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_$POWERS_OF_TAU.ptau --create-dirs -o artifacts/circuits/ptau$POWERS_OF_TAU
fi
circom circuits/poi-transaction-$1x$1.circom --r1cs --wasm --c --json --sym --wat -o artifacts/circuits
npx snarkjs groth16 setup artifacts/circuits/poi-transaction-$1x$1.r1cs artifacts/circuits/ptau$POWERS_OF_TAU artifacts/circuits/tmp_poi-transaction-$1x$1.zkey
echo "qwe" | npx snarkjs zkey contribute artifacts/circuits/tmp_poi-transaction-$1x$1.zkey artifacts/circuits/poi-transaction-$1x$1.zkey
npx snarkjs info -r artifacts/circuits/poi-transaction-$1x$1.r1cs
npx snarkjs zkey export verificationkey artifacts/circuits/poi-transaction-$1x$1.zkey artifacts/circuits/vkey-$1x$1.json
mv artifacts/circuits/poi-transaction-$1x$1_js/poi-transaction-$1x$1.wasm artifacts/circuits/poi-transaction-$1x$1.wasm