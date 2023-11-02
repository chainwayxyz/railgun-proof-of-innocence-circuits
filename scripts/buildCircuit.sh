#!/bin/bash -e
POWERS_OF_TAU=17 # circuit will support max 2^POWERS_OF_TAU constraints

# Check circom version
CIRCOM_VERSION=$(circom --version)
if [[ ! $CIRCOM_VERSION =~ "2.0.6" ]]; then
  echo "Error: circom version is not 2.0.6 or not installed"
  exit 1
fi

# Check brotli version
BROTLI_VERSION=$(brotli --version)
if [[ ! $BROTLI_VERSION =~ "1.0.9" ]]; then
  echo "Error: brotli version is not 1.0.9 or not installed"
  exit 1
fi

# Create folder for artifacts
mkdir -p artifacts/circuits

if [ ! -f "artifacts/circuits/ptau$POWERS_OF_TAU" ]; then
  echo "Downloading powers of tau file"
  curl -L https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_$POWERS_OF_TAU.ptau --create-dirs -o artifacts/circuits/ptau$POWERS_OF_TAU
fi

# Compile circuit
circom circuits/poi-transaction-$1x$1.circom --r1cs --wasm --c --json --sym --wat -o artifacts/circuits

# Setup SNARK
npx snarkjs groth16 setup artifacts/circuits/poi-transaction-$1x$1.r1cs artifacts/circuits/ptau$POWERS_OF_TAU artifacts/circuits/tmp_poi-transaction-$1x$1.zkey

# Contribute to zkey
echo "qwe" | npx snarkjs zkey contribute artifacts/circuits/tmp_poi-transaction-$1x$1.zkey artifacts/circuits/poi-transaction-$1x$1.zkey

# Get circuit info
npx snarkjs info -r artifacts/circuits/poi-transaction-$1x$1.r1cs

# Export verification key
npx snarkjs zkey export verificationkey artifacts/circuits/poi-transaction-$1x$1.zkey artifacts/circuits/vkey-$1x$1.json
# Create folder for final files
mkdir -p artifacts/circuits/POI_$1x$1

# Move and compress final files
brotli artifacts/circuits/poi-transaction-$1x$1.zkey
mv artifacts/circuits/poi-transaction-$1x$1.zkey.br artifacts/circuits/POI_$1x$1/zkey.br
brotli artifacts/circuits/poi-transaction-$1x$1_js/poi-transaction-$1x$1.wasm
mv artifacts/circuits/poi-transaction-$1x$1_js/poi-transaction-$1x$1.wasm.br artifacts/circuits/POI_$1x$1/wasm.br
brotli artifacts/circuits/poi-transaction-$1x$1_cpp/poi-transaction-$1x$1.dat
mv artifacts/circuits/poi-transaction-$1x$1_cpp/poi-transaction-$1x$1.dat.br artifacts/circuits/POI_$1x$1/dat.br
mv artifacts/circuits/vkey-$1x$1.json artifacts/circuits/POI_$1x$1/vkey.json
