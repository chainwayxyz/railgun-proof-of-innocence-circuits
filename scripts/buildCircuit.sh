#!/bin/bash -e
POWERS_OF_TAU=17 # circuit will support max 2^POWERS_OF_TAU constraints
mkdir -p artifacts/circuits
if [ ! -f artifacts/circuits/ptau$POWERS_OF_TAU ]; then
  echo "Downloading powers of tau file"
  curl -L https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_$POWERS_OF_TAU.ptau --create-dirs -o artifacts/circuits/ptau$POWERS_OF_TAU
fi
circom circuits/proof-of-innocence.circom --r1cs --wasm -o artifacts/circuits
npx snarkjs groth16 setup artifacts/circuits/proof-of-innocence.r1cs artifacts/circuits/ptau$POWERS_OF_TAU artifacts/circuits/tmp_proof-of-innocence.zkey
echo "qwe" | npx snarkjs zkey contribute artifacts/circuits/tmp_proof-of-innocence.zkey artifacts/circuits/proof-of-innocence.zkey
# npx snarkjs zkey export solidityverifier artifacts/circuits/proof-of-innocence.zkey artifacts/circuits/Verifier.sol
# sed -i.bak "s/contract Verifier/contract Verifier${1}/g" artifacts/circuits/Verifier$1.sol
#zkutil setup -c artifacts/circuits/proof-of-innocence$1.r1cs -p artifacts/circuits/proof-of-innocence$1.params
#zkutil generate-verifier -p artifacts/circuits/proof-of-innocence$1.params -v artifacts/circuits/Verifier.sol
npx snarkjs info -r artifacts/circuits/proof-of-innocence.r1cs
mv artifacts/circuits/proof-of-innocence_js/proof-of-innocence.wasm artifacts/circuits/proof-of-innocence.wasm