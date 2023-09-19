pragma circom 2.0.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/switcher.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "./merkle-proof-verifier.circom";
include "./nullifier-check.circom";

template Shield() {

    signal input commitment;
    signal output outBlindedCommitment;

    signal input token;
    signal input publicKey[2]; // Public key for signature verification denoted to as PK
    signal input nullifyingKey;
    signal input randomIn;
    signal input valueIn;
    signal input outCommitmentLeafIndex;


    // 4. Compute master public key
    component mpk = Poseidon(3);
    mpk.inputs[0] <== publicKey[0];
    mpk.inputs[1] <== publicKey[1];
    mpk.inputs[2] <== nullifyingKey;

    // 5. Verify Merkle proofs of membership
    component noteCommitment;
    component npk;

    npk = Poseidon(2);
    npk.inputs[0] <== mpk.out;
    npk.inputs[1] <== randomIn;
        // Compute note commitment
    noteCommitment = Poseidon(3);
    noteCommitment.inputs[0] <== npk.out;
    noteCommitment.inputs[1] <== token;
    noteCommitment.inputs[2] <== valueIn;
    commitment === noteCommitment.out;

    component outBlindedCommitmentHasher = Poseidon(3);
    outBlindedCommitmentHasher.inputs[0] <== commitment;
    outBlindedCommitmentHasher.inputs[1] <== randomIn;
    outBlindedCommitmentHasher.inputs[2] <== outCommitmentLeafIndex;
    outBlindedCommitment <== outBlindedCommitmentHasher.out;

}

component main{public [commitment]} = Shield();