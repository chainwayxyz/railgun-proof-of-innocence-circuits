pragma circom 2.0.6;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/switcher.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "./merkle-proof-verifier.circom";
include "./nullifier-check.circom";

template Step(MerkleTreeDepth, nInputs, nOutputs, maxInputs, maxOutputs, zeroLeaf) {
    signal input anyRailgunTxidMerklerootAfterTransaction;
    signal input railgunTxidIfHasUnshield;
    signal input poiMerkleroots[nInputs];
    signal output blindedCommitmentsOut[nOutputs];
    signal input boundParamsHash; // hash of ciphertext and adapterParameters
    signal input nullifiers[nInputs]; // Nullifiers for input notes
    signal input commitmentsOut[nOutputs]; // hash of output notes
    signal input spendingPublicKey[2]; // Public key for signature verification denoted to as PK
    signal input nullifyingKey;
    signal input token;
    signal input randomsIn[nInputs];
    signal input valuesIn[nInputs];
    signal input utxoPositionsIn[nInputs];
    signal input utxoTreeIn;
    signal input npksOut[nOutputs]; // Recipients' NPK
    signal input valuesOut[nOutputs];
    signal input utxoTreeOut;
    signal input utxoBatchStartPositionOut;
    signal input railgunTxidMerkleProofIndices;
    signal input railgunTxidMerkleProofPathElements[MerkleTreeDepth];
    signal input poiInMerkleProofIndices[nInputs];
    signal input poiInMerkleProofPathElements[nInputs][MerkleTreeDepth];
    component nullifiersHasher = Poseidon(maxInputs);
    for(var i = 0; i < nInputs; i++) { // Constraints: 543 (+0)
        nullifiersHasher.inputs[i] <== nullifiers[i]; // Constraints: 543 (+0)
    }
    for(var i = nInputs; i < maxInputs; i++){ // Constraints: 543 (+0)
        nullifiersHasher.inputs[i] <== zeroLeaf; // Constraints: 513 (+-30)
    }
    component commitmentsHasher = Poseidon(maxOutputs);
    for(var i = 0; i < nOutputs; i++) { // Constraints: 1056 (+543)
        commitmentsHasher.inputs[i] <== commitmentsOut[i]; // Constraints: 1056 (+0)
    }
    for(var i = nOutputs; i < maxOutputs; i++){ // Constraints: 1056 (+0)
        commitmentsHasher.inputs[i] <== zeroLeaf; // Constraints: 1026 (+-30)
    }
    component railgunTxidHasher = Poseidon(3);
    railgunTxidHasher.inputs[0] <== nullifiersHasher.out;
    railgunTxidHasher.inputs[1] <== commitmentsHasher.out;
    railgunTxidHasher.inputs[2] <== boundParamsHash;
    component txidTreeLeafHasher = Poseidon(3);
    txidTreeLeafHasher.inputs[0] <== railgunTxidHasher.out;
    txidTreeLeafHasher.inputs[1] <== utxoTreeIn;
    txidTreeLeafHasher.inputs[2] <== utxoTreeOut * 65536 + utxoBatchStartPositionOut;
    component railgunTxidVerifier = MerkleProofVerifier(MerkleTreeDepth);
    railgunTxidVerifier.merkleRoot <== anyRailgunTxidMerklerootAfterTransaction;
    for(var j = 0; j < MerkleTreeDepth; j++) { // Constraints: 5423 (+4397)
        railgunTxidVerifier.pathElements[j] <== railgunTxidMerkleProofPathElements[j]; // Constraints: 5423 (+0)
    }
    railgunTxidVerifier.leafIndex <== railgunTxidMerkleProofIndices;
    railgunTxidVerifier.leaf <== txidTreeLeafHasher.out;
    railgunTxidVerifier.enabled <== 1;
    component railgunTxidIfHasUnshieldCheck = ForceEqualIfEnabled();
    railgunTxidIfHasUnshieldCheck.in[0] <== railgunTxidIfHasUnshield;
    railgunTxidIfHasUnshieldCheck.in[1] <== railgunTxidHasher.out;
    railgunTxidIfHasUnshieldCheck.enabled <== railgunTxidIfHasUnshield;
    component isDummy[nInputs];
    for(var i=0; i<nInputs; i++) { // Constraints: 5423 (+0)
        isDummy[i] = IsZero(); // Constraints: 5429 (+6)
        isDummy[i].in <== valuesIn[i]; // Constraints: 5429 (+0)
    }
    component nullifiersHash[nInputs];
    for(var i=0; i<nInputs; i++) { // Constraints: 5429 (+0)
        nullifiersHash[i] = NullifierCheck(); // Constraints: 6158 (+729)
        nullifiersHash[i].nullifyingKey <== nullifyingKey; // Constraints: 6158 (+0)
        nullifiersHash[i].leafIndex <== utxoPositionsIn[i]; // Constraints: 6158 (+0)
        nullifiersHash[i].nullifier <== nullifiers[i]; // Constraints: 6158 (+0)
        nullifiersHash[i].enabled <== nullifiers[i] - zeroLeaf; // Constraints: 6158 (+0)
    }
    component mpk = Poseidon(3);
    mpk.inputs[0] <== spendingPublicKey[0];
    mpk.inputs[1] <== spendingPublicKey[1];
    mpk.inputs[2] <== nullifyingKey;
    component noteCommitmentsIn[nInputs];
    component npkIn[nInputs]; // note public keys
    component merkleVerifier[nInputs];
    component inBlindedCommitment[nInputs];
    for(var i=0; i<nInputs; i++) { // Constraints: 6419 (+261)
        npkIn[i] = Poseidon(2); // Constraints: 7139 (+720)
        npkIn[i].inputs[0] <== mpk.out; // Constraints: 7139 (+0)
        npkIn[i].inputs[1] <== randomsIn[i]; // Constraints: 7139 (+0)
        noteCommitmentsIn[i] = Poseidon(3); // Constraints: 7922 (+783)
        noteCommitmentsIn[i].inputs[0] <== npkIn[i].out; // Constraints: 7922 (+0)
        noteCommitmentsIn[i].inputs[1] <== token; // Constraints: 7922 (+0)
        noteCommitmentsIn[i].inputs[2] <== valuesIn[i]; // Constraints: 7922 (+0)
        inBlindedCommitment[i] = Poseidon(3); // Constraints: 8705 (+783)
        inBlindedCommitment[i].inputs[0] <== noteCommitmentsIn[i].out; // Constraints: 8705 (+0)
        inBlindedCommitment[i].inputs[1] <== npkIn[i].out; // Constraints: 8705 (+0)
        inBlindedCommitment[i].inputs[2] <== utxoTreeIn * 65536 + utxoPositionsIn[i]; // Constraints: 8705 (+0)
        merkleVerifier[i] = MerkleProofVerifier(MerkleTreeDepth); // Constraints: 20330 (+11625)
        merkleVerifier[i].leaf <== inBlindedCommitment[i].out; // Constraints: 20330 (+0)
        merkleVerifier[i].leafIndex <== poiInMerkleProofIndices[i]; // Constraints: 20330 (+0)
        for(var j=0; j<MerkleTreeDepth; j++) {
            merkleVerifier[i].pathElements[j] <== poiInMerkleProofPathElements[i][j];
        } // Constraints: 20330 (+0)
        merkleVerifier[i].merkleRoot <== poiMerkleroots[i]; // Constraints: 20330 (+0)
        merkleVerifier[i].enabled <== 1 - isDummy[i].out; // Constraints: 20330 (+0)
    }
    component outNoteHash[nOutputs];
    component outNoteChecker[nOutputs];
    component outBlindedCommitmentHasher[nOutputs];
    component isValueOutZero[nOutputs];
    for(var i=0; i<nOutputs; i++){ // Constraints: 20330 (+0)
        isValueOutZero[i] = IsZero(); // Constraints: 20336 (+6)
        isValueOutZero[i].in <== valuesOut[i]; // Constraints: 20336 (+0)
        outNoteHash[i] = Poseidon(3); // Constraints: 21119 (+783)
        outNoteHash[i].inputs[0] <== npksOut[i]; // Constraints: 21119 (+0)
        outNoteHash[i].inputs[1] <== token; // Constraints: 21119 (+0)
        outNoteHash[i].inputs[2] <== valuesOut[i]; // Constraints: 21119 (+0)
        outNoteChecker[i] = ForceEqualIfEnabled(); // Constraints: 21128 (+9)
        outNoteChecker[i].in[0] <== commitmentsOut[i]; // Constraints: 21128 (+0)
        outNoteChecker[i].in[1] <== outNoteHash[i].out; // Constraints: 21128 (+0)
        outNoteChecker[i].enabled <== (1 - isValueOutZero[i].out); // Constraints: 21128 (+0)
        outBlindedCommitmentHasher[i] = Poseidon(3); // Constraints: 21911 (+783)
        outBlindedCommitmentHasher[i].inputs[0] <== commitmentsOut[i]; // Constraints: 21911 (+0)
        outBlindedCommitmentHasher[i].inputs[1] <== npksOut[i]; // Constraints: 21911 (+0)
        outBlindedCommitmentHasher[i].inputs[2] <== utxoTreeOut * 65536 + utxoBatchStartPositionOut + i; // Constraints: 21911 (+0)
        blindedCommitmentsOut[i] <== outBlindedCommitmentHasher[i].out*(1 - isValueOutZero[i].out); // Constraints: 21914 (+3) // Constraints: 21914 (+3)
    }
}
