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
    for(var i = 0; i < nInputs; i++) {
        nullifiersHasher.inputs[i] <== nullifiers[i];
    }
    for(var i = nInputs; i < maxInputs; i++){
        nullifiersHasher.inputs[i] <== zeroLeaf;
    }
    component commitmentsHasher = Poseidon(maxOutputs);
    for(var i = 0; i < nOutputs; i++) {
        commitmentsHasher.inputs[i] <== commitmentsOut[i];
    }
    for(var i = nOutputs; i < maxOutputs; i++){
        commitmentsHasher.inputs[i] <== zeroLeaf;
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
    for(var j = 0; j < MerkleTreeDepth; j++) {
        railgunTxidVerifier.pathElements[j] <== railgunTxidMerkleProofPathElements[j];
    }
    railgunTxidVerifier.leafIndex <== railgunTxidMerkleProofIndices;
    railgunTxidVerifier.leaf <== txidTreeLeafHasher.out;
    railgunTxidVerifier.enabled <== 1;
    component railgunTxidIfHasUnshieldCheck = ForceEqualIfEnabled();
    railgunTxidIfHasUnshieldCheck.in[0] <== railgunTxidIfHasUnshield;
    railgunTxidIfHasUnshieldCheck.in[1] <== railgunTxidHasher.out;
    railgunTxidIfHasUnshieldCheck.enabled <== railgunTxidIfHasUnshield;
    component isDummy[nInputs];
    for(var i=0; i<nInputs; i++) {
        isDummy[i] = IsZero();
        isDummy[i].in <== valuesIn[i];
    }
    component nullifiersHash[nInputs];
    for(var i=0; i<nInputs; i++) {
        nullifiersHash[i] = NullifierCheck();
        nullifiersHash[i].nullifyingKey <== nullifyingKey;
        nullifiersHash[i].leafIndex <== utxoPositionsIn[i];
        nullifiersHash[i].nullifier <== nullifiers[i];
        nullifiersHash[i].enabled <== nullifiers[i] - zeroLeaf;
    }
    component mpk = Poseidon(3);
    mpk.inputs[0] <== spendingPublicKey[0];
    mpk.inputs[1] <== spendingPublicKey[1];
    mpk.inputs[2] <== nullifyingKey;
    component noteCommitmentsIn[nInputs];
    component npkIn[nInputs]; // note public keys
    component merkleVerifier[nInputs];
    component inBlindedCommitment[nInputs];
    for(var i=0; i<nInputs; i++) {
        npkIn[i] = Poseidon(2);
        npkIn[i].inputs[0] <== mpk.out;
        npkIn[i].inputs[1] <== randomsIn[i];
        noteCommitmentsIn[i] = Poseidon(3);
        noteCommitmentsIn[i].inputs[0] <== npkIn[i].out;
        noteCommitmentsIn[i].inputs[1] <== token;
        noteCommitmentsIn[i].inputs[2] <== valuesIn[i];
        inBlindedCommitment[i] = Poseidon(3);
        inBlindedCommitment[i].inputs[0] <== noteCommitmentsIn[i].out;
        inBlindedCommitment[i].inputs[1] <== npkIn[i].out;
        inBlindedCommitment[i].inputs[2] <== utxoTreeIn * 65536 + utxoPositionsIn[i];
        merkleVerifier[i] = MerkleProofVerifier(MerkleTreeDepth);
        merkleVerifier[i].leaf <== inBlindedCommitment[i].out;
        merkleVerifier[i].leafIndex <== poiInMerkleProofIndices[i];
        for(var j=0; j<MerkleTreeDepth; j++) {
            merkleVerifier[i].pathElements[j] <== poiInMerkleProofPathElements[i][j];
        }
        merkleVerifier[i].merkleRoot <== poiMerkleroots[i];
        merkleVerifier[i].enabled <== 1 - isDummy[i].out;
    }
    component outNoteHash[nOutputs];
    component outNoteChecker[nOutputs];
    component outBlindedCommitmentHasher[nOutputs];
    component isValueOutZero[nOutputs];
    for(var i=0; i<nOutputs; i++){
        isValueOutZero[i] = IsZero();
        isValueOutZero[i].in <== valuesOut[i];
        outNoteHash[i] = Poseidon(3);
        outNoteHash[i].inputs[0] <== npksOut[i];
        outNoteHash[i].inputs[1] <== token;
        outNoteHash[i].inputs[2] <== valuesOut[i];
        outNoteChecker[i] = ForceEqualIfEnabled();
        outNoteChecker[i].in[0] <== commitmentsOut[i];
        outNoteChecker[i].in[1] <== outNoteHash[i].out;
        outNoteChecker[i].enabled <== (1 - isValueOutZero[i].out);
        outBlindedCommitmentHasher[i] = Poseidon(3);
        outBlindedCommitmentHasher[i].inputs[0] <== commitmentsOut[i];
        outBlindedCommitmentHasher[i].inputs[1] <== npksOut[i];
        outBlindedCommitmentHasher[i].inputs[2] <== utxoTreeOut * 65536 + utxoBatchStartPositionOut + i;
        blindedCommitmentsOut[i] <== outBlindedCommitmentHasher[i].out*(1 - isValueOutZero[i].out); // Constraints: 21914 (+3)
    }
}
