pragma circom 2.0.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/switcher.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "./merkle-proof-verifier.circom";
include "./nullifier-check.circom";

template Step(MerkleTreeDepth, maxInputs, maxOutputs, zeroLeaf) {
    //********************** Public Signals *********************************
    signal input railgunTxidMerkleroot;
    signal input allowListRoot;
    signal output outBlindedCommitment;
    //***********************************************************************

    //********************** Private Signals ********************************
    signal input boundParamsHash; // hash of ciphertext and adapterParameters
    signal input nullifiers[maxInputs]; // Nullifiers for input notes
    signal input commitmentsOut[maxOutputs]; // hash of output notes

    signal input token;
    signal input publicKey[2]; // Public key for signature verification denoted to as PK
    // signal input signature[3]; // EDDSA signature (R, s) where R is a point (x,y) and s is a scalar
    signal input randomIn[maxInputs];
    signal input valueIn[maxInputs];
    signal input pathElements[maxInputs][MerkleTreeDepth]; // Merkle proofs of membership 
    signal input leavesIndices[maxInputs];
    signal input nullifyingKey;
    signal input npkOut[maxOutputs]; // Recipients' NPK
    signal input valueOut[maxOutputs];

    signal input railgunTxidPathElements[MerkleTreeDepth];
    signal input railgunTxidPathIndex;
    signal input allowListLeavesIndices[maxInputs];
    signal input allowListPathElements[maxInputs][MerkleTreeDepth];
    signal input outCommitment;
    //***********************************************************************    
    





    // 1 - Calculate railgunTxid
    component nullifiersHasher = Poseidon(maxInputs);
    for(var i = 0; i < maxInputs; i++) {
        nullifiersHasher.inputs[i] <== nullifiers[i];
    }
    component commitmentsHasher = Poseidon(maxOutputs);
    for(var i = 0; i < maxOutputs; i++) {
        commitmentsHasher.inputs[i] <== commitmentsOut[i];
    }
    component railgunTxidHasher = Poseidon(3);
    railgunTxidHasher.inputs[0] <== nullifiersHasher.out;
    railgunTxidHasher.inputs[1] <== commitmentsHasher.out;
    railgunTxidHasher.inputs[2] <== boundParamsHash;

    //***********************************************************************

    // 2 - Check if railgunTxid is in the merkle tree
    component railgunTxidVerifier = MerkleProofVerifier(MerkleTreeDepth);
    railgunTxidVerifier.merkleRoot <== railgunTxidMerkleroot;
    for(var j = 0; j < MerkleTreeDepth; j++) {
        railgunTxidVerifier.pathElements[j] <== railgunTxidPathElements[j];
    }
    railgunTxidVerifier.leafIndex <== railgunTxidPathIndex;
    railgunTxidVerifier.leaf <== railgunTxidHasher.out;
    railgunTxidVerifier.enabled <== 1;
    //***********************************************************************



    // 3. Check dummy inputs (i.e., with zero value)
    component isDummy[maxInputs];
    for(var i=0; i<maxInputs; i++) {
        isDummy[i] = IsZero();
        isDummy[i].in <== valueIn[i];
    }

    // 3. Verify nullifiers
    component nullifiersHash[maxInputs];
    for(var i=0; i<maxInputs; i++) {
        nullifiersHash[i] = NullifierCheck();
        nullifiersHash[i].nullifyingKey <== nullifyingKey;
        nullifiersHash[i].leafIndex <== leavesIndices[i];
        nullifiersHash[i].nullifier <== nullifiers[i];
        nullifiersHash[i].enabled <== 1-isDummy[i].out;
    }

    // 4. Compute master public key
    component mpk = Poseidon(3);
    mpk.inputs[0] <== publicKey[0];
    mpk.inputs[1] <== publicKey[1];
    mpk.inputs[2] <== nullifyingKey;

    // 5. Verify Merkle proofs of membership
    component noteCommitmentsIn[maxInputs];
    component npkIn[maxInputs]; // note public keys
    component merkleVerifier[maxInputs];
    component inBlindedCommitment[maxInputs];
    var sumIn = 0;

    for(var i=0; i<maxInputs; i++) {
        // Compute NPK
        npkIn[i] = Poseidon(2);
        npkIn[i].inputs[0] <== mpk.out;
        npkIn[i].inputs[1] <== randomIn[i];
        // Compute note commitment
        noteCommitmentsIn[i] = Poseidon(3);
        noteCommitmentsIn[i].inputs[0] <== npkIn[i].out;
        noteCommitmentsIn[i].inputs[1] <== token;
        noteCommitmentsIn[i].inputs[2] <== valueIn[i];

        inBlindedCommitment[i] = Poseidon(2);
        inBlindedCommitment[i].inputs[0] <== noteCommitmentsIn[i].out;
        inBlindedCommitment[i].inputs[1] <== npkIn[i].out;


        merkleVerifier[i] = MerkleProofVerifier(MerkleTreeDepth);
        merkleVerifier[i].leaf <== inBlindedCommitment[i].out;
        merkleVerifier[i].leafIndex <== allowListLeavesIndices[i];
        for(var j=0; j<MerkleTreeDepth; j++) {
            merkleVerifier[i].pathElements[j] <== allowListPathElements[i][j];
        }
        merkleVerifier[i].merkleRoot <== allowListRoot;
        merkleVerifier[i].enabled <== 1 - isDummy[i].out;

        sumIn = sumIn + valueIn[i];

        // We don't need to range check input amounts, since all inputs are valid UTXOs that
        // were already checked as in some railgunTxid
    }

    component n2b[maxOutputs];
    component outNoteHash[maxOutputs];
    component outNoteChecker[maxOutputs];
    component outEqualCounter[maxOutputs];
    var sumOut = 0;
    var outEqualCount = 0;
    for(var i=0; i<maxOutputs; i++){
        // 6. Verify output value is 120-bits
        n2b[i] = Num2Bits(120);
        n2b[i].in <== valueOut[i];

        // 7. Verify output commitments
        outNoteHash[i] = Poseidon(3);
        outNoteHash[i].inputs[0] <== npkOut[i];
        outNoteHash[i].inputs[1] <== token;
        outNoteHash[i].inputs[2] <== valueOut[i];

        outNoteChecker[i] = ForceEqualIfEnabled();
        outNoteChecker[i].in[0] <== commitmentsOut[i];
        outNoteChecker[i].in[1] <== outNoteHash[i].out;
        outNoteChecker[i].enabled <== commitmentsOut[i] - zeroLeaf;

        outEqualCounter[i] = IsEqual();
        outEqualCounter[i].in[0] <== commitmentsOut[i];
        outEqualCounter[i].in[1] <== outCommitment;
        outEqualCount = outEqualCount + outEqualCounter[i].out;

        sumOut = sumOut + valueOut[i];
    }

    // Verify that we output exactly one commitment
    outEqualCount === 1;

    // 8. Verify balance property
    sumIn === sumOut;


    component outBlindedCommitmentHasher = Poseidon(2);
    outBlindedCommitmentHasher.inputs[0] <== outCommitment;
    outBlindedCommitmentHasher.inputs[1] <== npkOut[0];
    outBlindedCommitment <== outBlindedCommitmentHasher.out;


}

component main{public [railgunTxidMerkleroot, allowListRoot]} = Step(16, 13, 13, 2051258411002736885948763699317990061539314419500486054347250703186609807356); // bytes32(uint256(keccak256("Railgun")) % SNARK_SCALAR_FIELD);