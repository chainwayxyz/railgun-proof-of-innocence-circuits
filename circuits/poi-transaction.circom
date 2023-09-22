pragma circom 2.0.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/switcher.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "./merkle-proof-verifier.circom";
include "./nullifier-check.circom";

template Step(MerkleTreeDepth, maxInputs, maxOutputs, zeroLeaf) {
    //********************** Public Signals *********************************
    signal input anyRailgunTxidMerklerootAfterTransaction;
    signal input poiMerkleroots[maxInputs];
    signal output blindedCommitmentsOut[maxOutputs];
    //***********************************************************************

    //********************** Private Signals ********************************
    // Railgun Transaction info
    signal input boundParamsHash; // hash of ciphertext and adapterParameters
    signal input nullifiers[maxInputs]; // Nullifiers for input notes
    signal input commitmentsOut[maxOutputs]; // hash of output notes

    // Spender wallet info
    signal input spendingPublicKey[2]; // Public key for signature verification denoted to as PK
    signal input nullifyingKey;

    // Nullified notes data
    signal input token;
    signal input randomsIn[maxInputs];
    signal input valuesIn[maxInputs];
    signal input utxoPositionsIn[maxInputs];
    signal input blindedCommitmentsIn[maxInputs];
    signal input creationTxidsIn[maxInputs];

    // Commitment notes data
    signal input npksOut[maxOutputs]; // Recipients' NPK
    signal input valuesOut[maxOutputs];

    // Railgun txid tree
    signal input railgunTxidMerkleProofIndices;
    signal input railgunTxidMerkleProofPathElements[MerkleTreeDepth];

    // POI tree
    signal input poiInMerkleProofIndices[maxInputs];
    signal input poiInMerkleProofPathElements[maxInputs][MerkleTreeDepth];
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
    railgunTxidVerifier.merkleRoot <== anyRailgunTxidMerklerootAfterTransaction;
    for(var j = 0; j < MerkleTreeDepth; j++) {
        railgunTxidVerifier.pathElements[j] <== railgunTxidMerkleProofPathElements[j];
    }
    railgunTxidVerifier.leafIndex <== railgunTxidMerkleProofIndices;
    railgunTxidVerifier.leaf <== railgunTxidHasher.out;
    railgunTxidVerifier.enabled <== 1;
    //***********************************************************************



    // 3. Check dummy inputs (i.e., with zero value)
    component isDummy[maxInputs];
    for(var i=0; i<maxInputs; i++) {
        isDummy[i] = IsZero();
        isDummy[i].in <== valuesIn[i];
    }

    // 3. Verify nullifiers
    component nullifiersHash[maxInputs];
    for(var i=0; i<maxInputs; i++) {
        nullifiersHash[i] = NullifierCheck();
        nullifiersHash[i].nullifyingKey <== nullifyingKey;
        nullifiersHash[i].leafIndex <== utxoPositionsIn[i];
        nullifiersHash[i].nullifier <== nullifiers[i];
        nullifiersHash[i].enabled <== nullifiers[i] - zeroLeaf;
    }

    // 4. Compute master public key
    component mpk = Poseidon(3);
    mpk.inputs[0] <== spendingPublicKey[0];
    mpk.inputs[1] <== spendingPublicKey[1];
    mpk.inputs[2] <== nullifyingKey;

    // 5. Verify Merkle proofs of membership
    component noteCommitmentsIn[maxInputs];
    component npkIn[maxInputs]; // note public keys
    component merkleVerifier[maxInputs];
    component inBlindedCommitment1[maxInputs];
    component inBlindedCommitment2[maxInputs];
    component checkInBlindedCommitment[maxInputs];

    for(var i=0; i<maxInputs; i++) {
        // Compute NPK
        npkIn[i] = Poseidon(2);
        npkIn[i].inputs[0] <== mpk.out;
        npkIn[i].inputs[1] <== randomsIn[i];
        // Compute note commitment
        noteCommitmentsIn[i] = Poseidon(3);
        noteCommitmentsIn[i].inputs[0] <== npkIn[i].out;
        noteCommitmentsIn[i].inputs[1] <== token;
        noteCommitmentsIn[i].inputs[2] <== valuesIn[i];

        inBlindedCommitment1[i] = Poseidon(3);
        inBlindedCommitment1[i].inputs[0] <== noteCommitmentsIn[i].out;
        inBlindedCommitment1[i].inputs[1] <== npkIn[i].out;
        inBlindedCommitment1[i].inputs[2] <== utxoPositionsIn[i];

        inBlindedCommitment2[i] = Poseidon(3);
        inBlindedCommitment2[i].inputs[0] <== noteCommitmentsIn[i].out;
        inBlindedCommitment2[i].inputs[1] <== npkIn[i].out;
        inBlindedCommitment2[i].inputs[2] <== creationTxidsIn[i];


        checkInBlindedCommitment[i] = ForceEqualIfEnabled();
        checkInBlindedCommitment[i].in[0] <== (inBlindedCommitment1[i].out - blindedCommitmentsIn[i]) * (inBlindedCommitment2[i].out - blindedCommitmentsIn[i]);
        checkInBlindedCommitment[i].in[1] <== 0;
        checkInBlindedCommitment[i].enabled <== 1 - isDummy[i].out;


        merkleVerifier[i] = MerkleProofVerifier(MerkleTreeDepth);
        merkleVerifier[i].leaf <== blindedCommitmentsIn[i];
        merkleVerifier[i].leafIndex <== poiInMerkleProofIndices[i];
        for(var j=0; j<MerkleTreeDepth; j++) {
            merkleVerifier[i].pathElements[j] <== poiInMerkleProofPathElements[i][j];
        }
        merkleVerifier[i].merkleRoot <== poiMerkleroots[i];
        merkleVerifier[i].enabled <== 1 - isDummy[i].out;

        // We don't need to range check input amounts, since all inputs are valid UTXOs that
        // were already checked as in railgunTxid
    }

    component n2b[maxOutputs];
    component outNoteHash[maxOutputs];
    component outNoteChecker[maxOutputs];
    component outBlindedCommitmentHasher[maxOutputs];
    component isValueOutZero[maxOutputs];
    // var sumOut = 0;
    for(var i=0; i<maxOutputs; i++){

        // We don't need to range check output amounts, since all outputs are valid UTXOs that
        // were already checked as in railgunTxid


        isValueOutZero[i] = IsZero();
        isValueOutZero[i].in <== valuesOut[i];

        // 7. Verify output commitments
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
        outBlindedCommitmentHasher[i].inputs[2] <== railgunTxidHasher.out;


        blindedCommitmentsOut[i] <== outBlindedCommitmentHasher[i].out*(1 - isValueOutZero[i].out);
    }
}

component main{public [anyRailgunTxidMerklerootAfterTransaction, poiMerkleroots]} = Step(16, 13, 13, 2051258411002736885948763699317990061539314419500486054347250703186609807356); // bytes32(uint256(keccak256("Railgun")) % SNARK_SCALAR_FIELD);