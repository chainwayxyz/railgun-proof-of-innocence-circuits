pragma circom 2.0.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/switcher.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "./merkle-proof-verifier.circom";
include "./nullifier-check.circom";

// AllowedCommitments: is a list of allowed commitments
// MessageHashesRoot: is a merkle root of all message hashes
// AllowedMessageHashes: is a list of allowed message hashes
// output MessageHash

// AllowList: is the list of allowed commitments for shields (has the same len of leaves as merkleRoot onchain, but zero as not allowed commitments)
// AllowedCommitments: is a list of allowed commitments, accumulated from previous transactions (Starts with as same as AllowList)
// MessageHashesRoot: is a merkle root of all message hashes merkle roots' merkle roots (Meta Merkle Root for all possible merkle trees for messageHashesRoot)
// ProofsMerkleRoot: is a merkle root of proof of innocence outputs 

// step_in is H(AllowList, AllowedCommitments, MessageHashesRoot, ProofsMerkleRoot)
// step_out is
// either H(output_commitment, rand) // if sending to shielded transaction, 
//      then proof is verified if the MessageHashesRoot and ProofsMerkleRoot is correct,
//      then H(AllowList, output_commitment, rand) is added to the merkle tree.
// or H(newAllowList, newAllowedCommitments, newMessageHashesRoot, newProofsMerkleRoot)
//     next step for folding.

// Operations:
// TODO: Add aggAllowlist from allowlist
// TODO: remove from aggAllowlist
// add commitment from proofs merkle root, the allowlist of that proof should be the same as the aggAllowlist
// add commitment from transaction, the input commitments should be in allowed commitments

// output operations:
// H(newAllowList, newAllowedCommitments, newMessageHashesRoot, newProofsMerkleRoot)
// or H(AllowList, output_commitment, rand)


template Step(MerkleTreeDepth, maxInputs, maxOutputs, zeroLeaf) {
    signal input messageHashesRoot;
    signal input messageHashPathElements[MerkleTreeDepth];
    signal input messageHashPathIndex;
    signal input nullifiers[maxInputs]; // Nullifiers for input notes
    signal input commitmentsOut[maxOutputs]; // hash of output notes
    signal input isTransactionMode;

    signal input token;
    signal input publicKey[2]; // Public key for signature verification denoted to as PK
    signal input randomIn[maxInputs];
    signal input valueIn[maxInputs];
    signal input leavesIndices[maxInputs];
    signal input nullifyingKey;

    // signal input commInTest;

    signal output noteCommitments[maxInputs];


    // PROVE THAT THIS IS A VALID TRANSACTION
    //  Compute hash over public signals
    // @input nullifiers[maxInputs], commitmentsOut[maxOutputs]
    // @output messageHasher.out
    component nullifiersHasher = Poseidon(maxInputs);
    for(var i=0; i<maxInputs; i++) {
        nullifiersHasher.inputs[i] <== nullifiers[i];
    }
    component commitmentsHasher = Poseidon(maxOutputs);
    for(var i=0; i<maxOutputs; i++) {
        commitmentsHasher.inputs[i] <== commitmentsOut[i];
    }
    component messageHasher = Poseidon(2);
    messageHasher.inputs[0] <== nullifiersHasher.out;
    messageHasher.inputs[1] <== commitmentsHasher.out;
    //***********************************************************************


    //  Check if messageHash is in the merkle tree
    // @input messageHashPathElements[MerkleTreeDepth], messageHashPathIndex, messageHasher.out, isTransactionMode
    component messageHashVerifier = MerkleProofVerifier(MerkleTreeDepth);
    messageHashVerifier.merkleRoot <== messageHashesRoot;
    for(var j=0; j<MerkleTreeDepth; j++) {
        messageHashVerifier.pathElements[j] <== messageHashPathElements[j];
    }
    messageHashVerifier.leafIndex <== messageHashPathIndex;
    messageHashVerifier.leaf <== messageHasher.out;
    messageHashVerifier.enabled <== isTransactionMode;
    //***********************************************************************




    // PROVE THAT CORRESPOMDING COMMITMENTS ARE VALID WITH RESPECT TO THE MESSAGE HASH NULLIFIERS
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

        noteCommitments[i] <== noteCommitmentsIn[i].out;
    }


    // noteCommitments[0] === commInTest;


}

component main{public [messageHashesRoot]} = Step(16, 13, 13, 2051258411002736885948763699317990061539314419500486054347250703186609807356); // bytes32(uint256(keccak256("Railgun")) % SNARK_SCALAR_FIELD);