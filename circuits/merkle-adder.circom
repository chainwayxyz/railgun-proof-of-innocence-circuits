pragma circom 2.0.6;
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/switcher.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

template MerkleAdder(MerkleTreeDepth, zeroLeaf) {
    signal input root;
    signal input leaf;
    signal input leafIndex; 
    signal input pathElements[MerkleTreeDepth];
    // signal input enabled;
    signal output newRoot;

    component hashers[MerkleTreeDepth];
    component switchers[MerkleTreeDepth];
    component hashers2[MerkleTreeDepth];
    component switchers2[MerkleTreeDepth];

    // Bitify leafIndex to get bit per each level
    component index = Num2Bits(MerkleTreeDepth);
    index.in <== leafIndex;

    var levelHash;
    levelHash = zeroLeaf;

    for (var i = 0; i < MerkleTreeDepth; i++) {
        switchers[i] = Switcher();
        switchers[i].L <== levelHash;
        switchers[i].R <== pathElements[i];
        switchers[i].sel <== index.out[i];
        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== switchers[i].outL;
        hashers[i].inputs[1] <== switchers[i].outR;
        levelHash = hashers[i].out;
    }
    root === levelHash;

    levelHash = leaf;
    for (var i = 0; i < MerkleTreeDepth; i++) {
        switchers2[i] = Switcher();
        switchers2[i].L <== levelHash;
        switchers2[i].R <== pathElements[i];
        switchers2[i].sel <== index.out[i];
        hashers2[i] = Poseidon(2);
        hashers2[i].inputs[0] <== switchers2[i].outL;
        hashers2[i].inputs[1] <== switchers2[i].outR;
        levelHash = hashers2[i].out;
    }
    newRoot <== levelHash;
}