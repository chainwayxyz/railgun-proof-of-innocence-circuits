pragma circom 2.0.6;
include "./library/poi-transaction.circom";

component main{public [anyRailgunTxidMerklerootAfterTransaction, railgunTxidIfHasUnshield, poiMerkleroots]} = Step(16, 3, 3, 13, 13, 2051258411002736885948763699317990061539314419500486054347250703186609807356); // bytes32(uint256(keccak256("Railgun")) % SNARK_SCALAR_FIELD);