const testVector = require('./test-vector-poi.json');

const tester = require('circom_tester').wasm;

const isPrefixed = (str) => str.startsWith('0x');
const prefix0x = (str) => (isPrefixed(str) ? str : `0x${str}`);
function hexToBigInt(str) {
  return BigInt(prefix0x(str));
}

const padWithZerosToMax = (array, max) => {
  const padded = [...array];
  while (padded.length < max) {
    padded.push(0n);
  }
  return padded;
};

const padWithArraysOfZerosToMaxAndLength = (array, max, length) => {
  const padded = [...array];
  while (padded.length < max) {
    padded.push(new Array(length).fill(0n));
  }
  return padded;
};

const formatInputs = (proofInputs) => {
  const maxInputs = 13;
  const maxOutputs = 13;

  return {
    anyRailgunTxidMerklerootAfterTransaction: hexToBigInt(
      proofInputs.anyRailgunTxidMerklerootAfterTransaction,
    ),
    // blindedCommitmentsOut: padWithZerosToMax(
    //   proofInputs.blindedCommitmentsOut.map(hexToBigInt),
    //   maxOutputs,
    // ),
    boundParamsHash: hexToBigInt(proofInputs.boundParamsHash),
    nullifiers: padWithZerosToMax(
      proofInputs.nullifiers.map(hexToBigInt),
      maxInputs,
    ),
    commitmentsOut: padWithZerosToMax(
      proofInputs.commitmentsOut.map(hexToBigInt),
      maxOutputs,
    ),
    spendingPublicKey: proofInputs.spendingPublicKey.map(hexToBigInt),
    nullifyingKey: hexToBigInt(proofInputs.nullifyingKey),
    token: hexToBigInt(proofInputs.token),
    randomsIn: padWithZerosToMax(
      proofInputs.randomsIn.map(hexToBigInt),
      maxInputs,
    ),
    valuesIn: padWithZerosToMax(
      proofInputs.valuesIn.map(hexToBigInt),
      maxInputs,
    ),
    utxoPositionsIn: padWithZerosToMax(
      proofInputs.utxoPositionsIn.map(BigInt),
      maxInputs,
    ),
    blindedCommitmentsIn: padWithZerosToMax(
      proofInputs.blindedCommitmentsIn.map(hexToBigInt),
      maxInputs,
    ),
    creationTxidsIn: padWithZerosToMax(
      proofInputs.creationTxidsIn.map(hexToBigInt),
      maxInputs,
    ),
    npksOut: padWithZerosToMax(
      proofInputs.npksOut.map(hexToBigInt),
      maxOutputs,
    ),
    valuesOut: padWithZerosToMax(
      proofInputs.valuesOut.map(hexToBigInt),
      maxOutputs,
    ),
    railgunTxidMerkleProofIndices: hexToBigInt(
      proofInputs.railgunTxidMerkleProofIndices,
    ),
    railgunTxidMerkleProofPathElements:
      proofInputs.railgunTxidMerkleProofPathElements.map(hexToBigInt),
    poiMerkleroots: padWithZerosToMax(
      proofInputs.poiMerkleroots.map(hexToBigInt),
      maxInputs,
    ),
    poiInMerkleProofIndices: padWithZerosToMax(
      proofInputs.poiInMerkleProofIndices.map(hexToBigInt),
      maxInputs,
    ),
    poiInMerkleProofPathElements: padWithArraysOfZerosToMaxAndLength(
      proofInputs.poiInMerkleProofPathElements.map((pathElements) =>
        pathElements.map(hexToBigInt),
      ),
      maxInputs,
      16,
    ),
  };
};

describe('Proof of Innocence', async () => {
  it('Should test POI circuit with mock inputs', async () => {
    const circuit = await tester('./circuits/poi-transaction.circom', {
      reduceConstraints: false,
    });

    const inputs = testVector;

    const inputsBigInt = formatInputs(inputs);

    const witness = await circuit.calculateWitness(inputsBigInt);
    await circuit.checkConstraints(witness);

    const output = await circuit.getDecoratedOutput(witness);
    console.log('output');
    console.log(output);
  });
});
