// const testVector = require('./test-vectors/inputs0.json');
const testVector = require('./test-format-vector-poi.json');

const tester = require('circom_tester').wasm;

const isPrefixed = (str) => str.startsWith('0x');
const prefix0x = (str) => (isPrefixed(str) ? str : `0x${str}`);
function hexToBigInt(str) {
  return BigInt(prefix0x(str));
}

const stringifySafe = (obj) => {
  return JSON.stringify(obj, (key, value) =>
    typeof value === 'bigint' ? value.toString(10) : value,
  );
};

const padWithZerosToMax = (
  array,
  max,
  zeroValue = 2051258411002736885948763699317990061539314419500486054347250703186609807356n,
) => {
  const padded = [...array];
  while (padded.length < max) {
    padded.push(zeroValue);
  }
  return padded;
};

const padWithArraysOfZerosToMaxAndLength = (
  array,
  max,
  length,
  zeroValue = 2051258411002736885948763699317990061539314419500486054347250703186609807356n,
) => {
  const padded = [...array];
  while (padded.length < max) {
    padded.push(new Array(length).fill(zeroValue));
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
    boundParamsHash: hexToBigInt(proofInputs.boundParamsHash),
    nullifiers: padWithZerosToMax(
      proofInputs.nullifiers.map(hexToBigInt),
      maxInputs,
    ),
    commitmentsOut: padWithZerosToMax(
      proofInputs.commitmentsOut.map(hexToBigInt),
      maxOutputs,
    ),
    spendingPublicKey: proofInputs.spendingPublicKey.map(BigInt),
    nullifyingKey: BigInt(proofInputs.nullifyingKey),
    token: hexToBigInt(proofInputs.token),
    randomsIn: padWithZerosToMax(
      proofInputs.randomsIn.map(hexToBigInt),
      maxInputs,
    ),
    valuesIn: padWithZerosToMax(
      proofInputs.valuesIn.map(BigInt),
      maxInputs,
      0n, // Use Zero = 0 here
    ),
    utxoPositionsIn: padWithZerosToMax(
      proofInputs.utxoPositionsIn.map(BigInt),
      maxInputs,
    ),
    utxoTreesIn: BigInt(proofInputs.utxoTreesIn),
    blindedCommitmentsIn: padWithZerosToMax(
      proofInputs.blindedCommitmentsIn.map(hexToBigInt),
      maxInputs,
      0n, // Use Zero = 0 here
    ),
    creationTxidsIn: padWithZerosToMax(
      proofInputs.creationTxidsIn.map(hexToBigInt),
      maxInputs,
    ),
    npksOut: padWithZerosToMax(proofInputs.npksOut.map(BigInt), maxOutputs),
    valuesOut: padWithZerosToMax(
      proofInputs.valuesOut.map(BigInt),
      maxOutputs,
      0n, // Use Zero = 0 here
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
      0n, // Use Zero = 0 here
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

describe('Proof of Innocence formatters', async () => {
  xit('Should test POI circuit with mock formatted inputs', async () => {
    const circuit = await tester('./circuits/poi-transaction-13x13.circom', {
      reduceConstraints: false,
    });

    const inputs = testVector;

    const inputsBigInt = formatInputs(inputs);
    // console.log(stringifySafe(inputsBigInt));

    const witness = await circuit.calculateWitness(inputsBigInt);
    await circuit.checkConstraints(witness);
  });
});
