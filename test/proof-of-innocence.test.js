let testVectors = [];
for (let i = 0; i < 8; i++) {
  const filePath = "./test-vectors/inputs" + i.toString() + ".json";
  const testVector = require(filePath);
  testVectors.push(testVector);
}

let testVectorsSmall = [];
for (let i = 0; i < 8; i++) {
  const filePath = "./test-vectors-small/inputs" + i.toString() + ".json";
  const testVector = require(filePath);
  testVectorsSmall.push(testVector);
}

const tester = require("circom_tester").wasm;

describe("Proof of Innocence", async () => {
  it("Should test poi-transaction-13x13 with mock inputs", async () => {
    const circuit = await tester("./circuits/poi-transaction-13x13.circom", {
      reduceConstraints: false,
    });

    for (let i = 0; i < testVectors.length; i++) {
      const inputs = testVectors[i];
      const witness = await circuit.calculateWitness(inputs);
      await circuit.checkConstraints(witness);
      const output = await circuit.getDecoratedOutput(witness);
      // console.log("output", i);
      // console.log(output);
    }
  });

  it("Should test poi-transaction-3x3 with mock inputs", async () => {
    const circuit = await tester("./circuits/poi-transaction-3x3.circom", {
      reduceConstraints: false,
    });

    for (let i = 0; i < testVectorsSmall.length; i++) {
      const inputs = testVectorsSmall[i];
      const witness = await circuit.calculateWitness(inputs);
      await circuit.checkConstraints(witness);
      const output = await circuit.getDecoratedOutput(witness);
      // console.log("output", i);
      // console.log(output);
    }
  });
});
