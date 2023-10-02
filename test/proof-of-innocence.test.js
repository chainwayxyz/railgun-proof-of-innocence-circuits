let testVectors = [];
for (let i = 0; i < 8; i++) {
  const filePath = "./test-vectors/inputs" + i.toString() + ".json";
  const testVector = require(filePath);
  testVectors.push(testVector);
}

const tester = require("circom_tester").wasm;

describe("Proof of Innocence", async () => {
  it("Should test POI circuit with mock inputs", async () => {
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
});
