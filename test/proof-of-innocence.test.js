let testVectors = [];
for (let i = 0; i < 8; i++) {
  const filePath = "./test-vectors/inputs" + i.toString() + ".json";
  const testVector = require(filePath);
  testVectors.push(testVector);
}

let testVectorsSmall = [];
for (let i = 0; i < 14; i++) {
  const filePath = "./test-vectors-small/inputs" + i.toString() + ".json";
  const testVector = require(filePath);
  testVectorsSmall.push(testVector);
}

const tester = require("circom_tester").wasm;

describe("Proof of Innocence", async () => {
  xit("Should test poi-transaction-13x13 with mock inputs", async () => {
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

  xit("Should test poi-transaction-3x3 with mock inputs", async () => {
    const circuit = await tester("./circuits/poi-transaction-3x3.circom", {
      reduceConstraints: false,
    });

    for (let i = 0; i < testVectorsSmall.length; i++) {
      const inputs = testVectorsSmall[i];
      // console.log("inputs", i);
      // console.log(inputs);
      const witness = await circuit.calculateWitness(inputs);
      await circuit.checkConstraints(witness);
      // const output = await circuit.getDecoratedOutput(witness);
      // console.log("output", i);
      // console.log(output);
    }
  });

  it("Should test poi-transaction-3x3 time with mock inputs", async () => {
    const circuit = await tester("./circuits/poi-transaction-3x3.circom", {
      reduceConstraints: false,
    });
  
    const numberOfRuns = 100;
    let allDurations = [];
  
    for (let i = 0; i < testVectorsSmall.length; i++) {
      const inputs = testVectorsSmall[i];
      // delete blindedCommitmentsOut from inputs
      delete inputs.blindedCommitmentsOut;
      inputs["utxoBatchGlobalStartPositionOut"] = inputs.utxoTreeOut * 64 + inputs.utxoBatchStartPositionOut;
      delete inputs.utxoTreeOut;
      delete inputs.utxoBatchStartPositionOut;
      let totalDuration = 0;
  
      for (let j = 0; j < numberOfRuns; j++) {
        const startTime = process.hrtime();
        const witness = await circuit.calculateWitness(inputs);
        const [seconds, nanoseconds] = process.hrtime(startTime);
        totalDuration += seconds * 1e9 + nanoseconds;  // Convert seconds to nanoseconds and add
      }
  
      const averageDuration = totalDuration / numberOfRuns;
      console.log(`Average time for input ${i}: ${(averageDuration / 1e6).toFixed(2)} ms`);
      allDurations.push(averageDuration);
  
      // Optionally check constraints and get decorated output
      // const witness = await circuit.calculateWitness(inputs);
      // await circuit.checkConstraints(witness);
      // const output = await circuit.getDecoratedOutput(witness);
    }
    const averageAllDurations = allDurations.reduce((a, b) => a + b, 0) / allDurations.length;
    console.log(`Average time for all inputs: ${(averageAllDurations / 1e6).toFixed(2)} ms`);
  });
  
  
});
