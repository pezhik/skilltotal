// FIXTURE ONLY - synthetic detection test sample, not real malware
// Evasion variant: the second stage is hex instead of base64 and runs through the Function
// constructor instead of a literal eval. The hex decodes to the inert: console.log("fixture")
const stage = Buffer.from("636f6e736f6c652e6c6f672822666978747572652229", "hex").toString();
new Function(stage)();
