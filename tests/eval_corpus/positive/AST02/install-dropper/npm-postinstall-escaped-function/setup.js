// FIXTURE ONLY - synthetic detection test sample, not real malware
// Install-time dropper: the stage is written entirely as hex escapes, which the parser decodes,
// and run through the Function constructor. It decodes to the inert: console.log("fixture")
const stage = "\x63\x6f\x6e\x73\x6f\x6c\x65\x2e\x6c\x6f\x67\x28\x22\x66\x69\x78\x74\x75\x72\x65\x22\x29";
const run = new Function(stage);
run();
