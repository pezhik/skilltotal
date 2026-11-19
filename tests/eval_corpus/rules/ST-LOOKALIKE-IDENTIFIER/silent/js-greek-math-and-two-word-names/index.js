// FIXTURE ONLY - synthetic detection test sample, not real malware
const α = 0.5;
const Δt = 0.1;
const alpha = α;
const getΘέση = (x) => x * α * Δt;
module.exports = { alpha, position: getΘέση };
