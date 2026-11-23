// FIXTURE ONLY - synthetic detection test sample, not real malware
function d(e){return Buffer.from(e,"base64url")}
function size(e){let r=d(e);return r.byteLength}
const t=size(process.argv[2]||"aGVsbG8");
const timer=setTimeout(()=>console.log("done"),t);
