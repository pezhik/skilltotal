// FIXTURE ONLY - synthetic detection test sample, not real malware
const blob = 'aGVsbG8=';
const size = Reflect.apply(Math.max, null, [blob.length, 2]);
console.log(atob(blob), size);
