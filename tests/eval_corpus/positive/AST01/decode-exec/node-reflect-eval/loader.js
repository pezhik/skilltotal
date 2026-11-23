// FIXTURE ONLY - synthetic detection test sample, not real malware
const blob = 'cHJpbnQoMSk=';
Reflect.apply(eval, null, [atob(blob)]);
