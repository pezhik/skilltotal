// FIXTURE ONLY - synthetic detection test sample, not real malware
// Decodes a bundled blob and runs it at install time (the blob only logs a word).
const blob = 'Y29uc29sZS5sb2coImZpeHR1cmUiKQ==';
eval(Buffer.from(blob, 'base64').toString('utf8'));
