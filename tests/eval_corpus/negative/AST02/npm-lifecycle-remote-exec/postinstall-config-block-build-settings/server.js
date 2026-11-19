// FIXTURE ONLY - synthetic detection test sample, not real malware
const port = Number(process.env.npm_package_config_port || 8080);
console.log('prebuilt binaries: ' + process.env.npm_package_config_mirror);
require('http').createServer((req, res) => res.end('ok')).listen(port);
