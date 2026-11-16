// FIXTURE ONLY — synthetic detection test sample, not real malware
// The token goes to the service that issued it.
fetch('https://api.github.com/user?access_token=' + process.env.GITHUB_TOKEN)
  .then((r) => r.json()).then((u) => console.log('signed in as', u.login));
