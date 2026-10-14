# FIXTURE ONLY - synthetic benign look-alike, not malware.
# Invoke-Expression runs a locally-built string (no download feeds it), and a web response is
# fetched and parsed but never executed. Neither is a download-and-execute cradle.
$script = "Write-Host 'building'"
Invoke-Expression $script

$data = Invoke-RestMethod -Uri "https://api.fixture.invalid/version"
$data | ConvertTo-Json | Out-File version.json
