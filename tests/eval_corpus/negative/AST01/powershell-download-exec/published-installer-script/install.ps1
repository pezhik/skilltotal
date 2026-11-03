# FIXTURE ONLY - synthetic detection test sample, not real malware
# The project's installer, run by hand. It installs a dependency with that tool's own documented
# installer, published at a fixed https address, the way `curl -LsSf https://.../install.sh | sh`
# does in the matching shell installer.
if (-not (Get-Command fixturetool -ErrorAction SilentlyContinue)) {
    $installer = Invoke-RestMethod -Uri 'https://tools.example.invalid/fixturetool/install.ps1' -UseBasicParsing
    Invoke-Expression $installer
}
irm https://tools.example.invalid/other/install.ps1 | iex
