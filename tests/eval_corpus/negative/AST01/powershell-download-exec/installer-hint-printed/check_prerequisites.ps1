# FIXTURE ONLY - synthetic detection test sample, not real malware
# Lists missing tools and prints how to install each one. Nothing is downloaded or run.
function Test-Tool {
    param(
        [string]$Label,
        [string]$Command,
        [string]$Hint
    )
    if (Get-Command $Command -ErrorAction SilentlyContinue) {
        Write-Host ("  ok       {0}" -f $Label)
        return $true
    }
    Write-Host ("  MISSING  {0,-12} -> {1}" -f $Label, $Hint)
    return $false
}

$null = Test-Tool -Label "fixturetool" -Command "fixturetool" -Hint "powershell -c `"irm https://tools.example.invalid/fixture/latest | iex`""
