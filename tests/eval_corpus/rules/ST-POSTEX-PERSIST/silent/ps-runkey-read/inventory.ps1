# FIXTURE ONLY - synthetic detection test sample, not real malware
# An inventory script that lists the Run-key entries with the same spliced key path. It only
# reads the key; nothing is written there.
$hive = "HKCU:\Software\Microsoft\Windows\CurrentVersion"
$key  = $hive + "\" + "Run"
Get-ItemProperty -Path $key | Format-List
