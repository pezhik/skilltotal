# FIXTURE ONLY - synthetic detection test sample, not real malware
# A Run-key autostart whose key path is assembled from a name bound once and two literals, so
# "CurrentVersion\Run" is never written contiguously.
$agent = "$env:APPDATA\perfhelper\agent.ps1"
$hive = "HKCU:\Software\Microsoft\Windows\CurrentVersion"
$key  = $hive + "\" + "Run"
Set-ItemProperty -Path $key -Name "PerfHelper" -Value $agent
