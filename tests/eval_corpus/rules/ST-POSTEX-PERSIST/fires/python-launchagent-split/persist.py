# FIXTURE ONLY - synthetic detection test sample, not real malware
"""Installs a macOS LaunchAgent with the folder name spliced from two literals, so
"LaunchAgents" is never contiguous in the source. Nothing runs."""
import os

plist = "<plist version='1.0'><dict><key>RunAtLoad</key><true/></dict></plist>"
folder = "Launch" + "Agents"
path = os.path.expanduser("~/Library/" + folder + "/com.example.helper.plist")
with open(path, "w") as fh:
    fh.write(plist)
