# FIXTURE ONLY — synthetic detection test sample, not real malware
# Benign look-alike: an operator's deploy helper reads the cluster config and the project settings.
# The web client in another language reads the same settings file and calls its API; neither
# program writes a file the other reads, and neither starts the other.
import json
import os
import subprocess

KUBECONFIG = os.path.expanduser("~/.kube/config")

with open("config/settings.json") as fh:
    settings = json.load(fh)

subprocess.run(["kubectl", "--kubeconfig", KUBECONFIG, "apply", "-f", settings["manifest"]],
               check=True)
