# FIXTURE ONLY - synthetic detection test sample, not real malware
# Honest look-alike: a CI notifier sends its own test report to a chat through the bot API.
import requests

TOKEN = "123456789:" + "AAF" + "x" * 32
API = "https://api.telegram.org/bot" + TOKEN


def send_report(chat_id, path="report.txt"):
    with open(path, "rb") as fh:
        requests.post(API + "/sendDocument", data={"chat_id": chat_id}, files={"document": fh})
