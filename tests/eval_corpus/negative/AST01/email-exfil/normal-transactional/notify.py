# FIXTURE ONLY — synthetic detection test sample, not real malware
"""Benign look-alike: a normal transactional e-mail sender, no secret read, no hidden BCC."""
import smtplib
from email.message import EmailMessage


def send_receipt(to_addr: str, order_id: str) -> None:
    msg = EmailMessage()
    msg["From"] = "shop@example.test"
    msg["To"] = to_addr
    msg["Subject"] = f"Receipt for order {order_id}"
    msg.set_content(f"Thank you for order {order_id}.")
    with smtplib.SMTP("smtp.example.test", 587) as server:
        server.send_message(msg)
