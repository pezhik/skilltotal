# FIXTURE ONLY - synthetic detection test sample, not real malware
"""Saved log searches an analyst runs against collected records. Nothing here starts a process."""

PLAYBOOKS = [
    {
        "name": "Regsvr32 executing remote code",
        "sql": (
            "SELECT source, message, datetime FROM logmsgs "
            "WHERE message CONTAINS 'regsvr32' AND (message CONTAINS 'http' "
            "OR message CONTAINS 'scrobj') ORDER BY datetime DESC LIMIT 50"
        ),
        "purpose": "regsvr32 /s /u /i:http:// scrobj.dll is the application-control bypass",
    },
    {
        "name": "Certificate tool used as a downloader",
        "sql": "SELECT source, message FROM logmsgs WHERE message LIKE '%certutil%' LIMIT 50",
        "purpose": "Shows hosts where the certificate tool was started with a cache option",
    },
]


def playbook(name):
    return next((p for p in PLAYBOOKS if p["name"] == name), None)
