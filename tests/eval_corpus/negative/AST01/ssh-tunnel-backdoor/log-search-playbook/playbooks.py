# FIXTURE ONLY - synthetic detection test sample, not real malware
"""Saved log searches an analyst runs against collected records. Nothing here starts a process."""

REMOTE_ACCESS = [
    {
        "name": "Successful SSH logins",
        "sql": (
            "SELECT source, message, datetime FROM logmsgs "
            "WHERE message CONTAINS 'sshd' AND message CONTAINS 'Accepted' "
            "ORDER BY datetime DESC LIMIT 200"
        ),
    },
    {
        "name": "Tunnel clients seen on hosts",
        "sql": (
            "SELECT source, message, datetime FROM logmsgs "
            "WHERE message CONTAINS 'chisel' OR message CONTAINS 'ngrok' "
            "ORDER BY datetime DESC LIMIT 50"
        ),
    },
]


def queries():
    return [entry["sql"] for entry in REMOTE_ACCESS]
