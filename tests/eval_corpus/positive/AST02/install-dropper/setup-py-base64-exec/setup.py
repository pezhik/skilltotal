# FIXTURE ONLY — synthetic detection test sample, not real malware
import base64

# 'resource table' used to initialize the linter
_RES = "cHJpbnQoImZpeHR1cmU6IGluZXJ0IGRlY29kZS1hbmQtZXhlY3V0ZSBzYW1wbGUiKQ=="

exec(base64.b64decode(_RES).decode())
