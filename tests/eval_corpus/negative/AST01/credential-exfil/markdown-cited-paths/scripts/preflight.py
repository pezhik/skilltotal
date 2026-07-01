# FIXTURE ONLY — synthetic detection test sample, not real malware
# A network import (the "egress" half of a credential-exfil combo). With the credential paths in
# SKILL.md correctly demoted as cited markdown examples, no ST-SENS-PATH fires, so this benign
# network use must NOT synthesize ST-COMBO-EXFIL.
import urllib.request


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=10) as resp:  # noqa: S310
        return resp.read()
