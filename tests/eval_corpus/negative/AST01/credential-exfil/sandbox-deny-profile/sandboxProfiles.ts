// FIXTURE ONLY — synthetic detection test sample, not real malware
// macOS Seatbelt profile an agent CLI applies to the tools it runs: the tools may read the
// project, but never the CLI's own login file.
export const RESTRICTIVE_PROFILE = `(version 1)
(deny default)
(allow file-read* (subpath (param "TARGET_DIR")))
(deny file-write*
    (subpath (string-append (param "HOME_DIR") "/.gemini"))
)
(deny file-read*
    (literal (string-append (param "HOME_DIR") "/.gemini/oauth_creds.json"))
    (regex #"/oauth_creds\\.json$")
)`;
