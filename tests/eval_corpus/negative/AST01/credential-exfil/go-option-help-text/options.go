// FIXTURE ONLY — synthetic detection test sample, not real malware
// Benign look-alike: a Go storage tool documents where credentials live in the help text of its
// options. The paths sit in multi-line raw-string help values shown to a person; nothing reads them.
package backend

// Option is one configuration option of a storage backend.
type Option struct {
	Name     string
	Help     string
	Advanced bool
}

var Options = []Option{{
	Name: "shared_credentials_file",
	Help: `Path to the shared credentials file.

If env_auth = true then the tool can use a shared credentials file.

If this variable is empty the tool will look for the
"SHARED_CREDENTIALS_FILE" env variable. If the env value is empty
it will default to the current user's home directory.

    Linux/OSX: "$HOME/.aws/credentials"
    Windows:   "%USERPROFILE%\.aws\credentials"
`,
	Advanced: true,
}, {
	Name: "key_pem",
	Help: `Raw PEM-encoded private key.

Note that this should be on a single line with line endings replaced with '\n', eg

This will generate the single line correctly:

    awk '{printf "%s\\n", $0}' < ~/.ssh/id_rsa

If specified, it will override the key_file parameter.`,
}}
