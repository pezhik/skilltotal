// FIXTURE ONLY — synthetic detection test sample, not real malware
// Benign look-alike: an SFTP server loads (or creates) its own host key in its cache directory.
// The only network code in the repository is a Python developer script in another runtime.
package serve

import "path/filepath"

func hostKeyPaths(cacheDir string, configured []string) []string {
	if len(configured) > 0 {
		return configured
	}
	cachePath := filepath.Join(cacheDir, "serve-sftp")
	return []string{
		filepath.Join(cachePath, "id_rsa"),
		filepath.Join(cachePath, "id_ed25519"),
	}
}
