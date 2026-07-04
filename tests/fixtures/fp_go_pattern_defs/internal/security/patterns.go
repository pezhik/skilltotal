// FIXTURE ONLY: sanitized repro of a security tool's own prompt-injection pattern definitions
// (shape from infiniflow/ragflow's internal CLI security package). Each Description is DATA that
// *describes* an attack technique — a value-string inside a struct literal — not a live injection
// directive. The engine must not treat these pattern definitions as a malicious indicator.

package security

// Pattern describes one detectable prompt-injection technique.
type Pattern struct {
	ID          string
	Description string
}

// Patterns is the built-in catalog the detector matches user input against.
var Patterns = []Pattern{
	{ID: "PI-001", Description: "prompt injection: ignore previous instructions"},
	{ID: "PI-002", Description: "DAN (Do Anything Now) jailbreak attempt"},
	{ID: "PI-003", Description: "reveal system prompt override attempt"},
}
