//! Validates API keys. The production code holds no secret; the fake key below lives only in an
//! inline `#[cfg(test)]` unit test (compiled for `cargo test`, never shipped), so it must NOT be
//! scored as an embedded secret and must NOT synthesize a credential-exfiltration combo.

pub fn validate_api_key(key: &str) -> bool {
    key.starts_with("sk-") && key.len() > 20
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_a_well_formed_key() {
        assert!(validate_api_key("sk-rusttestfixture0123456789ABCDEFGHIJKLMNOPQRS"));
    }

    #[test]
    fn rejects_empty() {
        assert!(!validate_api_key(""));
    }
}
