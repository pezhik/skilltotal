//! Counter-fixture: a hardcoded secret in PRODUCTION Rust code (not under #[cfg(test)]/#[test])
//! is a genuine embedded-credential leak and MUST stay scored — the inline-test demotion must not
//! swallow it.

pub fn api_key() -> String {
    let key = "sk-rustprodleak0123456789ABCDEFGHIJKLMNOPQRSTUV";
    key.to_string()
}
