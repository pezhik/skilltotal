// Paths the sandbox refuses to read, to PROTECT user credentials (a denylist, not access).
pub fn denied_paths() -> Vec<String> {
    vec![
        "id_rsa".to_string(),
        "**/.ssh/*".to_string(),
        ".aws/credentials".to_string(),
    ]
}
