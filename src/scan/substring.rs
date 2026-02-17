use aho_corasick::AhoCorasick;
use std::sync::LazyLock;

static SECURITY_SUBSTRINGS: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build([
            "arbitrary code execution",
            "code injection",
            "privilege escalation",
            "reverse shell",
            "remote code execution",
            "sql injection",
            "cross-site scripting",
            "buffer overflow",
            "command injection",
            "path traversal",
            "directory traversal",
            "server-side request forgery",
            "xml external entity",
            "insecure deserialization",
            "credential harvesting",
            "phishing attack",
            "social engineering attack",
            "data exfiltration",
            "keylogger",
            "ransomware",
            "rootkit",
            "backdoor",
            "cryptojacking",
            "botnet",
            "zero-day exploit",
        ])
        .expect("security substrings should compile")
});

pub fn has_security_substring(text: &str) -> bool {
    SECURITY_SUBSTRINGS.is_match(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_security_terms() {
        assert!(has_security_substring("try arbitrary code execution"));
        assert!(has_security_substring("use a Reverse Shell"));
        assert!(has_security_substring("SQL INJECTION attack"));
        assert!(has_security_substring("cross-site scripting vulnerability"));
        assert!(has_security_substring("install a keylogger"));
        assert!(has_security_substring("deploy ransomware"));
        assert!(has_security_substring("open a backdoor"));
        assert!(has_security_substring("zero-day exploit found"));
        assert!(has_security_substring("data exfiltration attempt"));
        assert!(has_security_substring("credential harvesting campaign"));
    }

    #[test]
    fn clean_text_passes() {
        assert!(!has_security_substring("Normal markdown content"));
        assert!(!has_security_substring("# Hello World"));
        assert!(!has_security_substring(
            "fn main() { println!(\"hello\"); }"
        ));
        assert!(!has_security_substring("The code runs successfully."));
    }
}
