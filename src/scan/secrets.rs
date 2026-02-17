use regex::RegexSet;
use std::sync::LazyLock;

static SECRET_PATTERNS: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        // AWS Access Key ID
        r"AKIA[0-9A-Z]{16}",
        // GitHub Personal Access Token (classic)
        r"gh[ps]_[A-Za-z0-9_]{36,}",
        // GitHub Fine-grained PAT
        r"github_pat_[A-Za-z0-9_]{82,}",
        // GitLab Personal Access Token
        r"glpat-[A-Za-z0-9\-_]{20,}",
        // Slack tokens
        r"xox[baprs]-[0-9a-zA-Z\-]{10,}",
        // OpenAI project key
        r"sk-proj-[A-Za-z0-9\-_]{40,}",
        // Anthropic API key
        r"sk-ant-[A-Za-z0-9\-_]{20,}",
        // Stripe secret/publishable key
        r"[rs]k_(test|live)_[A-Za-z0-9]{24,}",
        // Google API key
        r"AIza[0-9A-Za-z\-_]{35}",
        // JWT token
        r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+",
        // Private key header
        r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        // npm token
        r"npm_[A-Za-z0-9]{36}",
        // PyPI token
        r"pypi-[A-Za-z0-9]{16,}",
        // SendGrid API key
        r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        // Twilio API key
        r"SK[a-f0-9]{32}",
        // Discord bot token
        r"[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}",
    ])
    .expect("secret patterns should compile")
});

pub fn has_secret(text: &str) -> bool {
    SECRET_PATTERNS.is_match(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_aws_key() {
        assert!(has_secret("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn detects_github_pat() {
        assert!(has_secret(&format!("ghp_{}", "a".repeat(36))));
        assert!(has_secret(&format!("ghs_{}", "b".repeat(36))));
        assert!(has_secret(&format!("github_pat_{}", "c".repeat(82))));
    }

    #[test]
    fn detects_gitlab_pat() {
        assert!(has_secret(&format!("glpat-{}", "x".repeat(20))));
    }

    #[test]
    fn detects_slack_token() {
        assert!(has_secret("xoxb-1234567890-abcdef"));
    }

    #[test]
    fn detects_openai_key() {
        assert!(has_secret(&format!("sk-proj-{}", "a".repeat(40))));
    }

    #[test]
    fn detects_anthropic_key() {
        assert!(has_secret(&format!("sk-ant-{}", "a".repeat(20))));
    }

    #[test]
    fn detects_stripe_key() {
        assert!(has_secret(&format!("sk_live_{}", "a".repeat(24))));
        assert!(has_secret(&format!("rk_test_{}", "b".repeat(24))));
    }

    #[test]
    fn detects_google_api_key() {
        assert!(has_secret(&format!("AIza{}", "a".repeat(35))));
    }

    #[test]
    fn detects_jwt() {
        assert!(has_secret(
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456"
        ));
    }

    #[test]
    fn detects_private_key() {
        assert!(has_secret("-----BEGIN PRIVATE KEY-----"));
        assert!(has_secret("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(has_secret("-----BEGIN EC PRIVATE KEY-----"));
        assert!(has_secret("-----BEGIN OPENSSH PRIVATE KEY-----"));
    }

    #[test]
    fn detects_npm_token() {
        assert!(has_secret(&format!("npm_{}", "a".repeat(36))));
    }

    #[test]
    fn detects_pypi_token() {
        assert!(has_secret(&format!("pypi-{}", "a".repeat(16))));
    }

    #[test]
    fn detects_sendgrid_key() {
        let key = format!("SG.{}.{}", "a".repeat(22), "b".repeat(43));
        assert!(has_secret(&key));
    }

    #[test]
    fn detects_twilio_key() {
        assert!(has_secret(&format!("SK{}", "a".repeat(32))));
    }

    #[test]
    fn detects_discord_bot_token() {
        let token = format!("M{}.{}.{}", "a".repeat(23), "b".repeat(6), "c".repeat(27));
        assert!(has_secret(&token));
    }

    #[test]
    fn clean_text_passes() {
        assert!(!has_secret("Normal markdown content"));
        assert!(!has_secret("sk-not-long-enough"));
        assert!(!has_secret("The API key format is documented here"));
        assert!(!has_secret("ghp_tooshort"));
        assert!(!has_secret("Just a regular sentence with no secrets."));
    }
}
