//! Perl-specific exfiltration detection.

use tree_sitter::Language;

use super::lang::LangExfilDetector;

pub struct PerlDetector;

impl LangExfilDetector for PerlDetector {
    fn language(&self) -> Language {
        tree_sitter_perl::LANGUAGE.into()
    }

    fn network_sink_query(&self) -> &'static str {
        // Match network operations via identifier patterns
        r#"
        (identifier) @fn
        (#match? @fn "(get|post|request|socket|connect|LWP|HTTP|IO::Socket)")
        "#
    }

    fn file_source_query(&self) -> &'static str {
        // Match file reading operations via identifier patterns
        r#"
        (identifier) @fn
        (#match? @fn "(open|read|slurp)")
        "#
    }

    fn string_literal_query(&self) -> &'static str {
        r"
        (string_single_quoted) @string
        (string_double_quoted) @string
        (string_q_quoted) @string
        (string_qq_quoted) @string
        "
    }
}

#[cfg(test)]
mod tests {
    use tree_sitter::Query;

    use super::*;

    #[test]
    fn network_sink_query_is_valid() {
        let detector = PerlDetector;
        let result = Query::new(&detector.language(), detector.network_sink_query());
        assert!(result.is_ok(), "Query error: {:?}", result.err());
    }

    #[test]
    fn file_source_query_is_valid() {
        let detector = PerlDetector;
        let result = Query::new(&detector.language(), detector.file_source_query());
        assert!(result.is_ok(), "Query error: {:?}", result.err());
    }

    #[test]
    fn string_literal_query_is_valid() {
        let detector = PerlDetector;
        let result = Query::new(&detector.language(), detector.string_literal_query());
        assert!(result.is_ok(), "Query error: {:?}", result.err());
    }
}
