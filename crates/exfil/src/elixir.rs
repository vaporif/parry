//! Elixir-specific exfiltration detection.

use tree_sitter::Language;

use super::lang::LangExfilDetector;

pub struct ElixirDetector;

impl LangExfilDetector for ElixirDetector {
    fn language(&self) -> Language {
        tree_sitter_elixir::LANGUAGE.into()
    }

    fn network_sink_query(&self) -> &'static str {
        // Match network operations via identifier patterns
        r#"
        (identifier) @fn
        (#match? @fn "^(get|post|put|delete|request|get!|post!)$")
        "#
    }

    fn file_source_query(&self) -> &'static str {
        // Match file reading operations via identifier patterns
        r#"
        (identifier) @fn
        (#match? @fn "^(read|read!|stream!|open)$")
        "#
    }

    fn string_literal_query(&self) -> &'static str {
        r"
        (string) @string
        "
    }
}

#[cfg(test)]
mod tests {
    use tree_sitter::Query;

    use super::*;

    #[test]
    fn network_sink_query_is_valid() {
        let detector = ElixirDetector;
        let result = Query::new(&detector.language(), detector.network_sink_query());
        assert!(result.is_ok(), "Query error: {:?}", result.err());
    }

    #[test]
    fn file_source_query_is_valid() {
        let detector = ElixirDetector;
        let result = Query::new(&detector.language(), detector.file_source_query());
        assert!(result.is_ok(), "Query error: {:?}", result.err());
    }

    #[test]
    fn string_literal_query_is_valid() {
        let detector = ElixirDetector;
        let result = Query::new(&detector.language(), detector.string_literal_query());
        assert!(result.is_ok(), "Query error: {:?}", result.err());
    }
}
