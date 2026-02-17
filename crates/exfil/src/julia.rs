//! Julia-specific exfiltration detection.

use tree_sitter::Language;

use super::lang::LangExfilDetector;

pub struct JuliaDetector;

impl LangExfilDetector for JuliaDetector {
    fn language(&self) -> Language {
        tree_sitter_julia::LANGUAGE.into()
    }

    fn network_sink_query(&self) -> &'static str {
        // Match network operations:
        // - HTTP.request/get/post
        // - Downloads.download
        // - download()
        r#"
        (call_expression
          (field_expression) @fn
          (#match? @fn "(HTTP|Downloads)\\.(request|get|post|put|download)")
        ) @call

        (call_expression
          (identifier) @fn
          (#match? @fn "^(download|request)$")
        ) @call
        "#
    }

    fn file_source_query(&self) -> &'static str {
        // Match file reading operations:
        // - read(file)
        // - open(file)
        // - readlines(file)
        r#"
        (call_expression
          (identifier) @fn
          (#match? @fn "^(read|open|readlines|readchomp|readline)$")
        ) @call
        "#
    }

    fn string_literal_query(&self) -> &'static str {
        r"
        (string_literal) @string
        "
    }
}

#[cfg(test)]
mod tests {
    use tree_sitter::Query;

    use super::*;

    #[test]
    fn network_sink_query_is_valid() {
        let detector = JuliaDetector;
        let result = Query::new(&detector.language(), detector.network_sink_query());
        assert!(result.is_ok(), "Query error: {:?}", result.err());
    }

    #[test]
    fn file_source_query_is_valid() {
        let detector = JuliaDetector;
        let result = Query::new(&detector.language(), detector.file_source_query());
        assert!(result.is_ok(), "Query error: {:?}", result.err());
    }

    #[test]
    fn string_literal_query_is_valid() {
        let detector = JuliaDetector;
        let result = Query::new(&detector.language(), detector.string_literal_query());
        assert!(result.is_ok(), "Query error: {:?}", result.err());
    }
}
