//! Scala-specific exfiltration detection.

use tree_sitter::Language;

use super::lang::LangExfilDetector;

pub struct ScalaDetector;

impl LangExfilDetector for ScalaDetector {
    fn language(&self) -> Language {
        tree_sitter_scala::LANGUAGE.into()
    }

    fn network_sink_query(&self) -> &'static str {
        // Match network operations via identifier patterns
        r#"
        (identifier) @fn
        (#match? @fn "(fromURL|singleRequest|request|get|post|execute|URL|HttpURLConnection|Socket)")
        "#
    }

    fn file_source_query(&self) -> &'static str {
        // Match file reading operations via identifier patterns
        r#"
        (identifier) @fn
        (#match? @fn "(fromFile|readAllLines|readString|getLines|File|FileReader|FileInputStream|BufferedReader)")
        "#
    }

    fn string_literal_query(&self) -> &'static str {
        r"
        (string) @string
        (interpolated_string_expression) @string
        "
    }
}

#[cfg(test)]
mod tests {
    use tree_sitter::Query;

    use super::*;

    #[test]
    fn network_sink_query_is_valid() {
        let detector = ScalaDetector;
        let result = Query::new(&detector.language(), detector.network_sink_query());
        assert!(result.is_ok(), "Query error: {:?}", result.err());
    }

    #[test]
    fn file_source_query_is_valid() {
        let detector = ScalaDetector;
        let result = Query::new(&detector.language(), detector.file_source_query());
        assert!(result.is_ok(), "Query error: {:?}", result.err());
    }

    #[test]
    fn string_literal_query_is_valid() {
        let detector = ScalaDetector;
        let result = Query::new(&detector.language(), detector.string_literal_query());
        assert!(result.is_ok(), "Query error: {:?}", result.err());
    }
}
