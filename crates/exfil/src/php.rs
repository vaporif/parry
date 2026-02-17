//! PHP-specific exfiltration detection.

use tree_sitter::Language;

use super::lang::LangExfilDetector;

pub struct PhpDetector;

impl LangExfilDetector for PhpDetector {
    fn language(&self) -> Language {
        tree_sitter_php::LANGUAGE_PHP.into()
    }

    fn network_sink_query(&self) -> &'static str {
        // Match network operations:
        // - curl_exec(...)
        // - file_get_contents('http...')
        // - fopen('http...')
        // - fsockopen(...)
        r#"
        (function_call_expression
          function: (name) @fn
          (#match? @fn "^(curl_exec|curl_init|file_get_contents|fopen|fsockopen|stream_socket_client)$")
        ) @call
        "#
    }

    fn file_source_query(&self) -> &'static str {
        // Match file reading operations:
        // - file_get_contents(path)
        // - fopen(path, 'r')
        // - file(path)
        // - readfile(path)
        r#"
        (function_call_expression
          function: (name) @fn
          arguments: (arguments
            (argument
              (string) @path))
          (#match? @fn "^(file_get_contents|fopen|file|readfile|fread|fgets)$")
        ) @call
        "#
    }

    fn string_literal_query(&self) -> &'static str {
        r"
        (string) @string
        (encapsed_string) @string
        "
    }
}

#[cfg(test)]
mod tests {
    use tree_sitter::Query;

    use super::*;

    #[test]
    fn network_sink_query_is_valid() {
        let detector = PhpDetector;
        let result = Query::new(&detector.language(), detector.network_sink_query());
        assert!(result.is_ok(), "Query error: {:?}", result.err());
    }

    #[test]
    fn file_source_query_is_valid() {
        let detector = PhpDetector;
        let result = Query::new(&detector.language(), detector.file_source_query());
        assert!(result.is_ok(), "Query error: {:?}", result.err());
    }

    #[test]
    fn string_literal_query_is_valid() {
        let detector = PhpDetector;
        let result = Query::new(&detector.language(), detector.string_literal_query());
        assert!(result.is_ok(), "Query error: {:?}", result.err());
    }
}
