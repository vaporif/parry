//! Python-specific exfiltration detection.

use tree_sitter::Language;

use super::lang::LangExfilDetector;

pub struct PythonDetector;

impl LangExfilDetector for PythonDetector {
    fn language(&self) -> Language {
        tree_sitter_python::LANGUAGE.into()
    }

    fn network_sink_query(&self) -> &'static str {
        // Match function calls that are network sinks:
        // - urllib.request.urlopen(...)
        // - urllib.urlopen(...)
        // - requests.get/post/put/delete(...)
        // - http.client.HTTPConnection(...)
        // - socket.connect(...)
        // - socket.create_connection(...)
        r#"
        (call
          function: [
            ;; urllib.request.urlopen or urllib.urlopen
            (attribute
              object: (attribute) @obj
              attribute: (identifier) @method)
            (attribute
              object: (identifier) @obj
              attribute: (identifier) @method)
          ]
          (#match? @method "^(urlopen|get|post|put|delete|patch|request|connect|create_connection)$")
        ) @call

        (call
          function: (identifier) @fn
          (#match? @fn "^(urlopen)$")
        ) @call
        "#
    }

    fn file_source_query(&self) -> &'static str {
        // Match file reading operations:
        // - open(path)
        // - open(path).read()
        // - Path(path).read_text()
        r#"
        (call
          function: (identifier) @fn
          arguments: (argument_list
            (string) @path)
          (#match? @fn "^(open)$")
        ) @call

        (call
          function: (attribute
            object: (call
              function: (identifier) @fn
              (#match? @fn "^(open)$"))
            attribute: (identifier) @method
            (#match? @method "^(read|readlines|readline)$"))
        ) @call
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
        let detector = PythonDetector;
        let result = Query::new(&detector.language(), detector.network_sink_query());
        assert!(result.is_ok(), "Query error: {:?}", result.err());
    }

    #[test]
    fn file_source_query_is_valid() {
        let detector = PythonDetector;
        let result = Query::new(&detector.language(), detector.file_source_query());
        assert!(result.is_ok(), "Query error: {:?}", result.err());
    }

    #[test]
    fn string_literal_query_is_valid() {
        let detector = PythonDetector;
        let result = Query::new(&detector.language(), detector.string_literal_query());
        assert!(result.is_ok(), "Query error: {:?}", result.err());
    }
}
