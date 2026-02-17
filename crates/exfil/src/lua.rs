//! Lua-specific exfiltration detection.

use tree_sitter::Language;

use super::lang::LangExfilDetector;

pub struct LuaDetector;

impl LangExfilDetector for LuaDetector {
    fn language(&self) -> Language {
        tree_sitter_lua::LANGUAGE.into()
    }

    fn network_sink_query(&self) -> &'static str {
        // Match network operations:
        // - socket.http.request
        // - socket.connect
        // - http.request (LuaSocket)
        r#"
        (function_call
          name: [
            (dot_index_expression) @fn
            (identifier) @fn
          ]
          (#match? @fn "(http|socket|request|connect)")
        ) @call
        "#
    }

    fn file_source_query(&self) -> &'static str {
        // Match file reading operations:
        // - io.open(file)
        // - io.read()
        // - file:read()
        r#"
        (function_call
          name: [
            (dot_index_expression) @fn
            (method_index_expression) @fn
          ]
          (#match? @fn "(open|read|lines)")
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
        let detector = LuaDetector;
        let result = Query::new(&detector.language(), detector.network_sink_query());
        assert!(result.is_ok(), "Query error: {:?}", result.err());
    }

    #[test]
    fn file_source_query_is_valid() {
        let detector = LuaDetector;
        let result = Query::new(&detector.language(), detector.file_source_query());
        assert!(result.is_ok(), "Query error: {:?}", result.err());
    }

    #[test]
    fn string_literal_query_is_valid() {
        let detector = LuaDetector;
        let result = Query::new(&detector.language(), detector.string_literal_query());
        assert!(result.is_ok(), "Query error: {:?}", result.err());
    }
}
