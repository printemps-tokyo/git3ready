//! A very small JSON reader and writer.
//!
//! git3ready emits fixed, small JSON documents (the scan report, the rule
//! list, the environment check), so this module hand-rolls them rather than
//! adding `serde` plus `serde_json` to the dependency tree. The reader exists
//! so the tests can prove every document git3ready prints parses back.
//!
//! The parser accepts RFC 8259 JSON with two deliberate relaxations that make
//! hand-written input pleasant:
//!
//! - `//` line comments and `/* */` block comments are skipped.
//! - A single trailing comma is allowed before `]` or `}`.
//!
//! Numbers are parsed as `f64`. Object member order is preserved, and duplicate
//! keys keep the last value, matching what every mainstream parser does.

use std::fmt::Write as _;

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

/// Escape a string and wrap it in double quotes, ready to splice into output.
pub fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            // Control characters have no short escape; \u form is required.
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

/// A parsed JSON value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Value>),
    /// Members in source order.
    Object(Vec<(String, Value)>),
}

impl Value {
    /// The name of this value's type, for error messages.
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Null => "null",
            Value::Bool(_) => "boolean",
            Value::Number(_) => "number",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
        }
    }

    /// Look a member up by key. Later duplicates win.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(members) => members.iter().rev().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&[(String, Value)]> {
        match self {
            Value::Object(members) => Some(members),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }
}

/// Parse a complete JSON document. Errors carry a 1-based line and column.
pub fn parse(input: &str) -> Result<Value, String> {
    let mut p = Parser {
        src: input.as_bytes(),
        text: input,
        pos: 0,
    };
    p.skip_trivia();
    let value = p.value()?;
    p.skip_trivia();
    if p.pos < p.src.len() {
        return Err(p.error("trailing content after the top-level value"));
    }
    Ok(value)
}

struct Parser<'a> {
    src: &'a [u8],
    text: &'a str,
    pos: usize,
}

impl Parser<'_> {
    fn error(&self, msg: &str) -> String {
        let (line, col) = self.line_col();
        format!("line {line}, column {col}: {msg}")
    }

    fn line_col(&self) -> (usize, usize) {
        let upto = &self.text[..self.pos.min(self.text.len())];
        let line = upto.matches('\n').count() + 1;
        let col = upto
            .rsplit('\n')
            .next()
            .map_or(1, |l| l.chars().count() + 1);
        (line, col)
    }

    fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    /// Skip whitespace and both comment forms.
    fn skip_trivia(&mut self) {
        loop {
            while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
                self.pos += 1;
            }
            if self.src[self.pos..].starts_with(b"//") {
                self.pos += 2;
                while !matches!(self.peek(), None | Some(b'\n')) {
                    self.pos += 1;
                }
                continue;
            }
            if self.src[self.pos..].starts_with(b"/*") {
                self.pos += 2;
                while self.pos < self.src.len() && !self.src[self.pos..].starts_with(b"*/") {
                    self.pos += 1;
                }
                // An unterminated block comment just swallows the rest; the
                // parser then reports an unexpected end of input.
                self.pos = (self.pos + 2).min(self.src.len());
                continue;
            }
            return;
        }
    }

    fn value(&mut self) -> Result<Value, String> {
        match self.peek() {
            None => Err(self.error("unexpected end of input")),
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            Some(b'n') => self.literal("null", Value::Null),
            Some(_) => self.number(),
        }
    }

    fn literal(&mut self, word: &str, value: Value) -> Result<Value, String> {
        if self.src[self.pos..].starts_with(word.as_bytes()) {
            self.pos += word.len();
            Ok(value)
        } else {
            Err(self.error(&format!("expected '{word}'")))
        }
    }

    fn object(&mut self) -> Result<Value, String> {
        self.pos += 1; // '{'
        let mut members: Vec<(String, Value)> = Vec::new();
        loop {
            self.skip_trivia();
            if self.peek() == Some(b'}') {
                self.pos += 1;
                return Ok(Value::Object(members));
            }
            if self.peek() != Some(b'"') {
                return Err(self.error("expected a quoted member name"));
            }
            let key = self.string()?;
            self.skip_trivia();
            if self.peek() != Some(b':') {
                return Err(self.error("expected ':' after the member name"));
            }
            self.pos += 1;
            self.skip_trivia();
            let value = self.value()?;
            members.push((key, value));
            self.skip_trivia();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Value::Object(members));
                }
                _ => return Err(self.error("expected ',' or '}'")),
            }
        }
    }

    fn array(&mut self) -> Result<Value, String> {
        self.pos += 1; // '['
        let mut items = Vec::new();
        loop {
            self.skip_trivia();
            if self.peek() == Some(b']') {
                self.pos += 1;
                return Ok(Value::Array(items));
            }
            items.push(self.value()?);
            self.skip_trivia();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Value::Array(items));
                }
                _ => return Err(self.error("expected ',' or ']'")),
            }
        }
    }

    fn string(&mut self) -> Result<String, String> {
        self.pos += 1; // opening quote
        let mut out = String::new();
        loop {
            let Some(b) = self.peek() else {
                return Err(self.error("unterminated string"));
            };
            match b {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.pos += 1;
                    let Some(esc) = self.peek() else {
                        return Err(self.error("unterminated escape"));
                    };
                    self.pos += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{08}'),
                        b'f' => out.push('\u{0c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => out.push(self.unicode_escape()?),
                        other => {
                            return Err(
                                self.error(&format!("unknown escape '\\{}'", char::from(other)))
                            )
                        }
                    }
                }
                0x00..=0x1f => return Err(self.error("raw control character in a string")),
                _ => {
                    // Copy one whole UTF-8 scalar. The input came from &str, so
                    // the byte length is always valid here.
                    let rest = &self.text[self.pos..];
                    let c = rest.chars().next().expect("non-empty by construction");
                    out.push(c);
                    self.pos += c.len_utf8();
                }
            }
        }
    }

    /// Read the four hex digits of a `\u` escape, joining surrogate pairs.
    fn unicode_escape(&mut self) -> Result<char, String> {
        let high = self.hex4()?;
        if !(0xd800..0xdc00).contains(&high) {
            return char::from_u32(high).ok_or_else(|| self.error("invalid \\u escape"));
        }
        if !self.src[self.pos..].starts_with(b"\\u") {
            return Err(self.error("lone high surrogate in a \\u escape"));
        }
        self.pos += 2;
        let low = self.hex4()?;
        if !(0xdc00..0xe000).contains(&low) {
            return Err(self.error("expected a low surrogate"));
        }
        let combined = 0x1_0000 + ((high - 0xd800) << 10) + (low - 0xdc00);
        char::from_u32(combined).ok_or_else(|| self.error("invalid surrogate pair"))
    }

    fn hex4(&mut self) -> Result<u32, String> {
        if self.pos + 4 > self.src.len() {
            return Err(self.error("truncated \\u escape"));
        }
        let digits = &self.text[self.pos..self.pos + 4];
        let n = u32::from_str_radix(digits, 16)
            .map_err(|_| self.error("\\u escape needs four hex digits"))?;
        self.pos += 4;
        Ok(n)
    }

    fn number(&mut self) -> Result<Value, String> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while matches!(
            self.peek(),
            Some(b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')
        ) {
            self.pos += 1;
        }
        if start == self.pos {
            return Err(self.error("expected a value"));
        }
        let text = &self.text[start..self.pos];
        match text.parse::<f64>() {
            Ok(n) => Ok(Value::Number(n)),
            Err(_) => {
                let msg = format!("'{text}' is not a number");
                Err(self.error(&msg))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_escapes_the_json_specials() {
        assert_eq!(quote(r#"a"b\c"#), r#""a\"b\\c""#);
        assert_eq!(quote("a\nb\tc\r"), r#""a\nb\tc\r""#);
        assert_eq!(quote("\u{1}"), "\"\\u0001\"");
        assert_eq!(quote("日本語 ok"), "\"日本語 ok\"");
    }

    #[test]
    fn parses_the_basic_shapes() {
        let v = parse(r#"{"a": 1, "b": [true, false, null], "c": "x"}"#).unwrap();
        assert_eq!(v.get("a"), Some(&Value::Number(1.0)));
        assert_eq!(v.get("b").unwrap().as_array().unwrap().len(), 3);
        assert_eq!(v.get("c").unwrap().as_str(), Some("x"));
        assert!(v.get("missing").is_none());
    }

    #[test]
    fn round_trips_quoting_through_the_parser() {
        for s in ["plain", "with \"quotes\"", "tab\there", "日本語", "\u{7}"] {
            let doc = format!("[{}]", quote(s));
            let parsed = parse(&doc).unwrap();
            assert_eq!(parsed.as_array().unwrap()[0].as_str(), Some(s));
        }
    }

    #[test]
    fn accepts_comments_and_one_trailing_comma() {
        let v = parse(
            r#"
            // leading comment
            {
              /* block */
              "a": 1,
              "b": [1, 2,],
            }
            "#,
        )
        .unwrap();
        assert_eq!(v.get("b").unwrap().as_array().unwrap().len(), 2);
    }

    #[test]
    fn decodes_unicode_escapes_including_surrogate_pairs() {
        let v = parse(r#""Aé😀""#).unwrap();
        assert_eq!(v.as_str(), Some("Aé\u{1f600}"));
    }

    #[test]
    fn reports_line_and_column_on_error() {
        let err = parse("{\n  \"a\": ,\n}").unwrap_err();
        assert!(err.starts_with("line 2, column 8"), "{err}");
    }

    #[test]
    fn rejects_broken_documents() {
        for bad in [
            "",
            "{",
            "[1, 2",
            r#"{"a" 1}"#,
            r#"{a: 1}"#,
            r#""unterminated"#,
            "{} extra",
            r#""\q""#,
            r#""\ud83d""#,
        ] {
            assert!(parse(bad).is_err(), "{bad:?} should not parse");
        }
    }

    #[test]
    fn last_duplicate_key_wins() {
        let v = parse(r#"{"a": 1, "a": 2}"#).unwrap();
        assert_eq!(v.get("a"), Some(&Value::Number(2.0)));
    }
}
