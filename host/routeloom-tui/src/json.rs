//! Minimal JSON parser (std-only). The daemon emits hand-rolled JSON; the
//! TUI parses exactly what `routeloomctl` prints — there is no second
//! protocol. Numbers keep their raw token so u64 request/node IDs do not lose
//! precision through `f64`.

use std::fmt;

#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(entries) => entries
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Number(raw) => raw.parse().ok(),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Json::Number(raw) => raw.parse().ok(),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::String(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Array(items) => Some(items),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Json::Null)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JsonError {
    pub offset: usize,
    pub message: String,
}

impl fmt::Display for JsonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "JSON error at byte {}: {}",
            self.offset, self.message
        )
    }
}

impl std::error::Error for JsonError {}

pub fn parse(input: &str) -> Result<Json, JsonError> {
    let mut parser = Parser {
        bytes: input.as_bytes(),
        pos: 0,
    };
    parser.skip_ws();
    let value = parser.value()?;
    parser.skip_ws();
    if parser.pos != parser.bytes.len() {
        return Err(parser.error("trailing characters"));
    }
    Ok(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn error(&self, message: &str) -> JsonError {
        JsonError {
            offset: self.pos,
            message: message.to_string(),
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), JsonError> {
        if self.peek() == Some(byte) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.error(&format!("expected '{}'", byte as char)))
        }
    }

    fn literal(&mut self, text: &str, value: Json) -> Result<Json, JsonError> {
        if self.bytes[self.pos..].starts_with(text.as_bytes()) {
            self.pos += text.len();
            Ok(value)
        } else {
            Err(self.error("invalid literal"))
        }
    }

    fn value(&mut self) -> Result<Json, JsonError> {
        self.skip_ws();
        match self.peek() {
            Some(b'n') => self.literal("null", Json::Null),
            Some(b't') => self.literal("true", Json::Bool(true)),
            Some(b'f') => self.literal("false", Json::Bool(false)),
            Some(b'"') => Ok(Json::String(self.string()?)),
            Some(b'[') => self.array(),
            Some(b'{') => self.object(),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => Err(self.error("unexpected character")),
            None => Err(self.error("unexpected end of input")),
        }
    }

    fn number(&mut self) -> Result<Json, JsonError> {
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
            return Err(self.error("invalid number"));
        }
        let raw = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| self.error("invalid number"))?;
        // Reject tokens that are not numbers at all (e.g. a bare "-").
        if raw.parse::<f64>().is_err() {
            return Err(self.error("invalid number"));
        }
        Ok(Json::Number(raw.to_string()))
    }

    fn string(&mut self) -> Result<String, JsonError> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return Err(self.error("unterminated string")),
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.pos += 1;
                    out.push(self.escape()?);
                }
                Some(byte) => {
                    // Input is valid UTF-8 (it arrived as &str); copy the full
                    // multi-byte sequence verbatim.
                    let len = utf8_len(byte);
                    let end = self.pos + len;
                    if end > self.bytes.len() {
                        return Err(self.error("truncated UTF-8"));
                    }
                    out.push_str(
                        std::str::from_utf8(&self.bytes[self.pos..end])
                            .map_err(|_| self.error("invalid UTF-8"))?,
                    );
                    self.pos = end;
                }
            }
        }
    }

    fn escape(&mut self) -> Result<char, JsonError> {
        let byte = self.peek().ok_or_else(|| self.error("dangling escape"))?;
        self.pos += 1;
        Ok(match byte {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{0008}',
            b'f' => '\u{000c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => {
                let first = self.hex4()?;
                if (0xd800..0xdc00).contains(&first) {
                    // Surrogate pair: expect \uXXXX low surrogate.
                    if self.peek() == Some(b'\\') {
                        self.pos += 1;
                        self.expect(b'u')?;
                        let second = self.hex4()?;
                        if !(0xdc00..0xe000).contains(&second) {
                            return Err(self.error("invalid low surrogate"));
                        }
                        let scalar = 0x1_0000 + ((first - 0xd800) << 10) + (second - 0xdc00);
                        char::from_u32(scalar).ok_or_else(|| self.error("invalid surrogate"))?
                    } else {
                        return Err(self.error("lone high surrogate"));
                    }
                } else {
                    char::from_u32(first).ok_or_else(|| self.error("invalid \\u scalar"))?
                }
            }
            _ => return Err(self.error("invalid escape")),
        })
    }

    fn hex4(&mut self) -> Result<u32, JsonError> {
        let mut value = 0_u32;
        for _ in 0..4 {
            let byte = self.peek().ok_or_else(|| self.error("short \\u escape"))?;
            let digit = (byte as char)
                .to_digit(16)
                .ok_or_else(|| self.error("invalid \\u escape"))?;
            value = value * 16 + digit;
            self.pos += 1;
        }
        Ok(value)
    }

    fn array(&mut self) -> Result<Json, JsonError> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Json::Array(items));
        }
        loop {
            items.push(self.value()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Json::Array(items));
                }
                _ => return Err(self.error("expected ',' or ']'")),
            }
        }
    }

    fn object(&mut self) -> Result<Json, JsonError> {
        self.expect(b'{')?;
        let mut entries = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Json::Object(entries));
        }
        loop {
            self.skip_ws();
            let key = self.string()?;
            self.skip_ws();
            self.expect(b':')?;
            let value = self.value()?;
            entries.push((key, value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Json::Object(entries));
                }
                _ => return Err(self.error("expected ',' or '}'")),
            }
        }
    }
}

fn utf8_len(first: u8) -> usize {
    if first < 0x80 {
        1
    } else if first < 0xe0 {
        2
    } else if first < 0xf0 {
        3
    } else {
        4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_daemon_shapes() {
        let value =
            parse(r#"{"connected":true,"device":null,"rx_frames":12,"last_error":"x\"y\\z"}"#)
                .unwrap();
        assert_eq!(value.get("connected").unwrap().as_bool(), Some(true));
        assert!(value.get("device").unwrap().is_null());
        assert_eq!(value.get("rx_frames").unwrap().as_u64(), Some(12));
        assert_eq!(value.get("last_error").unwrap().as_str(), Some("x\"y\\z"));
    }

    #[test]
    fn big_numbers_keep_precision() {
        let value = parse("{\"id\":18446744073709551615}").unwrap();
        assert_eq!(
            value.get("id").unwrap().as_u64(),
            Some(18_446_744_073_709_551_615)
        );
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse("{").is_err());
        assert!(parse("{\"a\":}").is_err());
        assert!(parse("[1,]").is_err());
        assert!(parse("-").is_err());
        assert!(parse("{\"a\":1} extra").is_err());
    }

    #[test]
    fn unicode_escapes() {
        let value = parse(r#""aéb""#).unwrap();
        assert_eq!(value.as_str(), Some("a\u{e9}b"));
    }
}
