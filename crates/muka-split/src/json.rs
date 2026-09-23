//! A strict, zero-copy JSON *span* scanner.
//!
//! This is deliberately **not** a parser that builds a tree we later
//! re-serialise. It only reports byte ranges: `serde_json` re-writing a body
//! would reorder object keys (its default map is sorted), reformat numbers
//! (`1.0`, `1e10`) and unescape `\uXXXX`, which would silently change the
//! prompt the upstream tokenises and break its prefix cache.
//!
//! Every span handed back must satisfy: `&buf[span]` parses as a JSON value and
//! round-trips byte-identically. Invariants are asserted by tests in
//! `tests/identity.rs`.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub const fn new(start: usize, end: usize) -> Self {
        Span { start, end }
    }
    pub const fn len(&self) -> usize {
        self.end - self.start
    }
    pub const fn is_empty(&self) -> bool {
        self.end == self.start
    }
    pub fn slice<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        &buf[self.start..self.end]
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ValueKind {
    String,
    Number,
    Object,
    Array,
    Bool,
    Null,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ValueSpan {
    pub span: Span,
    pub kind: ValueKind,
}

#[derive(Clone, Debug)]
pub struct Member {
    /// Unescaped key, used only for matching against known field names.
    pub key: Box<[u8]>,
    pub key_span: Span,
    pub value: ValueSpan,
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum ScanError {
    #[error("json: truncated input at {0}")]
    Eof(usize),
    #[error("json: {0} at offset {1}")]
    Syntax(&'static str, usize),
    #[error("json: nesting deeper than {0}")]
    TooDeep(usize),
}

pub const MAX_DEPTH: usize = 128;

const fn is_ws(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\r' | b'\n')
}

#[inline]
fn at(buf: &[u8], i: usize) -> Result<u8, ScanError> {
    buf.get(i).copied().ok_or(ScanError::Eof(i))
}

/// Index of the first non-whitespace byte at or after `i`.
pub fn skip_ws(buf: &[u8], mut i: usize) -> usize {
    while i < buf.len() && is_ws(buf[i]) {
        i += 1;
    }
    i
}

/// `buf[at]` must be `"`. Returns the span including both quotes.
pub fn scan_string(buf: &[u8], at_pos: usize) -> Result<Span, ScanError> {
    if at(buf, at_pos)? != b'"' {
        return Err(ScanError::Syntax("expected string", at_pos));
    }
    let mut i = at_pos + 1;
    loop {
        let c = at(buf, i)?;
        match c {
            b'"' => return Ok(Span::new(at_pos, i + 1)),
            b'\\' => {
                let e = at(buf, i + 1)?;
                match e {
                    b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => i += 2,
                    b'u' => {
                        // four hex digits
                        for k in 0..4 {
                            let h = at(buf, i + 2 + k)?;
                            if !h.is_ascii_hexdigit() {
                                return Err(ScanError::Syntax("bad \\u escape", i + 2 + k));
                            }
                        }
                        i += 6;
                    }
                    _ => return Err(ScanError::Syntax("bad escape", i + 1)),
                }
            }
            _ if c < 0x20 => return Err(ScanError::Syntax("raw control byte in string", i)),
            _ => i += 1,
        }
    }
}

fn scan_number(buf: &[u8], start: usize) -> Result<Span, ScanError> {
    let mut i = start;
    if at(buf, i)? == b'-' {
        i += 1;
    }
    let first = at(buf, i)?;
    match first {
        b'0' => {
            i += 1;
        }
        b'1'..=b'9' => {
            while i < buf.len() && buf[i].is_ascii_digit() {
                i += 1;
            }
        }
        _ => return Err(ScanError::Syntax("bad number", i)),
    }
    if i < buf.len() && buf[i] == b'.' {
        i += 1;
        let mut n = 0;
        while i < buf.len() && buf[i].is_ascii_digit() {
            i += 1;
            n += 1;
        }
        if n == 0 {
            return Err(ScanError::Syntax("bad fraction", i));
        }
    }
    if i < buf.len() && (buf[i] == b'e' || buf[i] == b'E') {
        i += 1;
        if i < buf.len() && (buf[i] == b'+' || buf[i] == b'-') {
            i += 1;
        }
        let mut n = 0;
        while i < buf.len() && buf[i].is_ascii_digit() {
            i += 1;
            n += 1;
        }
        if n == 0 {
            return Err(ScanError::Syntax("bad exponent", i));
        }
    }
    Ok(Span::new(start, i))
}

fn scan_literal(buf: &[u8], start: usize, lit: &[u8]) -> Result<Span, ScanError> {
    if buf.len() < start + lit.len() || &buf[start..start + lit.len()] != lit {
        return Err(ScanError::Syntax("bad literal", start));
    }
    Ok(Span::new(start, start + lit.len()))
}

/// Scan one JSON value beginning at `pos` (leading whitespace skipped by the
/// caller or by this function - both are accepted).
pub fn scan_value(buf: &[u8], pos: usize) -> Result<ValueSpan, ScanError> {
    scan_value_depth(buf, pos, 0)
}

fn scan_value_depth(buf: &[u8], pos: usize, depth: usize) -> Result<ValueSpan, ScanError> {
    if depth > MAX_DEPTH {
        return Err(ScanError::TooDeep(pos));
    }
    let i = skip_ws(buf, pos);
    let c = at(buf, i)?;
    let (span, kind) = match c {
        b'"' => (scan_string(buf, i)?, ValueKind::String),
        b'{' | b'[' => {
            let close = if c == b'{' { b'}' } else { b']' };
            let mut j = i + 1;
            let mut d = 1usize;
            loop {
                let b = at(buf, j)?;
                match b {
                    b'"' => j = scan_string(buf, j)?.end,
                    b'{' | b'[' => {
                        d += 1;
                        if d > MAX_DEPTH {
                            return Err(ScanError::TooDeep(j));
                        }
                        j += 1;
                    }
                    b'}' | b']' => {
                        d -= 1;
                        j += 1;
                        if d == 0 {
                            if b != close {
                                return Err(ScanError::Syntax("mismatched bracket", j - 1));
                            }
                            break;
                        }
                    }
                    _ => j += 1,
                }
            }
            let kind = if c == b'{' {
                ValueKind::Object
            } else {
                ValueKind::Array
            };
            (Span::new(i, j), kind)
        }
        b't' => (scan_literal(buf, i, b"true")?, ValueKind::Bool),
        b'f' => (scan_literal(buf, i, b"false")?, ValueKind::Bool),
        b'n' => (scan_literal(buf, i, b"null")?, ValueKind::Null),
        b'-' | b'0'..=b'9' => (scan_number(buf, i)?, ValueKind::Number),
        _ => return Err(ScanError::Syntax("unexpected byte", i)),
    };
    Ok(ValueSpan { span, kind })
}

/// Members of an object value span. `obj` must be the span of an object.
pub fn members_of_object(buf: &[u8], obj: Span) -> Result<Vec<Member>, ScanError> {
    if at(buf, obj.start)? != b'{' {
        return Err(ScanError::Syntax("not an object", obj.start));
    }
    let mut out = Vec::new();
    let mut i = skip_ws(buf, obj.start + 1);
    if i < obj.end && at(buf, i)? == b'}' {
        return Ok(out);
    }
    loop {
        let ks = scan_string(buf, skip_ws(buf, i))?;
        let key = decode_string(buf, ks)?.into_boxed_slice();
        let mut j = skip_ws(buf, ks.end);
        if at(buf, j)? != b':' {
            return Err(ScanError::Syntax("expected colon", j));
        }
        j += 1;
        let value = scan_value_depth(buf, j, 1)?;
        if value.span.end > obj.end {
            return Err(ScanError::Syntax("value overruns object", value.span.start));
        }
        out.push(Member {
            key,
            key_span: ks,
            value,
        });
        j = skip_ws(buf, value.span.end);
        match at(buf, j)? {
            b',' => {
                i = j + 1;
            }
            b'}' => {
                if skip_ws(buf, j) + 1 != obj.end {
                    return Err(ScanError::Syntax("trailing bytes in object", j));
                }
                break;
            }
            _ => return Err(ScanError::Syntax("expected , or }", j)),
        }
    }
    Ok(out)
}

/// Element value spans of an array value span.
pub fn elements_of_array(buf: &[u8], arr: Span) -> Result<Vec<ValueSpan>, ScanError> {
    if at(buf, arr.start)? != b'[' {
        return Err(ScanError::Syntax("not an array", arr.start));
    }
    let mut out = Vec::new();
    let mut i = skip_ws(buf, arr.start + 1);
    if i < arr.end && at(buf, i)? == b']' {
        return Ok(out);
    }
    loop {
        let v = scan_value_depth(buf, i, 1)?;
        if v.span.end > arr.end {
            return Err(ScanError::Syntax("element overruns array", v.span.start));
        }
        out.push(v);
        let j = skip_ws(buf, v.span.end);
        match at(buf, j)? {
            b',' => i = j + 1,
            b']' => {
                if j + 1 != arr.end {
                    return Err(ScanError::Syntax("trailing bytes in array", j));
                }
                break;
            }
            _ => return Err(ScanError::Syntax("expected , or ]", j)),
        }
    }
    Ok(out)
}

/// The span of the single JSON value occupying the whole buffer (must be an
/// object, no trailing garbage).
pub fn scan_document(buf: &[u8]) -> Result<ValueSpan, ScanError> {
    let v = scan_value(buf, 0)?;
    if skip_ws(buf, v.span.end) != buf.len() {
        return Err(ScanError::Syntax("trailing bytes after document", v.span.end));
    }
    if v.kind != ValueKind::Object {
        return Err(ScanError::Syntax("document is not an object", v.span.start));
    }
    Ok(v)
}

/// Recursively check that a value's bytes really are JSON.
///
/// `scan_value` only finds a container's *extent* by bracket matching, so
/// inner garbage such as `{"a":01}` is invisible until something descends.
/// Used by `--doctor` and the test suite; the splitter itself surfaces the
/// same errors when it walks the levels it cares about.
pub fn validate(buf: &[u8], v: ValueSpan, depth: usize) -> Result<(), ScanError> {
    if depth > MAX_DEPTH {
        return Err(ScanError::TooDeep(v.span.start));
    }
    match v.kind {
        ValueKind::Object => {
            for m in members_of_object(buf, v.span)? {
                validate(buf, m.value, depth + 1)?;
            }
        }
        ValueKind::Array => {
            for e in elements_of_array(buf, v.span)? {
                validate(buf, e, depth + 1)?;
            }
        }
        ValueKind::String => {
            // Decode rather than just measure the extent: a lone surrogate is
            // invalid JSON and must not slip through a "valid" verdict. This is
            // not the hot path - the splitter never calls `validate`.
            decode_string(buf, v.span)?;
        }
        _ => {}
    }
    Ok(())
}

/// `scan_document` plus a full recursive validation.
pub fn strict_document(buf: &[u8]) -> Result<ValueSpan, ScanError> {
    let d = scan_document(buf)?;
    validate(buf, d, 0)?;
    Ok(d)
}

/// Unescape a JSON string span (quotes included) into its logical bytes.
pub fn decode_string(buf: &[u8], s: Span) -> Result<Vec<u8>, ScanError> {
    let raw = s.slice(buf);
    if raw.len() < 2 || raw[0] != b'"' || raw[raw.len() - 1] != b'"' {
        return Err(ScanError::Syntax("bad string span", s.start));
    }
    let body = &raw[1..raw.len() - 1];
    if !body.contains(&b'\\') {
        return Ok(body.to_vec());
    }
    let mut out = Vec::with_capacity(body.len());
    let mut i = 0;
    while i < body.len() {
        let c = body[i];
        if c != b'\\' {
            out.push(c);
            i += 1;
            continue;
        }
        i += 1;
        let Some(&e) = body.get(i) else {
            return Err(ScanError::Eof(s.start + i));
        };
        i += 1;
        match e {
            b'"' => out.push(b'"'),
            b'\\' => out.push(b'\\'),
            b'/' => out.push(b'/'),
            b'b' => out.push(0x08),
            b'f' => out.push(0x0c),
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b't' => out.push(b'\t'),
            b'u' => {
                let cp = read_hex4(body, &mut i, s)?;
                if (0xDC00..0xE000).contains(&cp) {
                    return Err(ScanError::Syntax("lone low surrogate", s.start + i));
                }
                let ch = if (0xD800..0xDC00).contains(&cp) {
                    if i + 2 > body.len() || body[i] != b'\\' || body[i + 1] != b'u' {
                        return Err(ScanError::Syntax("unpaired high surrogate", s.start + i));
                    }
                    i += 2;
                    let lo = read_hex4(body, &mut i, s)?;
                    if !(0xDC00..0xE000).contains(&lo) {
                        return Err(ScanError::Syntax("bad surrogate pair", s.start + i));
                    }
                    let combined =
                        0x1_0000 + (((cp - 0xD800) as u32) << 10) + (lo - 0xDC00) as u32;
                    char::from_u32(combined).unwrap_or('\u{fffd}')
                } else {
                    char::from_u32(cp as u32).unwrap_or('\u{fffd}')
                };
                let mut tmp = [0u8; 4];
                out.extend_from_slice(ch.encode_utf8(&mut tmp).as_bytes());
            }
            _ => return Err(ScanError::Syntax("bad escape", s.start + i)),
        }
    }
    Ok(out)
}

/// Four hex digits of a `\uXXXX` escape; `i` must point at the first digit.
fn read_hex4(body: &[u8], i: &mut usize, s: Span) -> Result<u16, ScanError> {
    if *i + 4 > body.len() {
        return Err(ScanError::Eof(s.start + *i));
    }
    let mut v = 0u16;
    for k in 0..4 {
        let d = (body[*i + k] as char)
            .to_digit(16)
            .ok_or(ScanError::Syntax("bad hex in \\u", s.start + *i + k))?;
        v = (v << 4) | d as u16;
    }
    *i += 4;
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }

    #[test]
    fn spans_are_exact() {
        let b = v(r#"{"a":1,"b":[1,2,{"c":"x"}],"d":"e\"f"}"#);
        let doc = scan_document(&b).unwrap();
        assert_eq!(doc.span, Span::new(0, b.len()));
        let ms = members_of_object(&b, doc.span).unwrap();
        assert_eq!(ms.len(), 3);
        assert_eq!(ms[0].key.as_ref(), b"a");
        assert_eq!(ms[0].value.span.slice(&b), b"1");
        assert_eq!(ms[1].value.kind, ValueKind::Array);
        let els = elements_of_array(&b, ms[1].value.span).unwrap();
        assert_eq!(els.len(), 3);
        assert_eq!(els[2].span.slice(&b), b"{\"c\":\"x\"}");
        assert_eq!(ms[2].value.span.slice(&b), b"\"e\\\"f\"");
        assert_eq!(decode_string(&b, ms[2].value.span).unwrap(), b"e\"f");
    }

    #[test]
    fn whitespace_and_layout_survive() {
        let b = b"{ \"a\" : [ 1 ,\n 2 ] , \"b\":true }".to_vec();
        let doc = scan_document(&b).unwrap();
        let ms = members_of_object(&b, doc.span).unwrap();
        assert_eq!(ms.len(), 2);
        assert_eq!(ms[0].key.as_ref(), b"a");
        let els = elements_of_array(&b, ms[0].value.span).unwrap();
        assert_eq!(els[0].span.slice(&b), b"1");
        assert_eq!(els[1].span.slice(&b), b"2");
    }

    #[test]
    fn rejects_garbage() {
        // top level shape
        assert!(scan_document(&v(r#"{"a":1} "#)).is_ok());
        assert!(scan_document(&v(r#"{"a":1}x"#)).is_err());
        assert!(scan_document(&v(r#""str""#)).is_err());
        assert!(scan_document(&v("{}")).is_ok());
        assert!(scan_document(&v("[]")).is_err());
        // garbage nested inside a container is only caught by a full walk
        assert!(scan_document(&v(r#"{"a":01}"#)).is_ok());
        assert!(strict_document(&v(r#"{"a":01}"#)).is_err());
        assert!(strict_document(&v(r#"{"a":1,}"#)).is_err());
        assert!(strict_document(&v(r#"{"a"}"#)).is_err());
        assert!(strict_document(&v(r#"{"a":{"b":[1,,2]}}"#)).is_err());
        assert!(strict_document(&v(r#"{"a":"\ud83d"}"#)).is_err());
        assert!(strict_document(&v(r#"{"a":1,"b":{"c":"x"}}"#)).is_ok());
        // primitives
        assert!(scan_value(&v(r#""\u12""#), 0).is_err());
        assert!(scan_number(&v("-"), 0).is_err());
        assert!(scan_number(&v("1e"), 0).is_err());
        assert!(scan_value(&v("[1"), 0).is_err());
        assert!(scan_value(&v("{]"), 0).is_err());
        // container scanning finds an *extent* by bracket matching and judges
        // nothing inside it; that is deliberate (it keeps the hot pass cheap),
        // and the error surfaces as soon as anything descends.
        assert_eq!(scan_value(&v("{(}"), 0).unwrap().kind, ValueKind::Object);
        assert!(members_of_object(&v("{(}"), Span::new(0, 3)).is_err());
        assert!(validate(&v("{(}"), ValueSpan { span: Span::new(0, 3), kind: ValueKind::Object }, 0).is_err());
    }

    #[test]
    fn nested_brackets_inside_strings_are_ignored() {
        let b = v(r#"{"a":"}]{{\"","b":2}"#);
        let doc = scan_document(&b).unwrap();
        let ms = members_of_object(&b, doc.span).unwrap();
        assert_eq!(ms.len(), 2);
        assert_eq!(ms[1].key.as_ref(), b"b");
    }

    #[test]
    fn surrogate_pairs_decode() {
        let b = v(r#""\ud83d\ude00""#);
        assert_eq!(decode_string(&b, Span::new(0, b.len())).unwrap(), "😀".as_bytes());
        let b2 = v(r#""\udfff""#);
        assert!(decode_string(&b2, Span::new(0, b2.len())).is_err());
    }
}
