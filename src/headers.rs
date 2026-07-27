use std::{
    borrow::Cow,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use rocket::http::{HeaderMap, uncased::Uncased};

use crate::canonical::canonical_ip;

/// One hop found in a chain header.
#[derive(Clone, Copy, Debug)]
pub(crate) enum ChainEntry {
    /// A hop with a usable IP address.
    Ip(IpAddr),

    /// A hop that exists but carries no usable IP address.
    ///
    /// This covers `unknown`, RFC 7239 obfuscated identifiers, unreadable text, and `Forwarded` elements without a `for` parameter. Such a hop cannot be checked against the trusted proxy rules, but it still takes one place in the chain.
    Opaque,
}

/// Collect the lines a request carries under one header name, in the order they arrived.
#[inline]
pub(crate) fn header_lines<'a>(headers: &'a HeaderMap<'_>, name: &Uncased<'_>) -> Vec<&'a str> {
    // Rocket hands out these lines through an iterator that cannot be walked backwards, so they are collected here and scanned from the collection instead.
    headers.get(name.as_str()).collect()
}

/// Read the single IP address of a configured client IP header.
///
/// Only the last line is read, because a proxy that appends instead of overwriting puts its own value after anything the client sent. A last line that is not a plain IP address makes the whole header unusable, so a value the client wrote earlier can never win.
pub(crate) fn configured_client_ip_header(
    headers: &HeaderMap<'_>,
    header: &Uncased<'_>,
) -> Option<IpAddr> {
    let raw = header_lines(headers, header).pop()?;

    if !is_visible_ascii(raw) {
        return None;
    }

    Some(canonical_ip(raw.trim().parse::<IpAddr>().ok()?))
}

/// Iterate the hops of an `X-Forwarded-For` style comma-separated header, from left to right.
///
/// Several lines of one header name are one list, joined in the order they arrived.
///
/// Returns [`None`] when a line is not readable as visible ASCII, because such a line hides an unknown number of hops and would shift the position of every hop next to it.
pub(crate) fn list_header_entries(
    lines: Vec<&str>,
) -> Option<impl DoubleEndedIterator<Item = ChainEntry> + '_> {
    // The whole header has to be judged before any hop is produced, so this check cannot be folded into the iterator below.
    if lines.iter().any(|line| !is_visible_ascii(line)) {
        return None;
    }

    Some(
        lines
            .into_iter()
            .flat_map(|raw| raw.split(','))
            .map(str::trim)
            // An empty part is list punctuation, not a hop.
            .filter(|part| !part.is_empty())
            .map(chain_entry),
    )
}

/// Collect the hops of a standard `Forwarded` header, from left to right.
///
/// The `Forwarded` syntax cannot be scanned backwards, because a quote mark only tells you whether it opens or closes a string once you know what came before it. The hops are therefore collected instead of iterated lazily.
///
/// Returns [`None`] when a line is not readable as visible ASCII, for the same reason as [`list_header_entries`].
pub(crate) fn forwarded_entries(lines: Vec<&str>) -> Option<Vec<ChainEntry>> {
    let mut entries = Vec::new();

    for raw in lines {
        if !is_visible_ascii(raw) {
            return None;
        }

        for element in SplitQuoted::new(raw, ',') {
            if element.is_empty() {
                continue;
            }

            entries.push(forwarded_element_entry(element));
        }
    }

    Some(entries)
}

/// Read the `for` parameter of one `Forwarded` element.
///
/// An element may also carry `by`, `host`, and `proto`, which say nothing about the client address and are skipped.
fn forwarded_element_entry(element: &str) -> ChainEntry {
    for pair in SplitQuoted::new(element, ';') {
        let Some((name, value)) = pair.split_once('=') else {
            continue;
        };

        // RFC 7239 parameter names are case-insensitive, so `For=` is the same as `for=`.
        if !name.trim().eq_ignore_ascii_case("for") {
            continue;
        }

        return chain_entry(&unquote_http_quoted_string(value.trim()));
    }

    ChainEntry::Opaque
}

#[inline]
fn chain_entry(raw: &str) -> ChainEntry {
    match parse_ip_like(raw) {
        Some(ip) => ChainEntry::Ip(canonical_ip(ip)),
        None => ChainEntry::Opaque,
    }
}

/// Check that a header line holds only the characters an HTTP header value may carry.
///
/// Rocket stores header values as text, but text is a wider set than a header value is allowed to use, and anything outside it cannot be placed in the chain.
#[inline]
fn is_visible_ascii(line: &str) -> bool {
    line.bytes().all(|byte| matches!(byte, 0x20..=0x7E | b'\t'))
}

/// Split by a delimiter, but ignore delimiters inside HTTP quoted strings.
///
/// Every item is trimmed, and an empty input yields one empty item.
struct SplitQuoted<'a> {
    input:     &'a str,
    delimiter: char,
    start:     Option<usize>,
}

impl<'a> SplitQuoted<'a> {
    #[inline]
    const fn new(input: &'a str, delimiter: char) -> Self {
        Self {
            input,
            delimiter,
            start: Some(0),
        }
    }
}

impl<'a> Iterator for SplitQuoted<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        let start = self.start?;
        let mut in_quotes = false;
        let mut escaped = false;

        for (offset, ch) in self.input[start..].char_indices() {
            // A backslash hides whatever follows it, even another backslash or a quote mark.
            if escaped {
                escaped = false;
                continue;
            }

            // Outside a quoted string a backslash is an ordinary character, so only quoted text starts an escape.
            if in_quotes && ch == '\\' {
                escaped = true;
                continue;
            }

            if ch == '"' {
                in_quotes = !in_quotes;
                continue;
            }

            // A delimiter inside a quoted string belongs to the value, not to the list.
            if ch == self.delimiter && !in_quotes {
                let end = start + offset;

                self.start = Some(end + ch.len_utf8());

                return Some(self.input[start..end].trim());
            }
        }

        self.start = None;

        Some(self.input[start..].trim())
    }
}

/// Remove the quotes of an HTTP quoted string and undo its escapes.
///
/// Input that is not quoted is returned as it is.
#[inline]
fn unquote_http_quoted_string(input: &str) -> Cow<'_, str> {
    let input = input.trim();

    if input.len() < 2 || !input.starts_with('"') || !input.ends_with('"') {
        return Cow::Borrowed(input);
    }

    let inner = &input[1..input.len() - 1];

    // Without a backslash the text between the quotes is already the value, so nothing has to be built.
    if !inner.contains('\\') {
        return Cow::Borrowed(inner);
    }

    let mut output = String::with_capacity(inner.len());
    let mut escaped = false;

    for ch in inner.chars() {
        if escaped {
            output.push(ch);
            escaped = false;
            continue;
        }

        if ch == '\\' {
            escaped = true;
            continue;
        }

        output.push(ch);
    }

    Cow::Owned(output)
}

/// Read the IP address of one hop, in any of the forms a proxy may write.
#[inline]
fn parse_ip_like(raw: &str) -> Option<IpAddr> {
    let raw = raw.trim();

    // `unknown` and identifiers that start with `_` are the RFC 7239 ways of naming a hop without revealing its address.
    if raw.is_empty() || raw.eq_ignore_ascii_case("unknown") || raw.starts_with('_') {
        return None;
    }

    // A plain address, such as `203.0.113.10` or `2001:db8::17`.
    if let Ok(ip) = raw.parse::<IpAddr>() {
        return Some(ip);
    }

    // A bracketed IPv6 address, such as `[2001:db8::17]` or `[2001:db8::17]:4711`.
    if let Some(rest) = raw.strip_prefix('[') {
        let close_bracket = rest.find(']')?;
        let ip_part = &rest[..close_bracket];
        let tail = &rest[close_bracket + 1..];

        if tail.is_empty() {
            return ip_part.parse::<IpAddr>().ok();
        }

        if let Some(port) = tail.strip_prefix(':')
            && is_valid_node_port(port)
        {
            return ip_part.parse::<IpAddr>().ok();
        }

        // Anything else after the bracket is not a hop this crate understands.
        return None;
    }

    // An IPv4 address with a normal port, such as `192.0.2.43:47011`.
    if let Ok(socket_addr) = raw.parse::<SocketAddr>() {
        return Some(socket_addr.ip());
    }

    // An IPv4 address whose port is hidden, such as `192.0.2.43:_secret`.
    if let Some((host, port)) = raw.rsplit_once(':')
        && host.parse::<Ipv4Addr>().is_ok()
        && is_valid_node_port(port)
    {
        return host.parse::<IpAddr>().ok();
    }

    None
}

/// Check the port part of an RFC 7239 node identifier.
///
/// A port is either a number or an obfuscated name that starts with `_`.
#[inline]
fn is_valid_node_port(port: &str) -> bool {
    if port.is_empty() {
        return false;
    }

    if port.chars().all(|ch| ch.is_ascii_digit()) {
        return true;
    }

    let Some(obfuscated) = port.strip_prefix('_') else {
        return false;
    };

    !obfuscated.is_empty()
        && obfuscated.chars().all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
}
