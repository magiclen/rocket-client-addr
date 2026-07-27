//! Tests for reading forwarding headers.
//!
//! Every test resolves a request with a trust-all config, because that model picks one hop by position and makes the parsed value of that hop directly visible.

use std::net::IpAddr;

use rocket_client_addr::{
    ChainHeader, ClientIpConfig, ClientIpSource, HeaderMap, TrustAllChainIpSelection, Uncased,
};

const SOCKET: &str = "10.0.0.2";

fn ip(input: &str) -> IpAddr {
    input.parse().unwrap()
}

/// Read the leftmost hop of a chain header, which is the hop a client can write freely.
fn leftmost(headers: &HeaderMap<'_>) -> IpAddr {
    ClientIpConfig::builder()
        .trust_all_proxies()
        .chain_ip_selection(TrustAllChainIpSelection::Leftmost)
        .build()
        .resolve_client_ip(headers, ip(SOCKET))
        .ip()
}

/// Read the rightmost hop of a chain header, which is the hop the nearest proxy wrote.
fn rightmost(headers: &HeaderMap<'_>) -> IpAddr {
    ClientIpConfig::builder()
        .trust_all_proxies()
        .build()
        .resolve_client_ip(headers, ip(SOCKET))
        .ip()
}

fn headers_of(name: &'static str, values: &[&'static str]) -> HeaderMap<'static> {
    let mut headers = HeaderMap::new();

    for value in values {
        headers.add_raw(name, *value);
    }

    headers
}

// A list header is split on commas, and the space after each comma is not part of a hop.
#[test]
fn a_list_header_is_split_on_commas() {
    let headers = headers_of("x-forwarded-for", &["203.0.113.10,  198.51.100.7 , 10.0.0.2"]);

    assert_eq!(ip("203.0.113.10"), leftmost(&headers));
    assert_eq!(ip("10.0.0.2"), rightmost(&headers));
}

// Several lines of one header name are one list, joined in the order they arrived.
#[test]
fn several_lines_of_a_list_header_are_one_chain() {
    let headers = headers_of("x-forwarded-for", &["203.0.113.10", "198.51.100.7, 10.0.0.2"]);

    assert_eq!(ip("203.0.113.10"), leftmost(&headers));
    assert_eq!(ip("10.0.0.2"), rightmost(&headers));
}

// An empty part is list punctuation rather than a hop, so it does not shift the positions around it.
#[test]
fn empty_parts_of_a_list_header_are_not_hops() {
    let headers = headers_of("x-forwarded-for", &[", 203.0.113.10, , 198.51.100.7,"]);

    assert_eq!(ip("203.0.113.10"), leftmost(&headers));
    assert_eq!(ip("198.51.100.7"), rightmost(&headers));
}

// A proxy may report the port it saw as well as the address, in either address family.
#[test]
fn a_hop_may_carry_a_port() {
    let headers = headers_of("x-forwarded-for", &["192.0.2.43:47011, [2001:db8::17]:4711"]);

    assert_eq!(ip("192.0.2.43"), leftmost(&headers));
    assert_eq!(ip("2001:db8::17"), rightmost(&headers));
}

// RFC 7239 allows a port to be hidden behind a name that starts with an underscore.
#[test]
fn a_hop_may_carry_an_obfuscated_port() {
    let headers = headers_of("x-forwarded-for", &["192.0.2.43:_secret"]);

    assert_eq!(ip("192.0.2.43"), rightmost(&headers));
}

// An IPv6 hop may be written inside brackets even when no port follows it.
#[test]
fn a_bracketed_hop_may_have_no_port() {
    let headers = headers_of("x-forwarded-for", &["[2001:db8::17]"]);

    assert_eq!(ip("2001:db8::17"), rightmost(&headers));
}

// A hop written in IPv4-mapped form resolves to the same address as the plain IPv4 form.
#[test]
fn an_ipv4_mapped_hop_is_rewritten_to_its_ipv4_form() {
    let headers = headers_of("x-forwarded-for", &["::ffff:203.0.113.10"]);

    assert_eq!(ip("203.0.113.10"), rightmost(&headers));
}

// A hop can exist without naming an address, and then it gives no answer at all.
#[test]
fn a_hop_without_a_usable_address_gives_no_answer() {
    for value in ["unknown", "_hidden"] {
        let mut headers = HeaderMap::new();
        headers.add_raw("x-forwarded-for", value);

        assert_eq!(ip(SOCKET), rightmost(&headers), "{value}");
    }
}

// Such a hop still takes one place in the chain, so counting from the right stays correct.
#[test]
fn a_hop_without_a_usable_address_still_takes_one_place() {
    let config = ClientIpConfig::builder()
        .trust_all_proxies()
        .chain_ip_selection(TrustAllChainIpSelection::SkipRightmostHops(1))
        .build();
    let headers = headers_of("x-forwarded-for", &["203.0.113.10, unknown"]);

    assert_eq!(ip("203.0.113.10"), config.resolve_client_ip(&headers, ip(SOCKET)).ip());
}

// A line that holds anything a header value may not carry hides an unknown number of hops, so the readable line next to it cannot be placed in the chain either.
#[test]
fn an_unreadable_line_makes_the_whole_header_unusable() {
    let headers = headers_of("x-forwarded-for", &["\u{FF}", "203.0.113.10"]);

    assert_eq!(ip(SOCKET), rightmost(&headers));
}

// A header name other than `forwarded` is read as a comma-separated list, whatever it is called.
#[test]
fn a_custom_chain_header_is_read_as_a_list() {
    let header = Uncased::from_borrowed("x-client-chain");
    let config = ClientIpConfig::builder()
        .trust_all_proxies()
        .chain_header_order([ChainHeader::new(header.clone())])
        .build();
    let headers = headers_of("x-client-chain", &["9.9.9.9, 203.0.113.10"]);

    let client_ip = config.resolve_client_ip(&headers, ip(SOCKET));

    assert_eq!(ip("203.0.113.10"), client_ip.ip());
    assert_eq!(&ClientIpSource::ChainHeader(header), client_ip.source());
}

// A proxy may send the RFC 7239 syntax under a name of its own, and that reading has to be asked for.
#[test]
fn a_custom_chain_header_can_be_read_as_forwarded() {
    let header = Uncased::from_borrowed("x-forwarded");
    let config = ClientIpConfig::builder()
        .trust_all_proxies()
        .chain_header_order([ChainHeader::forwarded_style(header.clone())])
        .build();
    let headers = headers_of("x-forwarded", &["for=9.9.9.9, for=203.0.113.10"]);

    let client_ip = config.resolve_client_ip(&headers, ip(SOCKET));

    assert_eq!(ip("203.0.113.10"), client_ip.ip());
    assert_eq!(&ClientIpSource::ChainHeader(header), client_ip.source());
}

// A Forwarded element carries named parameters, and only `for` says anything about the client address.
#[test]
fn forwarded_reads_the_for_parameter_and_ignores_the_others() {
    let headers =
        headers_of("forwarded", &["by=203.0.113.43;for=192.0.2.60;host=example.com;proto=http"]);

    assert_eq!(ip("192.0.2.60"), rightmost(&headers));
}

// RFC 7239 parameter names are case-insensitive.
#[test]
fn forwarded_parameter_names_are_case_insensitive() {
    let headers = headers_of("forwarded", &["For=192.0.2.60"]);

    assert_eq!(ip("192.0.2.60"), rightmost(&headers));
}

// A quoted value may contain the characters that separate elements and parameters, and they must not split it.
#[test]
fn a_quoted_forwarded_value_keeps_its_separators() {
    let headers = headers_of("forwarded", &[r#"for="[2001:db8::17]:4711";proto=https"#]);

    assert_eq!(ip("2001:db8::17"), rightmost(&headers));
}

// An element without a `for` parameter is a hop whose address is unknown.
#[test]
fn a_forwarded_element_without_for_gives_no_answer() {
    let headers = headers_of("forwarded", &["proto=https"]);

    assert_eq!(ip(SOCKET), rightmost(&headers));
}

// Several lines of Forwarded are one chain, just like several lines of a list header.
#[test]
fn several_lines_of_forwarded_are_one_chain() {
    let headers = headers_of("forwarded", &["for=203.0.113.10", "for=198.51.100.7, for=10.0.0.2"]);

    assert_eq!(ip("203.0.113.10"), leftmost(&headers));
    assert_eq!(ip("10.0.0.2"), rightmost(&headers));
}

// A proxy that appends instead of overwriting puts its own value after anything the client sent, so only the last line can be trusted.
#[test]
fn a_client_ip_header_uses_its_last_line() {
    let header = Uncased::from_borrowed("x-real-ip");
    let config =
        ClientIpConfig::builder().trust_all_proxies().client_ip_header(header.clone()).build();
    let headers = headers_of("x-real-ip", &["203.0.113.10", "198.51.100.7"]);

    let client_ip = config.resolve_client_ip(&headers, ip(SOCKET));

    assert_eq!(ip("198.51.100.7"), client_ip.ip());
    assert_eq!(&ClientIpSource::ConfiguredHeader(header), client_ip.source());
}

// If that last line is not a plain address the header is unusable, so a value the client wrote earlier can never win.
#[test]
fn a_client_ip_header_with_an_unusable_last_line_is_ignored() {
    let config = ClientIpConfig::builder()
        .trust_all_proxies()
        .client_ip_header(Uncased::from_borrowed("x-real-ip"))
        .disable_chain_headers()
        .build();
    let headers = headers_of("x-real-ip", &["203.0.113.10", "not-an-ip"]);

    assert_eq!(ip(SOCKET), config.resolve_client_ip(&headers, ip(SOCKET)).ip());
}

// Rocket looks a header up without regard to case, so a proxy that writes another case has to be read all the same.
#[test]
fn a_header_name_is_matched_without_regard_to_case() {
    let headers = headers_of("X-Forwarded-For", &["203.0.113.10"]);

    assert_eq!(ip("203.0.113.10"), rightmost(&headers));
}
