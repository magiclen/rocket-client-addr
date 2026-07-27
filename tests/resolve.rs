//! Tests for the rule each trust model uses to choose the client IP.
//!
//! Header syntax is covered in `headers.rs`, so every chain header here uses the plainest form it can.

use std::net::IpAddr;

use rocket_client_addr::{
    ChainHeader, ClientIpConfig, ClientIpSource, HeaderMap, IpCidr, TrustAllChainIpSelection,
    Uncased,
};

fn cidr(input: &str) -> IpCidr {
    input.parse().unwrap()
}

fn ip(input: &str) -> IpAddr {
    input.parse().unwrap()
}

fn chain_source(name: &'static str) -> ClientIpSource {
    ClientIpSource::ChainHeader(Uncased::from_borrowed(name))
}

fn headers_of(pairs: &[(&'static str, &'static str)]) -> HeaderMap<'static> {
    let mut headers = HeaderMap::new();

    for (name, value) in pairs {
        headers.add_raw(*name, *value);
    }

    headers
}

/// Trust 10.0.0.0/24 and 198.51.100.0/24, with no client IP header.
fn two_trusted_proxies() -> ClientIpConfig {
    ClientIpConfig::builder()
        .trusted_proxies()
        .proxy(cidr("10.0.0.0/24"))
        .proxy(cidr("198.51.100.0/24"))
        .build()
        .unwrap()
}

// Trusting no proxy means no header can change the answer.
#[test]
fn trust_no_proxy_always_answers_with_the_socket_peer() {
    let config = ClientIpConfig::builder().trust_no_proxy();
    let headers = headers_of(&[("x-forwarded-for", "203.0.113.10"), ("x-real-ip", "203.0.113.10")]);

    let client_ip = config.resolve_client_ip(&headers, ip("10.0.0.2"));

    assert_eq!(ip("10.0.0.2"), client_ip.ip());
    assert_eq!(&ClientIpSource::Socket, client_ip.source());
    assert_eq!(None, client_ip.source().header_name());
}

// A peer outside every trusted CIDR wrote its own headers, so none of them are read.
#[test]
fn an_untrusted_peer_answers_with_the_socket_peer() {
    let config = two_trusted_proxies();
    let headers = headers_of(&[("x-forwarded-for", "203.0.113.10")]);

    let client_ip = config.resolve_client_ip(&headers, ip("192.0.2.5"));

    assert_eq!(ip("192.0.2.5"), client_ip.ip());
    assert_eq!(&ClientIpSource::Socket, client_ip.source());
}

// A trusted peer whose rule names a client IP header answers from that header.
#[test]
fn a_trusted_peer_reads_the_client_ip_header_of_its_rule() {
    let config = ClientIpConfig::builder()
        .trusted_proxies()
        .proxy_with_x_real_ip(cidr("10.0.0.0/24"))
        .build()
        .unwrap();
    let headers = headers_of(&[("x-real-ip", "203.0.113.10")]);

    let client_ip = config.resolve_client_ip(&headers, ip("10.0.0.2"));

    assert_eq!(ip("203.0.113.10"), client_ip.ip());
    assert_eq!(
        &ClientIpSource::ConfiguredHeader(Uncased::from_borrowed("x-real-ip")),
        client_ip.source(),
    );
    assert_eq!(Some(&Uncased::from_borrowed("x-real-ip")), client_ip.source().header_name());
}

// The header belongs to one rule, so a peer matched by another rule may not use it.
#[test]
fn a_client_ip_header_is_only_read_for_the_rule_that_names_it() {
    let config = ClientIpConfig::builder()
        .trusted_proxies()
        .proxy_with_x_real_ip(cidr("10.0.0.0/24"))
        .proxy(cidr("198.51.100.0/24"))
        .disable_chain_headers()
        .build()
        .unwrap();
    let headers = headers_of(&[("x-real-ip", "203.0.113.10")]);

    let client_ip = config.resolve_client_ip(&headers, ip("198.51.100.7"));

    assert_eq!(ip("198.51.100.7"), client_ip.ip());
    assert_eq!(&ClientIpSource::Socket, client_ip.source());
}

// The client IP header of a rule wins before any chain header is read.
#[test]
fn a_client_ip_header_wins_over_a_chain_header() {
    let config = ClientIpConfig::builder()
        .trusted_proxies()
        .proxy_with_x_real_ip(cidr("10.0.0.0/24"))
        .build()
        .unwrap();
    let headers = headers_of(&[("x-real-ip", "203.0.113.10"), ("x-forwarded-for", "198.51.100.7")]);

    let client_ip = config.resolve_client_ip(&headers, ip("10.0.0.2"));

    assert_eq!(ip("203.0.113.10"), client_ip.ip());
}

// A rule may name a header the proxy did not send, and then the chain headers are still tried.
#[test]
fn a_missing_client_ip_header_falls_back_to_the_chain_header() {
    let config = ClientIpConfig::builder()
        .trusted_proxies()
        .proxy_with_x_real_ip(cidr("10.0.0.0/24"))
        .build()
        .unwrap();
    let headers = headers_of(&[("x-forwarded-for", "203.0.113.10")]);

    let client_ip = config.resolve_client_ip(&headers, ip("10.0.0.2"));

    assert_eq!(ip("203.0.113.10"), client_ip.ip());
    assert_eq!(&chain_source("x-forwarded-for"), client_ip.source());
}

// The chain is scanned from the socket side, and the first hop that is not a trusted proxy is the client.
#[test]
fn the_chain_is_scanned_from_the_right_past_trusted_proxies() {
    let config = two_trusted_proxies();
    let headers = headers_of(&[("x-forwarded-for", "203.0.113.10, 198.51.100.7, 10.0.0.2")]);

    let client_ip = config.resolve_client_ip(&headers, ip("10.0.0.2"));

    assert_eq!(ip("203.0.113.10"), client_ip.ip());
    assert_eq!(&chain_source("x-forwarded-for"), client_ip.source());
}

// A chain made only of trusted proxies names no client, so the socket peer stays the answer.
#[test]
fn a_chain_of_only_trusted_proxies_answers_with_the_socket_peer() {
    let config = two_trusted_proxies();
    let headers = headers_of(&[("x-forwarded-for", "198.51.100.7, 10.0.0.5")]);

    let client_ip = config.resolve_client_ip(&headers, ip("10.0.0.2"));

    assert_eq!(ip("10.0.0.2"), client_ip.ip());
    assert_eq!(&ClientIpSource::Socket, client_ip.source());
}

// A hop with no usable address cannot be compared with the trusted proxy rules, and neither can anything it may have written further left.
#[test]
fn the_scan_stops_at_a_hop_without_a_usable_address() {
    let config = two_trusted_proxies();
    let headers = headers_of(&[("x-forwarded-for", "203.0.113.10, unknown, 10.0.0.2")]);

    let client_ip = config.resolve_client_ip(&headers, ip("10.0.0.2"));

    assert_eq!(ip("10.0.0.2"), client_ip.ip());
    assert_eq!(&ClientIpSource::Socket, client_ip.source());
}

// A chain header the request does not carry is the only reason to try the next one.
#[test]
fn a_chain_header_that_is_absent_moves_on_to_the_next_one() {
    let config = two_trusted_proxies();
    let headers = headers_of(&[("forwarded", "for=203.0.113.10")]);

    let client_ip = config.resolve_client_ip(&headers, ip("10.0.0.2"));

    assert_eq!(ip("203.0.113.10"), client_ip.ip());
    assert_eq!(&chain_source("forwarded"), client_ip.source());
}

// A chain header the request does carry was written by the proxy that handled it, so a header that proxy may never have touched must not take over.
#[test]
fn a_chain_header_that_is_present_stops_the_search() {
    let config = two_trusted_proxies();
    let headers = headers_of(&[
        ("x-forwarded-for", "198.51.100.7, 10.0.0.2"),
        ("forwarded", "for=203.0.113.10"),
    ]);

    let client_ip = config.resolve_client_ip(&headers, ip("10.0.0.2"));

    assert_eq!(ip("10.0.0.2"), client_ip.ip());
    assert_eq!(&ClientIpSource::Socket, client_ip.source());
}

// The configured order decides which chain header is tried first.
#[test]
fn the_chain_header_order_decides_which_header_wins() {
    let config = ClientIpConfig::builder()
        .trusted_proxies()
        .proxy(cidr("10.0.0.0/24"))
        .chain_header_order([ChainHeader::forwarded(), ChainHeader::x_forwarded_for()])
        .build()
        .unwrap();
    let headers =
        headers_of(&[("x-forwarded-for", "203.0.113.10"), ("forwarded", "for=198.51.100.10")]);

    let client_ip = config.resolve_client_ip(&headers, ip("10.0.0.2"));

    assert_eq!(ip("198.51.100.10"), client_ip.ip());
    assert_eq!(&chain_source("forwarded"), client_ip.source());
}

// With no chain header left to read, a trusted peer without a usable client IP header answers with the socket peer.
#[test]
fn disabled_chain_headers_answer_with_the_socket_peer() {
    let config = ClientIpConfig::builder()
        .trusted_proxies()
        .proxy(cidr("10.0.0.0/24"))
        .disable_chain_headers()
        .build()
        .unwrap();
    let headers = headers_of(&[("x-forwarded-for", "203.0.113.10")]);

    let client_ip = config.resolve_client_ip(&headers, ip("10.0.0.2"));

    assert_eq!(ip("10.0.0.2"), client_ip.ip());
    assert_eq!(&ClientIpSource::Socket, client_ip.source());
}

// A dual-stack listener reports an IPv4 peer in IPv4-mapped form, and it still has to match an IPv4 rule.
#[test]
fn an_ipv4_mapped_socket_peer_matches_an_ipv4_rule() {
    let config = two_trusted_proxies();
    let headers = headers_of(&[("x-forwarded-for", "203.0.113.10")]);

    let client_ip = config.resolve_client_ip(&headers, ip("::ffff:10.0.0.2"));

    assert_eq!(ip("203.0.113.10"), client_ip.ip());
    assert_eq!(&chain_source("x-forwarded-for"), client_ip.source());
}

// Trusting all proxies takes the rightmost hop by default, which one appending proxy wrote and no client could choose.
#[test]
fn trust_all_takes_the_rightmost_hop_by_default() {
    let config = ClientIpConfig::builder().trust_all_proxies().build();
    let headers = headers_of(&[("x-forwarded-for", "9.9.9.9, 203.0.113.10")]);

    let client_ip = config.resolve_client_ip(&headers, ip("10.0.0.2"));

    assert_eq!(ip("203.0.113.10"), client_ip.ip());
    assert_eq!(&chain_source("x-forwarded-for"), client_ip.source());
}

// A proxy that overwrites the whole header leaves the client at the far left instead.
#[test]
fn trust_all_can_take_the_leftmost_hop() {
    let config = ClientIpConfig::builder()
        .trust_all_proxies()
        .chain_ip_selection(TrustAllChainIpSelection::Leftmost)
        .build();
    let headers = headers_of(&[("x-forwarded-for", "203.0.113.10, 198.51.100.7")]);

    let client_ip = config.resolve_client_ip(&headers, ip("10.0.0.2"));

    assert_eq!(ip("203.0.113.10"), client_ip.ip());
}

// A fixed number of appending proxies moves the client a fixed number of hops to the left.
#[test]
fn trust_all_can_skip_a_fixed_number_of_hops() {
    let config = ClientIpConfig::builder()
        .trust_all_proxies()
        .chain_ip_selection(TrustAllChainIpSelection::SkipRightmostHops(1))
        .build();
    let headers = headers_of(&[("x-forwarded-for", "203.0.113.10, 198.51.100.7, 10.0.0.2")]);

    let client_ip = config.resolve_client_ip(&headers, ip("10.0.0.3"));

    assert_eq!(ip("198.51.100.7"), client_ip.ip());
}

// A chain shorter than the selection needs proves nothing, so the socket peer stays the answer.
#[test]
fn trust_all_answers_with_the_socket_peer_when_the_chain_is_too_short() {
    let config = ClientIpConfig::builder()
        .trust_all_proxies()
        .chain_ip_selection(TrustAllChainIpSelection::SkipRightmostHops(2))
        .build();
    let headers = headers_of(&[("x-forwarded-for", "203.0.113.10, 198.51.100.7")]);

    let client_ip = config.resolve_client_ip(&headers, ip("10.0.0.2"));

    assert_eq!(ip("10.0.0.2"), client_ip.ip());
    assert_eq!(&ClientIpSource::Socket, client_ip.source());
}

// A configured client IP header is read before any chain header here too.
#[test]
fn trust_all_reads_the_client_ip_header_first() {
    let header = Uncased::from_borrowed("x-client-ip");
    let config =
        ClientIpConfig::builder().trust_all_proxies().client_ip_header(header.clone()).build();
    let headers =
        headers_of(&[("x-client-ip", "203.0.113.10"), ("x-forwarded-for", "198.51.100.7")]);

    let client_ip = config.resolve_client_ip(&headers, ip("10.0.0.2"));

    assert_eq!(ip("203.0.113.10"), client_ip.ip());
    assert_eq!(&ClientIpSource::ConfiguredHeader(header), client_ip.source());
}
