//! Tests for building a `ClientIpConfig` and reading it back.

use rocket_client_addr::{
    ChainHeader, ClientIpConfig, ClientIpConfigBuildError, IpCidr, TrustAllChainIpSelection,
    TrustedProxyRule, Uncased,
};

fn cidr(input: &str) -> IpCidr {
    input.parse().unwrap()
}

// A config made with no settings at all reads no header and reports the trust model it uses.
#[test]
fn the_default_config_trusts_no_proxy() {
    let config = ClientIpConfig::default();

    assert!(config.trusts_no_proxy());
    assert!(!config.trusts_all_proxies());
    assert_eq!(None, config.trust_all_proxy_mode());
    assert!(config.trusted_proxy_rules().is_empty());
    assert!(config.chain_header_order().is_empty());
    assert!(!config.is_trusted_proxy("10.0.0.2".parse().unwrap()));
}

// Without a chain header order of its own, a config reads X-Forwarded-For first and Forwarded second.
#[test]
fn the_default_chain_header_order_is_x_forwarded_for_then_forwarded() {
    let config =
        ClientIpConfig::builder().trusted_proxies().proxy(cidr("10.0.0.0/24")).build().unwrap();

    let names: Vec<&Uncased<'static>> =
        config.chain_header_order().iter().map(ChainHeader::as_header_name).collect();

    assert_eq!(
        vec![&Uncased::from_borrowed("x-forwarded-for"), &Uncased::from_borrowed("forwarded")],
        names
    );
}

// Two CIDRs that agree on their client IP header and sit next to each other become one wider rule.
#[test]
fn cidrs_with_the_same_client_ip_header_are_merged() {
    let config = ClientIpConfig::builder()
        .trusted_proxies()
        .proxy(cidr("10.0.0.0/25"))
        .proxy(cidr("10.0.0.128/25"))
        .build()
        .unwrap();

    assert_eq!(1, config.trusted_proxy_rules().len());
    assert_eq!("10.0.0.0/24", config.trusted_proxy_rules()[0].cidr().to_string());
}

// One socket peer must mean one policy, so CIDRs that share an address may not disagree on the client IP header.
#[test]
fn overlapping_cidrs_with_different_client_ip_headers_are_rejected() {
    let error = ClientIpConfig::builder()
        .trusted_proxies()
        .proxy(cidr("10.0.0.0/24"))
        .proxy_with_x_real_ip(cidr("10.0.0.0/25"))
        .build()
        .unwrap_err();

    assert!(matches!(error, ClientIpConfigBuildError::OverlappingTrustedProxyRules { .. }));
}

// The two conflicting rules are not neighbours once the rules are sorted, so the wide rule has to stay open across the rule nested inside it.
#[test]
fn an_overlap_is_found_even_with_another_rule_between_the_two() {
    let error = ClientIpConfig::builder()
        .trusted_proxies()
        .proxy(cidr("10.0.0.0/24"))
        .proxy(cidr("10.0.0.0/25"))
        .proxy_with_x_real_ip(cidr("10.0.0.128/25"))
        .build()
        .unwrap_err();

    assert!(matches!(error, ClientIpConfigBuildError::OverlappingTrustedProxyRules { .. }));
}

// The error message names both rules, so the setting that has to change can be found.
#[test]
fn the_overlap_error_names_both_rules() {
    let error = ClientIpConfig::builder()
        .trusted_proxies()
        .proxy(cidr("10.0.0.0/24"))
        .proxy_with_x_real_ip(cidr("10.0.0.0/25"))
        .build()
        .unwrap_err()
        .to_string();

    assert!(error.contains("10.0.0.0/24"), "{error}");
    assert!(error.contains("10.0.0.0/25"), "{error}");
    assert!(error.contains("x-real-ip"), "{error}");
    assert!(error.contains("no client IP header"), "{error}");
}

// An IPv4 network and an IPv6 network never cover a common address, so they may disagree freely.
#[test]
fn cidrs_of_different_address_families_never_overlap() {
    let config = ClientIpConfig::builder()
        .trusted_proxies()
        .proxy(cidr("0.0.0.0/0"))
        .proxy_with_x_real_ip(cidr("::/0"))
        .build()
        .unwrap();

    assert_eq!(2, config.trusted_proxy_rules().len());
}

// A peer address is rewritten to its IPv4 form before it is matched, so a rule written in IPv4-mapped form has to be rewritten the same way.
#[test]
fn an_ipv4_mapped_cidr_is_rewritten_to_its_ipv4_form() {
    let config = ClientIpConfig::builder()
        .trusted_proxies()
        .proxy(cidr("::ffff:10.0.0.0/120"))
        .build()
        .unwrap();

    assert_eq!("10.0.0.0/24", config.trusted_proxy_rules()[0].cidr().to_string());
    assert!(config.is_trusted_proxy("10.0.0.2".parse().unwrap()));
}

// A prefix shorter than 96 bits reaches outside the IPv4-mapped range, so it has no IPv4 form and stays as it is.
#[test]
fn a_short_ipv6_cidr_keeps_its_ipv6_form() {
    let config =
        ClientIpConfig::builder().trusted_proxies().proxy(cidr("2001:db8::/32")).build().unwrap();

    assert_eq!("2001:db8::/32", config.trusted_proxy_rules()[0].cidr().to_string());
    assert!(config.is_trusted_proxy("2001:db8::17".parse().unwrap()));
}

// The rewrite runs before the overlap check, so these two rules are seen as the two policies for one address that they really are.
#[test]
fn an_ipv4_mapped_cidr_overlaps_the_same_addresses_written_in_ipv4_form() {
    let error = ClientIpConfig::builder()
        .trusted_proxies()
        .proxy(cidr("10.0.0.0/24"))
        .proxy_with_x_real_ip(cidr("::ffff:10.0.0.0/120"))
        .build()
        .unwrap_err();

    assert!(matches!(error, ClientIpConfigBuildError::OverlappingTrustedProxyRules { .. }));
}

// Rules of both address families are stored together, and a lookup has to find the right one in either.
#[test]
fn trusted_proxy_lookup_handles_mixed_ipv4_and_ipv6_rules() {
    let config = ClientIpConfig::builder()
        .trusted_proxies()
        .proxy(cidr("10.0.0.0/24"))
        .proxy(cidr("192.168.0.0/16"))
        .proxy(cidr("2001:db8::/32"))
        .proxy(cidr("fd00::/8"))
        .build()
        .unwrap();

    assert_eq!(4, config.trusted_proxy_rules().len());

    assert!(config.is_trusted_proxy("10.0.0.2".parse().unwrap()));
    assert!(config.is_trusted_proxy("192.168.1.1".parse().unwrap()));
    assert!(config.is_trusted_proxy("2001:db8::17".parse().unwrap()));
    assert!(config.is_trusted_proxy("fd00::1".parse().unwrap()));

    assert!(!config.is_trusted_proxy("10.0.1.1".parse().unwrap()));
    assert!(!config.is_trusted_proxy("203.0.113.10".parse().unwrap()));
    assert!(!config.is_trusted_proxy("2001:db9::17".parse().unwrap()));
    assert!(!config.is_trusted_proxy("::1".parse().unwrap()));
}

// Rules that come from a config file or another runtime source can be added in one call.
#[test]
fn proxy_rules_can_be_added_in_bulk() {
    let config = ClientIpConfig::builder()
        .trusted_proxies()
        .proxies([
            TrustedProxyRule::with_x_real_ip(cidr("10.0.0.0/24")),
            TrustedProxyRule::new(cidr("198.51.100.0/24")),
        ])
        .build()
        .unwrap();

    assert_eq!(2, config.trusted_proxy_rules().len());
    assert!(config.is_trusted_proxy("10.0.0.2".parse().unwrap()));
    assert!(config.is_trusted_proxy("198.51.100.7".parse().unwrap()));
}

// A rule reports the CIDR it matches and the client IP header it allows, if it has one.
#[test]
fn a_trusted_proxy_rule_reports_its_cidr_and_client_ip_header() {
    let plain = TrustedProxyRule::new(cidr("10.0.0.0/24"));
    let with_header = TrustedProxyRule::with_x_real_ip(cidr("10.0.0.0/24"));

    assert_eq!(&cidr("10.0.0.0/24"), plain.cidr());
    assert_eq!(None, plain.client_ip_header());
    assert_eq!(Some(&Uncased::from_borrowed("x-real-ip")), with_header.client_ip_header());
}

// Both builders can turn chain header reading off completely.
#[test]
fn disable_chain_headers_leaves_no_chain_header_to_read() {
    let trusted = ClientIpConfig::builder()
        .trusted_proxies()
        .proxy(cidr("10.0.0.0/24"))
        .disable_chain_headers()
        .build()
        .unwrap();
    let trust_all = ClientIpConfig::builder().trust_all_proxies().disable_chain_headers().build();

    assert!(trusted.chain_header_order().is_empty());
    assert!(trust_all.chain_header_order().is_empty());
}

// A trust-all config keeps every setting it was given, and treats any address as a proxy.
#[test]
fn trust_all_settings_are_kept_in_the_built_config() {
    let config = ClientIpConfig::builder()
        .trust_all_proxies()
        .client_ip_header(Uncased::from_borrowed("x-client-ip"))
        .chain_header_order([ChainHeader::forwarded()])
        .chain_ip_selection(TrustAllChainIpSelection::Leftmost)
        .build();

    let mode = config.trust_all_proxy_mode().unwrap();

    assert!(config.trusts_all_proxies());
    assert!(!config.trusts_no_proxy());
    assert_eq!(Some(&Uncased::from_borrowed("x-client-ip")), mode.client_ip_header());
    assert_eq!(TrustAllChainIpSelection::Leftmost, mode.chain_ip_selection());
    assert_eq!(1, mode.chain_header_order().len());
    assert!(config.is_trusted_proxy("203.0.113.10".parse().unwrap()));
}

// The reading style of a chain header comes from its name, and `forwarded` keeps the RFC 7239 style however it is created.
#[test]
fn a_chain_header_keeps_the_name_it_was_made_from() {
    let custom = ChainHeader::new(Uncased::from_borrowed("x-client-chain"));
    let from_name = ChainHeader::from(Uncased::from_borrowed("forwarded"));

    assert_eq!(
        &Uncased::from_borrowed("x-forwarded-for"),
        ChainHeader::x_forwarded_for().as_header_name()
    );
    assert_eq!(Uncased::from_borrowed("x-client-chain"), custom.into_header_name());
    assert_eq!(ChainHeader::forwarded(), from_name);
}

// Rocket looks a header up without regard to case, so a name written in another case has to mean the same header.
#[test]
fn a_chain_header_name_is_case_insensitive() {
    let config = ClientIpConfig::builder()
        .trust_all_proxies()
        .chain_header_order([ChainHeader::new(Uncased::from_borrowed("Forwarded"))])
        .build();

    assert_eq!(ChainHeader::forwarded(), config.chain_header_order()[0]);
}
