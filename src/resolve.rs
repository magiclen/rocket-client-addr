use std::net::IpAddr;

use rocket::http::HeaderMap;

use crate::{
    ChainHeader, ClientIp, ClientIpConfig, ClientIpSource, TrustAllChainIpSelection,
    TrustAllProxyMode,
    canonical::canonical_ip,
    config::{ChainHeaderKind, TrustModel},
    headers::{
        ChainEntry, configured_client_ip_header, forwarded_entries, header_lines,
        list_header_entries,
    },
};

impl ClientIpConfig {
    /// Resolve the client IP of a request from its headers and its socket peer IP.
    ///
    /// Use this when the request does not come from Rocket, or when the [`ClientIp`] request guard is not convenient. The crate-level docs describe the full order in which the answer is chosen.
    pub fn resolve_client_ip(&self, headers: &HeaderMap<'_>, peer_ip: IpAddr) -> ClientIp {
        let peer_ip = canonical_ip(peer_ip);

        match &self.trust {
            TrustModel::NoProxy => ClientIp::new(peer_ip, ClientIpSource::Socket),
            TrustModel::TrustedProxies {
                chain_header_order, ..
            } => resolve_client_ip_from_trusted_proxies(headers, peer_ip, self, chain_header_order),
            TrustModel::TrustAllProxies(mode) => {
                resolve_client_ip_trusting_all_proxies(headers, peer_ip, mode)
            },
        }
    }
}

/// Resolve a request when proxies are trusted by CIDR.
fn resolve_client_ip_from_trusted_proxies(
    headers: &HeaderMap<'_>,
    socket_ip: IpAddr,
    config: &ClientIpConfig,
    chain_header_order: &[ChainHeader],
) -> ClientIp {
    // A peer that is not a trusted proxy wrote its own headers, so none of them may be read.
    let Some(socket_proxy_rule) = config.rule_for(socket_ip) else {
        return ClientIp::new(socket_ip, ClientIpSource::Socket);
    };

    if let Some(header) = socket_proxy_rule.client_ip_header()
        && let Some(ip) = configured_client_ip_header(headers, header)
    {
        return ClientIp::new(ip, ClientIpSource::ConfiguredHeader(header.clone()));
    }

    // Scan from the socket side toward the original client.
    if let Some((ip, source)) =
        client_ip_from_chain_headers(headers, chain_header_order, |entries| {
            first_non_trusted_from_right(entries, config)
        })
    {
        return ClientIp::new(ip, source);
    }

    ClientIp::new(socket_ip, ClientIpSource::Socket)
}

/// Resolve a request when every socket peer is treated as a trusted proxy.
fn resolve_client_ip_trusting_all_proxies(
    headers: &HeaderMap<'_>,
    socket_ip: IpAddr,
    mode: &TrustAllProxyMode,
) -> ClientIp {
    if let Some(header) = mode.client_ip_header()
        && let Some(ip) = configured_client_ip_header(headers, header)
    {
        return ClientIp::new(ip, ClientIpSource::ConfiguredHeader(header.clone()));
    }

    if let Some((ip, source)) =
        client_ip_from_chain_headers(headers, mode.chain_header_order(), |entries| {
            select_trust_all_chain_ip(entries, mode.chain_ip_selection())
        })
    {
        return ClientIp::new(ip, source);
    }

    ClientIp::new(socket_ip, ClientIpSource::Socket)
}

/// Return the IP that `pick` accepts in the first chain header the request carries.
///
/// `pick` receives the hops of one chain header in left-to-right order.
///
/// The configured chain headers are alternatives, not a search list. Only a chain header that the request does not carry at all moves the search on to the next one. A header the request does carry was written by whichever proxy handled it, so if it yields no answer the search stops there instead of falling back to a header that same proxy may never have touched.
fn client_ip_from_chain_headers(
    headers: &HeaderMap<'_>,
    chain_header_order: &[ChainHeader],
    mut pick: impl FnMut(&mut dyn DoubleEndedIterator<Item = ChainEntry>) -> Option<IpAddr>,
) -> Option<(IpAddr, ClientIpSource)> {
    for chain_header in chain_header_order {
        let header = chain_header.as_header_name();
        let lines = header_lines(headers, header);

        if lines.is_empty() {
            continue;
        }

        let ip = match chain_header.kind() {
            ChainHeaderKind::Forwarded => {
                let entries = forwarded_entries(lines)?;

                pick(&mut entries.into_iter())
            },
            ChainHeaderKind::XForwardedFor => {
                let mut entries = list_header_entries(lines)?;

                pick(&mut entries)
            },
        };

        // The request carries this header, so the answer comes from it or from nowhere.
        return Some((ip?, ClientIpSource::ChainHeader(header.clone())));
    }

    None
}

/// Pick one hop of a chain by position, for trust-all proxy mode.
fn select_trust_all_chain_ip(
    entries: &mut dyn DoubleEndedIterator<Item = ChainEntry>,
    selection: TrustAllChainIpSelection,
) -> Option<IpAddr> {
    let entry = match selection {
        TrustAllChainIpSelection::Leftmost => entries.next(),
        TrustAllChainIpSelection::Rightmost => entries.next_back(),
        // Counting is positional, so a hop without a usable IP address still takes one place.
        TrustAllChainIpSelection::SkipRightmostHops(hops) => entries.nth_back(hops),
    }?;

    match entry {
        ChainEntry::Ip(ip) => Some(ip),
        ChainEntry::Opaque => None,
    }
}

/// Walk a chain from the socket side toward the original client, and stop at the first hop that is not a trusted proxy.
fn first_non_trusted_from_right(
    entries: &mut dyn DoubleEndedIterator<Item = ChainEntry>,
    config: &ClientIpConfig,
) -> Option<IpAddr> {
    while let Some(entry) = entries.next_back() {
        match entry {
            // Keep walking left past hops that are known trusted proxies.
            ChainEntry::Ip(ip) if config.is_trusted_proxy(ip) => continue,
            ChainEntry::Ip(ip) => return Some(ip),
            // This hop cannot be compared with the trusted proxy rules, so it is unknown whether it is a proxy. Everything further left was written by a hop that is unknown too, so the scan cannot go on.
            ChainEntry::Opaque => return None,
        }
    }

    None
}
