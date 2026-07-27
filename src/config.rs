use std::net::IpAddr;

use cidr::IpCidr;
use rocket::http::uncased::Uncased;

use crate::{
    ClientIpConfigBuildError,
    canonical::{canonical_cidr, canonical_ip},
    cidr_merge::{ensure_no_cross_metadata_overlap, merge_rules_by_metadata},
};

/// Settings that decide how a client IP is resolved from a request.
///
/// A config uses exactly one trust model, picked as the first step of [`ClientIpConfig::builder`].
///
/// * Trust no proxy: no header is read, and every request resolves to the socket peer IP.
/// * Trusted proxies: headers are read only when the socket peer IP is inside one of the trusted CIDRs.
/// * Trust all proxies: every socket peer is treated as a trusted proxy.
///
/// The default config trusts no proxy.
///
/// The [`crate::ClientIp`] request guard reads this config out of Rocket's managed state, so a built config has to be passed to `rocket::build().manage(config)`.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ClientIpConfig {
    pub(crate) trust: TrustModel,
}

/// The trust model that a [`ClientIpConfig`] was built with.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) enum TrustModel {
    NoProxy,
    TrustedProxies {
        rules:              Vec<TrustedProxyRule>,
        chain_header_order: Vec<ChainHeader>,
    },
    TrustAllProxies(TrustAllProxyMode),
}

impl ClientIpConfig {
    /// Start building a config by choosing a trust model.
    #[inline]
    pub const fn builder() -> ClientIpConfigBuilder {
        ClientIpConfigBuilder
    }

    /// Return the trusted proxy rules, as they look after build-time merging.
    ///
    /// This is empty unless the config was built with trusted proxy CIDRs.
    #[inline]
    pub fn trusted_proxy_rules(&self) -> &[TrustedProxyRule] {
        match &self.trust {
            TrustModel::TrustedProxies {
                rules, ..
            } => rules,
            TrustModel::NoProxy | TrustModel::TrustAllProxies(_) => &[],
        }
    }

    /// Return the chain headers in the order they are tried.
    ///
    /// This is empty when the config trusts no proxy, because no header is read at all.
    #[inline]
    pub fn chain_header_order(&self) -> &[ChainHeader] {
        match &self.trust {
            TrustModel::NoProxy => &[],
            TrustModel::TrustedProxies {
                chain_header_order, ..
            } => chain_header_order,
            TrustModel::TrustAllProxies(mode) => &mode.chain_header_order,
        }
    }

    /// Return the trust-all proxy settings, if that trust model is in use.
    #[inline]
    pub const fn trust_all_proxy_mode(&self) -> Option<&TrustAllProxyMode> {
        match &self.trust {
            TrustModel::TrustAllProxies(mode) => Some(mode),
            _ => None,
        }
    }

    /// Check whether this config treats every socket peer as a trusted proxy.
    #[inline]
    pub const fn trusts_all_proxies(&self) -> bool {
        matches!(self.trust, TrustModel::TrustAllProxies(_))
    }

    /// Check whether this config reads no header at all and always answers with the socket peer IP.
    #[inline]
    pub const fn trusts_no_proxy(&self) -> bool {
        matches!(self.trust, TrustModel::NoProxy)
    }

    /// Check whether an address is treated as a trusted proxy.
    ///
    /// An IPv4-mapped IPv6 address is matched by its IPv4 form, on both sides of the comparison. A trusted proxy CIDR written as `::ffff:10.0.0.0/120` is rewritten to `10.0.0.0/24` while the config is built, so it matches the same addresses an IPv4 CIDR would. For the same reason an IPv6 CIDR such as `::/0` never matches an IPv4 peer, so both address families need their own CIDR.
    ///
    /// This is always true in trust-all proxy mode, and always false when no proxy is trusted.
    #[inline]
    pub fn is_trusted_proxy(&self, ip: IpAddr) -> bool {
        match &self.trust {
            TrustModel::NoProxy => false,
            TrustModel::TrustedProxies {
                ..
            } => self.rule_for(ip).is_some(),
            TrustModel::TrustAllProxies(_) => true,
        }
    }

    /// Find the trusted proxy rule that covers an address.
    #[inline]
    pub(crate) fn rule_for(&self, ip: IpAddr) -> Option<&TrustedProxyRule> {
        match &self.trust {
            TrustModel::TrustedProxies {
                rules, ..
            } => {
                let ip = canonical_ip(ip);

                // The rules never overlap and are sorted by first address, so only the last rule that starts at or before this address can contain it.
                let index = rules.partition_point(|rule| rule.cidr.first_address() <= ip);
                let rule = &rules[index.checked_sub(1)?];

                rule.cidr.contains(&ip).then_some(rule)
            },
            TrustModel::NoProxy | TrustModel::TrustAllProxies(_) => None,
        }
    }
}

impl Default for ClientIpConfig {
    #[inline]
    fn default() -> Self {
        Self {
            trust: TrustModel::NoProxy
        }
    }
}

/// The first step of building a [`ClientIpConfig`], where the trust model is chosen.
///
/// The chosen trust model decides which builder comes next, so a config can never mix trusted proxy CIDRs with trust-all proxy settings.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ClientIpConfigBuilder;

impl ClientIpConfigBuilder {
    /// Create a new config builder.
    #[inline]
    pub const fn new() -> Self {
        Self
    }

    /// Read no header and always answer with the socket peer IP.
    ///
    /// This is the same as [`ClientIpConfig::default`], and needs no further building.
    #[inline]
    pub const fn trust_no_proxy(self) -> ClientIpConfig {
        ClientIpConfig {
            trust: TrustModel::NoProxy
        }
    }

    /// Trust proxies whose socket peer IP falls inside a known CIDR.
    ///
    /// Use this whenever the proxy addresses are known ahead of time. It is the safest choice, because a client that reaches the service directly can never make it read forwarding headers.
    #[inline]
    pub fn trusted_proxies(self) -> TrustedProxiesBuilder {
        TrustedProxiesBuilder::new()
    }

    /// Treat every socket peer as a trusted proxy.
    ///
    /// Use this when the service can only be reached through a proxy, but the address of that proxy is not known ahead of time. Any socket peer may then choose its own address, so this must not be used on a service that clients can reach directly.
    #[inline]
    pub fn trust_all_proxies(self) -> TrustAllProxiesBuilder {
        TrustAllProxiesBuilder::new()
    }
}

/// Builder for a config that trusts proxies by CIDR.
///
/// A request is resolved from headers only when its socket peer IP matches one of the added CIDRs.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TrustedProxiesBuilder {
    rules:              Vec<TrustedProxyRule>,
    chain_header_order: Vec<ChainHeader>,
}

impl TrustedProxiesBuilder {
    /// Create a builder with the default chain header order.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a trusted proxy CIDR without a client IP header.
    ///
    /// Requests from this CIDR are resolved from the chain headers.
    #[must_use = "builder methods return an updated builder and do not mutate in place"]
    #[inline]
    pub fn proxy(self, cidr: IpCidr) -> Self {
        self.proxy_rule(TrustedProxyRule::new(cidr))
    }

    /// Add a trusted proxy CIDR with a client IP header.
    ///
    /// Use this when the proxy writes the client address into one header that holds a single IP. Common examples are `X-Real-IP`, `CF-Connecting-IP`, and `True-Client-IP`.
    ///
    /// The header is read only when the socket peer IP is inside this CIDR. If it is missing or unusable, the chain headers are still tried, so the proxy should also clear or overwrite the chain headers it does not set itself.
    #[must_use = "builder methods return an updated builder and do not mutate in place"]
    #[inline]
    pub fn proxy_with_client_ip_header(self, cidr: IpCidr, header: Uncased<'static>) -> Self {
        self.proxy_rule(TrustedProxyRule::with_client_ip_header(cidr, header))
    }

    /// Add a trusted proxy CIDR that sends the `X-Real-IP` header.
    ///
    /// This is a shortcut for [`Self::proxy_with_client_ip_header`], and it fits Nginx-like setups that pass one client address in `X-Real-IP`.
    #[must_use = "builder methods return an updated builder and do not mutate in place"]
    #[inline]
    pub fn proxy_with_x_real_ip(self, cidr: IpCidr) -> Self {
        self.proxy_rule(TrustedProxyRule::with_x_real_ip(cidr))
    }

    /// Add one prepared trusted proxy rule.
    #[must_use = "builder methods return an updated builder and do not mutate in place"]
    #[inline]
    pub fn proxy_rule(mut self, rule: TrustedProxyRule) -> Self {
        self.rules.push(rule);
        self
    }

    /// Add several prepared trusted proxy rules.
    ///
    /// Use this when the rules come from a config file or another runtime source.
    #[must_use = "builder methods return an updated builder and do not mutate in place"]
    #[inline]
    pub fn proxies(mut self, rules: impl IntoIterator<Item = TrustedProxyRule>) -> Self {
        self.rules.extend(rules);
        self
    }

    /// Set the chain headers, and the order they are tried in.
    ///
    /// Use [`ChainHeader::new`] for a custom comma-separated IP list header, and an empty iterator to read no chain header at all.
    #[must_use = "builder methods return an updated builder and do not mutate in place"]
    #[inline]
    pub fn chain_header_order(mut self, order: impl IntoIterator<Item = ChainHeader>) -> Self {
        self.chain_header_order = order.into_iter().collect();
        self
    }

    /// Read no chain header at all.
    ///
    /// Use this when the proxy sets a client IP header and cannot clear the chain headers a client may send.
    #[must_use = "builder methods return an updated builder and do not mutate in place"]
    #[inline]
    pub fn disable_chain_headers(self) -> Self {
        self.chain_header_order([])
    }

    /// Build an immutable config.
    ///
    /// CIDRs that use the same client IP header are merged into as few rules as possible. CIDRs that use different client IP headers must not overlap, because one socket peer IP would then mean two policies.
    ///
    /// An IPv4-mapped IPv6 CIDR, such as `::ffff:10.0.0.0/120`, is rewritten to its IPv4 form first, so [`TrustedProxyRule::cidr`] may report a different CIDR than the one that was added.
    ///
    /// # Errors
    ///
    /// Returns [`ClientIpConfigBuildError::OverlappingTrustedProxyRules`] when two rules cover a common address but do not agree on the client IP header.
    pub fn build(self) -> Result<ClientIpConfig, ClientIpConfigBuildError> {
        let mut rules = self.rules;

        // Rewriting before the overlap check lets an IPv4-mapped CIDR clash with a plain IPv4 CIDR that covers the same addresses.
        for rule in &mut rules {
            rule.cidr = canonical_cidr(rule.cidr);
        }

        ensure_no_cross_metadata_overlap(&rules)?;

        let mut rules = merge_rules_by_metadata(rules);

        // Merging only joins networks of one metadata group, so it covers exactly the same addresses and cannot create a new cross-metadata overlap.
        debug_assert!(ensure_no_cross_metadata_overlap(&rules).is_ok());

        // Merging leaves the rules of one metadata group disjoint, and rules of different groups were already rejected if they overlapped, so no address can match two rules. Sorting by first address therefore only fixes the order that the metadata grouping left undefined, and it lets a lookup binary search instead of scan.
        rules.sort_by_key(|rule| rule.cidr.first_address());

        Ok(ClientIpConfig {
            trust: TrustModel::TrustedProxies {
                rules,
                chain_header_order: self.chain_header_order,
            },
        })
    }
}

impl Default for TrustedProxiesBuilder {
    #[inline]
    fn default() -> Self {
        Self {
            rules: Vec::new(), chain_header_order: default_chain_header_order()
        }
    }
}

/// Builder for a config that treats every socket peer as a trusted proxy.
///
/// This fits a service that is always behind a proxy whose address is not known. It is safe only when clients cannot reach the service directly and the proxy clears the forwarding headers it does not set itself.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct TrustAllProxiesBuilder {
    mode: TrustAllProxyMode,
}

impl TrustAllProxiesBuilder {
    /// Create a builder with the default trust-all proxy settings.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a header that holds a single client IP, checked before any chain header.
    ///
    /// It must contain one plain IP address, such as the value a proxy usually sends in `X-Real-IP`.
    #[must_use = "builder methods return an updated builder and do not mutate in place"]
    #[inline]
    pub fn client_ip_header(mut self, header: Uncased<'static>) -> Self {
        self.mode.client_ip_header = Some(header);
        self
    }

    /// Set the chain headers, and the order they are tried in.
    ///
    /// Use [`ChainHeader::new`] for a custom comma-separated IP list header, and an empty iterator to read no chain header at all.
    #[must_use = "builder methods return an updated builder and do not mutate in place"]
    #[inline]
    pub fn chain_header_order(mut self, order: impl IntoIterator<Item = ChainHeader>) -> Self {
        self.mode.chain_header_order = order.into_iter().collect();
        self
    }

    /// Read no chain header at all.
    ///
    /// Use this when the proxy sets a client IP header and cannot clear the chain headers a client may send.
    #[must_use = "builder methods return an updated builder and do not mutate in place"]
    #[inline]
    pub fn disable_chain_headers(self) -> Self {
        self.chain_header_order([])
    }

    /// Set which hop of a chain header becomes the client IP.
    #[must_use = "builder methods return an updated builder and do not mutate in place"]
    #[inline]
    pub const fn chain_ip_selection(mut self, selection: TrustAllChainIpSelection) -> Self {
        self.mode.chain_ip_selection = selection;
        self
    }

    /// Build an immutable config.
    #[inline]
    pub fn build(self) -> ClientIpConfig {
        ClientIpConfig {
            trust: TrustModel::TrustAllProxies(self.mode)
        }
    }
}

/// Settings used when every socket peer is treated as a trusted proxy.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TrustAllProxyMode {
    pub(crate) client_ip_header:   Option<Uncased<'static>>,
    pub(crate) chain_header_order: Vec<ChainHeader>,
    pub(crate) chain_ip_selection: TrustAllChainIpSelection,
}

impl TrustAllProxyMode {
    /// Return the header that holds a single client IP, checked before any chain header.
    #[inline]
    pub const fn client_ip_header(&self) -> Option<&Uncased<'static>> {
        self.client_ip_header.as_ref()
    }

    /// Return the chain headers in the order they are tried.
    #[inline]
    pub fn chain_header_order(&self) -> &[ChainHeader] {
        &self.chain_header_order
    }

    /// Return which hop of a chain header becomes the client IP.
    #[inline]
    pub const fn chain_ip_selection(&self) -> TrustAllChainIpSelection {
        self.chain_ip_selection
    }
}

impl Default for TrustAllProxyMode {
    #[inline]
    fn default() -> Self {
        Self {
            client_ip_header:   None,
            chain_header_order: default_chain_header_order(),
            chain_ip_selection: TrustAllChainIpSelection::Rightmost,
        }
    }
}

/// Which hop of a chain header becomes the client IP in trust-all proxy mode.
///
/// There are no CIDRs to compare against in this mode, so one hop is picked by position instead of by scanning the chain. If that hop carries no usable IP address, the search stops and the socket peer IP becomes the answer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TrustAllChainIpSelection {
    /// Use the first hop of the chain.
    ///
    /// This is the value people usually mean by "the `X-Forwarded-For` address", but it is also the part a client can write freely. It is safe only when the proxy in front of the service overwrites or clears the header instead of appending to it.
    Leftmost,

    /// Use the last hop of the chain.
    ///
    /// A proxy that appends writes the address it received the request from, so the last hop is the one value in the chain that a client cannot choose. This is the default, and it is correct when exactly one proxy appends to the header.
    Rightmost,

    /// Skip a number of hops from the right, then use the next one.
    ///
    /// Use this when a fixed number of proxies append to the header, such as a CDN in front of a load balancer. `SkipRightmostHops(0)` is the same as [`Self::Rightmost`].
    ///
    /// Every hop counts, including one that carries no usable IP address. When the chain is shorter than this needs, the search stops and the socket peer IP becomes the answer.
    SkipRightmostHops(usize),
}

/// Extra behavior attached to a trusted proxy rule.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct TrustedProxyMetadata {
    pub(crate) client_ip_header: Option<Uncased<'static>>,
}

impl TrustedProxyMetadata {
    #[inline]
    pub(crate) const fn none() -> Self {
        Self {
            client_ip_header: None
        }
    }

    #[inline]
    pub(crate) const fn with_client_ip_header(header: Uncased<'static>) -> Self {
        Self {
            client_ip_header: Some(header)
        }
    }
}

/// A trusted proxy CIDR, and the client IP header that proxy is allowed to set.
///
/// The CIDR decides when this rule applies. If the rule names a client IP header, that header is read before any chain header.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TrustedProxyRule {
    pub(crate) cidr:     IpCidr,
    pub(crate) metadata: TrustedProxyMetadata,
}

impl TrustedProxyRule {
    /// Create a trusted proxy rule without a client IP header.
    #[inline]
    pub const fn new(cidr: IpCidr) -> Self {
        Self {
            cidr,
            metadata: TrustedProxyMetadata::none(),
        }
    }

    /// Create a trusted proxy rule with a client IP header.
    ///
    /// Use this when the proxy writes the client address into one header that holds a single IP. The header is read only for socket peers inside this CIDR. If it is missing or unusable, the chain headers are still tried, so the proxy should also clear or overwrite the chain headers it does not set itself.
    #[inline]
    pub const fn with_client_ip_header(cidr: IpCidr, header: Uncased<'static>) -> Self {
        Self {
            cidr,
            metadata: TrustedProxyMetadata::with_client_ip_header(header),
        }
    }

    /// Create a trusted proxy rule for the `X-Real-IP` header.
    #[inline]
    pub const fn with_x_real_ip(cidr: IpCidr) -> Self {
        Self::with_client_ip_header(cidr, Uncased::from_borrowed("x-real-ip"))
    }

    /// Return the CIDR this rule matches.
    #[inline]
    pub const fn cidr(&self) -> &IpCidr {
        &self.cidr
    }

    /// Return the client IP header of this rule, if it has one.
    #[inline]
    pub const fn client_ip_header(&self) -> Option<&Uncased<'static>> {
        self.metadata.client_ip_header.as_ref()
    }
}

/// A header that carries a chain of client and proxy addresses.
///
/// `Forwarded` is read with the RFC 7239 syntax. Every other header name, including `X-Forwarded-For`, is read as a comma-separated list of addresses.
///
/// The reading style is decided once, when the chain header is created. [`ChainHeader::new`] takes it from the header name, and [`ChainHeader::forwarded_style`] sets it to the RFC 7239 syntax whatever the name is.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ChainHeader {
    name: Uncased<'static>,
    kind: ChainHeaderKind,
}

/// How the value of a chain header is read.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum ChainHeaderKind {
    /// An `X-Forwarded-For` style comma-separated list, which is also how every custom chain header is read.
    XForwardedFor,

    /// The RFC 7239 `Forwarded` syntax.
    Forwarded,
}

impl ChainHeader {
    /// Create a chain header from a header name.
    ///
    /// Use this for a custom header that carries an `X-Forwarded-For` style comma-separated list. The name `forwarded` still gets its RFC 7239 reading, and [`Self::forwarded_style`] gives that reading to any other name.
    #[inline]
    pub fn new(header: Uncased<'static>) -> Self {
        let kind = if header == "forwarded" {
            ChainHeaderKind::Forwarded
        } else {
            ChainHeaderKind::XForwardedFor
        };

        Self {
            name: header,
            kind,
        }
    }

    /// Create the `X-Forwarded-For` chain header.
    #[inline]
    pub const fn x_forwarded_for() -> Self {
        Self {
            name: Uncased::from_borrowed("x-forwarded-for"),
            kind: ChainHeaderKind::XForwardedFor,
        }
    }

    /// Create the `Forwarded` chain header.
    #[inline]
    pub const fn forwarded() -> Self {
        Self {
            name: Uncased::from_borrowed("forwarded"), kind: ChainHeaderKind::Forwarded
        }
    }

    /// Create a chain header that is read with the RFC 7239 `Forwarded` syntax.
    ///
    /// Use this for a proxy that sends that syntax under a name of its own, because [`Self::new`] reads every name other than `forwarded` as a comma-separated list.
    #[inline]
    pub const fn forwarded_style(header: Uncased<'static>) -> Self {
        Self {
            name: header, kind: ChainHeaderKind::Forwarded
        }
    }

    /// Return the wrapped header name.
    #[inline]
    pub const fn as_header_name(&self) -> &Uncased<'static> {
        &self.name
    }

    /// Consume this chain header and return the wrapped header name.
    #[inline]
    pub fn into_header_name(self) -> Uncased<'static> {
        self.name
    }

    #[inline]
    pub(crate) const fn kind(&self) -> ChainHeaderKind {
        self.kind
    }
}

impl From<Uncased<'static>> for ChainHeader {
    #[inline]
    fn from(header: Uncased<'static>) -> Self {
        Self::new(header)
    }
}

/// The chain headers a config reads when none are named: `X-Forwarded-For`, then `Forwarded`.
#[inline]
fn default_chain_header_order() -> Vec<ChainHeader> {
    vec![ChainHeader::x_forwarded_for(), ChainHeader::forwarded()]
}
