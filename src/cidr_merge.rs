use std::{cmp::Reverse, collections::HashMap};

use cidr::IpCidr;
use cidr_utils::combiner::{Ipv4CidrCombiner, Ipv6CidrCombiner};

use crate::{ClientIpConfigBuildError, TrustedProxyRule, config::TrustedProxyMetadata};

/// Reject rules that share an address but do not agree on what that address means.
///
/// One socket peer must lead to one policy. Two rules that cover a common address but name different client IP headers would give that address two policies, so the config is rejected instead of picking one.
pub(crate) fn ensure_no_cross_metadata_overlap(
    rules: &[TrustedProxyRule],
) -> Result<(), ClientIpConfigBuildError> {
    let mut order: Vec<&TrustedProxyRule> = rules.iter().collect();

    // A network must be visited before the ones it contains, so a tie on the first address puts the wider network first.
    order.sort_by_key(|rule| (rule.cidr.first_address(), Reverse(rule.cidr.last_address())));

    // This holds the widest network that is still open, and it is the only one a later rule can reach into. Two networks of one address family are either nested or disjoint, so a rule that reaches into it is nested inside it and ends no later than it does. An address family change ends it too, because every IPv4 address sorts before every IPv6 address.
    let mut open: Option<&TrustedProxyRule> = None;

    for rule in order {
        match open {
            Some(outer) if rule.cidr.first_address() <= outer.cidr.last_address() => {
                // Every rule already nested inside this one had to agree with it to get here, so agreeing with the widest is agreeing with them all.
                if outer.metadata != rule.metadata {
                    return Err(ClientIpConfigBuildError::OverlappingTrustedProxyRules {
                        left:  Box::new(outer.clone()),
                        right: Box::new(rule.clone()),
                    });
                }
            },
            _ => open = Some(rule),
        }
    }

    Ok(())
}

/// Join rules that agree on their metadata into as few rules as possible.
///
/// Rules are grouped by metadata first, because only rules with the same metadata may be replaced by one wider rule. Rules of different groups are left alone, and [`ensure_no_cross_metadata_overlap`] has already proven that they do not overlap.
pub(crate) fn merge_rules_by_metadata(rules: Vec<TrustedProxyRule>) -> Vec<TrustedProxyRule> {
    let mut groups: HashMap<TrustedProxyMetadata, Vec<IpCidr>> = HashMap::new();

    for rule in rules {
        groups.entry(rule.metadata).or_default().push(rule.cidr);
    }

    let mut merged = Vec::new();

    for (metadata, cidrs) in groups {
        merged.extend(merge_cidrs(cidrs).into_iter().map(|cidr| TrustedProxyRule {
            cidr,
            metadata: metadata.clone(),
        }));
    }

    merged
}

/// Turn a list of networks into the shortest list of networks that covers the same addresses.
fn merge_cidrs(cidrs: Vec<IpCidr>) -> Vec<IpCidr> {
    // The two address families never merge into each other, so each one gets its own combiner.
    let mut ipv4 = Ipv4CidrCombiner::new();
    let mut ipv6 = Ipv6CidrCombiner::new();

    for cidr in cidrs {
        match cidr {
            IpCidr::V4(cidr) => ipv4.push(cidr),
            IpCidr::V6(cidr) => ipv6.push(cidr),
        }
    }

    let mut merged = Vec::new();

    for cidr in ipv4.into_ipv4_cidr_vec() {
        merged.push(IpCidr::V4(cidr));
    }

    for cidr in ipv6.into_ipv6_cidr_vec() {
        merged.push(IpCidr::V6(cidr));
    }

    merged
}
