use std::net::IpAddr;

use cidr::{IpCidr, Ipv4Cidr};

/// Rewrite an IPv4-mapped IPv6 address into its IPv4 form.
///
/// A dual-stack listener reports an IPv4 peer as `::ffff:a.b.c.d`, and some proxies write that form into their headers. Every address is passed through this function, so one client always resolves to one address, and an IPv4 CIDR matches an IPv4 client no matter which form arrived.
#[inline]
pub(crate) const fn canonical_ip(ip: IpAddr) -> IpAddr {
    ip.to_canonical()
}

/// Rewrite an IPv4-mapped IPv6 network into its IPv4 form.
///
/// An address is canonicalized before it is matched, so a rule written as `::ffff:10.0.0.0/120` would never match anything unless the rule is rewritten the same way.
pub(crate) const fn canonical_cidr(cidr: IpCidr) -> IpCidr {
    let IpCidr::V6(v6) = cidr else {
        return cidr;
    };

    // The IPv4-mapped range is `::ffff:0:0/96`, so a shorter prefix covers addresses outside it and has no IPv4 form.
    let Some(network_length) = v6.network_length().checked_sub(96) else {
        return cidr;
    };

    let Some(first_address) = v6.first_address().to_ipv4_mapped() else {
        return cidr;
    };

    match Ipv4Cidr::new(first_address, network_length) {
        Ok(v4) => IpCidr::V4(v4),
        Err(_) => cidr,
    }
}
