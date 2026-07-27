use std::{error::Error, fmt};

use crate::TrustedProxyRule;

/// An error returned while building a [`crate::ClientIpConfig`].
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ClientIpConfigBuildError {
    /// Trusted proxy CIDRs cover a common address but do not agree on the client IP header.
    ///
    /// One socket peer IP has to mean one policy, so the config cannot be built until the CIDRs are changed to agree or to stop overlapping.
    OverlappingTrustedProxyRules {
        /// The first of the two rules that overlap.
        left: Box<TrustedProxyRule>,

        /// The second of the two rules that overlap.
        right: Box<TrustedProxyRule>,
    },
}

impl fmt::Display for ClientIpConfigBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OverlappingTrustedProxyRules {
                left,
                right,
            } => write!(
                f,
                "trusted proxy CIDRs overlap but use different client IP headers: {} ({}) \
                 overlaps {} ({})",
                left.cidr(),
                describe_client_ip_header(left),
                right.cidr(),
                describe_client_ip_header(right),
            ),
        }
    }
}

/// Name the client IP header of a rule, for an error message.
fn describe_client_ip_header(rule: &TrustedProxyRule) -> &str {
    match rule.client_ip_header() {
        Some(header) => header.as_str(),
        None => "no client IP header",
    }
}

impl Error for ClientIpConfigBuildError {}

/// The error returned by the [`crate::ClientIp`] request guard.
///
/// Both variants are server setup mistakes rather than bad requests, so the guard fails with [`rocket::http::Status::InternalServerError`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ClientIpRejection {
    /// No [`crate::ClientIpConfig`] is in Rocket's managed state.
    ///
    /// Pass a built config to `rocket::build().manage(config)` so that the guard knows which trust model to use.
    MissingConfig,

    /// The request carries no remote address.
    ///
    /// Every answer falls back to the socket peer IP, so a request without one cannot be resolved at all. Rocket records the address of every real connection, so this only shows up on a local test client that was not given one with `LocalRequest::remote`.
    MissingRemoteAddr,
}

impl fmt::Display for ClientIpRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingConfig => {
                write!(f, "no ClientIpConfig is managed; pass one to rocket::build().manage()")
            },
            Self::MissingRemoteAddr => write!(f, "the request has no remote address"),
        }
    }
}

impl Error for ClientIpRejection {}
