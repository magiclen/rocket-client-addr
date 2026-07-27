use std::{fmt, net::IpAddr};

use rocket::{
    http::{Status, uncased::Uncased},
    outcome::Outcome,
    request::{self, FromRequest, Request},
};

use crate::{
    ClientIpConfig,
    ClientIpRejection::{self, MissingConfig, MissingRemoteAddr},
};

/// The resolved client IP, and where it came from.
///
/// This is a Rocket request guard. It reads a [`ClientIpConfig`] out of Rocket's managed state, so the config has to be passed to `rocket::build().manage(config)`, and it falls back to the address of the connection that Rocket records in [`Request::remote`].
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ClientIp {
    ip:     IpAddr,
    source: ClientIpSource,
}

impl ClientIp {
    #[inline]
    pub(crate) const fn new(ip: IpAddr, source: ClientIpSource) -> Self {
        Self {
            ip,
            source,
        }
    }

    /// Return the resolved client IP.
    #[inline]
    pub const fn ip(&self) -> IpAddr {
        self.ip
    }

    /// Return where the client IP came from.
    ///
    /// Use this to tell a header value apart from the socket peer IP, for example when logging.
    #[inline]
    pub const fn source(&self) -> &ClientIpSource {
        &self.source
    }

    /// Consume this value and return the client IP and its source.
    #[inline]
    pub fn into_parts(self) -> (IpAddr, ClientIpSource) {
        (self.ip, self.source)
    }
}

impl fmt::Display for ClientIp {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.ip, f)
    }
}

impl From<ClientIp> for IpAddr {
    #[inline]
    fn from(client_ip: ClientIp) -> Self {
        client_ip.ip
    }
}

/// Where a [`ClientIp`] came from.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum ClientIpSource {
    /// The client IP header of a trusted proxy, such as `X-Real-IP`.
    ///
    /// The name inside is the header that gave the address.
    ConfiguredHeader(Uncased<'static>),

    /// One hop of a chain header, such as `X-Forwarded-For` or `Forwarded`.
    ///
    /// The name inside is the header that gave the address.
    ChainHeader(Uncased<'static>),

    /// The socket peer IP, which is the address the connection came from.
    ///
    /// This is the answer whenever no header is trusted enough to change it.
    Socket,
}

impl ClientIpSource {
    /// Return the header that gave the address, or [`None`] for [`Self::Socket`].
    #[inline]
    pub const fn header_name(&self) -> Option<&Uncased<'static>> {
        match self {
            Self::ConfiguredHeader(header) | Self::ChainHeader(header) => Some(header),
            Self::Socket => None,
        }
    }
}

/// Resolve the client IP of a request, or name the setup mistake that stopped it.
fn from_request(request: &Request<'_>) -> Result<ClientIp, ClientIpRejection> {
    let config = request.rocket().state::<ClientIpConfig>().ok_or(MissingConfig)?;
    let remote = request.remote().ok_or(MissingRemoteAddr)?;

    Ok(config.resolve_client_ip(request.headers(), remote.ip()))
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ClientIp {
    type Error = ClientIpRejection;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        match from_request(request) {
            Ok(client_ip) => Outcome::Success(client_ip),
            // Neither failure is caused by the request, so this is a server error rather than a bad request.
            Err(rejection) => Outcome::Error((Status::InternalServerError, rejection)),
        }
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for &'r ClientIp {
    type Error = ClientIpRejection;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        // A route may take the client IP more than once, directly or through another guard, and the chain headers are only worth walking once per request.
        let cache: &Result<ClientIp, ClientIpRejection> =
            request.local_cache(|| from_request(request));

        match cache {
            Ok(client_ip) => Outcome::Success(client_ip),
            Err(rejection) => Outcome::Error((Status::InternalServerError, *rejection)),
        }
    }
}
