use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Ipv6MulticastScope};

use crate::rocket::Outcome;
use crate::rocket::request::{self, Request, FromRequest};

/// The request guard used for getting an IP address from a client.
#[derive(Debug, Clone)]
pub struct ClientAddr {
    /// IP address from a client.
    pub ip: IpAddr
}

#[inline]
fn is_local_ip(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(addr) => {
            addr.is_private() || addr.is_loopback() || addr.is_link_local() || addr.is_broadcast() || addr.is_documentation() || addr.is_unspecified()
        }
        IpAddr::V6(addr) => {
            match addr.multicast_scope() {
                Some(Ipv6MulticastScope::Global) => false,
                None => {
                    addr.is_multicast() || addr.is_loopback() || addr.is_unicast_link_local() || addr.is_unicast_site_local() || addr.is_unique_local() || addr.is_unspecified() || addr.is_documentation()
                }
                _ => true
            }
        }
    }
}

macro_rules! impl_request_guard {
    ($request:ident) => {
        {
            let (remote_ip, ok) = match $request.remote() {
                Some(addr) => {
                    let ip = addr.ip();

                    let ok = !is_local_ip(&ip);

                    (Some(ip), ok)
                }
                None => {
                    (None, false)
                }
            };

            if ok {
                match remote_ip {
                    Some(ip) => Some(ClientAddr {
                        ip
                    }),
                    None => unreachable!()
                }
            } else {
                let forwarded_for_ip: Option<&str> = $request.headers().get("x-forwarded-for").next(); // Only fetch the first one.

                match forwarded_for_ip {
                    Some(forwarded_for_ip) => {
                        let forwarded_for_ips = forwarded_for_ip.rsplit(",");

                        let mut last_ip = None;

                        for forwarded_for_ip in forwarded_for_ips {
                            match forwarded_for_ip.trim().parse::<IpAddr>() {
                                Ok(ip) => {
                                    if is_local_ip(&ip) {
                                        last_ip = Some(ip);
                                    } else {
                                        last_ip = Some(ip);
                                        break;
                                    }
                                }
                                Err(_) => {
                                    break;
                                }
                            }
                        }

                        match last_ip {
                            Some(ip) => Some(ClientAddr {
                                ip
                            }),
                            None => match $request.real_ip() {
                                Some(real_ip) => Some(ClientAddr {
                                    ip: real_ip
                                }),
                                None => match remote_ip {
                                    Some(ip) => Some(ClientAddr {
                                        ip
                                    }),
                                    None => None
                                }
                            }
                        }
                    },
                    None => {
                        match $request.real_ip() {
                            Some(real_ip) => Some(ClientAddr {
                                ip: real_ip
                            }),
                            None => match remote_ip {
                                Some(ip) => Some(ClientAddr {
                                    ip
                                }),
                                None => None
                            }
                        }
                    }
                }
            }
        }
    }
}

impl<'a, 'r> FromRequest<'a, 'r> for ClientAddr {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Self, Self::Error> {
        match impl_request_guard!(request) {
            Some(client_addr) => Outcome::Success(client_addr),
            None => Outcome::Forward(())
        }
    }
}

impl<'a, 'r> FromRequest<'a, 'r> for &'a ClientAddr {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Self, Self::Error> {
        let cache: &Option<ClientAddr> = request.local_cache(|| impl_request_guard!(request));

        match cache.as_ref() {
            Some(client_addr) => Outcome::Success(client_addr),
            None => Outcome::Forward(())
        }
    }
}

impl ClientAddr {
    /// Get an `Ipv4Addr` instance.
    pub fn get_ipv4(&self) -> Option<Ipv4Addr> {
        match &self.ip {
            IpAddr::V4(ipv4) => {
                Some(ipv4.clone())
            }
            IpAddr::V6(ipv6) => {
                ipv6.to_ipv4()
            }
        }
    }

    /// Get an IPv4 string.
    pub fn get_ipv4_string(&self) -> Option<String> {
        match &self.ip {
            IpAddr::V4(ipv4) => {
                Some(ipv4.to_string())
            }
            IpAddr::V6(ipv6) => {
                ipv6.to_ipv4().map(|ipv6| ipv6.to_string())
            }
        }
    }

    /// Get an `Ipv6Addr` instance.
    pub fn get_ipv6(&self) -> Ipv6Addr {
        match &self.ip {
            IpAddr::V4(ipv4) => {
                ipv4.to_ipv6_mapped()
            }
            IpAddr::V6(ipv6) => {
                ipv6.clone()
            }
        }
    }

    /// Get an IPv6 string.
    pub fn get_ipv6_string(&self) -> String {
        match &self.ip {
            IpAddr::V4(ipv4) => {
                ipv4.to_ipv6_mapped().to_string()
            }
            IpAddr::V6(ipv6) => {
                ipv6.to_string()
            }
        }
    }
}