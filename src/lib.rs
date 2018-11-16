/*!
# Client's IP Address Request Guard for Rocket Framework

This crate provides a request guard used for getting an IP address from a client.

See `examples`.
*/

#![feature(ip)]

extern crate rocket;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Ipv6MulticastScope};

use rocket::Outcome;
use rocket::request::{self, Request, FromRequest};

/// The request guard used for getting an IP address from a client.
pub struct ClientAddr {
    /// IP address from a client.
    pub ip: IpAddr
}

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

impl<'a, 'r> FromRequest<'a, 'r> for ClientAddr {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Self, Self::Error> {
        let remote_ip = match request.remote() {
            Some(addr) => {
                let ip = addr.ip();

                if !is_local_ip(&ip) {
                    return Outcome::Success(ClientAddr { ip });
                }

                Some(ip)
            }
            None => {
                None
            }
        };

        let real_ip: Option<&str> = request.headers().get("x-real-ip").next(); // Only fetch the first one.

        match real_ip {
            Some(real_ip) => {
                match real_ip.parse::<IpAddr>() {
                    Ok(ip) => {
                        Outcome::Success(ClientAddr { ip })
                    }
                    Err(_) => Outcome::Forward(())
                }
            }
            None => {
                let forwarded_for_ip: Option<&str> = request.headers().get("x-forwarded-for").next(); // Only fetch the first one.

                match forwarded_for_ip {
                    Some(forwarded_for_ip) => {
                        match forwarded_for_ip.parse::<IpAddr>() {
                            Ok(ip) => {
                                Outcome::Success(ClientAddr { ip })
                            }
                            Err(_) => Outcome::Forward(())
                        }
                    }
                    None => {
                        match remote_ip {
                            Some(ip) => Outcome::Success(ClientAddr { ip }),
                            None => Outcome::Forward(())
                        }
                    }
                }
            }
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

    /// Get a ipv4 string.
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

    /// Get a ipv6 string.
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