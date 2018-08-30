#![cfg_attr(feature = "nightly", feature(ip))]

//! # Client's IP Address Request Guard for Rocket Framework
//! This crate provides a request guard used for getting an IP address from a client.

extern crate rocket;

use std::net::IpAddr;
#[cfg(feature = "nightly")]
use std::net::Ipv6MulticastScope;

use rocket::Outcome;
use rocket::request::{self, Request, FromRequest};

/// The request guard used for getting an IP address from a client.
pub struct ClientAddr {
    /// IP address from a client.
    pub ip: IpAddr
}

#[cfg(not(feature = "nightly"))]
fn is_local_ip(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(addr) => {
            addr.is_private() || addr.is_loopback() || addr.is_link_local() || addr.is_broadcast() || addr.is_documentation() || addr.is_unspecified()
        }
        IpAddr::V6(addr) => {
            addr.is_multicast() || addr.is_loopback() || addr.is_unspecified()
        }
    }
}

#[cfg(feature = "nightly")]
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
        let mut from_header = false;

        let remote_ip = match request.remote() {
            Some(addr) => {
                let ip = addr.ip();

                if is_local_ip(&ip) {
                    from_header = true;
                }

                Some(ip)
            }
            None => {
                from_header = true;
                None
            }
        };

        if from_header {
            let values: Vec<_> = request.headers().get("x-real-ip").collect();

            if values.len() < 1 {
                let values: Vec<_> = request.headers().get("x-forwarded-for").collect();

                if values.len() < 1 {
                    return match remote_ip {
                        Some(ip) => Outcome::Success(ClientAddr { ip }),
                        None => Outcome::Forward(())
                    };
                }

                let value = values[0];

                return match value.parse::<IpAddr>() {
                    Ok(ip) => {
                        Outcome::Success(ClientAddr { ip })
                    }
                    Err(_) => Outcome::Forward(())
                };
            }

            let value = values[0];

            match value.parse::<IpAddr>() {
                Ok(ip) => {
                    Outcome::Success(ClientAddr { ip })
                }
                Err(_) => Outcome::Forward(())
            }
        } else {
            Outcome::Success(ClientAddr { ip: remote_ip.unwrap() })
        }
    }
}