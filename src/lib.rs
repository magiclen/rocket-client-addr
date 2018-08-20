//! # Client's IP Address Request Guard for Rocket Framework
//! This crate provides a request guard used for getting an IP address from a client.

extern crate rocket;

use std::net::IpAddr;

use rocket::Outcome;
use rocket::request::{self, Request, FromRequest};

/// The request guard used for getting an IP address from a client.
pub struct ClientAddr {
    /// IP address from a client.
    pub ip: IpAddr
}

fn is_local_ip(addr: &IpAddr) -> bool {
    addr.is_unspecified() || addr.is_loopback()
}

impl<'a, 'r> FromRequest<'a, 'r> for ClientAddr {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Self, Self::Error> {
        let ip = match request.remote() {
            Some(addr) => {
                let ip = addr.ip();

                if is_local_ip(&ip) {
                    None
                } else {
                    Some(ip)
                }
            }
            None => {
                None
            }
        };

        match ip {
            Some(ip) => {
                Outcome::Success(ClientAddr { ip })
            }
            None => {
                let values: Vec<_> = request.headers().get("x-real-ip").collect();

                if values.len() < 1 {
                    let values: Vec<_> = request.headers().get("x-forwarded-for").collect();

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
            }
        }
    }
}