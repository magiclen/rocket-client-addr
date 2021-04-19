/*!
# Client's IP Address Request Guard for Rocket Framework

This crate provides two request guards used for getting an IP address from a client.

See `examples`.
*/

extern crate rocket;

mod client_addr;
mod client_real_addr;

pub use client_addr::ClientAddr;
pub use client_real_addr::ClientRealAddr;
