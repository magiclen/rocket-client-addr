#[macro_use]
extern crate rocket;

use rocket_client_addr::{
    ChainHeader, ClientIp, ClientIpConfig, TrustAllChainIpSelection, Uncased,
};

#[get("/")]
fn index(client_ip: &ClientIp) -> String {
    // The source is usually ConfiguredHeader("x-real-ip").
    // If X-Real-IP is missing or unusable, it becomes ChainHeader("x-forwarded-for") instead.
    format!("client_ip={} source={:?}\n", client_ip.ip(), client_ip.source())
}

#[launch]
fn rocket() -> _ {
    // Use this setup only when clients cannot reach the Rust service directly.
    // A common case is a service that listens on a private network, with Nginx handling all public traffic.
    //
    // Trust-all mode treats every socket peer as a trusted proxy.
    // That helps when Nginx is always in front of the service, but its address is not stable or not known ahead of time.
    let config = ClientIpConfig::builder()
        .trust_all_proxies()
        // X-Real-IP holds a single address.
        // If it is present and holds a plain IP, it wins before any chain header is read.
        .client_ip_header(Uncased::from_borrowed("x-real-ip"))
        // X-Forwarded-For is a comma-separated list header.
        .chain_header_order([ChainHeader::x_forwarded_for()])
        // Rightmost is the default, and it is the safe choice here.
        // A client can write anything on the left of X-Forwarded-For, but a proxy that appends always writes the address it received the request from.
        // Use Leftmost only when Nginx overwrites the whole header instead of appending to it.
        .chain_ip_selection(TrustAllChainIpSelection::Rightmost)
        .build();

    // A direct client could send its own X-Real-IP or X-Forwarded-For in this mode.
    // Keep this server behind Nginx, and make Nginx clear or overwrite both headers before it forwards a request.
    rocket::build().manage(config).mount("/", routes![index])
}
