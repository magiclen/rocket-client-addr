#[macro_use]
extern crate rocket;

use rocket_client_addr::{ClientIp, ClientIpConfig};

#[get("/")]
fn index(client_ip: &ClientIp) -> String {
    // The source is always ClientIpSource::Socket here, because no header is trusted.
    format!("client_ip={} source={:?}\n", client_ip.ip(), client_ip.source())
}

#[launch]
fn rocket() -> _ {
    // This is the safest and smallest setup.
    // No proxy is trusted, so headers such as X-Real-IP and X-Forwarded-For are ignored.
    // The answer is always the address the TCP connection came from.
    let config = ClientIpConfig::builder().trust_no_proxy();

    // The ClientIp guard looks the config up by type, so it has to be managed here.
    rocket::build().manage(config).mount("/", routes![index])
}
