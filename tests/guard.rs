//! Tests for the `ClientIp` request guard and how it reads the config out of Rocket's managed state.

use std::net::{IpAddr, SocketAddr};

use rocket::{
    Build, Rocket, get,
    http::{Header, Status},
    local::blocking::{Client, LocalRequest},
    routes,
};
use rocket_client_addr::{ClientIp, ClientIpConfig, HeaderMap, IpCidr, Uncased};

/// Report the resolved address and where it came from, in a form a test can compare.
fn describe(client_ip: &ClientIp) -> String {
    match client_ip.source().header_name() {
        Some(header) => format!("{} {header}", client_ip.ip()),
        None => format!("{} socket", client_ip.ip()),
    }
}

#[get("/owned")]
fn owned(client_ip: ClientIp) -> String {
    describe(&client_ip)
}

#[get("/borrowed")]
fn borrowed(client_ip: &ClientIp) -> String {
    describe(client_ip)
}

#[get("/optional")]
fn optional(client_ip: Option<ClientIp>) -> String {
    match client_ip {
        Some(client_ip) => describe(&client_ip),
        None => "none".to_string(),
    }
}

#[get("/cached")]
fn cached(first: &ClientIp, second: &ClientIp) -> String {
    std::ptr::eq(first, second).to_string()
}

fn ip(input: &str) -> IpAddr {
    input.parse().unwrap()
}

/// Trust 10.0.0.0/24, and let it send the client address in X-Real-IP.
fn trusted_config() -> ClientIpConfig {
    ClientIpConfig::builder()
        .trusted_proxies()
        .proxy_with_x_real_ip("10.0.0.0/24".parse::<IpCidr>().unwrap())
        .build()
        .unwrap()
}

fn rocket_with_config() -> Rocket<Build> {
    rocket::build().manage(trusted_config()).mount("/", routes![owned, borrowed, optional, cached])
}

/// A request from the trusted proxy 10.0.0.2, reporting the client 203.0.113.10.
fn request<'c>(client: &'c Client, path: &str) -> LocalRequest<'c> {
    client
        .get(path.to_string())
        .remote("10.0.0.2:12345".parse::<SocketAddr>().unwrap())
        .header(Header::new("x-real-ip", "203.0.113.10"))
}

// A request from a trusted proxy is resolved from the header that proxy is allowed to set.
#[test]
fn the_guard_resolves_a_request_from_a_trusted_proxy() {
    let client = Client::tracked(rocket_with_config()).unwrap();

    let response = request(&client, "/owned").dispatch();

    assert_eq!(Status::Ok, response.status());
    assert_eq!("203.0.113.10 x-real-ip", response.into_string().unwrap());
}

// The borrowed guard answers the same request the same way.
#[test]
fn the_borrowed_guard_gives_the_same_answer() {
    let client = Client::tracked(rocket_with_config()).unwrap();

    let response = request(&client, "/borrowed").dispatch();

    assert_eq!("203.0.113.10 x-real-ip", response.into_string().unwrap());
}

// Two borrowed guards on one route share the cached answer instead of walking the headers twice.
#[test]
fn the_borrowed_guard_resolves_a_request_only_once() {
    let client = Client::tracked(rocket_with_config()).unwrap();

    let response = request(&client, "/cached").dispatch();

    assert_eq!("true", response.into_string().unwrap());
}

// A peer outside the trusted CIDR wrote its own header, so the answer is the address it connected from.
#[test]
fn an_untrusted_peer_answers_with_its_own_address() {
    let client = Client::tracked(rocket_with_config()).unwrap();

    let response = client
        .get("/owned")
        .remote("192.0.2.5:12345".parse::<SocketAddr>().unwrap())
        .header(Header::new("x-real-ip", "203.0.113.10"))
        .dispatch();

    assert_eq!("192.0.2.5 socket", response.into_string().unwrap());
}

// Without a managed config the guard cannot know which trust model to use, and that is a server setup mistake rather than a bad request.
#[test]
fn the_guard_fails_without_a_managed_config() {
    let client = Client::tracked(rocket::build().mount("/", routes![owned])).unwrap();

    let response = request(&client, "/owned").dispatch();

    assert_eq!(Status::InternalServerError, response.status());
}

// Every answer falls back to the socket peer, so a request without one cannot be resolved at all.
#[test]
fn the_guard_fails_without_a_remote_address() {
    let client = Client::tracked(rocket_with_config()).unwrap();

    let response = client.get("/owned").header(Header::new("x-real-ip", "203.0.113.10")).dispatch();

    assert_eq!(Status::InternalServerError, response.status());
}

// The optional guard reports nothing instead of failing the request.
#[test]
fn the_optional_guard_is_none_without_a_remote_address() {
    let client = Client::tracked(rocket_with_config()).unwrap();

    let response = client.get("/optional").dispatch();

    assert_eq!("none", response.into_string().unwrap());
}

// With a remote address the optional guard answers just like the plain one.
#[test]
fn the_optional_guard_resolves_when_a_remote_address_is_present() {
    let client = Client::tracked(rocket_with_config()).unwrap();

    let response = request(&client, "/optional").dispatch();

    assert_eq!("203.0.113.10 x-real-ip", response.into_string().unwrap());
}

// The resolved address can be read, split apart, printed, or turned into a plain IpAddr.
#[test]
fn a_resolved_client_ip_can_be_read_in_several_ways() {
    let mut headers = HeaderMap::new();
    headers.add_raw("x-real-ip", "203.0.113.10");

    let client_ip = trusted_config().resolve_client_ip(&headers, ip("10.0.0.2"));

    assert_eq!("203.0.113.10", client_ip.to_string());
    assert_eq!(ip("203.0.113.10"), IpAddr::from(client_ip.clone()));

    let (address, source) = client_ip.into_parts();

    assert_eq!(ip("203.0.113.10"), address);
    assert_eq!(Some(&Uncased::from_borrowed("x-real-ip")), source.header_name());
}
