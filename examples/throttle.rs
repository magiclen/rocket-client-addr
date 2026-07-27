#[macro_use]
extern crate rocket;

use std::{net::IpAddr, num::NonZeroU32};

use governor::{DefaultKeyedRateLimiter, Quota};
use rocket::{
    Request,
    http::Status,
    outcome::Outcome,
    request::{self, FromRequest},
};
use rocket_client_addr::{ClientIp, ClientIpConfig};

type RateLimiter = DefaultKeyedRateLimiter<IpAddr>;

/// A request guard that lets a request through only while its client IP is still under the quota.
struct Throttled;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Throttled {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let client_ip = match request.guard::<&ClientIp>().await {
            Outcome::Success(client_ip) => client_ip,
            // Without a client IP there is no key to throttle by, so the answer of the ClientIp guard is passed on unchanged.
            Outcome::Error((status, _)) => return Outcome::Error((status, ())),
            Outcome::Forward(status) => return Outcome::Forward(status),
        };

        let rate_limiter =
            request.rocket().state::<RateLimiter>().expect("the rate limiter is managed in main");

        if rate_limiter.check_key(&client_ip.ip()).is_err() {
            return Outcome::Error((Status::TooManyRequests, ()));
        }

        Outcome::Success(Self)
    }
}

#[get("/")]
fn index(_throttled: Throttled, client_ip: &ClientIp) -> String {
    // The Throttled guard already resolved this address, and the cache hands out the same value here.
    format!("client_ip={} source={:?}\n", client_ip.ip(), client_ip.source())
}

#[catch(429)]
async fn too_many_requests(request: &Request<'_>) -> String {
    match request.guard::<&ClientIp>().await {
        Outcome::Success(client_ip) => format!("too many requests from {}\n", client_ip.ip()),
        _ => "too many requests\n".to_string(),
    }
}

#[launch]
fn rocket() -> _ {
    // This keeps the address behavior of the basic example: no header is read, so the throttle key is the socket address.
    let client_ip_config = ClientIpConfig::builder().trust_no_proxy();

    // Each address may send a burst of 3 requests, and then gets one more request per second.
    // Governor uses GCRA, which behaves like a token bucket rather than a fixed window.
    let quota =
        Quota::per_second(NonZeroU32::new(1).unwrap()).allow_burst(NonZeroU32::new(3).unwrap());

    // This throttle lives in memory, inside one process.
    // Use shared storage if the limit has to cover several instances of the service.
    rocket::build()
        .manage(client_ip_config)
        .manage(RateLimiter::keyed(quota))
        .mount("/", routes![index])
        .register("/", catchers![too_many_requests])
}
