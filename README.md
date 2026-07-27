Client's IP Address Request Guard for Rocket Framework
====================

[![CI](https://github.com/magiclen/rocket-client-addr/actions/workflows/ci.yml/badge.svg)](https://github.com/magiclen/rocket-client-addr/actions/workflows/ci.yml)

Resolve client IP addresses in `rocket` from trusted proxy headers with safe socket fallback.

The `ClientIp` request guard reads a `ClientIpConfig` from Rocket's managed state. The config decides how much of a request is allowed to change the answer, and every answer falls back to the socket peer IP that Rocket records in `Request::remote`.

## Why the socket address is not enough

The socket peer IP is the address the connection came from. When the service sits behind a proxy, that address belongs to the proxy, and the client is one or more hops further away.

Proxies report the hops they hid in a forwarding header. A header is only text a client can also write, though, so the service has to decide which parts of it were written by something it trusts.

## Forwarding headers

### X-Forwarded-For

`X-Forwarded-For` is a comma-separated list of addresses. Each proxy along the path appends the address it received the request from, so the list grows on the right.

Take a client at `203.0.113.10` that reaches the service through two proxies.

```text
203.0.113.10  ->  198.51.100.7  ->  10.0.0.2  ->  service
   client            proxy 1         proxy 2
```

The service then sees this request.

```text
X-Forwarded-For: 203.0.113.10, 198.51.100.7
socket peer: 10.0.0.2
```

* The **leftmost** value is the oldest hop. It is the original client if every proxy on the path appended honestly, but it is also the part a client can write freely, because the first proxy appends to whatever the client sent instead of replacing it.
* The **rightmost** value is the newest hop, written by the proxy closest to the service. It is the address that proxy received the request from, and it is the one value in the list that no client can choose.
* The **socket peer IP is not in the header**. It belongs to the proxy that opened the connection, so the full path is the header values followed by the socket peer.

Every hop is only as trustworthy as the proxy that wrote it. Everything left of the rightmost value was copied from what an earlier hop claimed.

Several lines of the same header name are read as one list, joined in the order they arrived.

### Forwarded

`Forwarded` (RFC 7239) carries the same chain in a different syntax, with the same left-to-right meaning.

```text
Forwarded: for=203.0.113.10, for=198.51.100.7
```

Only the `for` parameter is read. An element may also carry `by`, `host`, and `proto`, which say nothing about the client address and are ignored. Parameter names are case-insensitive, so `For=` works too.

### What one hop may look like

A hop may carry a port, and an IPv6 hop may be bracketed and quoted.

```text
203.0.113.10
192.0.2.43:47011
[2001:db8::17]:4711
for="[2001:db8::17]:4711"
```

A hop may also exist without revealing an address. `unknown` and an obfuscated identifier such as `_hidden` are hops with no usable IP address, and so is a `Forwarded` element without a `for` parameter. Such a hop still takes one place in the chain.

A header value that cannot be read as visible ASCII hides an unknown number of hops, so that whole chain header becomes unusable.

## How the client IP is chosen

Two rules run through every trust model.

* The socket peer IP is always the fallback. It is the answer whenever no header is trusted enough to change it.
* A header is only read when a proxy the config trusts is known to have written it.

Chain headers are configured as an ordered list, but they are alternatives rather than a search list. Only a chain header that the request does not carry at all moves the search on to the next one. A header the request does carry was written by whichever proxy handled it, so if it yields no answer the search stops there and the socket peer IP is used, rather than falling back to a header that same proxy may never have touched.

## Trust models

A config uses exactly one trust model, chosen as the first step of `ClientIpConfig::builder`.

### Trust no proxy

No header is read. Every request resolves to the socket peer IP. This is also what `ClientIpConfig::default` gives you.

Use this when clients reach the service directly.

```rust
use std::net::IpAddr;

use rocket_client_addr::{ClientIpConfig, ClientIpSource, HeaderMap};

let config = ClientIpConfig::builder().trust_no_proxy();

let mut headers = HeaderMap::new();
headers.add_raw("x-forwarded-for", "203.0.113.10");

// The header is never read, so the answer is the address the connection came from.
let client_ip = config.resolve_client_ip(&headers, "198.51.100.7".parse::<IpAddr>().unwrap());

assert_eq!("198.51.100.7".parse::<IpAddr>().unwrap(), client_ip.ip());
assert_eq!(&ClientIpSource::Socket, client_ip.source());
```

### Trusted proxies

Headers are read only when the socket peer IP falls inside one of the trusted CIDRs. Use this whenever the proxy addresses are known, because a client that reaches the service directly can never make it read forwarding headers.

The answer is chosen in this order.

1. If the socket peer IP matches no trusted proxy rule, the socket peer IP is the answer.
2. If the matched rule names a client IP header, such as `X-Real-IP`, and the last value of that header is a plain IP address, that address is the answer.
3. Otherwise the first chain header the request carries, in the configured order, which is `X-Forwarded-For` then `Forwarded` by default.
4. Otherwise the socket peer IP is the answer.

A chain header is scanned from the socket side toward the original client, and the first hop that is not itself a trusted proxy becomes the client IP. A hop with no usable IP address ends the scan, because it cannot be compared with the trusted proxy rules, and neither can anything further left that such a hop may have written.

The example below resolves the request from the diagram above.

```rust
use std::net::IpAddr;

use rocket_client_addr::{ClientIpConfig, ClientIpSource, HeaderMap, IpCidr, Uncased};

let config = ClientIpConfig::builder()
    .trusted_proxies()
    .proxy("10.0.0.0/24".parse::<IpCidr>().unwrap())
    .proxy("198.51.100.0/24".parse::<IpCidr>().unwrap())
    .build()
    .unwrap();

let mut headers = HeaderMap::new();
headers.add_raw("x-forwarded-for", "203.0.113.10, 198.51.100.7");

// The socket peer 10.0.0.2 is a trusted proxy, so the chain is read, starting from the right.
// 198.51.100.7 is a trusted proxy too, so the scan walks one hop further left.
// 203.0.113.10 is not a trusted proxy, so it is the client.
let client_ip = config.resolve_client_ip(&headers, "10.0.0.2".parse::<IpAddr>().unwrap());

assert_eq!("203.0.113.10".parse::<IpAddr>().unwrap(), client_ip.ip());
assert_eq!(
    &ClientIpSource::ChainHeader(Uncased::from_borrowed("x-forwarded-for")),
    client_ip.source(),
);

// The same header sent from an address outside the trusted CIDRs is never read.
let direct = config.resolve_client_ip(&headers, "192.0.2.5".parse::<IpAddr>().unwrap());

assert_eq!("192.0.2.5".parse::<IpAddr>().unwrap(), direct.ip());
assert_eq!(&ClientIpSource::Socket, direct.source());
```

### Trust all proxies

Every socket peer is treated as a trusted proxy. Use this only when the service can never be reached directly, because any client that can open a connection can then choose its own address.

The answer is chosen in this order.

1. If a client IP header is configured and holds a plain IP address, that address is the answer.
2. Otherwise the first chain header the request carries, in the configured order, with one hop picked by `TrustAllChainIpSelection`.
3. Otherwise the socket peer IP is the answer.

There are no CIDRs to compare against here, so the chain is not scanned. One hop is picked by position instead. If that hop carries no usable IP address, or the chain is shorter than the selection needs, the socket peer IP is the answer.

```rust
use std::net::IpAddr;

use rocket_client_addr::{ClientIpConfig, HeaderMap, TrustAllChainIpSelection};

// Rightmost is the default, and it fits one proxy that appends to the header.
let one_proxy = ClientIpConfig::builder().trust_all_proxies().build();

let mut headers = HeaderMap::new();
// The client wrote 9.9.9.9 itself, and then the proxy appended the address it saw.
headers.add_raw("x-forwarded-for", "9.9.9.9, 203.0.113.10");

let client_ip = one_proxy.resolve_client_ip(&headers, "10.0.0.2".parse::<IpAddr>().unwrap());

assert_eq!("203.0.113.10".parse::<IpAddr>().unwrap(), client_ip.ip());

// With two proxies appending, the client is one more hop to the left.
let two_proxies = ClientIpConfig::builder()
    .trust_all_proxies()
    .chain_ip_selection(TrustAllChainIpSelection::SkipRightmostHops(1))
    .build();

let mut headers = HeaderMap::new();
headers.add_raw("x-forwarded-for", "203.0.113.10, 198.51.100.7, 10.0.0.2");

let client_ip = two_proxies.resolve_client_ip(&headers, "10.0.0.3".parse::<IpAddr>().unwrap());

assert_eq!("198.51.100.7".parse::<IpAddr>().unwrap(), client_ip.ip());
```

## Using the request guard

```rust
#[macro_use]
extern crate rocket;

use rocket_client_addr::{ClientIp, ClientIpConfig, IpCidr};

#[get("/")]
fn index(client_ip: &ClientIp) -> String {
    format!("client_ip={} source={:?}\n", client_ip.ip(), client_ip.source())
}

#[launch]
fn rocket() -> _ {
    let config = ClientIpConfig::builder()
        .trusted_proxies()
        // Trust this proxy range, and read X-Real-IP only when the socket peer is inside it.
        .proxy_with_x_real_ip("10.0.0.0/24".parse::<IpCidr>().unwrap())
        .build()
        .unwrap();

    // The guard looks the config up by type, so it has to be managed here.
    rocket::build().manage(config).mount("/", routes![index])
}
```

A route may take `&ClientIp` as above, or an owned `ClientIp`. The borrowed form resolves the address once per request and caches it, so prefer it when several guards on one route need the client address.

Without a managed `ClientIpConfig` the guard fails with `ClientIpRejection::MissingConfig`, and Rocket answers `500 Internal Server Error`. Both are server setup mistakes rather than bad requests, so neither is reported to the client.

A route may also take `Option<ClientIp>`, which resolves to `None` instead of failing the request.

## Rocket's own `ip_header`

Rocket has a client address mechanism of its own. `Config::ip_header` names one header, `X-Real-IP` by default, and it feeds `Request::real_ip`, `Request::client_ip`, and Rocket's built-in `IpAddr` request guard. That header is trusted no matter which address the request came from.

This crate ignores all of it. Nothing here reads `ip_header`, and a header only becomes the answer through a `ClientIpConfig` that trusts the proxy that sent it. Setting `ip_header = false` in `Rocket.toml` turns the built-in mechanism off, so that the two cannot disagree.

## IPv4-mapped IPv6 addresses

A dual-stack listener reports an IPv4 peer as `::ffff:203.0.113.10`, and some proxies write that form into their headers.

Every address is rewritten to its IPv4 form first. This covers the socket peer IP as well as every header value, so a service on a dual-stack listener still matches trusted proxy CIDRs that are written in IPv4 form, and one client always resolves to one address. A trusted proxy CIDR written in the same form, such as `::ffff:10.0.0.0/120`, is rewritten to `10.0.0.0/24` while the config is built.

Because the socket peer IP is rewritten first, an IPv6 CIDR such as `::/0` never matches an IPv4 peer, not even one that arrived as `::ffff:10.0.0.2`. Add a CIDR for each address family you want to trust.

## Custom chain headers

Some proxies use their own list header instead of `X-Forwarded-For`. Pass its name to `ChainHeader::new`, and it is read as a comma-separated list of addresses.

```rust
use std::net::IpAddr;

use rocket_client_addr::{ChainHeader, ClientIpConfig, HeaderMap, Uncased};

let config = ClientIpConfig::builder()
    .trust_all_proxies()
    .chain_header_order([ChainHeader::new(Uncased::from_borrowed("x-client-chain"))])
    .build();

let mut headers = HeaderMap::new();
headers.add_raw("x-client-chain", "9.9.9.9, 203.0.113.10");

let client_ip = config.resolve_client_ip(&headers, "10.0.0.2".parse::<IpAddr>().unwrap());

assert_eq!("203.0.113.10".parse::<IpAddr>().unwrap(), client_ip.ip());
```

The name `forwarded` keeps its RFC 7239 reading even when it goes through `ChainHeader::new`.

A proxy may also send the RFC 7239 syntax under a name of its own. `ChainHeader::forwarded_style` gives that reading to any header name.

```rust
use std::net::IpAddr;

use rocket_client_addr::{ChainHeader, ClientIpConfig, HeaderMap, Uncased};

let config = ClientIpConfig::builder()
    .trust_all_proxies()
    .chain_header_order([ChainHeader::forwarded_style(Uncased::from_borrowed("x-forwarded"))])
    .build();

let mut headers = HeaderMap::new();
headers.add_raw("x-forwarded", "for=9.9.9.9, for=203.0.113.10");

let client_ip = config.resolve_client_ip(&headers, "10.0.0.2".parse::<IpAddr>().unwrap());

assert_eq!("203.0.113.10".parse::<IpAddr>().unwrap(), client_ip.ip());
```

## Security notes

* A client IP header only means something if the proxy always overwrites it. If the proxy appends instead, the last value wins, because that is the one the client could not write.
* A trusted proxy rule that names a client IP header still tries the chain headers when that header is missing or unusable, so the proxy should also clear the chain headers it does not set itself. Use `disable_chain_headers` if it cannot.
* In trust-all proxy mode, `TrustAllChainIpSelection::Leftmost` returns the part of the chain that a client can write freely. It is safe only when the proxy overwrites the whole header.
* Rocket drops a whole header line whose value is not valid UTF-8 before this crate ever sees the request, and only logs a warning. A chain header that lost a line that way looks one hop shorter than it was, which matters to `TrustAllChainIpSelection::SkipRightmostHops`. A proxy does not write such values, so this only comes up when a client can reach the service directly.

## Crates.io

https://crates.io/crates/rocket-client-addr

## Documentation

https://docs.rs/rocket-client-addr

## License

[MIT](LICENSE)
