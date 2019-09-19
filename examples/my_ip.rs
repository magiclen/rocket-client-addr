#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;

extern crate rocket_client_addr;

use rocket_client_addr::ClientAddr;

#[get("/ipv4")]
fn ipv4(client_addr: &ClientAddr) -> String {
    client_addr.get_ipv4_string().unwrap()
}

#[get("/ipv6")]
fn ipv6(client_addr: &ClientAddr) -> String {
    client_addr.get_ipv6_string()
}

fn main() {
    rocket::ignite().mount("/", routes![ipv4]).mount("/", routes![ipv6]).launch();
}
