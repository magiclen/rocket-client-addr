#[macro_use]
extern crate rocket;

use rocket_client_addr::ClientRealAddr;

#[get("/ipv4")]
fn ipv4(client_addr: &ClientRealAddr) -> String {
    client_addr.get_ipv4_string().unwrap()
}

#[get("/ipv6")]
fn ipv6(client_addr: &ClientRealAddr) -> String {
    client_addr.get_ipv6_string()
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![ipv4]).mount("/", routes![ipv6])
}
