//! FQDN resolver
//!
//! This module will resolve IP address from the ldap FQDN
//! Resolver can be used with UDP or TCP DNS request with **--dns-tcp** args
//! Resolver can be used with custome DNS name server with **-n 127.0.0.1** or **--name-server 127.0.0.1**
//!
//! <https://docs.rs/trust-dns-resolver/latest/trust_dns_resolver/index.html>
//! <https://github.com/shadowsocks/shadowsocks-rust/blob/master/crates/shadowsocks-service/src/config.rs>
//!
pub mod resolv;