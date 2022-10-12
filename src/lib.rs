//! <p align="center">
//! <img width="30%" src="../../../img/rusthound_logo_v3.png">
//! </p>
//! 
//! RustHound is a cross-platform and cross-compiled BloodHound collector tool, written in Rust.
//! RustHound generate users,groups,computers,ous,gpos,containers,domains json files to analyze it with BloodHound application.
//! 
//! You can either run the binary:
//!```
//!---------------------------------------------------
//!Initializing RustHound at 13:37:00 UTC on 10/04/22
//!Powered by g0h4n from OpenCyber
//!---------------------------------------------------
//!
//!RustHound 1.0.0
//!g0h4n https://twitter.com/g0h4n_0
//!Active Directory data collector for BloodHound.
//!
//!USAGE:
//!    rusthound [FLAGS] [OPTIONS] --domain <domain>
//!
//!FLAGS:
//!        --dns-tcp          Use TCP instead of UDP for DNS queries
//!        --fqdn-resolver    [MODULE] Use fqdn-resolver module to get computers IP address
//!    -h, --help             Prints help information
//!        --ldaps            Prepare ldaps request. Like ldaps://G0H4N.LAB/
//!    -v                     Sets the level of verbosity
//!    -V, --version          Prints version information
//!    -z, --zip              RustHound will compress the JSON files into a zip archive (doesn't work with Windows)
//!
//!OPTIONS:
//!    -d, --domain <domain>                Domain name like: G0H4N.LAB
//!    -f, --ldapfqdn <ldapfqdn>            Domain Controler FQDN like: DC01.G0H4N.LAB
//!    -i, --ldapip <ldapip>                Domain Controller IP address
//!    -p, --ldappassword <ldappassword>    Ldap password to use
//!    -P, --ldapport <ldapport>            Ldap port, default is 389
//!    -u, --ldapusername <ldapusername>    Ldap username to use
//!    -n, --name-server <name-server>      Alternative IP address name server to use for queries
//!    -o, --dirpath <path>                 Path where you would like to save json files
//!```
//! Or build your own using the ldap_search() function:
//! ```
//!let result = ldap_search(
//!    &ldaps,
//!    &ip,
//!    &port,
//!    &domain,
//!    &ldapfqdn,
//!    &username,
//!    &password,
//!);
//!```
//! Here is an example of how to use rusthound:
//! ![demo](../../../img/demo.gif)
//! 
pub mod args;
pub mod banner;
pub mod errors;
pub mod ldap;

pub mod enums;
pub mod json;
pub mod modules;

extern crate bitflags;
extern crate chrono;
extern crate regex;

// Reimport key functions and structure
#[doc(inline)]
pub use crate::errors::Error;
#[doc(inline)]
pub use ldap::ldap_search;
#[doc(inline)]
pub use ldap3::SearchEntry;
