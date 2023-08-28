//! <p align="center">
//! <img width="30%" src="https://raw.githubusercontent.com/OPENCYBER-FR/RustHound/main/img/rusthound_logo_v3.png">
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
//!RustHound
//!g0h4n https://twitter.com/g0h4n_0
//!Active Directory data collector for BloodHound.
//!
//!Usage: rusthound_musl [OPTIONS] --domain <domain>
//!
//!Options:
//!  -v...          Set the level of verbosity
//!  -h, --help     Print help
//!  -V, --version  Print version
//!
//!REQUIRED VALUES:
//!  -d, --domain <domain>  Domain name like: DOMAIN.LOCAL
//!
//!OPTIONAL VALUES:
//!  -u, --ldapusername <ldapusername>  LDAP username, like: user@domain.local
//!  -p, --ldappassword <ldappassword>  LDAP password
//!  -f, --ldapfqdn <ldapfqdn>          Domain Controler FQDN like: DC01.DOMAIN.LOCAL or just DC01
//!  -i, --ldapip <ldapip>              Domain Controller IP address like: 192.168.1.10
//!  -P, --ldapport <ldapport>          LDAP port [default: 389]
//!  -n, --name-server <name-server>    Alternative IP address name server to use for DNS queries
//!  -o, --output <output>              Output directory where you would like to save JSON files [default: ./]
//!
//!OPTIONAL FLAGS:
//!      --ldaps           Force LDAPS using for request like: ldaps://DOMAIN.LOCAL/
//!  -k, --kerberos        Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters for Linux.
//!      --dns-tcp         Use TCP instead of UDP for DNS queries
//!      --dc-only         Collects data only from the domain controller. Will not try to retrieve CA security/configuration or check for Web Enrollment
//!      --old-bloodhound  For ADCS only. Output result as BloodHound data for the original BloodHound version from @BloodHoundAD without PKI support
//!  -z, --zip             Compress the JSON files into a zip archive
//!
//!OPTIONAL MODULES:
//!      --fqdn-resolver  Use fqdn-resolver module to get computers IP address
//!      --adcs           Use ADCS module to enumerate Certificate Templates, Certificate Authorities and other configurations.
//!                       (For the custom-built BloodHound version from @ly4k with PKI support)
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
//! ![demo](https://raw.githubusercontent.com/OPENCYBER-FR/RustHound/main/img/demo.gif)
//! 
pub mod args;
pub mod banner;
pub mod errors;
pub mod ldap;
pub mod exec;

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
