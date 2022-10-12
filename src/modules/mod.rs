//! List of RustHound add-on modules
#[doc(inline)]
pub use resolver::*;
pub mod resolver;

use std::collections::HashMap;
use crate::args::*;

pub async fn run_modules(
   common_args: &Options, 
   fqdn_ip: &mut HashMap<String, String>, 
   vec_computers: &mut Vec<serde_json::value::Value>
) {
   // Running module to resolve FQDN to IP address?
   if common_args.fqdn_resolver {
      fqdn_resolver(common_args.dns_tcp, &common_args.ip, &common_args.name_server, fqdn_ip, &vec_computers).await;
   }

   // Other modules need to be add here...
}