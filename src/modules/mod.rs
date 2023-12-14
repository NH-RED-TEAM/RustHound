//! List of RustHound add-on modules
pub mod resolver;

use std::collections::HashMap;
use crate::args::Options;
use crate::objects::computer::Computer;

/// Function to run all modules requested
pub async fn run_modules(
   common_args:   &Options, 
   fqdn_ip:       &mut HashMap<String, String>, 
   vec_computers: &mut Vec<Computer>,
) {
   // [MODULE - RESOLVER] Running module to resolve FQDN to IP address?
   if common_args.fqdn_resolver {
      resolver::resolv::resolving_all_fqdn(
         common_args.dns_tcp,
         &common_args.name_server,
         fqdn_ip,
         &vec_computers
      ).await;
   }
   // Other modules need to be add here...
}