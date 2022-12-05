//! List of RustHound add-on modules
pub mod resolver;
pub mod adcs;

use log::info;
use std::collections::HashMap;
use crate::args::*;
use crate::json::checker::add_type_for_ace;

/// Function to run all modules requested
pub async fn run_modules(
   common_args: &Options, 
   fqdn_ip: &mut HashMap<String, String>, 
   vec_computers: &mut Vec<serde_json::value::Value>,
   vec_cas: &mut Vec<serde_json::value::Value>,
   vec_templates: &mut Vec<serde_json::value::Value>,
   adcs_templates: &mut HashMap<String, Vec<String>>,
   sid_type: &mut HashMap<String, String>,
) {
   // [MODULE - RESOLVER] Running module to resolve FQDN to IP address?
   if common_args.fqdn_resolver {
      resolver::resolv::resolving_all_fqdn(
         common_args.dns_tcp,
         &common_args.name_server,
         fqdn_ip, &vec_computers
      ).await;
   }

   // [MODULE - ADCS] Running last function for adcs templates
   if common_args.adcs {
      info!("Starting checker for ADCS values...");
      adcs::checker::check_enabled_template(
         vec_cas,
         vec_templates,
         adcs_templates,
         common_args.old_bloodhound,
      );
      // Getting conf if dc-only isn't set
      // <https://github.com/ly4k/Certipy/blob/main/certipy/commands/find.py#L236>
      adcs::checker::get_conf(
            vec_cas,
            common_args.dc_only,
            common_args.dns_tcp,
            &common_args.name_server,
      ).await;
      add_type_for_ace(vec_cas, &sid_type);
      add_type_for_ace(vec_templates, &sid_type);
      info!("Checking for ADCS values finished!");
   }

   // Other modules need to be add here...
}