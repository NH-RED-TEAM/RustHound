use ldap3::SearchEntry;
use log::{debug, trace};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use crate::enums::secdesc::LdapSid;
use crate::enums::sid::sid_maker;
use crate::enums::trusts::get_trust_flag;

/// Trust structure
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Trust {
   #[serde(rename = "TargetDomainSid")]
   target_domain_sid: String,
   #[serde(rename = "TargetDomainName")]
   target_domain_name: String,
   #[serde(rename = "IsTransitive")]
   is_transitive: bool,
   #[serde(rename = "SidFilteringEnabled")]
   sid_filtering_enabled: bool,
   #[serde(rename = "TrustDirection")]
   trust_direction: String,
   #[serde(rename = "TrustType")]
   trust_type: String,
}

impl Trust {
   // New trust link for domain.
    pub fn new() -> Self { 
      Self {
         ..Default::default()
      } 
   }

   // Imutable access.
   pub fn target_domain_sid(&self) -> &String {
      &self.target_domain_sid
   }
   pub fn target_domain_name(&self) -> &String {
      &self.target_domain_name
   }

   // Mutable access.
   pub fn is_transitive_mut(&mut self) -> &mut bool {
      &mut self.is_transitive
   }
   pub fn sid_filtering_enabled_mut(&mut self) -> &mut bool {
      &mut self.sid_filtering_enabled
   }
   pub fn trust_type_mut(&mut self) -> &mut String {
      &mut self.trust_type
   }

   /// Function to parse and replace value for trust domain object.
   pub fn parse(
      &mut self,
      result: SearchEntry,
      domain: &String
   )  {
      let result_dn: String = result.dn.to_uppercase();
      let result_attrs: HashMap<String, Vec<String>> = result.attrs;
      let result_bin: HashMap<String, Vec<Vec<u8>>> = result.bin_attrs;

      // Debug for current object
      debug!("Parse TrustDomain: {}", result_dn);
      // Trace all result attributes
      for (key, value) in &result_attrs {
         trace!("  {:?}:{:?}", key, value);
      }
      // Trace all bin result attributes
      for (key, value) in &result_bin {
         trace!("  {:?}:{:?}", key, value);
      }

      // With a check
      for (key, value) in &result_attrs {
         match key.as_str() {
            "name" => {
                  self.target_domain_name = value[0].to_uppercase();
            }
            "trustDirection" => {
                  let trustdirection: u8 = value[0].parse::<u8>().unwrap_or(0);
                  // <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/5026a939-44ba-47b2-99cf-386a9e674b04>
                  self.trust_direction = match trustdirection { 
                     1 => "Inbound",
                     2 => "Outbound",
                     3 => "Bidirectional",
                     _ => "Disabled"
                  }.to_string()
            }
            "trustAttributes" => {
                  let trustflag: u32 = value[0].parse::<u32>().unwrap_or(0);
                  get_trust_flag(trustflag, self);
            }
            _ => {}
         }
      }
      // For all, bins attributs
      for (key, value) in &result_bin {
         match key.as_str() {
            "securityIdentifier" => {
                  let sid = sid_maker(LdapSid::parse(&value[0]).unwrap().1, domain);
                  self.target_domain_sid = sid.to_owned();
            }
            _ => {}
         }
      }
      
      // Trace and return tRUST struct
      // trace!("TRUST VALUE: {:?}",&self);
   }
}