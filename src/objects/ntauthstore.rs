use serde_json::value::Value;
use serde::{Deserialize, Serialize};

use crate::enums::{decode_guid, parse_ntsecuritydescriptor};
use crate::utils::date::string_to_epoch;
use crate::objects::common::{
    LdapObject,
    AceTemplate,
    SPNTarget,
    Link,
    Member
};
use crate::utils::crypto::calculate_sha1;
use ldap3::SearchEntry;
use log::{debug, trace};
use std::collections::HashMap;


/// NtAuthStore structure
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct NtAuthStore {
    #[serde(rename = "Properties")]
    properties: NtAuthStoreProperties,
    #[serde(rename = "DomainSID")]
    domain_sid: String,
    #[serde(rename = "Aces")]
    aces: Vec<AceTemplate>,
    #[serde(rename = "ObjectIdentifier")]
    object_identifier: String,
    #[serde(rename = "IsDeleted")]
    is_deleted: bool,
    #[serde(rename = "IsACLProtected")]
    is_acl_protected: bool,
    #[serde(rename = "ContainedBy")]
    contained_by: Option<Member>,
}

impl NtAuthStore {
    // New NtAuthStore
    pub fn new() -> Self { 
        Self { ..Default::default() } 
    }

    /// Function to parse and replace value in json template for NT Auth Store object.
    pub fn parse(
        &mut self,
        result: SearchEntry,
        domain: &String,
        dn_sid: &mut HashMap<String, String>,
        sid_type: &mut HashMap<String, String>,
        domain_sid: &String
    ) {
        let result_dn: String;
        result_dn = result.dn.to_uppercase();
  
        let result_attrs: HashMap<String, Vec<String>>;
        result_attrs = result.attrs;
  
        let result_bin: HashMap<String, Vec<Vec<u8>>>;
        result_bin = result.bin_attrs;
  
        // Debug for current object
        debug!("Parse NtAuthStore: {}", result_dn);
        // Trace all result attributes
        for (key, value) in &result_attrs {
            trace!("  {:?}:{:?}", key, value);
        }
        // Trace all bin result attributes
        for (key, value) in &result_bin {
            trace!("  {:?}:{:?}", key, value);
        }
  
        // Change all values...
        self.properties.domain = domain.to_uppercase();
        self.properties.distinguishedname = result_dn;    
        self.properties.domainsid = domain_sid.to_string();
        self.domain_sid = domain_sid.to_string();
  
        // With a check
        for (key, value) in &result_attrs {
            match key.as_str() {
                "name" => {
                    let name = format!("{}@{}",&value[0],domain);
                    self.properties.name = name.to_uppercase();
                }
                "description" => {
                    self.properties.description = Some(value[0].to_owned());
                }
                "whenCreated" => {
                    let epoch = string_to_epoch(&value[0]);
                    if epoch.is_positive() {
                        self.properties.whencreated = epoch;
                    }
                }
                "IsDeleted" => {
                    self.is_deleted = true.into();
                }
                _ => {}
            }
        }
  
        // For all, bins attributs
        for (key, value) in &result_bin {
            match key.as_str() {
                "objectGUID" => {
                    // objectGUID raw to string
                    let guid = decode_guid(&value[0]);
                    self.object_identifier = guid.to_owned().into();
                }
                "nTSecurityDescriptor" => {
                    // Needed with acl
                    let entry_type = "NtAuthStore".to_string();
                    // nTSecurityDescriptor raw to string
                    let relations_ace = parse_ntsecuritydescriptor(
                        self,
                        &value[0],
                        entry_type,
                        &result_attrs,
                        &result_bin,
                        &domain,
                    );
                    self.aces = relations_ace;
                }
                "cACertificate" => {
                    //info!("{:?}:{:?}", key,value[0].to_owned());
                    let mut certthumbprints: Vec<String> = Vec::new();
                    certthumbprints.push(calculate_sha1(&value[0]));
                    self.properties.certthumbprints = certthumbprints;
                }
                _ => {}
            }
        }
  
        // Push DN and SID in HashMap
        if self.object_identifier.to_string() != "SID" {
            dn_sid.insert(
                self.properties.distinguishedname.to_string(),
                self.object_identifier.to_string()
            );
            // Push DN and Type
            sid_type.insert(
                self.object_identifier.to_string(),
                "NtAuthStore".to_string()
            );
        }
  
        // Trace and return NtAuthStore struct
        // trace!("JSON OUTPUT: {:?}",serde_json::to_string(&self).unwrap());
    }
}

impl LdapObject for NtAuthStore {
    // To JSON
    fn to_json(&self) -> Value {
        serde_json::to_value(&self).unwrap()
    }

    // Get values
    fn get_object_identifier(&self) -> &String {
        &self.object_identifier
    }
    fn get_is_acl_protected(&self) -> &bool {
        &self.is_acl_protected
    }
    fn get_aces(&self) -> &Vec<AceTemplate> {
        &self.aces
    }
    fn get_spntargets(&self) -> &Vec<SPNTarget> {
        panic!("Not used by current object.");
    }
    fn get_allowed_to_delegate(&self) -> &Vec<Member> {
        panic!("Not used by current object.");
    }
    fn get_links(&self) -> &Vec<Link> {
        panic!("Not used by current object.");
    }
    fn get_contained_by(&self) -> &Option<Member> {
        &self.contained_by
    }
    fn get_child_objects(&self) -> &Vec<Member> {
        panic!("Not used by current object.");
    }
    fn get_haslaps(&self) -> &bool {
        &false
    }
    
    // Edit values
    fn set_is_acl_protected(&mut self, is_acl_protected: bool) {
        self.is_acl_protected = is_acl_protected;
    }
    fn set_aces(&mut self, aces: Vec<AceTemplate>) {
        self.aces = aces;
    }
    fn set_spntargets(&mut self, _spn_targets: Vec<SPNTarget>) {
        // Not used by current object.
    }
    fn set_allowed_to_delegate(&mut self, _allowed_to_delegate: Vec<Member>) {
        // Not used by current object.
    }
    fn set_links(&mut self, _links: Vec<Link>) {
        // Not used by current object.
    }
    fn set_contained_by(&mut self, contained_by: Option<Member>) {
        self.contained_by = contained_by;
    }
    fn set_child_objects(&mut self, _child_objects: Vec<Member>) {
        // Not used by current object.
    }
}


// NtAuthStore properties structure
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct NtAuthStoreProperties {
   domain: String,
   name: String,
   distinguishedname: String,
   domainsid: String,
   certthumbprints: Vec<String>,
   description: Option<String>,
   whencreated: i64,
}