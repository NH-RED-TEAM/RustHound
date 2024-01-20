use serde_json::value::Value;
use serde::{Deserialize, Serialize};

use crate::objects::common::{
    LdapObject,
    AceTemplate,
    SPNTarget,
    Link,
    Member
};

use ldap3::SearchEntry;
use log::{debug, trace};
use std::collections::HashMap;

use crate::enums::acl::parse_ntsecuritydescriptor;
use crate::enums::sid::decode_guid;
use crate::utils::date::string_to_epoch;

/// Container structure
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Container {
    #[serde(rename = "Properties")]
    properties: ContainerProperties,
    #[serde(rename = "ChildObjects")]
    child_objects: Vec<Member>,
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

impl Container {
    // New container.
    pub fn new() -> Self { 
        Self { ..Default::default() } 
    }

    /// Function to parse and replace value for Container object.
    pub fn parse(
        &mut self,
        result: SearchEntry,
        domain: &String,
        dn_sid: &mut HashMap<String, String>,
        sid_type: &mut HashMap<String, String>,
        domain_sid: &String
    ) {
        let result_dn: String = result.dn.to_uppercase();
        let result_attrs: HashMap<String, Vec<String>> = result.attrs;
        let result_bin: HashMap<String, Vec<Vec<u8>>> = result.bin_attrs;

        // Debug for current object
        debug!("Parse Container: {}", result_dn);
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

        // With a check
        for (key, value) in &result_attrs {
            match key.as_str() {
                "name" => {
                    let name = &value[0];
                    let email = format!("{}@{}",name.to_owned(),domain);
                    self.properties.name = email.to_uppercase();
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
                _ => {}
            }
        }
        // For all, bins attributs
        for (key, value) in &result_bin {
            match key.as_str() {
                "objectGUID" => {
                    let guid = decode_guid(&value[0]);
                    self.object_identifier = guid.to_owned();
                }
                "nTSecurityDescriptor" => {
                    // Needed with acl
                    let entry_type = "Container".to_string();
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
                "IsDeleted" => {
                    self.is_deleted = true;
                }
                _ => {}
            }
        }

        // Push DN and SID in HashMap
        dn_sid.insert(
            self.properties.distinguishedname.to_string(),
            self.object_identifier.to_string()
        );
        // Push DN and Type
        sid_type.insert(
            self.object_identifier.to_string(),
            "Container".to_string(),
        );

        // Trace and return Contaier struct
        // trace!("JSON OUTPUT: {:?}",serde_json::to_string(&self).unwrap());
    }
}

/// Default FSP properties structure
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ContainerProperties {
   domain: String,
   name: String,
   distinguishedname: String,
   domainsid: String,
   highvalue: bool,
   description: Option<String>,
   whencreated: i64,
}

impl LdapObject for Container {
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
        &self.child_objects
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
    fn set_child_objects(&mut self, child_objects: Vec<Member>) {
        self.child_objects = child_objects
    }
}