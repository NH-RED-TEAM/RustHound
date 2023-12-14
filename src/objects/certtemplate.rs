use serde_json::value::Value;
use serde::{Deserialize, Serialize};

use crate::enums::{decode_guid, parse_ntsecuritydescriptor, get_pki_cert_name_flags, get_pki_enrollment_flags};
use crate::json::checker::common::get_name_from_full_distinguishedname;
use crate::utils::date::{string_to_epoch, span_to_string, filetime_to_span};
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

/// CertTemplate structure
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct CertTemplate {
    #[serde(rename = "Properties")]
    properties: CertTemplateProperties,
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

impl CertTemplate {
    // New CertTemplate
    pub fn new() -> Self { 
        Self { ..Default::default() } 
    }

    // Immutable access.
    pub fn properties(&self) -> &CertTemplateProperties {
        &self.properties
    }
    pub fn object_identifier(&self) -> &String {
        &self.object_identifier
    }

    /// Function to parse and replace value in json template for Certificate Template object.
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
        debug!("Parse CertTemplate: {}", result_dn);
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
        let _ca_name = get_name_from_full_distinguishedname(&self.properties.distinguishedname);

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
                "displayName" => {
                    self.properties.displayname = value[0].to_owned();
                }
                "msPKI-Certificate-Name-Flag" => {
                    if value.len() != 0 {
                        self.properties.certificatenameflag = get_pki_cert_name_flags(value[0].parse::<i64>().unwrap_or(0) as u64);
                        if self.properties.certificatenameflag.contains("ENROLLEE_SUPPLIES_SUBJECT") {
                            self.properties.enrolleesuppliessubject = true;
                        } else {
                            self.properties.enrolleesuppliessubject = false;
                        }
                        if self.properties.certificatenameflag.contains("SUBJECT_ALT_REQUIRE_UPN") {
                            self.properties.subjectaltrequireupn = true;
                        } else {
                            self.properties.subjectaltrequireupn = false;
                        }
                        
                    }
                }
                "msPKI-Enrollment-Flag" => {
                    if value.len() != 0 {
                        self.properties.enrollmentflag = get_pki_enrollment_flags(value[0].parse::<i64>().unwrap_or(0) as u64);
                        if self.properties.enrollmentflag.contains("PEND_ALL_REQUESTS") {
                            self.properties.requiresmanagerapproval = true;
                        } else {
                            self.properties.requiresmanagerapproval = false;
                        }
                        if self.properties.enrollmentflag.contains("NO_SECURITY_EXTENSION") {
                            self.properties.nosecurityextension = true;
                        } else {
                            self.properties.nosecurityextension = false;
                        }
                    }
                }
                "msPKI-Private-Key-Flag" => {
                    // if value.len() != 0 {
                    //     self.properties.() = get_pki_private_flags(value[0].parse::<i64>().unwrap_or(0) as u64);
                    // }
                }
                "msPKI-RA-Signature" => {
                    if value.len() != 0 {
                        self.properties.authorizedsignatures = value[0].parse::<i64>().unwrap_or(0);
                    } else {
                        self.properties.authorizedsignatures = 0;
                    }
                }
                "msPKI-RA-Application-Policies" => {
                    if value.len() != 0 {
                        self.properties.applicationpolicies = value.to_owned();
                    }
                }
                "msPKI-Certificate-Application-Policy" => {
                    if value.len() != 0 {
                        self.properties.certificateapplicationpolicy = value.to_owned();
                    }
                }
                "msPKI-RA-Policies" => {
                    if value.len() != 0 {
                        self.properties.issuancepolicies = value.to_owned();
                    }
                }
                "msPKI-Cert-Template-OID" => {
                    if value.len() != 0 {
                        self.properties.oid = value[0].to_owned();
                    }
                }
                "pKIExtendedKeyUsage" => {
                    if value.len() != 0 {
                        self.properties.ekus = value.to_owned();
                    }
                }
                "msPKI-Template-Schema-Version" => {
                    self.properties.schemaversion = value[0].parse::<i64>().unwrap_or(0);
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
                    let entry_type = "CertTemplate".to_string();
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
                "pKIExpirationPeriod" => {
                    self.properties.validityperiod = span_to_string(filetime_to_span(value[0].to_owned()));
                }
                "pKIOverlapPeriod" => {
                    self.properties.renewalperiod = span_to_string(filetime_to_span(value[0].to_owned()));
                }
                _ => {}
            }
        }

        // Get all effective ekus.
        self.properties.effectiveekus = Self::get_effectiveekus(
            &self.properties.schemaversion,
            &self.properties.ekus,
            &self.properties.certificateapplicationpolicy,
        );

        // Check if authentication is enabled or not for this template.
        self.properties.authenticationenabled = Self::authentication_is_enabled(self);

        // Push DN and SID in HashMap
        if self.object_identifier.to_string() != "SID" {
            dn_sid.insert(
                self.properties.distinguishedname.to_string(),
                self.object_identifier.to_string()
            );
            // Push DN and Type
            sid_type.insert(
                self.object_identifier.to_string(),
                "CertTemplate".to_string()
            );
        }

        // Trace and return CertTemplate struct
        // trace!("JSON OUTPUT: {:?}",serde_json::to_string(&self).unwrap());
    }

    /// Function to get effective ekus for one template.
    fn get_effectiveekus(
        schema_version: &i64,
        ekus: &Vec<String>,
        certificateapplicationpolicy: &Vec<String>,
    ) -> Vec<String> {
        if schema_version == &1 && ekus.len() > 0 {
            return ekus.to_vec()
        } else {
            return certificateapplicationpolicy.to_vec();
        }
    }

    /// Function to check if authentication is enabled or not.
    fn authentication_is_enabled(&mut self) -> bool {
        let authentication_oids = vec![
            "1.3.6.1.5.5.7.3.2", // ClientAuthentication,
            "1.3.6.1.5.2.3.4", // PKINITClientAuthentication
            "1.3.6.1.4.1.311.20.2.2", // SmartcardLogon
            "2.5.29.37.0", // AnyPurpose
        ];
        self.properties.effectiveekus.iter()
            .any(|eku| authentication_oids.contains(&eku.as_str()))
            || self.properties.effectiveekus.is_empty()
    }
}

impl LdapObject for CertTemplate {
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


// CertTemplate properties structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CertTemplateProperties {
   domain: String,
   name: String,
   distinguishedname: String,
   domainsid: String,
   description: Option<String>,
   whencreated: i64,
   validityperiod: String,
   renewalperiod: String,
   schemaversion: i64,
   displayname: String,
   oid: String,
   enrollmentflag: String,
   requiresmanagerapproval: bool,
   nosecurityextension: bool,
   certificatenameflag: String,
   enrolleesuppliessubject: bool,
   subjectaltrequireupn: bool,
   ekus: Vec<String>,
   certificateapplicationpolicy: Vec<String>,
   authorizedsignatures: i64,
   applicationpolicies: Vec<String>,
   issuancepolicies: Vec<String>,
   effectiveekus: Vec<String>,
   authenticationenabled: bool,
}

impl Default for CertTemplateProperties {
    fn default() -> CertTemplateProperties {
        CertTemplateProperties {
            domain: String::from(""),
            name: String::from(""),
            distinguishedname: String::from(""),
            domainsid: String::from(""),
            description: None,
            whencreated: -1,
            validityperiod: String::from(""),
            renewalperiod: String::from(""),
            schemaversion: 1,
            displayname: String::from(""),
            oid: String::from(""),
            enrollmentflag: String::from(""),
            requiresmanagerapproval: false,
            nosecurityextension: false,
            certificatenameflag: String::from(""),
            enrolleesuppliessubject: false,
            subjectaltrequireupn: true,
            ekus: Vec::new(),
            certificateapplicationpolicy: Vec::new(),
            authorizedsignatures: 0,
            applicationpolicies: Vec::new(),
            issuancepolicies: Vec::new(),
            effectiveekus: Vec::new(),
            authenticationenabled: false,
       }
    }
 }

impl CertTemplateProperties {
    // Immutable access.
    pub fn name(&self) -> &String {
        &self.name
    }
}