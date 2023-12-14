use colored::Colorize;
use serde_json::value::Value;
use serde::{Deserialize, Serialize};
use x509_parser::oid_registry::asn1_rs::oid;
use x509_parser::prelude::*;

use crate::enums::{decode_guid, parse_ntsecuritydescriptor, MaskFlags, SecurityDescriptor, AceFormat, Acl, sid_maker, parse_ca_security};
use crate::json::checker::common::get_name_from_full_distinguishedname;
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
use log::{debug, error, info, trace};
use std::collections::HashMap;

/// EnterpriseCA structure
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct EnterpriseCA {
    #[serde(rename = "Properties")]
    properties: EnterpriseCAProperties,
    #[serde(rename = "HostingComputer")]
    hosting_computer: String,
    #[serde(rename = "CARegistryData")]
    ca_registry_data: CARegistryData,
    #[serde(rename = "EnabledCertTemplates")]
    enabled_cert_templates: Vec<Member>,
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

impl EnterpriseCA {
    // New EnterpriseCA
    pub fn new() -> Self { 
        Self { ..Default::default() } 
    }

    // Immutable access.
    pub fn enabled_cert_templates(&self) -> &Vec<Member> {
        &self.enabled_cert_templates
    }

    // Mutable access.
    pub fn enabled_cert_templates_mut(&mut self) -> &mut Vec<Member> {
        &mut self.enabled_cert_templates
    }

    /// Function to parse and replace value in json template for Enterprise CA object.
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
        debug!("Parse EnterpriseCA: {}", result_dn);
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
        let ca_name = get_name_from_full_distinguishedname(&self.properties.distinguishedname);
        self.properties.caname = ca_name;

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
                "dNSHostName" => {
                    self.properties.dnshostname = value[0].to_owned();
                }
                "certificateTemplates" => {
                    if value.len() <= 0 {
                        error!("No certificate templates enabled for {}",self.properties.caname);
                    } else {
                        //ca.enabled_templates = value.to_vec();
                        info!("Found {} enabled certificate templates",value.len().to_string().bold());
                        trace!("Enabled certificate templates: {:?}",value);
                        let mut enabled_templates: Vec<Member> = Vec::new();
                        for template_name in value {
                            let mut member = Member::new();
                            *member.object_identifier_mut() = template_name.to_owned();
                            *member.object_type_mut() = String::from("CertTemplate");
                            enabled_templates.push(member);
                        }
                        self.enabled_cert_templates = enabled_templates.to_owned();
                    }
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
                    let entry_type = "EnterpriseCA".to_string();
                    // nTSecurityDescriptor raw to string
                    let relations_ace = parse_ntsecuritydescriptor(
                        self,
                        &value[0],
                        entry_type,
                        &result_attrs,
                        &result_bin,
                        &domain,
                    );
                    // Aces
                    self.aces = relations_ace;
                    // HostingComputer
                    self.hosting_computer = Self::get_hosting_computer(&value[0], &domain);
                    // CASecurity
                    let ca_security_data = parse_ca_security(&value[0], &self.hosting_computer, &domain);
                    if ca_security_data.len() != 0 {
                        let ca_security = CASecurity { data: ca_security_data, collected: true, failure_reason: None };
                        self.properties.casecuritycollected = true;
                        let ca_registry_data = CARegistryData::new(ca_security);
                        self.ca_registry_data = ca_registry_data;
                    } else {
                        let ca_security = CASecurity { data: Vec::new(), collected: false, failure_reason: Some(String::from("Failed to get CASecurity!")) };
                        self.properties.casecuritycollected = false;
                        let ca_registry_data = CARegistryData::new(ca_security);
                        self.ca_registry_data = ca_registry_data;
                    }
                }
                "cACertificate" => {
                    //info!("{:?}:{:?}", key,value[0].to_owned());
                    let certsha1: String = calculate_sha1(&value[0]);
                    self.properties.certthumbprint = certsha1.to_string();
                    self.properties.certname = certsha1.to_string();
                    let mut vec_certsha1: Vec<String> = Vec::new();
                    vec_certsha1.push(certsha1);
                    self.properties.certchain = vec_certsha1;

                    // Parsing certificate.
                    let res = X509Certificate::from_der(&value[0]);
                    match res {
                        Ok((_rem, cert)) => {
                            // println!("Basic Constraints Extensions:");
                            for ext in cert.extensions() {
                                // println!("{:?} : {:?}",&ext.oid, ext);
                                if &ext.oid == &oid!(2.5.29.19) {
                                    // <https://docs.rs/x509-parser/latest/x509_parser/extensions/struct.BasicConstraints.html>
                                    if let ParsedExtension::BasicConstraints(basic_constraints) = &ext.parsed_extension() {
                                        let _ca = &basic_constraints.ca;
                                        let _path_len_constraint = &basic_constraints.path_len_constraint;
                                        // println!("ca: {:?}", _ca);
                                        // println!("path_len_constraint: {:?}", _path_len_constraint);
                                        match _path_len_constraint {
                                            Some(_path_len_constraint) => {
                                                if _path_len_constraint > &0 {
                                                    self.properties.hasbasicconstraints = true;
                                                    self.properties.basicconstraintpathlength = _path_len_constraint.to_owned();

                                                } else {
                                                    self.properties.hasbasicconstraints = false;
                                                    self.properties.basicconstraintpathlength = 0 as u32;
                                                }
                                            },
                                            None => {
                                                self.properties.hasbasicconstraints = false;
                                                self.properties.basicconstraintpathlength = 0 as u32;
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        _ => error!("CA x509 certificate parsing failed: {:?}", res),
                    }
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
                "EnterpriseCA".to_string()
            );
        }

        // Trace and return EnterpriseCA struct
        // trace!("JSON OUTPUT: {:?}",serde_json::to_string(&self).unwrap());
    }

    /// Function to get HostingComputer from ACL if ACE get ManageCertificates and is not Group.
    fn get_hosting_computer(
        nt: &Vec<u8>,
        domain: &String,
    ) -> String {
        let mut hosting_computer = String::from("Not found");
        let blacklist_sid = vec![
            // <https://learn.microsoft.com/fr-fr/windows-server/identity/ad-ds/manage/understand-security-identifiers>
            "-544", // Administrators
            "-519", // Enterprise Administrators
            "-512", // Domain Admins
        ];
        let secdesc: SecurityDescriptor = SecurityDescriptor::parse(&nt).unwrap().1;
        if secdesc.offset_dacl as usize != 0 
        {
            let res = Acl::parse(&nt[secdesc.offset_dacl as usize..]);    
            match res {
                Ok(_res) => {
                    let dacl = _res.1;
                    let aces = dacl.data;
                    for ace in aces {
                        if ace.ace_type == 0x00 {
                            let sid = sid_maker(AceFormat::get_sid(ace.data.to_owned()).unwrap(), domain);
                            let mask = match AceFormat::get_mask(ace.data.to_owned()) {
                                Some(mask) => mask,
                                None => continue,
                            };
                            if (MaskFlags::MANAGE_CERTIFICATES.bits() | mask) == mask
                            && !blacklist_sid.iter().any(|blacklisted| sid.ends_with(blacklisted)) 
                            {
                                // println!("SID MANAGE_CERTIFICATES: {:?}",&sid);
                                hosting_computer = sid;
                                return hosting_computer
                            }
                        }
                    }
                },
                Err(err) => error!("Error. Reason: {err}")
            }
        }
        hosting_computer
    }
}

impl LdapObject for EnterpriseCA {
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


// EnterpriseCA properties structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EnterpriseCAProperties {
   domain: String,
   name: String,
   distinguishedname: String,
   domainsid: String,
   description: Option<String>,
   whencreated: i64,
   flags: String,
   caname: String,
   dnshostname: String,
   certthumbprint: String,
   certname: String,
   certchain: Vec<String>,
   hasbasicconstraints: bool,
   basicconstraintpathlength: u32,
   casecuritycollected: bool,
   enrollmentagentrestrictionscollected: bool,
   isuserspecifiessanenabledcollected: bool,
}

impl Default for EnterpriseCAProperties {
    fn default() -> EnterpriseCAProperties {
        EnterpriseCAProperties {
            domain: String::from(""),
            name: String::from(""),
            distinguishedname: String::from(""),
            domainsid: String::from(""),
            description: None,
            whencreated: -1,
            flags: String::from(""),
            caname: String::from(""),
            dnshostname: String::from(""),
            certthumbprint: String::from(""),
            certname: String::from(""),
            certchain: Vec::new(),
            hasbasicconstraints: false,
            basicconstraintpathlength: 0,
            casecuritycollected: false,
            enrollmentagentrestrictionscollected: false,
            isuserspecifiessanenabledcollected: false,
       }
    }
 }

// CARegistryData properties structure
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct CARegistryData {
    #[serde(rename = "CASecurity")]
    ca_security: CASecurity,
    #[serde(rename = "EnrollmentAgentRestrictions")]
    enrollment_agent_restrictions: EnrollmentAgentRestrictions,
    #[serde(rename = "IsUserSpecifiesSanEnabled")]
    is_user_specifies_san_enabled: IsUserSpecifiesSanEnabled,
}

impl CARegistryData {
    pub fn new(
        ca_security: CASecurity,
    ) -> Self { 
        Self { 
            ca_security,
            ..Default::default()
        }
    }
}

// CASecurity properties structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CASecurity {
    #[serde(rename = "Data")]
    data: Vec<AceTemplate>,
    #[serde(rename = "Collected")]
    collected: bool,
    #[serde(rename = "FailureReason")]
    failure_reason: Option<String>,
}


impl Default for CASecurity {
    fn default() -> CASecurity {
        CASecurity {
            data: Vec::new(),
            collected: true,
            failure_reason: None,
       }
    }
}

// EnrollmentAgentRestrictions properties structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EnrollmentAgentRestrictions {
    #[serde(rename = "Restrictions")]
    restrictions: Vec<String>, // data to validate
    #[serde(rename = "Collected")]
    collected: bool,
    #[serde(rename = "FailureReason")]
    failure_reason: Option<String>,
}

impl Default for EnrollmentAgentRestrictions {
    fn default() -> EnrollmentAgentRestrictions {
        EnrollmentAgentRestrictions {
            restrictions: Vec::new(),
            collected: true,
            failure_reason: None,
       }
    }
}

// IsUserSpecifiesSanEnabled properties structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IsUserSpecifiesSanEnabled {
    #[serde(rename = "Value")]
    value: bool,
    #[serde(rename = "Collected")]
    collected: bool,
    #[serde(rename = "FailureReason")]
    failure_reason: Option<String>,
}

impl Default for IsUserSpecifiesSanEnabled {
    fn default() -> IsUserSpecifiesSanEnabled {
        IsUserSpecifiesSanEnabled {
            value: false,
            collected: true,
            failure_reason: None,
       }
    }
}