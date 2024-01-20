use serde_json::value::Value;
use serde::{Deserialize, Serialize};

use crate::objects::common::{
    LdapObject,
    AceTemplate,
    SPNTarget,
    Link,
    Member
};

use colored::Colorize;
use ldap3::SearchEntry;
use log::{info, debug, error, trace};
use regex::Regex;
use std::collections::HashMap;
use x509_parser::prelude::*;

use crate::enums::acl::{parse_ntsecuritydescriptor, parse_gmsa};
use crate::utils::date::{convert_timestamp, string_to_epoch};
use crate::enums::secdesc::LdapSid;
use crate::enums::sid::sid_maker;
use crate::enums::spntasks::check_spn;
use crate::enums::uacflags::get_flag;


/// User structure
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct User {
   #[serde(rename = "ObjectIdentifier")]
   object_identifier: String,
   #[serde(rename = "IsDeleted")]
   is_deleted: bool,
   #[serde(rename = "IsACLProtected")]
   is_acl_protected: bool,
   #[serde(rename = "Properties")]
   properties: UserProperties,
   #[serde(rename = "PrimaryGroupSID")]
   primary_group_sid: String,
   #[serde(rename = "SPNTargets")]
   spn_targets: Vec<SPNTarget>,
   #[serde(rename = "Aces")]
   aces: Vec<AceTemplate>,
   #[serde(rename = "AllowedToDelegate")]
   allowed_to_delegate: Vec<Member>,
   #[serde(rename = "HasSIDHistory")]
   has_sid_history: Vec<String>,
   #[serde(rename = "ContainedBy")]
   contained_by: Option<Member>,
}

impl User {
   // New User
   pub fn new() -> Self { 
      Self { ..Default::default() } 
   }

   // Immutable access.
   pub fn properties(&self) -> &UserProperties {
      &self.properties
   }
   pub fn aces(&self) -> &Vec<AceTemplate> {
      &self.aces
   }

   // Mutable access.
   pub fn properties_mut(&mut self) -> &mut UserProperties {
      &mut self.properties
   }
   pub fn aces_mut(&mut self) -> &mut Vec<AceTemplate> {
      &mut self.aces
   }
   pub fn object_identifier_mut(&mut self) -> &mut String {
      &mut self.object_identifier
   }

   /// Function to parse and replace value for user object.
   /// <https://bloodhound.readthedocs.io/en/latest/further-reading/json.html#users>
   pub fn parse(
      &mut self,
      result: SearchEntry,
      domain: &String,
      dn_sid: &mut HashMap<String, String>,
      sid_type: &mut HashMap<String, String>,
   ) {
      let result_dn: String;
      result_dn = result.dn.to_uppercase();

      let result_attrs: HashMap<String, Vec<String>>;
      result_attrs = result.attrs;

      let result_bin: HashMap<String, Vec<Vec<u8>>>;
      result_bin = result.bin_attrs;

      debug!("Parse user: {}", result_dn);
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
      self.properties.enabled = true;

      // With a check
      let mut group_id: String = "".to_owned();
      for (key, value) in &result_attrs {
         match key.as_str() {
            "sAMAccountName" => {
                  let name = &value[0];
                  let email = format!("{}@{}",name.to_owned(),domain);
                  self.properties.name = email.to_uppercase();
                  self.properties.samaccountname = name.to_string();
            }
            "description" => {
                  self.properties.description = Some(value[0].to_owned());
            }
            "mail" => {
                  self.properties.email = value[0].to_owned();
            }
            "title" => {
                  self.properties.title = value[0].to_owned();
            }
            "userPassword" => {
                  self.properties.userpassword = value[0].to_owned();
            }
            "unixUserPassword" => {
                  self.properties.unixpassword = value[0].to_owned();
            }
            "unicodepwd" => {
                  self.properties.unicodepassword = value[0].to_owned();
            }
            "sfupassword" => {
                  //self.properties.sfupassword = value[0].to_owned();
            }
            "displayName" => {
                  self.properties.displayname = value[0].to_owned();
            }
            "adminCount" => {
                  let isadmin = &value[0];
                  let mut admincount = false;
                  if isadmin == "1" {
                     admincount = true;
                  }
                  self.properties.admincount = admincount.into();
            }
            "homeDirectory" => {
                  self.properties.homedirectory = value[0].to_owned();
            }
            "scriptpath" => {
                  self.properties.logonscript = value[0].to_owned();
            }
            "userAccountControl" => {
                  let uac = &value[0].parse::<u32>().unwrap_or(0);
                  let uac_flags = get_flag(*uac);
                  //trace!("UAC : {:?}",uac_flags);
                  for flag in uac_flags {
                     if flag.contains("AccountDisable") {
                        self.properties.enabled = false;
                     };
                     //if flag.contains("Lockout") { let enabled = true; user_json["Properties"]["enabled"] = enabled.into(); };
                     if flag.contains("PasswordNotRequired") {
                        self.properties.passwordnotreqd = true;
                     };
                     if flag.contains("DontExpirePassword") {
                        self.properties.pwdneverexpires = true;
                     };
                     if flag.contains("DontReqPreauth") {
                        self.properties.dontreqpreauth = true;
                     };
                     // KUD (Kerberos Unconstrained Delegation)
                     if flag.contains("TrustedForDelegation") {
                        self.properties.unconstraineddelegation = true;
                     };
                     if flag.contains("NotDelegated") {
                        self.properties.sensitive = true;
                     };
                     //if flag.contains("PasswordExpired") { let password_expired = true; user_json["Properties"]["pwdneverexpires"] = password_expired.into(); };
                     if flag.contains("TrustedToAuthForDelegation") {
                        self.properties.trustedtoauth = true;
                     };
                  }
            }
            "msDS-AllowedToDelegateTo"  => {
                  // KCD (Kerberos Constrained Delegation)
                  //trace!(" AllowToDelegateTo: {:?}",&value);
                  // AllowedToDelegate
                  let mut vec_members2: Vec<Member> = Vec::new();
                  for objet in value {
                     let mut member_allowed_to_delegate = Member::new();
                     let split = objet.split("/");
                     let fqdn = split.collect::<Vec<&str>>()[1];
                     let mut checker = false;
                     for member in &vec_members2 {
                        if member.object_identifier().contains(fqdn.to_uppercase().as_str()) {
                              checker = true;
                        }
                     }
                     if !checker {
                        *member_allowed_to_delegate.object_identifier_mut() = fqdn.to_uppercase().to_owned().to_uppercase();
                        *member_allowed_to_delegate.object_type_mut() = "Computer".to_owned();
                        vec_members2.push(member_allowed_to_delegate.to_owned()); 
                     }
                  }
                  // *properties.allowedtodelegate = vec_members2.to_owned();
                  self.allowed_to_delegate = vec_members2;
            }
            "lastLogon" => {
                  let lastlogon = &value[0].parse::<i64>().unwrap_or(0);
                  if lastlogon.is_positive() {
                     let epoch = convert_timestamp(*lastlogon);
                     self.properties.lastlogon = epoch;
                  }
            }
            "lastLogonTimestamp" => {
                  let lastlogontimestamp = &value[0].parse::<i64>().unwrap_or(0);
                  if lastlogontimestamp.is_positive() {
                     let epoch = convert_timestamp(*lastlogontimestamp);
                     self.properties.lastlogontimestamp = epoch;
                  }
            }
            "pwdLastSet" => {
                  let pwdlastset = &value[0].parse::<i64>().unwrap_or(0);
                  if pwdlastset.is_positive() {
                     let epoch = convert_timestamp(*pwdlastset);
                     self.properties.pwdlastset = epoch;
                  }
            }
            "whenCreated" => {
                  let epoch = string_to_epoch(&value[0]);
                  if epoch.is_positive() {
                     self.properties.whencreated = epoch;
                  }
            }
            "servicePrincipalName" => {
                  // SPNTargets values
                  let mut targets: Vec<SPNTarget> = Vec::new();
                  let mut result: Vec<String> = Vec::new();
                  let mut added: bool = false;
                  for v in value {
                     result.push(v.to_owned());
                     // Checking the spn for service-account (mssql?)
                     let _target = match check_spn(v).to_owned() {
                        Some(_target) => {
                              if !added {
                                 targets.push(_target.to_owned());
                                 added = true;
                              }
                        },
                        None => { }
                     };
                  }
                  self.properties.serviceprincipalnames = result;
                  self.properties.hasspn = true;
                  self.spn_targets = targets;
            }
            "primaryGroupID" => {
                  group_id = value[0].to_owned();
            }
            "IsDeleted" => {
                  // OID to use: 1.2.840.113556.1.4.417
                  // https://ldapwiki.com/wiki/IsDeleted
                  //trace!("isDeleted: {:?}",&value[0]);
                  self.is_deleted = true;
            }
            _ => {}
         }
      }

      // For all, bins attributs
      let mut sid: String = "".to_owned();
      for (key, value) in &result_bin {
         match key.as_str() {
            "objectSid" => {
                  sid = sid_maker(LdapSid::parse(&value[0]).unwrap().1, domain);
                  self.object_identifier = sid.to_owned();

                  let re = Regex::new(r"^S-[0-9]{1}-[0-9]{1}-[0-9]{1,}-[0-9]{1,}-[0-9]{1,}-[0-9]{1,}").unwrap();
                  for domain_sid in re.captures_iter(&sid) 
                  {
                     self.properties.domainsid = domain_sid[0].to_owned().to_string();
                  }
            }
            "nTSecurityDescriptor" => {
                  // Needed with acl
                  let entry_type = "User".to_string();
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
            "sIDHistory" => {
                  // not tested! #tocheck
                  //debug!("sIDHistory: {:?}",&value[0]);
                  let mut list_sid_history: Vec<String> = Vec::new();
                  for bsid in value {
                     debug!("sIDHistory: {:?}", &bsid);
                     list_sid_history.push(sid_maker(LdapSid::parse(&bsid).unwrap().1, domain));
                     // Todo function to add the sid history in user_json['HasSIDHistory']
                  }
                  self.properties.sidhistory = list_sid_history;
            }
            "msDS-GroupMSAMembership" => {
                  let entry_type = "User".to_string();
                  // nTSecurityDescriptor raw to string
                  let mut relations_ace = parse_ntsecuritydescriptor(
                     self,
                     &value[0],
                     entry_type,
                     &result_attrs,
                     &result_bin,
                     &domain,
                  );
                  // Now add the new ACE wich who can read GMSA password
                  // trace!("User ACES before GMSA: {:?}", user.aces());
                  parse_gmsa(&mut relations_ace, self);
                  // info!("User ACES after GMSA: {:?}", user.aces());
            }
            "userCertificate" => {
                  // <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adls/d66d1662-0b4f-44ab-a4c8-e788f3ae39cf>
                  // <https://docs.rs/x509-parser/latest/x509_parser/certificate/struct.X509Certificate.html>
                  let res = X509Certificate::from_der(&value[0]);
                  match res {
                     Ok((_rem, cert)) => {
                        info!("ADCS found {}, use {} args to collect the certificate templates and certificate authority.",cert.issuer().to_string().replace(" ","").bold().green(),&"--adcs".bold().yellow());
                     },
                     _ => error!("CA x509 certificate parsing failed: {:?}", res),
                  }
            }
            _ => {}
         }
      }

      // primaryGroupID if group_id is set
      #[allow(irrefutable_let_patterns)]
      if let id = group_id {
         let re = Regex::new(r"S-.*-").unwrap();
         let part1 = re.find(&sid).unwrap();
         self.primary_group_sid = format!("{}{}", part1.as_str(), id); 
      }

      // Push DN and SID in HashMap
      dn_sid.insert(
         self.properties.distinguishedname.to_owned(),
         self.object_identifier.to_owned(),
      );
      // Push DN and Type
      sid_type.insert(
         self.object_identifier.to_owned(),
         "User".to_string(),
      );

      // Trace and return User struct
      // trace!("JSON OUTPUT: {:?}",serde_json::to_string(&self).unwrap());
   }
}

/// Function to change some values from LdapObject trait for User
impl LdapObject for User {
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
      &self.spn_targets
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
   fn set_spntargets(&mut self, spn_targets: Vec<SPNTarget>) {
      self.spn_targets = spn_targets;
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

/// User properties structure
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct UserProperties {
   domain: String,
   name: String,
   domainsid: String,
   distinguishedname: String,
   highvalue: bool,
   description: Option<String>,
   whencreated: i64,
   sensitive: bool,
   dontreqpreauth: bool,
   passwordnotreqd: bool,
   unconstraineddelegation: bool,
   pwdneverexpires: bool,
   enabled: bool,
   trustedtoauth: bool,
   lastlogon: i64,
   lastlogontimestamp: i64,
   pwdlastset: i64,
   serviceprincipalnames: Vec<String>,
   hasspn: bool,
   displayname: String,
   email: String,
   title: String,
   homedirectory: String,
   logonscript: String,
   samaccountname: String,
   userpassword: String,
   unixpassword: String,
   unicodepassword: String,
   sfupassword: String,
   admincount: bool,
   sidhistory: Vec<String>,
   allowedtodelegate: Vec<String>
}

impl UserProperties {
   // Immutable access.
   pub fn name(&self) -> &String {
      &self.name
   }
   pub fn domainsid(&self) -> &String {
      &self.domainsid
   }

   // Mutable access.
   pub fn name_mut(&mut self) -> &mut String {
      &mut self.name
   }
   pub fn domainsid_mut(&mut self) -> &mut String {
      &mut self.domainsid
   }
}