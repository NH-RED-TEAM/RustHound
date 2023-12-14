use std::collections::HashMap;

use ldap3::SearchEntry;
use log::trace;
use serde_json::{json,value::Value};
use serde::{Deserialize, Serialize};


/// LdapObject structure
pub trait LdapObject {
   // Ldap object structure (User,Group,Computer...) to JSON
   fn to_json(&self) -> Value;

   // Get values
   fn get_object_identifier(&self) -> &String;
   fn get_is_acl_protected(&self) -> &bool;
   fn get_aces(&self) -> &Vec<AceTemplate>;
   fn get_spntargets(&self) -> &Vec<SPNTarget>;
   fn get_allowed_to_delegate(&self) -> &Vec<Member>;
   fn get_links(&self) -> &Vec<Link>;
   fn get_contained_by(&self) -> &Option<Member>;
   fn get_child_objects(&self) -> &Vec<Member>;
   // Only for computer objects
   fn get_haslaps(&self) -> &bool;

   // Edit values
   fn set_is_acl_protected(&mut self, is_acl_protected: bool);
   fn set_aces(&mut self, aces: Vec<AceTemplate>);
   fn set_spntargets(&mut self, spn_targets: Vec<SPNTarget>);
   fn set_allowed_to_delegate(&mut self, allowed_to_delegate: Vec<Member>);
   fn set_links(&mut self, links: Vec<Link>);
   fn set_contained_by(&mut self, contained_by: Option<Member>);
   fn set_child_objects(&mut self, child_objects: Vec<Member>);
}

/// LocalGroup structure
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct LocalGroup {
   #[serde(rename = "ObjectIdentifier")]
   object_identifier: String,
   #[serde(rename = "Results")]
   results: Vec<Member>,
   #[serde(rename = "LocalNames")]
   local_names: Vec<String>,
   #[serde(rename = "Collected")]
   collected: bool,
   #[serde(rename = "FailureReason")]
   failure_reason: Option<String>,
}

impl LocalGroup {
   // New Local Group.
   pub fn new() -> Self { 
      Self { 
         ..Default::default()
      }
   }

   // Immutable access.
   pub fn object_identifier(&self) -> &String {
      &self.object_identifier
   }
   pub fn results(&self) -> &Vec<Member> {
      &self.results
   }
   pub fn local_names(&self) -> &Vec<String> {
      &self.local_names
   }
   pub fn collected(&self) -> &bool {
      &self.collected
   }
   pub fn failure_reason(&self) -> &Option<String> {
      &self.failure_reason
   }

   // Mutable access.
   pub fn object_identifier_mut(&mut self) -> &mut String {
      &mut self.object_identifier
   }
   pub fn results_mut(&mut self) -> &mut Vec<Member> {
      &mut self.results
   }
   pub fn local_names_mut(&mut self) -> &mut Vec<String> {
      &mut self.local_names
   }
   pub fn collected_mut(&mut self) -> &mut bool {
      &mut self.collected
   }
   pub fn failure_reason_mut(&mut self) -> &mut Option<String> {
      &mut self.failure_reason
   }
}

/// Session structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Session {
   #[serde(rename = "Results")]
   results: Vec<UserComputerSession>,
   #[serde(rename = "Collected", default = "default_true")]
   collected: bool,
   #[serde(rename = "FailureReason")]
   failure_reason: Option<String>,
}

impl Default for Session {
   /// Default values for Session structure.
   fn default() -> Session {
      Session {
         results: Vec::new(),
         collected: true,
         failure_reason: None,
       }
   }
}

impl Session {
   // New session.
   pub fn new() -> Self { 
      Self { 
         collected: true,
         ..Default::default()
      }
   }

   // Immutable access.
   pub fn results(&self) -> &Vec<UserComputerSession> {
      &self.results
   }
   pub fn collected(&self) -> &bool {
      &self.collected
   }
   pub fn failure_reason(&self) -> &Option<String> {
      &self.failure_reason
   }

   // Mutable access.
   pub fn results_mut(&mut self) -> &mut Vec<UserComputerSession> {
      &mut self.results
   }
   pub fn collected_mut(&mut self) -> &mut bool {
      &mut self.collected
   }
   pub fn failure_reason_mut(&mut self) -> &mut Option<String> {
      &mut self.failure_reason
   }
}

/// UserSID to ComputerSID Session link structure
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct UserComputerSession {
   #[serde(rename = "UserSID")]
   user_sid: String,
   #[serde(rename = "ComputerSID")]
   computer_sid: String,
}

impl UserComputerSession {
   // New User Computer Session.
   pub fn new() -> Self { 
      Self { 
         ..Default::default()
      }
   }

   // Immutable access.
   pub fn user_sid(&self) -> &String {
      &self.user_sid
   }
   pub fn computer_sid(&self) -> &String {
      &self.computer_sid
   }

   // Mutable access.
   pub fn user_sid_mut(&mut self) -> &mut String {
      &mut self.user_sid
   }
   pub fn computer_sid_mut(&mut self) -> &mut String {
      &mut self.computer_sid
   }
   
}

/// Session structure
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct UserRight {
   #[serde(rename = "Privilege")]
   privilege: String,
   #[serde(rename = "Results")]
   results: Vec<Member>,
   #[serde(rename = "LocalNames")]
   local_names: Vec<String>,
   #[serde(rename = "Collected", default = "default_true")]
   collected: bool,
   #[serde(rename = "FailureReason")]
   failure_reason: Option<String>,
}

impl UserRight {
   // New User Right.
   pub fn new() -> Self { 
      Self { 
         ..Default::default()
      }
   }

   // Immutable access.
   pub fn privilege(&self) -> &String {
      &self.privilege
   }
   pub fn results(&self) -> &Vec<Member> {
      &self.results
   }
   pub fn local_names(&self) -> &Vec<String> {
      &self.local_names
   }
   pub fn collected(&self) -> &bool {
      &self.collected
   }
   pub fn failure_reason(&self) -> &Option<String> {
      &self.failure_reason
   }

   // Mutable access.
   pub fn privilege_mut(&mut self) -> &mut String {
      &mut self.privilege
   }
   pub fn results_mut(&mut self) -> &mut Vec<Member> {
      &mut self.results
   }
   pub fn local_names_mut(&mut self) -> &mut Vec<String> {
      &mut self.local_names
   }
   pub fn collected_mut(&mut self) -> &mut bool {
      &mut self.collected
   }
   pub fn failure_reason_mut(&mut self) -> &mut Option<String> {
      &mut self.failure_reason
   }
}


/// DCRegistryData structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DCRegistryData {
   #[serde(rename = "CertificateMappingMethods")]
   certificate_mapping_methods: Option<RegistryData>,
   #[serde(rename = "StrongCertificateBindingEnforcement")]
   strong_certificate_binding_enforcement: Option<RegistryData>,
}

impl Default for DCRegistryData {
   fn default() -> DCRegistryData {
      DCRegistryData {
         certificate_mapping_methods: None,
         strong_certificate_binding_enforcement: None,
      }
   }
}

/// RegistryData structure
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct RegistryData {
   #[serde(rename = "Value")]
   value: i8,
   #[serde(rename = "Collected", default = "default_true")]
   collected: bool,
   #[serde(rename = "FailureReason")]
   failure_reason: Option<String>,
}

impl RegistryData {
   // New RegistryData.
   pub fn new() -> Self { 
      Self {
         collected: true,
         ..Default::default()
      }
   }
}

/// Function to return default value for struct.
pub fn default_true() -> bool {
   true
}

/// Member structure
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Member {
   #[serde(rename = "ObjectIdentifier")]
   object_identifier: String,
   #[serde(rename = "ObjectType")]
   object_type: String,
}

impl Member {
   // New member.
    pub fn new() -> Self {
      Self { 
         object_identifier: "SID".to_string(),
         ..Default::default()
      }
   }

   // Immutable access.
   pub fn object_identifier(&self) -> &String {
      &self.object_identifier
   }
   pub fn object_type(&self) -> &String {
      &self.object_type
   }

   // Mutable access.
   pub fn object_identifier_mut(&mut self) -> &mut String {
      &mut self.object_identifier
   }
   pub fn object_type_mut(&mut self) -> &mut String {
      &mut self.object_type
   }
}

/// AceTemplate structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AceTemplate {
   #[serde(rename = "PrincipalSID")]
   principal_sid: String,
   #[serde(rename = "PrincipalType")]
   principal_type: String,
   #[serde(rename = "RightName")]
   right_name: String,
   #[serde(rename = "IsInherited")]
   is_inherited: bool,
}

impl AceTemplate {
   // New ACE object.
   pub fn new(
      principal_sid: String,
      principal_type: String,
      right_name: String,
      is_inherited: bool
   ) -> Self { 
      Self { principal_sid, principal_type , right_name, is_inherited} 
   }

   // Immutable access.
   pub fn principal_sid(&self) -> &String {
      &self.principal_sid
   }
   pub fn principal_type(&self) -> &String {
      &self.principal_type
   }
   pub fn right_name(&self) -> &String {
      &self.right_name
   }
   pub fn is_inherited(&self) -> &bool {
      &self.is_inherited
   }

   // Mutable access.
   pub fn principal_sid_mut(&mut self) -> &mut String {
      &mut self.principal_sid
   }
   pub fn principal_type_mut(&mut self) -> &mut String {
      &mut self.principal_type
   }
   pub fn right_name_mut(&mut self) -> &mut String {
      &mut self.right_name
   }
   pub fn is_inherited_mut(&mut self) -> &mut bool {
      &mut self.is_inherited
   }
}

/// Link structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Link {
   #[serde(rename = "IsEnforced")]
   is_enforced: bool,
   #[serde(rename = "GUID")]
   guid: String,
}

impl Link {
   // New object.
   pub fn new(is_enforced: bool, guid: String) -> Self { Self { is_enforced, guid } }
   
   // Immutable access.
   pub fn is_enforced(&self) -> &bool {
      &self.is_enforced
   }
   pub fn guid(&self) -> &String {
      &self.guid
   }
 
   // Mutable access.
   pub fn is_enforced_mut(&mut self) -> &mut bool {
      &mut self.is_enforced
   }
   pub fn guid_mut(&mut self) -> &mut String {
      &mut self.guid
   }
}

/// GPOChange structure
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct GPOChange {
   #[serde(rename = "LocalAdmins")]
   local_admins: Vec<Member>,
   #[serde(rename = "RemoteDesktopUsers")]
   remote_desktop_users: Vec<Member>,
   #[serde(rename = "DcomUsers")]
   dcom_users: Vec<Member>,
   #[serde(rename = "PSRemoteUsers")]
   psremote_users: Vec<Member>,
   #[serde(rename = "AffectedComputers")]
   affected_computers: Vec<Member>,
}

impl GPOChange {
   // New GPOChanges.
   pub fn new() -> Self { 
      Self {
         ..Default::default()
      } 
   }

   // Imutable access.
   pub fn local_admins(&self) -> &Vec<Member> {
      &self.local_admins
   }
   pub fn remote_desktop_users(&self) -> &Vec<Member> {
      &self.remote_desktop_users
   }
   pub fn dcom_users(&self) -> &Vec<Member> {
      &self.dcom_users
   }
   pub fn psremote_users(&self) -> &Vec<Member> {
      &self.psremote_users
   }
   pub fn affected_computers(&self) -> &Vec<Member> {
      &self.affected_computers
   }

   // Mutable access.
   pub fn local_admins_mut(&mut self) -> &mut Vec<Member> {
      &mut self.local_admins
   }
   pub fn remote_desktop_users_mut(&mut self) -> &mut Vec<Member> {
      &mut self.remote_desktop_users
   }
   pub fn dcom_users_mut(&mut self) -> &mut Vec<Member> {
      &mut self.dcom_users
   }
   pub fn psremote_users_mut(&mut self) -> &mut Vec<Member> {
      &mut self.psremote_users
   }
   pub fn affected_computers_mut(&mut self) -> &mut Vec<Member> {
      &mut self.affected_computers
   }
}

/// SPNTarget structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SPNTarget {
   #[serde(rename = "ComputerSID")]
   computer_sid: String,
   #[serde(rename = "Port")]
   port: i32,
   #[serde(rename = "Service")]
   service: String,
}

impl SPNTarget {
   // New object.
   pub fn new() -> Self { 
      Self { 
         computer_sid: "SID".to_string(), 
         port: 1433, 
         service: "SQLAdmin".to_string()
      } 
   }

   // Immutable access.
   pub fn computer_sid(&self) -> &String {
      &self.computer_sid
   }
   pub fn port(&self) -> &i32 {
      &self.port
   }
   pub fn service(&self) -> &String {
      &self.service
   }

   // Mutable access.
   pub fn computer_sid_mut(&mut self) -> &mut String {
      &mut self.computer_sid
   }
   pub fn port_mut(&mut self) -> &mut i32 {
      &mut self.port
   }
   pub fn service_mut(&mut self) -> &mut String {
      &mut self.service
   }
}

/// Final JSON structure
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct FinalJson{
   data: Vec<Value>,
   meta: Meta,
}

impl FinalJson  {
   // New FinalJson.
   pub fn new(data: Vec<Value>, meta: Meta) -> Self { 
      Self {
         data,
         meta
      }
   }
   // Imutable access.
   pub fn data(&self) -> &Vec<Value> {
      &self.data
   }
   pub fn meta(&self) -> &Meta {
      &self.meta
   }

   // Mutable access.
   pub fn data_mut(&mut self) -> &mut Vec<Value> {
      &mut self.data
   }
   pub fn meta_mut(&mut self) -> &mut Meta {
      &mut self.meta
   }
}

/// Meta data for final JSON structure
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Meta {
   methods: i32,
   #[serde(rename = "type")]
   mtype: String,
   count: i32,
   version: i8
}

impl Meta {
   // New Meta.
   pub fn new(
      methods: i32,
      mtype: String,
      count: i32,
      version: i8
   ) -> Self { 
      Self { 
         methods,
         mtype,
         count,
         version
      } 
   }
   
   // Imutable access.
   pub fn methods(&self) -> &i32 {
      &self.methods
   }
   pub fn mtype(&self) -> &String {
      &self.mtype
   }
   pub fn count(&self) -> &i32 {
      &self.count
   }
   pub fn version(&self) -> &i8 {
      &self.version
   }

   // Mutable access.
   pub fn methods_mut(&mut self) -> &mut i32 {
      &mut self.methods
   }
   pub fn mtype_mut(&mut self) -> &mut String {
      &mut self.mtype
   }
   pub fn count_mut(&mut self) -> &mut i32 {
      &mut self.count
   }
   pub fn version_mut(&mut self) -> &mut i8 {
      &mut self.version
   }
}


/// Function to parse and replace value for unknown object.
pub fn parse_unknown(result: SearchEntry, _domain: &String) -> serde_json::value::Value  {

   let _result_dn = result.dn.to_uppercase();

   let _result_attrs: HashMap<String, Vec<String>>;
   _result_attrs = result.attrs;

   let _result_bin: HashMap<String, Vec<Vec<u8>>>;
   _result_bin = result.bin_attrs;

   let unknown_json = json!({
       "unknown": null,
   });

   // Debug for current object
   trace!("Parse Unknown object: {}", _result_dn);
   // for (key, value) in &_result_attrs {
   //    println!("  {:?}:{:?}", key, value);
   // }
   // //trace result bin
   // for (key, value) in &_result_bin {
   //    println!("  {:?}:{:?}", key, value);
   // }

   return unknown_json
}