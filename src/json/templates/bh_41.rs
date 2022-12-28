use serde_json::json;

/// Return the json template for one user
pub fn prepare_user_json_template() -> serde_json::value::Value
{
   return json!({
      "ObjectIdentifier": "SID",
      "IsDeleted": false,
      "IsACLProtected": false,
      "Properties": {
         "domain": "domain.com",
         "name": "name@domain.com",
         "domainsid": "SID",
         "distinguishedname": "CN=name,DN=domain,DN=com",
         "highvalue": false,
         "description": null,
         "whencreated": -1,
         "sensitive": false,
         "dontreqpreauth": false,
         "passwordnotreqd": false,
         "unconstraineddelegation": false,
         "pwdneverexpires": false,
         "enabled": true,
         "trustedtoauth": false,  
         "lastlogon": -1,
         "lastlogontimestamp": -1,
         "pwdlastset": -1,
         "serviceprincipalnames": [],
         "hasspn": false,
         "displayname": null,
         "email": null,
         "title": null,
         "homedirectory": null,
         "logonscript": null,
         "samaccountname": null,
         "userpassword": null,
         "unixpassword": null,
         "unicodepassword": null,
         "sfupassword": null,
         "admincount": false,
         "sidhistory": [],
         "allowedtodelegate": []
      },
      "PrimaryGroupSID": null,
      "SPNTargets": [],
      "Aces": [],
      "AllowedToDelegate": [],
      // TODO
      "HasSIDHistory": [],
   });
}

/// Return the json template for one group
pub fn prepare_group_json_template() -> serde_json::value::Value
{
   return json!({
      "ObjectIdentifier": "SID",
      "IsDeleted": false,
      "IsACLProtected": false,
      "Properties": {
         "domain": "domain.com",
         "domainsid": "SID",
         "name": "name@domain.com",
         "distinguishedname": "DN",
         "samaccountname": null,
         "highvalue": false,
         "admincount": false,
         "description": null,
         "whencreated": -1
      },
      "Members": [],
      "Aces": [],
   });
}

/// Return the json template for one computer
pub fn prepare_computer_json_template() -> serde_json::value::Value
{
   return json!({
      "ObjectIdentifier": "SID",
      "IsDeleted": false,
      "IsACLProtected": false,
      "Properties": {
         "domain": "domain.com",
         "name": "name.domain.com",
         "distinguishedname": "DN",
         "highvalue": false,
         "samaccountname": null,
         "domainsid": "SID",
         "haslaps": false,
         "description": null,
         "whencreated": -1,
         "enabled": true,
         "unconstraineddelegation": false,
         "trustedtoauth": false,
         "lastlogon": -1,
         "lastlogontimestamp": -1,
         "pwdlastset": -1,
         "serviceprincipalnames": [],
         "operatingsystem": null,
         "sidhistory": [],
      },
      "PrimaryGroupSID": "PGSID",
      "Aces": [],
      "AllowedToDelegate": [],
      "AllowedToAct": [],
      "Status": null,
      //TODO
      "HasSIDHistory": [],
      "Sessions": {
         "Results": [],
         "Collected": false,
         "FailureReason": null
      },
      "PrivilegedSessions": {
         "Results": [],
         "Collected": false,
         "FailureReason": null
      },
      "RegistrySessions": {
         "Results": [],
         "Collected": false,
         "FailureReason": null
      },
      "LocalAdmins": {
         "Results": [],
         "Collected": false,
         "FailureReason": null
      },
      "RemoteDesktopUsers": {
         "Results": [],
         "Collected": false,
         "FailureReason": null
      },
      "DcomUsers": {
         "Results": [],
         "Collected": false,
         "FailureReason": null
      },
      "PSRemoteUsers": {
         "Results": [],
         "Collected": false,
         "FailureReason": null
      },
   });
}

/// Return the json template for one OU
pub fn prepare_ou_json_template() -> serde_json::value::Value
{
   return json!({
      "ObjectIdentifier": "SID",
      "IsDeleted": false,
      "IsACLProtected": false,
      "Properties": {
         "name": "name@domain.com",
         "domain": "domain.com",
         "domainsid": "SID",
         "distinguishedname": "DN",
         "highvalue": false,
         "description": null,
         "blocksinheritance": false,
         "whencreated": -1
      },
      "ACLProtected": false,
      "Links": [],
      "ChildObjects": [],
      "Aces": [],
      // TODO
      "GPOChanges": {
         "LocalAdmins" :  [],
         "RemoteDesktopUsers" :  [],
         "DcomUsers" :  [],
         "PSRemoteUsers" :  [],
         // OK for affected computers
         "AffectedComputers" :  []
      },
   });
}

/// Return the json template for one GPO
pub fn prepare_gpo_json_template() -> serde_json::value::Value
{
   return json!({
      "IsDeleted": false,
      "IsACLProtected": false,
      "Properties": {
         "name": "name@domain.com",
         "domain": "domain.com",
         "domainsid": "SID",
         "distinguishedname": "DN",
         "highvalue": false,
         "description": null,
         "gpcpath": "GPO_PATH",
         "whencreated": -1
      },
      "ObjectIdentifier": "SID",
      "Aces": [],
   });
}

/// Return the json template for one domain
pub fn prepare_domain_json_template() -> serde_json::value::Value
{
   return json!({
      "ChildObjects": [],
      "Trusts": [],
      "Aces": [],
      "ObjectIdentifier": "SID",
      "IsACLProtected": false,
      "IsDeleted": false,
      "Properties": {
         "domain": "domain.com",
         "name": "domain.com",
         "distinguishedname": "DN",
         "domainsid": "SID",
         "description": null,
         "highvalue": true,
         "whencreated": -1,
         "functionallevel": "Unknown",
      },
      // Todo
      "GPOChanges": {
         "LocalAdmins" :  [],
         "RemoteDesktopUsers" :  [],
         "DcomUsers" :  [],
         "PSRemoteUsers" :  [],
         // Ok for affected computers
         "AffectedComputers" :  []
      },
      // Todo
      "Links": [],
   });
}

/// Return the json template for one ForeignSecurityPrincipal
pub fn prepare_fsp_json_template() -> serde_json::value::Value
{
   return json!({
      "ObjectIdentifier": "SID",
      "IsDeleted": false,
      "IsACLProtected": false,
      "Properties": {
         "name": "domain.com",
         "domainsid": "SID",
         "distinguishedname": "DN",
         "type":"Unknown",
         "whencreated": -1
      },
   });
}

/// Return the json template for one Container
pub fn prepare_container_json_template() -> serde_json::value::Value
{
   return json!({
      "ObjectIdentifier": "SID",
      "IsDeleted": false,
      "IsACLProtected": false,
      "Properties": {
         "name": "xyz@domain.com",
         "domain": "domain.local",
         "domainsid": "SID",
         "distinguishedname": "DN",
         "highvalue": false,
      },
      "ChildObjects": [],
      "Aces": [],
   });
}

/// Return the json template for one member
pub fn prepare_member_json_template() -> serde_json::value::Value
{
   return json!({
      "ObjectIdentifier": "",
      "ObjectType": ""
   });
}

/// Return the json template for one acl relation
pub fn prepare_acl_relation_template() -> serde_json::value::Value
{
   return json!({
      "RightName": "",
      "IsInherited": false,
      "PrincipalSID": "",
      "PrincipalType": ""
   });
}

/// Return the json template for final file
pub fn prepare_final_json_file_template(version: i8, bh_type: String) -> serde_json::value::Value
{
   return json!({
      "data": [],
      "meta": {
          "methods": 0,
          "type": bh_type,
          "count": 0,
          "version": version
      }
   });
}

/// Return the json template for gplink
pub fn prepare_gplink_json_template() -> serde_json::value::Value
{
   return json!({
      "IsEnforced": false,
      "GUID": "GUID"
   });
}

/// Return the json template for default group
pub fn prepare_default_group_json_template() -> serde_json::value::Value
{
   return json!({
      "Members": [],
      "Aces": [],
      "ObjectIdentifier": "SID",
      "IsDeleted": false,
      "IsACLProtected": false,
      "Properties": {
          "name": "name@domain.com",
          "domainsid": "SID",
          "domain": "domain.com",
          "highvalue": false,
      },
   });
}

/// Return the json template for default user
pub fn prepare_default_user_json_template() -> serde_json::value::Value
{
   return json!({
      "AllowedToDelegate": [],
      "IsDeleted": false,
      "IsACLProtected": false,
      "ObjectIdentifier": "SID",
      "PrimaryGroupSID": null,
      "Properties": {
          "domain": "domain.com",
          "domainsid": "SID",
          "name": "name@domain.com",
      },
      "SPNTargets": [],
      "Aces": [],
      // TODO
      "HasSIDHistory": [],
   });
}

/// Return the json template for mssqlsvc spn
pub fn prepare_mssqlsvc_spn_json_template() -> serde_json::value::Value
{
   return json!({
      "ComputerSID": "",
      "Port": 1433,
      "Service": "SQLAdmin"
   });
}

/// Return the json template for one trust domain
pub fn prepare_trust_json_template() -> serde_json::value::Value
{
   return json!({
      "TargetDomainSid": "SID",
      "TargetDomainName": "DOMAIN.LOCAL",
      "IsTransitive": null,
      "SidFilteringEnabled": null,
      "TrustDirection": 0,
      "TrustType": 0
   });
}

/// ADCS needed template for BloodHound ly4k version
/// Return the json template for one Certificate Authority (CA)
pub fn prepare_adcs_ca_json_template() -> serde_json::value::Value
{
   return json!({
      "Properties": {
         "name": "CANAME@DOMAIN.LOCAL",
         "highvalue": false, // <https://github.com/ly4k/Certipy/blob/main/certipy/commands/find.py#L588>
         "CA Name": "CANAME",
         "DNS Name": "fqdn.domain.local",
         "Certificate Subject": "DN",
         "Certificate Serial Number": "0000000000000000000000000000",
         "Certificate Validity Start": "0000-00-00 00:00:00+00:00",
         "Certificate Validity End": "0000-00-00 00:00:00+00:00",
         "Web Enrollment": "Enabled", 
         "User Specified SAN": "Enabled", //TODO Need DCERPC
         "Request Disposition": "Issue", //TODO Need DCERPC
         "domain": "DOMAIN.LOCAL"
       },
       "ObjectIdentifier": "GUID",
       "Aces": []
   });
}

/// ADCS needed template for BloodHound ly4k version
/// Return the json template for one Certificate Template
pub fn prepare_adcs_template_json_template() -> serde_json::value::Value
{
   return json!({
      "Properties": {
         "name": "NAME@DOMAIN.LOCAL",
         "highvalue": false,
         "Template Name": "NAME",
         "Display Name": "NAME",
         "Certificate Authorities": [],
         "Enabled": false,
         "Client Authentication": false,
         "Enrollment Agent": false,
         "Any Purpose": false,
         "Enrollee Supplies Subject": false,
         "Certificate Name Flag": [],
         "Enrollment Flag": [],
         "Private Key Flag": [],
         "Extended Key Usage": [],
         "Requires Manager Approval": false,
         "Requires Key Archival": false,
         "Authorized Signatures Required": 0,
         "Validity Period": "x",
         "Renewal Period": "x",
         "domain": "DOMAIN.LOCAL"
       },
       "ObjectIdentifier": "GUID",
       "Aces": [],
       //"cas_ids": [] //automatically add if is ly4k BloodHound version
   });
}