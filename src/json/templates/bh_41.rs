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
      // Todo ! récupérer les valeurs suivantes:
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
      // Todo ! fonction pour récupérer les valeurs suivantes
      "AllowedToAct": [],
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
      "Status": null,
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
         "description": null,
         "blocksinheritance": false,
         "whencreated": -1
      },
      "ACLProtected": false,
      "Links": [],
      "ChildObjects": [],
      "Aces": [],
      //todo
      "GPOChanges": {
         "LocalAdmins" :  [],
         "RemoteDesktopUsers" :  [],
         "DcomUsers" :  [],
         "PSRemoteUsers" :  [],
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
      // Todo ! fonction permettant de récupérer les valeurs suivantes:
      "GPOChanges": {
         "LocalAdmins" :  [],
         "RemoteDesktopUsers" :  [],
         "DcomUsers" :  [],
         "PSRemoteUsers" :  [],
         "AffectedComputers" :  []
      },
      // Todo ! fonction permettant de récupérer les valeurs suivantes:
      "Links": [],
      "IsDeleted": false,
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
      },
      "ChildObjects": [],
      "Aces": [],
   });
}

/// Return the json template for one member
pub fn prepare_member_json_template() -> serde_json::value::Value
{
   return json!({
      "ObjectIdentifier": "SID",
      "ObjectType": "Type"
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
      "HasSIDHistory": [],
      "Aces": []
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