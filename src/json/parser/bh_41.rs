
use colored::Colorize;
use ldap3::SearchEntry;
use log::{info, debug, trace};
use regex::Regex;
use serde_json::json;
use std::collections::HashMap;

use crate::enums::acl::{parse_ntsecuritydescriptor,parse_gmsa};
use crate::enums::date::{convert_timestamp,string_to_epoch};
use crate::enums::forestlevel::get_forest_level;
use crate::enums::gplink::parse_gplink;
use crate::enums::secdesc::LdapSid;
use crate::enums::sid::{decode_guid, objectsid_to_vec8, sid_maker};
use crate::enums::spntasks::check_spn;
use crate::enums::uacflags::get_flag;
use crate::enums::trusts::get_trust_flag;

use crate::json::templates::bh_41::*;
//use crate::errors::{Error, Result};

/*
function 1 : users
function 2 : groups
function 3 : computers
function 4 : ous
function 5 : domains
function 6 : gpos
function 7 : ForeignSecurityPrincipal
function 8 : containers
function 9 : trust domain
function 10: unknown values
*/

/*****************************************
******************************************
1- Function to parse users information
******************************************
*****************************************/
/// Function to parse and replace value in json template for user object.
/// <https://bloodhound.readthedocs.io/en/latest/further-reading/json.html#users>
pub fn parse_user(
    result: SearchEntry,
    domain: &String,
    dn_sid: &mut HashMap<String, String>,
    sid_type: &mut HashMap<String, String>,
) -> serde_json::value::Value {

    let result_dn: String;
    result_dn = result.dn.to_uppercase();

    let result_attrs: HashMap<String, Vec<String>>;
    result_attrs = result.attrs;

    let result_bin: HashMap<String, Vec<Vec<u8>>>;
    result_bin = result.bin_attrs;

    debug!("Parse user: {}", result_dn);
    //for (key, value) in &result_attrs {
    //    trace!("  {:?}:{:?}", key, value);
    //}
    //trace result bin
    //for (key, value) in &result_bin {
    //    trace!("  {:?}:{:?}", key, value);
    //}

    // json template for one user
    let mut user_json = prepare_user_json_template();

    // Change all values...
    user_json["Properties"]["domain"] = domain.to_uppercase().into();
    user_json["Properties"]["distinguishedname"] = result_dn.into();

    // With a check
    let mut group_id: String = "".to_owned();
    for (key, value) in &result_attrs {
        match key.as_str() {
            "sAMAccountName" => {
                let name = &result_attrs["sAMAccountName"][0];
                let mut email: String = name.to_owned();
                email.push_str("@");
                email.push_str(domain.as_str());
                user_json["Properties"]["name"] = email.to_uppercase().into();
                user_json["Properties"]["samaccountname"] = name.to_uppercase().into();
                //trace!("NAME: {}", name);
            }
            "description" => {
                let description = &result_attrs["description"][0];
                user_json["Properties"]["description"] = description.to_owned().into();
            }
            "mail" => {
                let email = &result_attrs["mail"][0];
                user_json["Properties"]["email"] = email.to_owned().into();
            }
            "title" => {
                let title = &result_attrs["title"][0];
                user_json["Properties"]["title"] = title.to_owned().into();
            }
            "userPassword" => {
                let userpassword = &result_attrs["userPassword"][0];
                user_json["Properties"]["userpassword"] = userpassword.to_owned().into();
            }
            "unixUserPassword" => {
                let unixpassword = &result_attrs["unixUserPassword"][0];
                user_json["Properties"]["unixpassword"] = unixpassword.to_owned().into();
            }
            "unicodepwd" => {
                let unicodepwd = &result_attrs["unicodepwd"][0];
                user_json["Properties"]["unicodepassword"] = unicodepwd.to_owned().into();
            }
            "sfupassword" => {
                let _sfupassword = &result_attrs["sfupassword"][0];
                //user_json["Properties"]["unicodepassword"] = unicodepwd.to_owned().into();
            }
            "displayName" => {
                let displayname = &result_attrs["displayName"][0];
                user_json["Properties"]["displayname"] = displayname.to_owned().into();
            }
            "adminCount" => {
                let isadmin = &result_attrs["adminCount"][0];
                let mut admincount = false;
                if isadmin == "1" {
                    admincount = true;
                }
                user_json["Properties"]["admincount"] = admincount.into();
            }
            "homeDirectory" => {
                let homedirectory = &result_attrs["homeDirectory"][0];
                user_json["Properties"]["homedirectory"] = homedirectory.to_owned().into();
            }
            "scriptpath" => {
                let logonscript = &result_attrs["scriptpath"][0];
                user_json["Properties"]["logonscript"] = logonscript.to_owned().into();
            }
            "userAccountControl" => {
                let uac = &result_attrs["userAccountControl"][0].parse::<u32>().unwrap();
                let uac_flags = get_flag(*uac);
                //trace!("UAC : {:?}",uac_flags);
                for flag in uac_flags {
                    if flag.contains("AccountDisable") {
                        let enabled = false;
                        user_json["Properties"]["enabled"] = enabled.into();
                    };
                    //if flag.contains("Lockout") { let enabled = true; user_json["Properties"]["enabled"] = enabled.into(); };
                    if flag.contains("PasswordNotRequired") {
                        let password_not_reqd = true;
                        user_json["Properties"]["passwordnotreqd"] = password_not_reqd.into();
                    };
                    if flag.contains("DontExpirePassword") {
                        let pwd_never_expires = true;
                        user_json["Properties"]["pwdneverexpires"] = pwd_never_expires.into();
                    };
                    if flag.contains("TrustedForDelegation") {
                        let trusted_for_delegation = true;
                        user_json["Properties"]["unconstraineddelegation"] =
                            trusted_for_delegation.into();
                    };
                    if flag.contains("NotDelegated") {
                        let not_delegated = true;
                        user_json["Properties"]["unconstraineddelegation"] = not_delegated.into();
                    };
                    if flag.contains("DontReqPreauth") {
                        let dont_req_preauth = true;
                        user_json["Properties"]["dontreqpreauth"] = dont_req_preauth.into();
                    };
                    //if flag.contains("PasswordExpired") { let password_expired = true; user_json["Properties"]["pwdneverexpires"] = password_expired.into(); };
                    if flag.contains("TrustedToAuthForDelegation") {
                        let trusted_to_auth_for_delegation = true;
                        user_json["Properties"]["trustedtoauth"] = trusted_to_auth_for_delegation.into();
                    };
                }
            }
            "msDS-AllowedToDelegateTo"  => {
                //trace!(" AllowToDelegateTo: {:?}",&value);
                user_json["Properties"]["allowedtodelegate"] = value.to_owned().into();
                // AllowedToDelegate
                let mut vec_members: Vec<serde_json::value::Value> = Vec::new();
                let mut allowed_to_delegate = prepare_member_json_template();
                for objet in value {
                    let split = objet.split("/");
                    let fqdn = split.collect::<Vec<&str>>()[1];
                    let mut checker = false;
                    for member in &vec_members {
                        if member["ObjectIdentifier"].to_string().contains(fqdn.to_uppercase().as_str()) {
                            checker = true;
                        }
                    }
                    if !checker {
                        allowed_to_delegate["ObjectIdentifier"] = fqdn.to_uppercase().to_owned().to_uppercase().into();
                        allowed_to_delegate["ObjectType"] = "Computer".to_owned().into();
                        vec_members.push(allowed_to_delegate.to_owned()); 
                    }
                }
                user_json["AllowedToDelegate"] = vec_members.to_owned().into();
            }
            "lastLogon" => {
                let lastlogon = &result_attrs["lastLogon"][0].parse::<i64>().unwrap();
                if lastlogon.is_positive() {
                    let epoch = convert_timestamp(*lastlogon);
                    user_json["Properties"]["lastlogon"] = epoch.into();
                }
            }
            "lastLogonTimestamp" => {
                let lastlogontimestamp = &result_attrs["lastLogonTimestamp"][0]
                    .parse::<i64>()
                    .unwrap_or(0);
                if lastlogontimestamp.is_positive() {
                    let epoch = convert_timestamp(*lastlogontimestamp);
                    user_json["Properties"]["lastlogontimestamp"] = epoch.into();
                }
            }
            "pwdLastSet" => {
                let pwdlastset = &result_attrs["pwdLastSet"][0].parse::<i64>().unwrap();
                if pwdlastset.is_positive() {
                    let epoch = convert_timestamp(*pwdlastset);
                    user_json["Properties"]["pwdlastset"] = epoch.into();
                }
            }
            "whenCreated" => {
               let whencreated = &result_attrs["whenCreated"][0];
               let epoch = string_to_epoch(&whencreated);
               if epoch.is_positive() {
                   user_json["Properties"]["whencreated"] = epoch.into();
               }
           }
            "servicePrincipalName" => {
                let mut result: Vec<String> = Vec::new();
                // SPNTargets values
                let mut targets: Vec<serde_json::value::Value> = Vec::new();

                let mut added: bool = false;
                for value in &result_attrs["servicePrincipalName"] {
                    result.push(value.to_owned());

                    // Checking the spn for service-account (mssql?)
                    let target = check_spn(value).to_owned();
                    if target.to_string().contains("Port") && !added {
                        targets.push(target.to_owned());
                        added = true;
                    }
                }
                user_json["Properties"]["serviceprincipalnames"] = result.to_owned().into();
                let hasspn = true;
                user_json["Properties"]["hasspn"] = hasspn.into();
                user_json["SPNTargets"] = targets.into();
            }
            "primaryGroupID" => {
                group_id = value[0].to_owned();
            }
            "IsDeleted" => {
                // OID to use: 1.2.840.113556.1.4.417
                // https://ldapwiki.com/wiki/IsDeleted
                let is_deleted = true;
                debug!("isDeleted: {:?}",&result_attrs["IsDeleted"][0]);
                user_json["IsDeleted"] = is_deleted.to_owned().into();
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
                user_json["ObjectIdentifier"] = sid.to_owned().into();

                let re = Regex::new(r"^S-[0-9]{1}-[0-9]{1}-[0-9]{1,}-[0-9]{1,}-[0-9]{1,}-[0-9]{1,}").unwrap();
                for domain_sid in re.captures_iter(&sid) 
                {
                    user_json["Properties"]["domainsid"] = domain_sid[0].to_owned().to_string().into();
                }
            }
            "nTSecurityDescriptor" => {
                // Needed with acl
                let entry_type = "user".to_string();
                // nTSecurityDescriptor raw to string
                let relations_ace = parse_ntsecuritydescriptor(
                    &mut user_json,
                    &value[0],
                    entry_type,
                    &result_attrs,
                    &result_bin,
                    &domain,
                );
                user_json["Aces"] = relations_ace.into();
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
                user_json["Properties"]["sidhistory"] = list_sid_history.into();
            }
            "msDS-GroupMSAMembership" => {
                let entry_type = "user".to_string();
                // nTSecurityDescriptor raw to string
                let mut relations_ace = parse_ntsecuritydescriptor(
                    &mut user_json,
                    &value[0],
                    entry_type,
                    &result_attrs,
                    &result_bin,
                    &domain,
                );
                // Now add the new ACE wich who can read GMSA password
                let mut relations_ace_b = user_json["Aces"].as_array_mut().unwrap();
                trace!("msDS-GroupMSAMembership ACE ? {:?}", relations_ace);
                //trace!("user_json['Aces'] before : {:?}", relations_ace_b);
                parse_gmsa(&mut relations_ace, &mut relations_ace_b);
                //info!("user_json['Aces'] after : {:?}", relations_ace_b);
            }
            _ => {}
        }
    }

    // primaryGroupID if group_id is set
    #[allow(irrefutable_let_patterns)]
    if let id = group_id {
        let re = Regex::new(r"S-.*-").unwrap();
        let part1 = re.find(&sid).unwrap();
        let mut primary_group_id: String = "".to_owned();
        primary_group_id.push_str(&part1.as_str());
        primary_group_id.push_str(&id.as_str());
        user_json["PrimaryGroupSID"] = primary_group_id.to_owned().into();
    }

    // Push DN and SID in HashMap
    dn_sid.insert(
        user_json["Properties"]["distinguishedname"]
            .as_str()
            .unwrap()
            .to_string(),
        user_json["ObjectIdentifier"].as_str().unwrap().to_string(),
    );
    // Push DN and Type
    sid_type.insert(
        user_json["ObjectIdentifier"].as_str().unwrap().to_string(),
        "User".to_string(),
    );

    return user_json;
}

/*****************************************
******************************************
2- Function to parse groups information
******************************************
*****************************************/
/// Function to parse and replace value in json template for group object.
/// <https://bloodhound.readthedocs.io/en/latest/further-reading/json.html#groups>
pub fn parse_group(
    result: SearchEntry,
    domain: &String,
    dn_sid: &mut HashMap<String, String>,
    sid_type: &mut HashMap<String, String>,
) -> serde_json::value::Value {
    let result_dn: String;
    result_dn = result.dn.to_uppercase();

    let result_attrs: HashMap<String, Vec<String>>;
    result_attrs = result.attrs;

    let result_bin: HashMap<String, Vec<Vec<u8>>>;
    result_bin = result.bin_attrs;

    debug!("Parse group: {}", result_dn);
    //for (key, value) in &result_attrs {
    //    trace!("  {:?}:{:?}", key, value);
    //}
    ////trace result bin
    //for (key, value) in &result_bin {
    //    trace!("  {:?}:{:?}", key, value);
    //}

    // json template for one group
    let mut group_json = prepare_group_json_template();

    // json template for all members
    let mut vec_members: Vec<serde_json::value::Value> = Vec::new();
    let mut member_json = prepare_member_json_template();

    // Change all values...
    group_json["Properties"]["domain"] = domain.to_uppercase().into();
    group_json["Properties"]["distinguishedname"] = result_dn.into();

    #[allow(unused_assignments)]
    let mut sid: String = "".to_owned();
    // With a check
    for (key, _value) in &result_attrs {
        match key.as_str() {
            "name" => {
                let name = &result_attrs["name"][0];
                let mut email: String = name.to_owned();
                email.push_str("@");
                email.push_str(domain.as_str());
                group_json["Properties"]["name"] = email.to_uppercase().into();
            }
            "description" => {
                let description = &result_attrs["description"][0];
                group_json["Properties"]["description"] = description.to_owned().into();
            }
            "adminCount" => {
                let isadmin = &result_attrs["adminCount"][0];
                let mut admincount = false;
                if isadmin == "1" {
                    admincount = true;
                }
                group_json["Properties"]["admincount"] = admincount.into();
            }
            "member" => {
                for member in &result_attrs["member"] {
                    member_json["ObjectIdentifier"] = member.to_owned().to_uppercase().into();
                    vec_members.push(member_json.to_owned());
                }
                group_json["Members"] = vec_members.to_owned().into();
            }
            "objectSid" => {
                // objectSid to vec and raw to string
                let vec_sid = objectsid_to_vec8(&result_attrs["objectSid"][0]);
                sid = sid_maker(LdapSid::parse(&vec_sid).unwrap().1, domain);
                group_json["ObjectIdentifier"] = sid.to_owned().into();
            
                /*let re = Regex::new(r"^S-[0-9]{1}-[0-9]{1}-[0-9]{1,}-[0-9]{1,}-[0-9]{1,}-[0-9]{1,}").unwrap();
                for domain_sid in re.captures_iter(&sid) 
                {
                    group_json["Properties"]["domainsid"] = domain_sid[0].to_owned().to_string().into();
                }*/
            }
            "whenCreated" => {
                let whencreated = &result_attrs["whenCreated"][0];
                let epoch = string_to_epoch(&whencreated);
                if epoch.is_positive() {
                    group_json["Properties"]["whencreated"] = epoch.into();
                }
            }
            _ => {}
        }
    }

    // For all, bins attributs
    for (key, value) in &result_bin {
        match key.as_str() {
            "objectSid" => {
                // objectSid raw to string
                sid = sid_maker(LdapSid::parse(&value[0]).unwrap().1, domain);
                group_json["ObjectIdentifier"] = sid.to_owned().into();

                let re = Regex::new(r"^S-[0-9]{1}-[0-9]{1}-[0-9]{1,}-[0-9]{1,}-[0-9]{1,}-[0-9]{1,}").unwrap();
                for domain_sid in re.captures_iter(&sid) 
                {
                    group_json["Properties"]["domainsid"] = domain_sid[0].to_owned().to_string().into();
                }
            }
            "nTSecurityDescriptor" => {
                // Needed with acl
                let entry_type = "group".to_string();
                // nTSecurityDescriptor raw to string
                let relations_ace = parse_ntsecuritydescriptor(
                    &mut group_json,
                    &value[0],
                    entry_type,
                    &result_attrs,
                    &result_bin,
                    &domain,
                );
                group_json["Aces"] = relations_ace.into();
            }
            _ => {}
        }
    }

    // Push DN and SID in HashMap
    dn_sid.insert(
        group_json["Properties"]["distinguishedname"]
            .as_str()
            .unwrap()
            .to_string(),
        group_json["ObjectIdentifier"].as_str().unwrap().to_string(),
    );
    // Push DN and Type
    sid_type.insert(
        group_json["ObjectIdentifier"].as_str().unwrap().to_string(),
        "Group".to_string(),
    );

    return group_json;
}

/*****************************************
******************************************
3- Function to parse computers information
******************************************
*****************************************/
/// Function to parse and replace value in json template for computer object.
/// <https://bloodhound.readthedocs.io/en/latest/further-reading/json.html#computers>
pub fn parse_computer(
    result: SearchEntry,
    domain: &String,
    dn_sid: &mut HashMap<String, String>,
    sid_type: &mut HashMap<String, String>,
    fqdn_sid: &mut HashMap<String, String>,
    fqdn_ip: &mut HashMap<String, String>,
) -> serde_json::value::Value {
    let result_dn: String;
    result_dn = result.dn.to_uppercase();

    let result_attrs: HashMap<String, Vec<String>>;
    result_attrs = result.attrs;

    let result_bin: HashMap<String, Vec<Vec<u8>>>;
    result_bin = result.bin_attrs;

    debug!("Parse computer: {}", result_dn);
    //for (key, value) in &result_attrs {
    //    trace!("  {:?}:{:?}", key, value);
    //}
    ////trace result bin
    //for (key, value) in &result_bin {
    //    trace!("  {:?}:{:?}", key, value);
    //}

    // json template for one computer
    let mut computer_json = prepare_computer_json_template();

    let mut vec_localadmins: Vec<serde_json::value::Value> = Vec::new();
    let mut localadmin_json = json!({
        "MemberId": "SID",
        "MemberType": "Type"
    });

    // Change all values...
    computer_json["Properties"]["domain"] = domain.to_uppercase().into();
    computer_json["Properties"]["distinguishedname"] = result_dn.into();
    let mut sid: String = "".to_owned();
    let mut group_id: String = "".to_owned();
    // With a check
    for (key, value) in &result_attrs {
        match key.as_str() {
            "name" => {
                let name = &result_attrs["name"][0];
                let mut email: String = name.to_owned();
                email.push_str(".");
                email.push_str(domain.as_str());
                computer_json["Properties"]["name"] = email.to_uppercase().into();
            }
            "sAMAccountName" => {
                let samaccountname = &result_attrs["sAMAccountName"][0];
                computer_json["Properties"]["samaccoutname"] = samaccountname.to_uppercase().into();
            }
            "dNSHostName" => {
                let name = &result_attrs["dNSHostName"][0];
                computer_json["Properties"]["name"] = name.to_uppercase().into();
            }
            "description" => {
                let description = &result_attrs["description"][0];
                computer_json["Properties"]["description"] = description.to_owned().into();
            }
            "operatingSystem" => {
                let operatingsystem = &result_attrs["operatingSystem"][0];
                computer_json["Properties"]["operatingsystem"] = operatingsystem.to_owned().into();
            }
            //"operatingSystemServicePack" => {
            //    //operatingsystem
            //    let mut operating_system_servicepack = "".to_owned();
            //    //if result_attrs["operatingSystem"].len() > 0 {
            //    //    operating_system_servicepack.push_str(&result_attrs["operatingSystem"][0]);
            //    //}
            //    //operating_system_servicepack.push_str(&" ");
            //   operating_system_servicepack.push_str(&result_attrs["operatingSystemServicePack"][0]);
            //    computer_json["Properties"]["operatingsystem"] = operating_system_servicepack.to_owned().into();
            //}
            "member" => {
                for member in &result_attrs["LocalAdmins"] {
                    localadmin_json["MemberId"] = member.to_owned().into();
                    vec_localadmins.push(localadmin_json.to_owned());
                }
                computer_json["Members"] = vec_localadmins.to_owned().into();
            }
            "lastLogonTimestamp" => {
                let lastlogontimestamp = &result_attrs["lastLogonTimestamp"][0]
                    .parse::<i64>()
                    .unwrap();
                if lastlogontimestamp.is_positive() {
                    let epoch = convert_timestamp(*lastlogontimestamp);
                    computer_json["Properties"]["lastlogontimestamp"] = epoch.into();
                }
            }
            "pwdLastSet" => {
                let pwdlastset = &result_attrs["pwdLastSet"][0].parse::<i64>().unwrap();
                if pwdlastset.is_positive() {
                    let epoch = convert_timestamp(*pwdlastset);
                    computer_json["Properties"]["pwdlastset"] = epoch.into();
                }
            }
            "whenCreated" => {
                let whencreated = &result_attrs["whenCreated"][0];
                let epoch = string_to_epoch(&whencreated);
                if epoch.is_positive() {
                    computer_json["Properties"]["whencreated"] = epoch.into();
                }
            }
            "servicePrincipalName" => {
                //servicePrincipalName and hasspn
                let mut result: Vec<String> = Vec::new();
                for value in &result_attrs["servicePrincipalName"] {
                    result.push(value.to_owned());
                }
                computer_json["Properties"]["serviceprincipalnames"] = result.to_owned().into();
            }
            "userAccountControl" => {
                //userAccountControl
                let uac = &result_attrs["userAccountControl"][0]
                    .parse::<u32>()
                    .unwrap();
                let uac_flags = get_flag(*uac);
                //trace!("UAC : {:?}",uac_flags);
                for flag in uac_flags {
                    if flag.contains("AccountDisable") {
                        let enabled = false;
                        computer_json["Properties"]["enabled"] = enabled.into();
                    };
                    //if flag.contains("Lockout") { let enabled = true; computer_json["Properties"]["enabled"] = enabled.into(); };

                    // https://beta.hackndo.com/constrained-unconstrained-delegation/#constrained--unconstrained-delegation
                    // https://beta.hackndo.com/unconstrained-delegation-attack/
                    if flag.contains("TrustedForDelegation") {
                        let trusted_for_delegation = true;
                        computer_json["Properties"]["unconstraineddelegation"] =
                            trusted_for_delegation.into();
                    };
                    if flag.contains("NotDelegated") {
                        let not_delegated = true;
                        computer_json["Properties"]["unconstraineddelegation"] =
                            not_delegated.into();
                    };
                    //if flag.contains("PasswordExpired") { let password_expired = true; computer_json["Properties"]["pwdneverexpires"] = password_expired.into(); };
                    if flag.contains("TrustedToAuthForDelegation") {
                        let trusted_to_auth_for_delegation = true;
                        computer_json["Properties"]["unconstraineddelegation"] =
                            trusted_to_auth_for_delegation.into();
                        computer_json["Properties"]["trustedtoauth"] = true.into();
                    };
                }
            }
            "msDS-AllowedToDelegateTo"  => {
                //trace!(" AllowToDelegateTo: {:?}",&value);
                computer_json["Properties"]["allowedtodelegate"] = value.to_owned().into();
                // AllowedToDelegate
                let mut vec_members: Vec<serde_json::value::Value> = Vec::new();
                let mut allowed_to_delegate = prepare_member_json_template();
                for objet in value {
                    let split = objet.split("/");
                    let fqdn = split.collect::<Vec<&str>>()[1];
                    let mut checker = false;
                    for member in &vec_members {
                        if member["ObjectIdentifier"].to_string().contains(fqdn.to_uppercase().as_str()) {
                            checker = true;
                        }
                    }
                    if !checker {
                        allowed_to_delegate["ObjectIdentifier"] = fqdn.to_uppercase().to_owned().to_uppercase().into();
                        allowed_to_delegate["ObjectType"] = "Computer".to_owned().into();
                        vec_members.push(allowed_to_delegate.to_owned()); 
                    }
                }
                computer_json["AllowedToDelegate"] = vec_members.to_owned().into();
            }
            "ms-Mcs-AdmPwd" => {
                //laps is set, random password for local adminsitrator
                // https://github.com/BloodHoundAD/SharpHound3/blob/7615860d963ba70751e1e5a00e02bb3fbca154c6/SharpHound3/Tasks/ACLTasks.cs#L313
                let laps = true;
                info!(
                    "Your user can read LAPS password on {}: {}",
                    &result_attrs["name"][0].yellow().bold(),
                    &result_attrs["ms-Mcs-AdmPwd"][0].yellow().bold()
                );
                computer_json["Properties"]["haslaps"] = laps.into();
            }
            "ms-Mcs-AdmPwdExpirationTime" => {
                //laps is set, random password for local adminsitrator
                let laps = true;
                computer_json["Properties"]["haslaps"] = laps.into();
            }
            "primaryGroupID" => {
                // primaryGroupID
                group_id = result_attrs["primaryGroupID"][0].to_owned();
            }
            _ => {}
        }
    }
    // For all, bins attributs
    for (key, value) in &result_bin {
        match key.as_str() {
            "objectSid" => {
                // objectSid raw to string
                sid = sid_maker(LdapSid::parse(&value[0]).unwrap().1, domain);
                computer_json["ObjectIdentifier"] = sid.to_owned().into();

                let re = Regex::new(r"^S-[0-9]{1}-[0-9]{1}-[0-9]{1,}-[0-9]{1,}-[0-9]{1,}-[0-9]{1,}").unwrap();
                for domain_sid in re.captures_iter(&sid) 
                {
                    computer_json["Properties"]["domainsid"] = domain_sid[0].to_owned().to_string().into();
                }
                
            }
            "nTSecurityDescriptor" => {
                // Needed with acl
                let entry_type = "computer".to_string();
                // nTSecurityDescriptor raw to string
                let relations_ace = parse_ntsecuritydescriptor(
                    &mut computer_json,
                    &value[0],
                    entry_type,
                    &result_attrs,
                    &result_bin,
                    &domain,
                );
                computer_json["Aces"] = relations_ace.into();
            }
            "msDS-AllowedToActOnBehalfOfOtherIdentity" => {
                // Needed with acl
                let entry_type = "computer".to_string();
                // msDS-AllowedToActOnBehalfOfOtherIdentity parsing ACEs
                let relations_ace = parse_ntsecuritydescriptor(
                    &mut computer_json,
                    &value[0],
                    entry_type,
                    &result_attrs,
                    &result_bin,
                    &domain,
                );
                let mut vec_members: Vec<serde_json::value::Value> = Vec::new();
                let mut allowed_to_act = prepare_member_json_template();
                for delegated in relations_ace {
                    //trace!("msDS-AllowedToActOnBehalfOfOtherIdentity => ACE: {:?}",delegated);
                    // delegated["RightName"] == "Owner" => continue
                    if delegated["RightName"] == "GenericAll" {
                        allowed_to_act["ObjectIdentifier"] = delegated["PrincipalSID"].as_str().unwrap().to_string().into();
                        vec_members.push(allowed_to_act.to_owned()); 
                        continue
                    }
                }
                computer_json["AllowedToAct"] = vec_members.into();
            }
            _ => {}
        }
    }
    // primaryGroupID if group_id is set
    #[allow(irrefutable_let_patterns)]
    if let id = group_id {
        let re = Regex::new(r"S-.*-").unwrap();
        let part1 = re.find(&sid).unwrap();
        let mut primary_group_id: String = "".to_owned();
        primary_group_id.push_str(&part1.as_str());
        primary_group_id.push_str(&id.as_str());
        computer_json["PrimaryGroupSID"] = primary_group_id.to_owned().into();
    }

    // Push DN and SID in HashMap
    dn_sid.insert(
        computer_json["Properties"]["distinguishedname"]
            .as_str()
            .unwrap()
            .to_string(),
        computer_json["ObjectIdentifier"]
            .as_str()
            .unwrap()
            .to_string(),
    );
    // Push DN and Type
    sid_type.insert(
        computer_json["ObjectIdentifier"]
            .as_str()
            .unwrap()
            .to_string(),
        "Computer".to_string(),
    );

    fqdn_sid.insert(
        computer_json["Properties"]["name"]
            .as_str()
            .unwrap()
            .to_string(),
        computer_json["ObjectIdentifier"]
            .as_str()
            .unwrap()
            .to_string(),
    );

    fqdn_ip.insert(
        computer_json["Properties"]["name"]
            .as_str()
            .unwrap()
            .to_string(),
        "".to_string(),
    );

    return computer_json;
}

/*****************************************
******************************************
4- Function to parse OUs information
******************************************
*****************************************/
/// Function to parse and replace value in json template for OU object.
/// <https://bloodhound.readthedocs.io/en/latest/further-reading/json.html#ous>
pub fn parse_ou(
    result: SearchEntry,
    domain: &String,
    dn_sid: &mut HashMap<String, String>,
    sid_type: &mut HashMap<String, String>,
) -> serde_json::value::Value {

    let result_dn: String;
    result_dn = result.dn.to_uppercase();

    let result_attrs: HashMap<String, Vec<String>>;
    result_attrs = result.attrs;

    let result_bin: HashMap<String, Vec<Vec<u8>>>;
    result_bin = result.bin_attrs;

    // Debug for current object
    debug!("Parse OU: {}", result_dn);
    //for (key, value) in &result_attrs {
    //    trace!("  {:?}:{:?}", key, value);
    //}
    ////trace result bin
    //for (key, value) in &result_bin {
    //    trace!("  {:?}:{:?}", key, value);
    //}

    // json template for one ou
    let mut ou_json = prepare_ou_json_template();

    ou_json["Properties"]["domain"] = domain.to_uppercase().into();
    ou_json["Properties"]["distinguishedname"] = result_dn.into();
    // Check and replace value
    for (key, _value) in &result_attrs {
        match key.as_str() {
            "name" => {
                let name = &result_attrs["name"][0];
                let mut email: String = name.to_owned();
                email.push_str("@");
                email.push_str(domain.as_str());
                ou_json["Properties"]["name"] = email.to_uppercase().into();
            }
            "description" => {
                let description = &result_attrs["description"][0];
                ou_json["Properties"]["description"] = description.to_owned().into();
            }
            "whenCreated" => {
                let whencreated = &result_attrs["whenCreated"][0];
                let epoch = string_to_epoch(&whencreated);
                if epoch.is_positive() {
                    ou_json["Properties"]["whencreated"] = epoch.into();
                }
            }
            "gPLink" => {
                ou_json["Links"] = parse_gplink(result_attrs["gPLink"][0].to_string()).into();
            }
            _ => {}
        }
    }

    // For all, bins attributs
    #[allow(unused_assignments)]
    let mut guid: String = "".to_owned();
    for (key, value) in &result_bin {
        match key.as_str() {
            "objectGUID" => {
                // objectGUID raw to string
                guid = decode_guid(&value[0]);
                ou_json["ObjectIdentifier"] = guid.to_owned().into();
            }
            "nTSecurityDescriptor" => {
                trace!("nTSecurityDescriptor ACES ACLS ?");
                // Needed with acl
                let entry_type = "ou".to_string();
                // nTSecurityDescriptor raw to string
                let relations_ace = parse_ntsecuritydescriptor(
                    &mut ou_json,
                    &value[0],
                    entry_type,
                    &result_attrs,
                    &result_bin,
                    &domain,
                );
                ou_json["Aces"] = relations_ace.into();
            }
            _ => {}
        }
    }
    // Push DN and SID in HashMap
    dn_sid.insert(
        ou_json["Properties"]["distinguishedname"]
            .as_str()
            .unwrap()
            .to_string(),
        ou_json["ObjectIdentifier"].as_str().unwrap().to_string(),
    );
    // Push DN and Type
    sid_type.insert(
        ou_json["ObjectIdentifier"].as_str().unwrap().to_string(),
        "OU".to_string(),
    );

    return ou_json;
}
/*****************************************
******************************************
5- Function to parse domains information
******************************************
*****************************************/
/// Function to parse and replace value in json template for domain object.
/// <https://bloodhound.readthedocs.io/en/latest/further-reading/json.html#domains>
pub fn parse_domain(
    result: SearchEntry,
    domain: &String,
    dn_sid: &mut HashMap<String, String>,
    sid_type: &mut HashMap<String, String>,
) -> serde_json::value::Value {

    let _result_dn: String;
    _result_dn = result.dn.to_uppercase();

    let result_attrs: HashMap<String, Vec<String>>;
    result_attrs = result.attrs;

    let result_bin: HashMap<String, Vec<Vec<u8>>>;
    result_bin = result.bin_attrs;

    // Debug for current object
    //debug!("Parse domain: {}", _result_dn);
    //for (key, value) in &result_attrs {
    //    trace!("  {:?}:{:?}", key, value);
    //}
    ////trace result bin
    //for (key, value) in &result_bin {
    //    trace!("  {:?}:{:?}", key, value);
    //}

    // json template for one domain
    let mut domain_json = prepare_domain_json_template();

    // Change all values...
    #[allow(unused_assignments)]
    let mut sid: String = "".to_owned();
    // With a check
    for (key, value) in &result_attrs {
        match key.as_str() {
            "distinguishedName" => {
                // name & domain & distinguishedname
                domain_json["Properties"]["distinguishedname"] = value[0].to_owned().to_uppercase().into();
                let split = value[0].split(",");
                let vec = split.collect::<Vec<&str>>();
                let first = vec[0].split("DC=");
                let vec1 = first.collect::<Vec<&str>>();
                let last = vec[1].split("DC=");
                let vec2 = last.collect::<Vec<&str>>();
                let mut name = "".to_string();
                name.push_str(vec1[1]);
                name.push_str(".");
                name.push_str(vec2[1]);
                domain_json["Properties"]["name"] = name.to_uppercase().into();
                domain_json["Properties"]["domain"] = name.to_uppercase().into();
            }
            "msDS-Behavior-Version" => {
                let level = get_forest_level(result_attrs["msDS-Behavior-Version"][0].to_string());
                domain_json["Properties"]["functionallevel"] = level.into();
            }
            "whenCreated" => {
                let whencreated = &result_attrs["whenCreated"][0];
                let epoch = string_to_epoch(&whencreated);
                if epoch.is_positive() {
                    domain_json["Properties"]["whencreated"] = epoch.into();
                }
            }
            "gPLink" => {
                domain_json["Links"] = parse_gplink(result_attrs["gPLink"][0].to_string()).into();
            }
            "isCriticalSystemObject" => {
                let mut iscriticalsystemobject = false;
                if result_attrs["isCriticalSystemObject"][0].contains("TRUE") {
                    iscriticalsystemobject = true;
                }
                domain_json["Properties"]["highvalue"] = iscriticalsystemobject.into();
            }
            // The number of computer accounts that a user is allowed to create in a domain.
            "ms-DS-MachineAccountQuota" => {
                let machine_account_quota = result_attrs["ms-DS-MachineAccountQuota"][0].parse::<i32>().unwrap_or(0);
                if machine_account_quota > 0 {
                    info!("MachineAccountQuota: {}",machine_account_quota.to_string().yellow().bold());
                }
            }
            _ => {}
        }
    }
    // For all, bins attributs
    for (key, value) in &result_bin {
        match key.as_str() {
            "objectSid" => {
                // objectSid raw to string
                sid = sid_maker(LdapSid::parse(&value[0]).unwrap().1, domain);
                domain_json["ObjectIdentifier"] = sid.to_owned().into();

                let re = Regex::new(r"^S-[0-9]{1}-[0-9]{1}-[0-9]{1,}-[0-9]{1,}-[0-9]{1,}-[0-9]{1,}").unwrap();
                for domain_sid in re.captures_iter(&sid) 
                {
                    domain_json["Properties"]["domainsid"] = domain_sid[0].to_owned().to_string().into();
                }
            }
            "nTSecurityDescriptor" => {
                // Needed with acl
                let entry_type = "domain".to_string();
                // nTSecurityDescriptor raw to string
                let relations_ace = parse_ntsecuritydescriptor(
                    &mut domain_json,
                    &value[0],
                    entry_type,
                    &result_attrs,
                    &result_bin,
                    &domain,
                );
                domain_json["Aces"] = relations_ace.into();
            }
            _ => {}
        }
    }

    // Push DN and SID in HashMap
    dn_sid.insert(
        domain_json["Properties"]["distinguishedname"]
            .as_str()
            .unwrap()
            .to_string(),
        domain_json["ObjectIdentifier"]
            .as_str()
            .unwrap()
            .to_string(),
    );
    // Push DN and Type
    sid_type.insert(
        domain_json["ObjectIdentifier"]
            .as_str()
            .unwrap()
            .to_string(),
        "Domain".to_string(),
    );

    return domain_json;
}
/*****************************************
******************************************
6- Function to parse GPOs values
******************************************
*****************************************/
/// Function to parse and replace value in json template for GPO object.
/// <https://bloodhound.readthedocs.io/en/latest/further-reading/json.html#gpos>
pub fn parse_gpo(
    result: SearchEntry,
    domain: &String,
    dn_sid: &mut HashMap<String, String>,
    sid_type: &mut HashMap<String, String>,
) -> serde_json::value::Value {

    let result_dn: String;
    result_dn = result.dn.to_uppercase();

    let result_attrs: HashMap<String, Vec<String>>;
    result_attrs = result.attrs;

    let result_bin: HashMap<String, Vec<Vec<u8>>>;
    result_bin = result.bin_attrs;

    // Debug for current object
    debug!("Parse gpo: {}", result_dn);
    //for (key, value) in &result_attrs {
    //    trace!("  {:?}:{:?}", key, value);
    //}
    ////trace result bin
    //for (key, value) in &result_bin {
    //    trace!("  {:?}:{:?}", key, value);
    //}

    // json template for one gpo
    let mut gpo_json = prepare_gpo_json_template();

    gpo_json["Properties"]["domain"] = domain.to_uppercase().into();
    gpo_json["Properties"]["distinguishedname"] = result_dn.into();    
    // Check and replace value
    for (key, _value) in &result_attrs {
        match key.as_str() {
            "displayName" => {
                let name = &result_attrs["displayName"][0].to_uppercase();
                let mut email: String = name.to_owned();
                email.push_str("@");
                email.push_str(domain.as_str());
                gpo_json["Properties"]["name"] = email.to_uppercase().into();
            }
            "description" => {
                let description = &result_attrs["description"][0];
                gpo_json["Properties"]["description"] = description.to_owned().into();
            }
            "whenCreated" => {
                let whencreated = &result_attrs["whenCreated"][0];
                let epoch = string_to_epoch(&whencreated);
                if epoch.is_positive() {
                    gpo_json["Properties"]["whencreated"] = epoch.into();
                }
            }
            "gPCFileSysPath" => {
                let gpcpath = &result_attrs["gPCFileSysPath"][0];
                gpo_json["Properties"]["gpcpath"] = gpcpath.to_owned().into();
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
                gpo_json["ObjectIdentifier"] = guid.to_owned().into();
            }
            "nTSecurityDescriptor" => {
                // Needed with acl
                let entry_type = "gpo".to_string();
                // nTSecurityDescriptor raw to string
                let relations_ace = parse_ntsecuritydescriptor(
                    &mut gpo_json,
                    &value[0],
                    entry_type,
                    &result_attrs,
                    &result_bin,
                    &domain,
                );
                gpo_json["Aces"] = relations_ace.into();
            }
            _ => {}
        }
    }

    // Push DN and SID in HashMap
    dn_sid.insert(
        gpo_json["Properties"]["distinguishedname"]
            .as_str()
            .unwrap()
            .to_string(),
        gpo_json["ObjectIdentifier"].as_str().unwrap().to_string(),
    );
    // Push DN and Type
    sid_type.insert(
        gpo_json["ObjectIdentifier"].as_str().unwrap().to_string(),
        "Gpo".to_string(),
    );

    return gpo_json;
}
/*****************************************
******************************************
7- Function to parse ForeignSecurityPrincipal
******************************************
*****************************************/
/// Function to parse and replace value in json template for ForeignSecurityPrincipal object.
pub fn parse_fsp(
    result: SearchEntry,
    domain: &String,
    dn_sid: &mut HashMap<String, String>,
    sid_type: &mut HashMap<String, String>,
) -> serde_json::value::Value {

    let result_dn: String;
    result_dn = result.dn.to_uppercase();

    let result_attrs: HashMap<String, Vec<String>>;
    result_attrs = result.attrs;

    let _result_bin: HashMap<String, Vec<Vec<u8>>>;
    _result_bin = result.bin_attrs;

    // Debug for current object
    debug!("Parse ForeignSecurityPrincipal: {}", result_dn);
    //for (key, value) in &result_attrs {
    //    trace!("  {:?}:{:?}", key, value);
    //}
    ////trace result bin
    //for (key, value) in &result_bin {
    //    trace!("  {:?}:{:?}", key, value);
    //}

    // json template for one fsp
    let mut fsp_json = prepare_fsp_json_template();

    fsp_json["Properties"]["distinguishedname"] = result_dn.into();
    #[allow(unused_assignments)]
    let mut sid: String = "".to_owned();
    // With a check
    for (key, _value) in &result_attrs {
        match key.as_str() {
            "name" => {
                let mut name = "".to_string();
                name.push_str(domain.as_str());
                name.push_str("-");
                name.push_str(&result_attrs["name"][0]);
                fsp_json["Properties"]["name"] = name.to_uppercase().into();

                // Type for group Member maker
                // based on https://docs.microsoft.com/fr-fr/troubleshoot/windows-server/identity/security-identifiers-in-windows
                let split = result_attrs["name"][0].split("-");
                let vec = split.collect::<Vec<&str>>();
                let len = vec.len();
                let last = vec[len - 1].parse::<i32>().unwrap_or(0);
                if last >= 17 {
                    fsp_json["Properties"]["type"] = "User".into();
                } else {
                    fsp_json["Properties"]["type"] = "Group".into();
                }
            }
            "whenCreated" => {
                let whencreated = &result_attrs["whenCreated"][0];
                let epoch = string_to_epoch(&whencreated);
                if epoch.is_positive() {
                    fsp_json["Properties"]["whencreated"] = epoch.into();
                }
            }
            "objectSid" => {
                //objectSid to vec and raw to string
                let vec_sid = objectsid_to_vec8(&result_attrs["objectSid"][0]);
                sid = sid_maker(LdapSid::parse(&vec_sid).unwrap().1, domain);
                fsp_json["ObjectIdentifier"] = sid.to_owned().into();

                let re = Regex::new(r"^S-[0-9]{1}-[0-9]{1}-[0-9]{1,}-[0-9]{1,}-[0-9]{1,}-[0-9]{1,}").unwrap();
                for domain_sid in re.captures_iter(&sid) 
                {
                    fsp_json["Properties"]["domainsid"] = domain_sid[0].to_owned().to_string().into();
                }
            }
            _ => {}
        }
    }

    // Push DN and SID in HashMap
    dn_sid.insert(
        fsp_json["Properties"]["distinguishedname"]
            .as_str()
            .unwrap()
            .to_string(),
        fsp_json["ObjectIdentifier"].as_str().unwrap().to_string(),
    );
    // Push DN and Type
    sid_type.insert(
        fsp_json["ObjectIdentifier"].as_str().unwrap().to_string(),
        fsp_json["Properties"]["type"].as_str().unwrap().to_string(),
    );

    return fsp_json;
}


/*****************************************
******************************************
8- Function to parse Container
******************************************
*****************************************/
/// Function to parse and replace value in json template for Container object.
pub fn parse_container(
    result: SearchEntry,
    domain: &String,
    dn_sid: &mut HashMap<String, String>,
    sid_type: &mut HashMap<String, String>,
) -> serde_json::value::Value {

    let result_dn: String;
    result_dn = result.dn.to_uppercase();

    let result_attrs: HashMap<String, Vec<String>>;
    result_attrs = result.attrs;

    let result_bin: HashMap<String, Vec<Vec<u8>>>;
    result_bin = result.bin_attrs;

    // Debug for current object
    debug!("Parse Container: {}", result_dn.to_uppercase());
    //for (key, value) in &result_attrs {
    //    trace!("  {:?}:{:?}", key, value);
    //}
    ////trace result bin
    //for (key, value) in &result_bin {
    //    trace!("  {:?}:{:?}", key, value);
    //}

    // json template for one container
    let mut container_json = prepare_container_json_template();

    container_json["Properties"]["domain"] = domain.to_owned().to_uppercase().into();
    container_json["Properties"]["distinguishedname"] = result_dn.into();
    // With a check
    for (key, _value) in &result_attrs {
        match key.as_str() {
            "name" => {
                let name = &result_attrs["name"][0].to_uppercase();
                let mut email: String = name.to_owned();
                email.push_str("@");
                email.push_str(domain.as_str());
                container_json["Properties"]["name"] = email.to_uppercase().into();
            }
            _ => {}
        }
    }
    // For all, bins attributs
    for (key, value) in &result_bin {
        match key.as_str() {
            "objectGUID" => {
                let guid = decode_guid(&value[0]);
                container_json["ObjectIdentifier"] = guid.to_owned().into();
            }
            "nTSecurityDescriptor" => {
                // Needed with acl
                let entry_type = "container".to_string();
                // nTSecurityDescriptor raw to string
                let relations_ace = parse_ntsecuritydescriptor(
                    &mut container_json,
                    &value[0],
                    entry_type,
                    &result_attrs,
                    &result_bin,
                    &domain,
                );
                container_json["Aces"] = relations_ace.into();
            }
            _ => {}
        }
    }

    // Push DN and SID in HashMap
    dn_sid.insert(
        container_json["Properties"]["distinguishedname"]
            .as_str()
            .unwrap()
            .to_string(),
        container_json["ObjectIdentifier"].as_str().unwrap().to_string(),
    );
    // Push DN and Type
    sid_type.insert(
        container_json["ObjectIdentifier"].as_str().unwrap().to_string(),
        "Container".to_string(),
    );

    return container_json;
}

/*****************************************
******************************************
9- Function to parse trust domain values
******************************************
*****************************************/
/// Function to parse and replace value in json template for trust domain object.
pub fn parse_trust(result: SearchEntry, domain: &String) -> serde_json::value::Value  {

    let result_dn: String;
    result_dn = result.dn.to_uppercase();

    let result_attrs: HashMap<String, Vec<String>>;
    result_attrs = result.attrs;

    let result_bin: HashMap<String, Vec<Vec<u8>>>;
    result_bin = result.bin_attrs;

    let mut trust_json = prepare_trust_json_template();

    // Debug for current object
    debug!("Parse TrustDomain: {}", result_dn);
    //for (key, value) in &result_attrs {
    //    trace!("  {:?}:{:?}", key, value);
    //}
    ////trace result bin
    //for (key, value) in &result_bin {
    //    trace!("  {:?}:{:?}", key, value);
    //}

    // With a check
    for (key, _value) in &result_attrs {
        match key.as_str() {
            "name" => {
                let name = &result_attrs["name"][0].to_uppercase();
                trust_json["TargetDomainName"] = name.to_uppercase().into();
            }
            "trustDirection" => {
                let trustdirection: u8 = result_attrs["trustDirection"][0].parse::<u8>().unwrap_or(0);
                // <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/5026a939-44ba-47b2-99cf-386a9e674b04>
                match trustdirection { 
                    1 => { trust_json["TrustDirection"] ="Inbound".into(); }
                    2 => { trust_json["TrustDirection"] = "Outbound".into(); }
                    3 => { trust_json["TrustDirection"] = "Bidirectional".into(); } 
                    _ => { trust_json["TrustDirection"] = "Disable".into(); }
                }
            }
            "trustAttributes" => {
                let trustflag: u32 = result_attrs["trustAttributes"][0].parse::<u32>().unwrap_or(0);
                get_trust_flag(trustflag, &mut trust_json);
            }
            _ => {}
        }
    }
    // For all, bins attributs
    for (key, value) in &result_bin {
        match key.as_str() {
            "securityIdentifier" => {
                let sid = sid_maker(LdapSid::parse(&value[0]).unwrap().1, domain);
                trust_json["TargetDomainSid"] = sid.to_owned().into();
            }
            _ => {}
        }
    }
    //trace!("TRUST VALUE: {:?}",trust_json);
    return trust_json
}

/*****************************************
******************************************
10- Function to parse unknown values
******************************************
*****************************************/
/// Function to parse and replace value in json template for unknown object.
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
    //debug!("Parse Unknown: {}", _result_dn);
    //for (key, value) in &_result_attrs {
    //    trace!("  {:?}:{:?}", key, value);
    //}
    ////trace result bin
    //for (key, value) in &_result_bin {
    //    trace!("  {:?}:{:?}", key, value);
    //}

    return unknown_json
}