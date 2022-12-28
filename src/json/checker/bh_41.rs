use std::collections::HashMap;
use regex::Regex;
//use log::{info,debug,trace};
use crate::json::templates::*;
use crate::ldap::prepare_ldap_dc;
use indicatif::ProgressBar;
use crate::banner::progress_bar;
use std::convert::TryInto;

/// Function to add default groups
/// <https://github.com/fox-it/BloodHound.py/blob/645082e3462c93f31b571db945cde1fd7b837fb9/bloodhound/enumeration/memberships.py#L411>
pub fn add_default_groups(vec_groups: &mut Vec<serde_json::value::Value>, vec_computers: &Vec<serde_json::value::Value>, domain: String)
{
    let mut domain_sid = "".to_owned();
    let mut template_json = bh_41::prepare_default_group_json_template();
    template_json["Properties"]["domain"] = domain.to_owned().to_uppercase().into();
    let mut template_member = bh_41::prepare_member_json_template();
    template_member["ObjectType"] = "Computer".into();

    // ENTERPRISE DOMAIN CONTROLLERS
    let mut edc_group = template_json.to_owned();
    let mut sid = domain.to_uppercase();
    sid.push_str("-S-1-5-9");

    let mut name = "ENTERPRISE DOMAIN CONTROLLERS@".to_owned();
    name.push_str(&domain.to_uppercase());

    let mut vec_members: Vec<serde_json::value::Value> = Vec::new();
    for computer in vec_computers {
        if computer["Properties"]["unconstraineddelegation"].as_bool().unwrap()
        {
            template_member["ObjectIdentifier"] = computer["ObjectIdentifier"].as_str().unwrap().to_string().into();
            vec_members.push(template_member.to_owned());
            let re = Regex::new(r"^S-[0-9]{1}-[0-9]{1}-[0-9]{1,}-[0-9]{1,}-[0-9]{1,}-[0-9]{1,}").unwrap();
            let mut sids: Vec<String> = Vec::new();
            for sid in re.captures_iter(&computer["ObjectIdentifier"].as_str().unwrap().to_string())
            {
                sids.push(sid[0].to_owned().to_string());
            }
            domain_sid = sids[0].to_string();
        }
    }

    edc_group["ObjectIdentifier"] = sid.into();
    edc_group["Properties"]["name"] = name.into();
    edc_group["Members"] = vec_members.into();
    vec_groups.push(edc_group);

    // ACCOUNT OPERATORS
    let mut account_operators_group = template_json.to_owned();
    sid = domain.to_uppercase();
    sid.push_str("-S-1-5-32-548");
    let mut name = "ACCOUNT OPERATORS@".to_owned();
    name.push_str(&domain.to_uppercase());
    
    account_operators_group["ObjectIdentifier"] = sid.into();
    account_operators_group["Properties"]["name"] = name.into();
    account_operators_group["Properties"]["highvalue"] = true.into();
    vec_groups.push(account_operators_group);

    // WINDOWS AUTHORIZATION ACCESS GROUP
    let mut waag_group = template_json.to_owned();
    sid = domain.to_uppercase();
    sid.push_str("-S-1-5-32-560");
    let mut name = "WINDOWS AUTHORIZATION ACCESS GROUP@".to_owned();
    name.push_str(&domain.to_uppercase());
            
    waag_group["ObjectIdentifier"] = sid.into();
    waag_group["Properties"]["name"] = name.into();
    vec_groups.push(waag_group);

    // EVERYONE
    let mut everyone_group = template_json.to_owned();
    sid = domain.to_uppercase();
    sid.push_str("-S-1-1-0");
    let mut name = "EVERYONE@".to_owned();
    name.push_str(&domain.to_uppercase());

    let mut vec_everyone_members: Vec<serde_json::value::Value> = Vec::new();
    let mut member_id = domain_sid.to_owned();
    member_id.push_str("-515");
    template_member["ObjectIdentifier"] = member_id.to_owned().into();
    template_member["ObjectType"] = "Group".into();
    vec_everyone_members.push(template_member.to_owned());

    member_id = domain_sid.to_owned();
    member_id.push_str("-513");
    template_member["ObjectIdentifier"] = member_id.to_owned().into();
    template_member["ObjectType"] = "Group".into();
    vec_everyone_members.push(template_member.to_owned());

    everyone_group["ObjectIdentifier"] = sid.into();
    everyone_group["Properties"]["name"] = name.into();
    everyone_group["Members"] = vec_everyone_members.into();
    vec_groups.push(everyone_group);

    // AUTHENTICATED USERS
    let mut auth_users_group = template_json.to_owned();
    sid = domain.to_uppercase();
    sid.push_str("-S-1-5-11");
    let mut name = "AUTHENTICATED USERS@".to_owned();
    name.push_str(&domain.to_uppercase());

    let mut vec_auth_users_members: Vec<serde_json::value::Value> = Vec::new();
    member_id = domain_sid.to_owned();
    member_id.push_str("-515");
    template_member["ObjectIdentifier"] = member_id.to_owned().into();
    template_member["ObjectType"] = "Group".into();
    vec_auth_users_members.push(template_member.to_owned());

    member_id = domain_sid.to_owned();
    member_id.push_str("-513");
    template_member["ObjectIdentifier"] = member_id.to_owned().into();
    template_member["ObjectType"] = "Group".into();
    vec_auth_users_members.push(template_member.to_owned());

    auth_users_group["ObjectIdentifier"] = sid.into();
    auth_users_group["Properties"]["name"] = name.into();
    auth_users_group["Members"] = vec_auth_users_members.into();
    vec_groups.push(auth_users_group);

    // ADMINISTRATORS
    let mut administrators_group = template_json.to_owned();
    sid = domain.to_uppercase();
    sid.push_str("-S-1-5-32-544");
    let mut name = "ADMINISTRATORS@".to_owned();
    name.push_str(&domain.to_uppercase());

    administrators_group["ObjectIdentifier"] = sid.into();
    administrators_group["Properties"]["name"] = name.into();
    administrators_group["Properties"]["highvalue"] = true.into();
    vec_groups.push(administrators_group);

    // PRE-WINDOWS 2000 COMPATIBLE ACCESS
    let mut pw2000ca_group = template_json.to_owned();
    sid = domain.to_uppercase();
    sid.push_str("-S-1-5-32-554");
    let mut name = "PRE-WINDOWS 2000 COMPATIBLE ACCESS@".to_owned();
    name.push_str(&domain.to_uppercase());
            
    pw2000ca_group["ObjectIdentifier"] = sid.into();
    pw2000ca_group["Properties"]["name"] = name.into();
    vec_groups.push(pw2000ca_group);    

    // INTERACTIVE
    let mut interactive_group = template_json.to_owned();
    sid = domain.to_uppercase();
    sid.push_str("-S-1-5-4");
    let mut name = "INTERACTIVE@".to_owned();
    name.push_str(&domain.to_uppercase());

    interactive_group["ObjectIdentifier"] = sid.into();
    interactive_group["Properties"]["name"] = name.into();
    vec_groups.push(interactive_group);

    // PRINT OPERATORS
    let mut print_operators_group = template_json.to_owned();
    sid = domain.to_uppercase();
    sid.push_str("-S-1-5-32-550");
    let mut name = "PRINT OPERATORS@".to_owned();
    name.push_str(&domain.to_uppercase());
            
    print_operators_group["ObjectIdentifier"] = sid.into();
    print_operators_group["Properties"]["name"] = name.into();
    print_operators_group["Properties"]["highvalue"] = true.into();
    vec_groups.push(print_operators_group); 

    // TERMINAL SERVER LICENSE SERVERS
    let mut tsls_group = template_json.to_owned();
    sid = domain.to_uppercase();
    sid.push_str("-S-1-5-32-561");
    let mut name = "TERMINAL SERVER LICENSE SERVERS@".to_owned();
    name.push_str(&domain.to_uppercase());
            
    tsls_group["ObjectIdentifier"] = sid.into();
    tsls_group["Properties"]["name"] = name.into();
    vec_groups.push(tsls_group); 

    // INCOMING FOREST TRUST BUILDERS
    let mut iftb_group = template_json.to_owned();
    sid = domain.to_uppercase();
    sid.push_str("-S-1-5-32-557");
    let mut name = "INCOMING FOREST TRUST BUILDERS@".to_owned();
    name.push_str(&domain.to_uppercase());
            
    iftb_group["ObjectIdentifier"] = sid.into();
    iftb_group["Properties"]["name"] = name.into();
    vec_groups.push(iftb_group); 
 
    // THIS ORGANIZATION 
    let mut this_organization_group = template_json.to_owned();
    sid = domain.to_uppercase();
    sid.push_str("-S-1-5-15");
    let mut name = "THIS ORGANIZATION@".to_owned();
    name.push_str(&domain.to_uppercase());
            
    this_organization_group["ObjectIdentifier"] = sid.into();
    this_organization_group["Properties"]["name"] = name.into();
    vec_groups.push(this_organization_group); 
}


/// Function to add default user
/// <https://github.com/fox-it/BloodHound.py/blob/645082e3462c93f31b571db945cde1fd7b837fb9/bloodhound/enumeration/memberships.py#L411>
pub fn add_default_users(vec_users: &mut Vec<serde_json::value::Value>, domain: String)
{
    let mut template_json = bh_41::prepare_default_user_json_template();
    template_json["Properties"]["domain"] = domain.to_owned().to_uppercase().into();

    // NT AUTHORITY
    let mut ntauthority_user = template_json.to_owned();
    let mut sid = domain.to_uppercase();
    sid.push_str("-S-1-5-20");
    let mut name = "NT AUTHORITY@".to_owned();
    name.push_str(&domain.to_uppercase());
    ntauthority_user["Properties"]["name"] = name.into();
    ntauthority_user["ObjectIdentifier"] = sid.into();
    ntauthority_user["Properties"]["domainsid"] = vec_users[0]["Properties"]["domainsid"].as_str().unwrap().to_string().into();

    vec_users.push(ntauthority_user);
}

/// This function is to push user SID in ChildObjects bh4.1+
pub fn add_childobjects_members(vec_replaced: &mut Vec<serde_json::value::Value>, dn_sid: &HashMap<String, String>,  sid_type: &HashMap<String, String>)
{
    // Needed for progress bar stats
    let pb = ProgressBar::new(1);
    let mut count = 0;
    let total = vec_replaced.len();
        
    //trace!("add_childobjects_members");

    for object in vec_replaced
    {
        // Manage progress bar
		count += 1;
        let pourcentage = 100 * count / total;
        progress_bar(pb.to_owned(),"Adding childobjects members".to_string(),pourcentage.try_into().unwrap(),"%".to_string());

        let mut direct_members: Vec<serde_json::value::Value> = Vec::new();
        let mut affected_computers: Vec<serde_json::value::Value> = Vec::new();

        let null: String = "NULL".to_string();
        let dn = object["Properties"]["distinguishedname"].as_str().unwrap().to_string().to_uppercase();
        let mut name = object["Properties"]["name"].as_str().unwrap().to_string();
        let sid = dn_sid.get(&object["Properties"]["distinguishedname"].as_str().unwrap().to_string()).unwrap_or(&null);
        let otype = sid_type.get(sid).unwrap();
        //trace!("SID OBJECT: {:?} : {:?} : {:?}",&dn,&sid,&otype);

        if otype != "Domain"
        {
            let split = name.split("@");
            let vec = split.collect::<Vec<&str>>();
            name = vec[0].to_owned();
        }

        for value in dn_sid 
        {
            let dn_object = value.0.to_string().to_uppercase();
            //trace!("{:?}", &dn_object);
            let split = dn_object.split(",");
            let vec = split.collect::<Vec<&str>>();
            let mut first = vec[1].to_owned();
            //trace!("{:?}", &first);
            let split = first.split("=");
            let vec = split.collect::<Vec<&str>>();
            if vec.len() >= 2 {
                //trace!("{:?}", &vec.len());
                first = vec[1].to_owned();
            }
            else
            {
                continue
            }
            //trace!("{:?}", &first);

            if otype != "Domain"{
                if (dn_object.contains(&dn)) && (&dn_object != &dn) && (&first == &name)
                {
                    let mut object = bh_41::prepare_member_json_template();
                    object["ObjectIdentifier"] = value.1.as_str().to_string().into();
                    let object_type = sid_type.get(&value.1.as_str().to_string()).unwrap();
                    object["ObjectType"] = object_type.to_string().into();
                    direct_members.push(object.to_owned());

                    // if the direct object is one computer add it in affected_computers to push it in OU 
                    if object_type.to_string() == "Computer" 
                    {
                        affected_computers.push(object.to_owned());
                    }
                }
            }
            else
            {
                let mut object = bh_41::prepare_member_json_template();                 
                let split = name.split(".");
                let vec = split.collect::<Vec<&str>>();
                let cn = vec[0].to_owned();
                if first.contains(&cn)
                {
                    object["ObjectIdentifier"] = value.1.as_str().to_string().into();
                    let object_type = sid_type.get(&value.1.as_str().to_string()).unwrap();
                    object["ObjectType"] = object_type.to_string().into();
                    direct_members.push(object);
                }
            }
        }
        //trace!("direct_members for Object '{}': {:?}",name,direct_members);
        
        object["ChildObjects"] = direct_members.into();
        if otype == "OU"
        {
            object["GPOChanges"]["AffectedComputers"] = affected_computers.into();
        }
    }
    pb.finish_and_clear();
}

/// This function check Guid for all Gplink to replace with correct guid
pub fn replace_guid_gplink(vec_replaced: &mut Vec<serde_json::value::Value>, dn_sid: &HashMap<String, String>)
{
    // Needed for progress bar stats
    let pb = ProgressBar::new(1);
    let mut count = 0;
    let total = vec_replaced.len();

    for i in 0..vec_replaced.len()
    {
        // Manage progress bar
		count += 1;
        let pourcentage = 100 * count / total;
        progress_bar(pb.to_owned(),"Replacing GUID for gplink".to_string(),pourcentage.try_into().unwrap(),"%".to_string());

        // ACE by ACE
        if vec_replaced[i]["Links"].as_array().unwrap().len() != 0 {
            for j in 0..vec_replaced[i]["Links"].as_array().unwrap().len()
            {
                for value in dn_sid 
                {
                  //trace!("{:?}",&vec_replaced[i]["Links"][j]["Guid"].as_str().unwrap().to_string());
                  if value.0.contains(&vec_replaced[i]["Links"][j]["GUID"].as_str().unwrap().to_string())
                  {
                        vec_replaced[i]["Links"][j]["GUID"] = value.1.to_owned().into();
                  }
                }
            }
        }   
    }
    pb.finish_and_clear();
}

/// This function will ad domainsid
pub fn add_domain_sid(
    vec_replaced: &mut Vec<serde_json::value::Value>, 
    dn_sid: &HashMap<String, String>)
{
    // Needed for progress bar stats
    let pb = ProgressBar::new(1);
    let mut count = 0;
    let total = vec_replaced.len();

    let mut domain_sid = "".to_owned();
    for value in dn_sid 
    {
        // Manage progress bar
		count += 1;
        let pourcentage = 100 * count / total;
        progress_bar(pb.to_owned(),"Getting domain SID".to_string(),pourcentage.try_into().unwrap(),"%".to_string());

        let sid = value.1.to_owned();
        let re = Regex::new(r"^S-[0-9]{1}-[0-9]{1}-[0-9]{1,}-[0-9]{1,}-[0-9]{1,}-[0-9]{1,}").unwrap();
        for value in re.captures_iter(&sid) 
        {
            domain_sid = value[0].to_owned().to_string();
            break
        }
        if domain_sid.len() > 0 {
            break
        }
    }
    pb.finish_and_clear();
    //trace!("domain_sid: {:?}",&domain_sid);

    // Needed for progress bar stats
    let pb = ProgressBar::new(1);
    let mut count = 0;
    let total = vec_replaced.len();
    
    for i in 0..vec_replaced.len()
    {
        // Manage progress bar
		count += 1;
        let pourcentage = 100 * count / total;
        progress_bar(pb.to_owned(),"Adding domain SID".to_string(),pourcentage.try_into().unwrap(),"%".to_string());

        //let name = vec_replaced[i]["Properties"]["name"].as_str().unwrap().to_string();
        //trace!("name: {:?}",&name);
        vec_replaced[i]["Properties"]["domainsid"] = domain_sid.to_owned().into();
    }
    pb.finish_and_clear();
}

/// This function push computer sid in domain GpoChanges
pub fn add_affected_computers(vec_domains: &mut Vec<serde_json::value::Value>, sid_type: &HashMap<String, String>)
{
    let mut vec_affected_computers: Vec<serde_json::value::Value> = Vec::new();

    for value in sid_type
    {
        if value.1 == "Computer"
        {
            let mut json_template_object = bh_41::prepare_member_json_template();
            json_template_object["ObjectType"] = "Computer".into();
            json_template_object["ObjectIdentifier"] = value.0.to_owned().to_string().into();
            vec_affected_computers.push(json_template_object);
        }
    }

    vec_domains[0]["GPOChanges"]["AffectedComputers"] = vec_affected_computers.into();
}

/// This function is to replace fqdn by sid in users SPNTargets:ComputerSID
pub fn replace_fqdn_by_sid(vec_src: &mut Vec<serde_json::value::Value>, fqdn_sid: &HashMap<String, String>) 
{
    // Needed for progress bar stats
    let pb = ProgressBar::new(1);
    let mut count = 0;
    let total = vec_src.len();

    for i in 0..vec_src.len()
    {
        // Manage progress bar
		count += 1;
        let pourcentage = 100 * count / total;
        progress_bar(pb.to_owned(),"Replacing FQDN by SID".to_string(),pourcentage.try_into().unwrap(),"%".to_string());

        if vec_src[i]["SPNTargets"].as_array().unwrap_or(&Vec::new()).len() != 0 {
            for j in 0..vec_src[i]["SPNTargets"].as_array().unwrap().len()
            {
               let default = &vec_src[i]["SPNTargets"][j]["ComputerSID"].as_str().unwrap().to_string();
               let sid = fqdn_sid.get(&vec_src[i]["SPNTargets"][j]["ComputerSID"].as_str().unwrap().to_string()).unwrap_or(default);
               //trace!("SPNTargets: {} = {}",&vec_users[i]["SPNTargets"][j]["ComputerSID"].to_string(),&sid);
               vec_src[i]["SPNTargets"][j]["ComputerSID"] = sid.to_owned().into();
            }
        }
        if vec_src[i]["AllowedToDelegate"].as_array().unwrap_or(&Vec::new()).len() != 0 {
            for j in 0..vec_src[i]["AllowedToDelegate"].as_array().unwrap().len()
            {
               let default = &vec_src[i]["AllowedToDelegate"][j]["ObjectIdentifier"].as_str().unwrap().to_string();
               let sid = fqdn_sid.get(&vec_src[i]["AllowedToDelegate"][j]["ObjectIdentifier"].as_str().unwrap().to_string()).unwrap_or(default);
               //trace!("AllowedToDelegate: {} = {}",&vec_users[i]["AllowedToDelegate"][j]["ObjectIdentifier"].to_string(),&sid);
               vec_src[i]["AllowedToDelegate"][j]["ObjectIdentifier"] = sid.to_owned().into();
            }
        }
    }
    pb.finish_and_clear();
}

/// This function is to check and replace object name by SID in group members.
pub fn replace_sid_members(vec_groups: &mut Vec<serde_json::value::Value>, dn_sid: &HashMap<String, String>, sid_type: &HashMap<String, String>, vec_trusts: &Vec<serde_json::value::Value>)
{
    // Needed for progress bar stats
    let pb = ProgressBar::new(1);
    let mut count = 0;
    let total = vec_groups.len();

    // GROUP by GROUP
    for i in 0..vec_groups.len()
    {
        // Manage progress bar
		count += 1;
        let pourcentage = 100 * count / total;
        progress_bar(pb.to_owned(),"Replacing SID for groups".to_string(),pourcentage.try_into().unwrap(),"%".to_string());

        // MEMBER by MEMBER
        if vec_groups[i]["Members"].as_array().unwrap().len() != 0 {
            for j in 0..vec_groups[i]["Members"].as_array().unwrap().len()
            {
                let null: String = "NULL".to_string();
                let sid = dn_sid.get(&vec_groups[i]["Members"][j]["ObjectIdentifier"].as_str().unwrap().to_string()).unwrap_or(&null);
                if sid.contains("NULL"){
                    let dn = &vec_groups[i]["Members"][j]["ObjectIdentifier"].as_str().unwrap().to_string();
                    // Check if DN match trust domain to get SID and Type
                    let sid = sid_maker_from_another_domain(vec_trusts, dn);
                    let type_object = "Group".to_string();
                    vec_groups[i]["Members"][j]["ObjectIdentifier"] = sid.to_owned().into();
                    vec_groups[i]["Members"][j]["ObjectType"] = type_object.to_owned().into();
                }
                else
                {
                    let type_object = sid_type.get(sid).unwrap_or(&null);
                    vec_groups[i]["Members"][j]["ObjectIdentifier"] = sid.to_owned().into();
                    vec_groups[i]["Members"][j]["ObjectType"] = type_object.to_owned().into();
                }

            }
        }
    }
    pb.finish_and_clear();
}
// Make the SID from domain present in trust
fn sid_maker_from_another_domain(vec_trusts: &Vec<serde_json::value::Value>, object_identifier: &String) -> String
{
    for i in 0..vec_trusts.len() {
        let ldap_dc = prepare_ldap_dc(&vec_trusts[i]["TargetDomainName"].as_str().unwrap().to_string(),false);
        //trace!("LDAP_DC TRUSTED {:?}: {:?}", &i,&vec_trusts[i]);
        if object_identifier.contains(ldap_dc[0].as_str())
        {
            //trace!("object_identifier '{}' contains trust domain '{}'",&object_identifier, &ldap_dc);
            let id = get_id_from_objectidentifier(object_identifier);
            let sid = vec_trusts[i]["TargetDomainSid"].as_str().unwrap().to_string() + id.as_str();
            return sid
        }
    }
    if object_identifier.contains("CN=S-") {
        let re = Regex::new(r"S-[0-9]{1}-[0-9]{1}-[0-9]{1,}-[0-9]{1,}-[0-9]{1,}-[0-9]{1,}-[0-9]{1,}").unwrap();
        for sid in re.captures_iter(&object_identifier) 
        {
            return sid[0].to_owned().to_string();
        }
    }
    return object_identifier.to_string()
}

// Get id from objectidentifier for all common group (Administrators ...)
// https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
fn get_id_from_objectidentifier(object_identifier: &String) -> String
{
    // Hashmap to link GROUP NAME to RID
    let mut name_to_rid = HashMap::new();
    name_to_rid.insert("DOMAIN ADMINS".to_string(), "-512".to_string());
    name_to_rid.insert("ADMINISTRATEURS DU DOMAINE".to_string(), "-512".to_string());
    name_to_rid.insert("DOMAIN USERS".to_string(), "-513".to_string());
    name_to_rid.insert("UTILISATEURS DU DOMAINE".to_string(), "-513".to_string());
    name_to_rid.insert("DOMAIN GUESTS".to_string(), "-514".to_string());
    name_to_rid.insert("INVITES DE DOMAINE".to_string(), "-514".to_string());
    name_to_rid.insert("DOMAIN COMPUTERS".to_string(), "-515".to_string());
    name_to_rid.insert("ORDINATEURS DE DOMAINE".to_string(), "-515".to_string());
    name_to_rid.insert("DOMAIN CONTROLLERS".to_string(), "-516".to_string());
    name_to_rid.insert("CONTRÔLEURS DE DOMAINE".to_string(), "-516".to_string());
    name_to_rid.insert("CERT PUBLISHERS".to_string(), "-517".to_string());
    name_to_rid.insert("EDITEURS DE CERTIFICATS".to_string(), "-517".to_string());
    name_to_rid.insert("SCHEMA ADMINS".to_string(), "-518".to_string());
    name_to_rid.insert("ADMINISTRATEURS DU SCHEMA".to_string(), "-518".to_string());
    name_to_rid.insert("ENTERPRISE ADMINS".to_string(), "-519".to_string());
    name_to_rid.insert("ADMINISTRATEURS DE L'ENTREPRISE".to_string(), "-519".to_string());

    for value in name_to_rid {
        if object_identifier.contains(value.0.as_str())
        {
            //trace!("name_to_rid: {:?}", value);
            return value.1.to_string()
        }
    }
    return "NULL_ID1".to_string()
}

/// This function push trust domain values in domain
pub fn add_trustdomain(vec_domains: &mut Vec<serde_json::value::Value>, vec_trusts: &mut Vec<serde_json::value::Value>)
{
    if !&vec_trusts[0]["TargetDomainSid"].to_string().contains("SID") {
        let mut trusts: Vec<serde_json::value::Value> = Vec::new();
        for trust in vec_trusts {
            trusts.push(trust.to_owned());
        }
        vec_domains[0]["Trusts"] = trusts.to_owned().into();
    }
}