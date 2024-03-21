use std::collections::HashMap;
use regex::Regex;
use crate::enums::ldaptype::*;
use crate::objects::{
    user::User,
    computer::Computer,
    group::Group,
    ou::Ou,
    domain::Domain,
    trust::Trust,
    common::{Member,GPOChange,LdapObject}
};
//use log::{info,debug,trace};
use crate::ldap::prepare_ldap_dc;
use indicatif::ProgressBar;
use crate::banner::progress_bar;
use std::convert::TryInto;

/// Function to add default groups
/// <https://github.com/fox-it/BloodHound.py/blob/645082e3462c93f31b571db945cde1fd7b837fb9/bloodhound/enumeration/memberships.py#L411>
pub fn add_default_groups(vec_groups: &mut Vec<Group>, vec_computers: &Vec<Computer>, domain: String)
{
    let mut domain_sid = "".to_owned();
    let mut template_member = Member::new();
    *template_member.object_type_mut() = "Computer".to_string();

    // ENTERPRISE DOMAIN CONTROLLERS
    let mut edc_group = Group::new();
    let mut sid = domain.to_uppercase();
    sid.push_str("-S-1-5-9");

    let mut name = "ENTERPRISE DOMAIN CONTROLLERS@".to_owned();
    name.push_str(&domain.to_uppercase());

    let mut vec_members: Vec<Member> = Vec::new();
    for computer in vec_computers {
        if computer.properties().unconstraineddelegation().to_owned()
        {
            *template_member.object_identifier_mut() = computer.object_identifier().to_string();
            vec_members.push(template_member.to_owned());
            let re = Regex::new(r"^S-[0-9]{1}-[0-9]{1}-[0-9]{1,}-[0-9]{1,}-[0-9]{1,}-[0-9]{1,}").unwrap();
            let mut sids: Vec<String> = Vec::new();
            for sid in re.captures_iter(&computer.object_identifier().to_string())
            {
                sids.push(sid[0].to_owned().to_string());
            }
            domain_sid = sids[0].to_string();
        }
    }

    *edc_group.object_identifier_mut() = sid;
    *edc_group.properties_mut().name_mut() = name;
    *edc_group.members_mut() = vec_members;
    vec_groups.push(edc_group);

    // ACCOUNT OPERATORS
    let mut account_operators_group = Group::new();
    sid = domain.to_uppercase();
    sid.push_str("-S-1-5-32-548");
    let mut name = "ACCOUNT OPERATORS@".to_owned();
    name.push_str(&domain.to_uppercase());
    
    *account_operators_group.object_identifier_mut() = sid;
    *account_operators_group.properties_mut().name_mut() = name;
    *account_operators_group.properties_mut().highvalue_mut() = true;
    vec_groups.push(account_operators_group);

    // WINDOWS AUTHORIZATION ACCESS GROUP
    let mut waag_group = Group::new();
    sid = domain.to_uppercase();
    sid.push_str("-S-1-5-32-560");
    let mut name = "WINDOWS AUTHORIZATION ACCESS GROUP@".to_owned();
    name.push_str(&domain.to_uppercase());
    *waag_group.object_identifier_mut() = sid;
    *waag_group.properties_mut().name_mut() = name;
    vec_groups.push(waag_group);

    // EVERYONE
    let mut everyone_group = Group::new();
    sid = domain.to_uppercase();
    sid.push_str("-S-1-1-0");
    let mut name = "EVERYONE@".to_owned();
    name.push_str(&domain.to_uppercase());

    let mut vec_everyone_members: Vec<Member> = Vec::new();
    let mut member_id = domain_sid.to_owned();
    member_id.push_str("-515");
    *template_member.object_identifier_mut() = member_id.to_owned();
    *template_member.object_type_mut() = "Group".to_string();
    vec_everyone_members.push(template_member.to_owned());

    member_id = domain_sid.to_owned();
    member_id.push_str("-513");
    *template_member.object_identifier_mut() = member_id.to_owned();
    *template_member.object_type_mut() = "Group".to_string();
    vec_everyone_members.push(template_member.to_owned());

    *everyone_group.object_identifier_mut() = sid;
    *everyone_group.properties_mut().name_mut() = name;
    *everyone_group.members_mut() = vec_everyone_members;
    vec_groups.push(everyone_group);

    // AUTHENTICATED USERS
    let mut auth_users_group = Group::new();
    sid = domain.to_uppercase();
    sid.push_str("-S-1-5-11");
    let mut name = "AUTHENTICATED USERS@".to_owned();
    name.push_str(&domain.to_uppercase());

    let mut vec_auth_users_members: Vec<Member> = Vec::new();
    member_id = domain_sid.to_owned();
    member_id.push_str("-515");
    *template_member.object_identifier_mut() = member_id.to_owned();
    *template_member.object_type_mut() = "Group".to_string();
    vec_auth_users_members.push(template_member.to_owned());

    member_id = domain_sid.to_owned();
    member_id.push_str("-513");
    *template_member.object_identifier_mut() = member_id.to_owned();
    *template_member.object_type_mut() = "Group".to_string();
    vec_auth_users_members.push(template_member.to_owned());

    *auth_users_group.object_identifier_mut() = sid;
    *auth_users_group.properties_mut().name_mut() = name;
    *auth_users_group.members_mut() = vec_auth_users_members;
    vec_groups.push(auth_users_group);

    // ADMINISTRATORS
    let mut administrators_group = Group::new();
    sid = domain.to_uppercase();
    sid.push_str("-S-1-5-32-544");
    let mut name = "ADMINISTRATORS@".to_owned();
    name.push_str(&domain.to_uppercase());

    *administrators_group.object_identifier_mut() = sid;
    *administrators_group.properties_mut().name_mut() = name;
    *administrators_group.properties_mut().highvalue_mut() = true;
    vec_groups.push(administrators_group);

    // PRE-WINDOWS 2000 COMPATIBLE ACCESS
    let mut pw2000ca_group = Group::new();
    sid = domain.to_uppercase();
    sid.push_str("-S-1-5-32-554");
    let mut name = "PRE-WINDOWS 2000 COMPATIBLE ACCESS@".to_owned();
    name.push_str(&domain.to_uppercase());
            
    *pw2000ca_group.object_identifier_mut() = sid;
    *pw2000ca_group.properties_mut().name_mut() = name;
    vec_groups.push(pw2000ca_group);    

    // INTERACTIVE
    let mut interactive_group = Group::new();
    sid = domain.to_uppercase();
    sid.push_str("-S-1-5-4");
    let mut name = "INTERACTIVE@".to_owned();
    name.push_str(&domain.to_uppercase());

    *interactive_group.object_identifier_mut() = sid;
    *interactive_group.properties_mut().name_mut() = name;
    vec_groups.push(interactive_group);

    // PRINT OPERATORS
    let mut print_operators_group = Group::new();
    sid = domain.to_uppercase();
    sid.push_str("-S-1-5-32-550");
    let mut name = "PRINT OPERATORS@".to_owned();
    name.push_str(&domain.to_uppercase());
            
    *print_operators_group.object_identifier_mut() = sid;
    *print_operators_group.properties_mut().name_mut() = name;
    *print_operators_group.properties_mut().highvalue_mut() = true;
    vec_groups.push(print_operators_group); 

    // TERMINAL SERVER LICENSE SERVERS
    let mut tsls_group = Group::new();
    sid = domain.to_uppercase();
    sid.push_str("-S-1-5-32-561");
    let mut name = "TERMINAL SERVER LICENSE SERVERS@".to_owned();
    name.push_str(&domain.to_uppercase());
            
    *tsls_group.object_identifier_mut() = sid;
    *tsls_group.properties_mut().name_mut() = name;
    vec_groups.push(tsls_group); 

    // INCOMING FOREST TRUST BUILDERS
    let mut iftb_group = Group::new();
    sid = domain.to_uppercase();
    sid.push_str("-S-1-5-32-557");
    let mut name = "INCOMING FOREST TRUST BUILDERS@".to_owned();
    name.push_str(&domain.to_uppercase());
            
    *iftb_group.object_identifier_mut() = sid;
    *iftb_group.properties_mut().name_mut() = name;
    vec_groups.push(iftb_group); 
 
    // THIS ORGANIZATION 
    let mut this_organization_group = Group::new();
    sid = domain.to_uppercase();
    sid.push_str("-S-1-5-15");
    let mut name = "THIS ORGANIZATION@".to_owned();
    name.push_str(&domain.to_uppercase());
            
    *this_organization_group.object_identifier_mut() = sid;
    *this_organization_group.properties_mut().name_mut() = name;
    vec_groups.push(this_organization_group); 
}


/// Function to add default user
/// <https://github.com/fox-it/BloodHound.py/blob/645082e3462c93f31b571db945cde1fd7b837fb9/bloodhound/enumeration/memberships.py#L411>
pub fn add_default_users(vec_users: &mut Vec<User>, domain: String)
{
    // NT AUTHORITY
    let mut ntauthority_user = User::new();
    let mut sid = domain.to_uppercase();
    sid.push_str("-S-1-5-20");
    let mut name = "NT AUTHORITY@".to_owned();
    name.push_str(&domain.to_uppercase());
    *ntauthority_user.properties_mut().name_mut() = name;
    *ntauthority_user.object_identifier_mut() = sid;
    *ntauthority_user.properties_mut().domainsid_mut() = vec_users[0].properties().domainsid().to_string();
    vec_users.push(ntauthority_user);
}



/// This function is to push user SID in ChildObjects
pub fn add_childobjects_members<T: LdapObject>(
    vec_replaced: &mut Vec<T>,
    dn_sid: &HashMap<String, String>,
    sid_type: &HashMap<String, String>
) {
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

        let mut direct_members: Vec<Member> = Vec::new();
        let null: String = "NULL".to_string();
        let sid = object.get_object_identifier().to_string().to_uppercase();
        let dn = dn_sid.iter().find(|(_, v)| **v == sid).map(|(k, _)| k).unwrap_or(&null);
        let name = get_name_from_full_distinguishedname(dn);
        let _otype = sid_type.get(&sid).unwrap();
        //trace!("SID OBJECT: {:?} : {:?} : {:?}",&dn,&sid,&otype);

        for value in dn_sid 
        {
            let dn_object = value.0.to_string().to_uppercase();
            //trace!("{:?}", &dn_object);
            let split = dn_object.split(",");
            let vec = split.collect::<Vec<&str>>();
            //trace!("{:?}", &first);
            if vec.len() >= 2 {
                let mut first = vec.get(1).unwrap_or(&"").to_string();
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
                if (dn_object.contains(dn)) && (&dn_object != dn) && (&first == &name)
                {
                    let mut member = Member::new();
                    *member.object_identifier_mut() = value.1.as_str().to_string();
                    let object_type = sid_type.get(&value.1.as_str().to_string()).unwrap_or(&null);
                    *member.object_type_mut() = object_type.to_string();
                    if !member.object_identifier().is_empty() {
                        direct_members.push(member.to_owned());
                    }
                }
            }


        }
        //trace!("direct_members for Object '{}': {:?}",name,direct_members);
        object.set_child_objects(direct_members);
    }
    pb.finish_and_clear();
}

/// This function is to push user SID in ChildObjects for Ou
pub fn add_childobjects_members_for_ou(
    vec_replaced: &mut Vec<Ou>,
    dn_sid: &HashMap<String, String>, 
    sid_type: &HashMap<String, String>
) {
    // Needed for progress bar stats
    let pb = ProgressBar::new(1);
    let mut count = 0;
    let total = vec_replaced.len();
        
    //trace!("add_childobjects_members_for_ous");

    for object in vec_replaced
    {
        // Manage progress bar
		count += 1;
        let pourcentage = 100 * count / total;
        progress_bar(pb.to_owned(),"Adding childobjects members".to_string(),pourcentage.try_into().unwrap(),"%".to_string());

        let mut direct_members: Vec<Member> = Vec::new();
        let mut affected_computers: Vec<Member> = Vec::new();

        let null: String = "NULL".to_string();
        let dn = object.properties().distinguishedname();
        let mut name = object.properties().name().to_string().to_owned();
        let sid = dn_sid.get(dn).unwrap_or(&null);
        let otype = sid_type.get(sid).unwrap_or(&null);
        //trace!("SID OBJECT: {:?} : {:?} : {:?}",&dn,&sid,&otype);

        if otype != "Domain"
        {
            let split = name.split("@");
            let vec = split.collect::<Vec<&str>>();
            name = vec[0].to_string();
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
                if (dn_object.contains(dn)) && (&dn_object != dn) && (first == name.to_string())
                {
                    let mut object = Member::new();
                    *object.object_identifier_mut() = value.1.as_str().to_string();
                    let object_type = sid_type.get(&value.1.as_str().to_string()).unwrap();
                    *object.object_type_mut() = object_type.to_string();
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
                let mut object = Member::new();                 
                let split = name.split(".");
                let vec = split.collect::<Vec<&str>>();
                let cn = vec[0].to_owned();
                if first.contains(&cn)
                {
                    *object.object_identifier_mut() = value.1.as_str().to_string();
                    let object_type = sid_type.get(&value.1.as_str().to_string()).unwrap();
                    *object.object_type_mut() = object_type.to_string();
                    direct_members.push(object);
                }
            }
        }
        //trace!("direct_members for Object '{}': {:?}",name,direct_members);
        
        *object.child_objects_mut() = direct_members;
        if otype == "OU"
        {
            let mut gpo_changes = GPOChange::new();
            *gpo_changes.affected_computers_mut() = affected_computers;
            *object.gpo_changes_mut() = gpo_changes;
        }
    }
    pb.finish_and_clear();
}

/// This function check Guid for all Gplink to replace with correct guid
pub fn replace_guid_gplink<T: LdapObject>(
    vec_replaced: &mut Vec<T>,
    dn_sid: &HashMap<String, String>
) {
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
        if vec_replaced[i].get_links().len() != 0 {
            for j in 0..vec_replaced[i].get_links().len()
            {
                for value in dn_sid 
                {
                    if value.0.contains(&vec_replaced[i].get_links()[j].guid().to_string())
                    {
                        let mut links = vec_replaced[i].get_links().to_owned();
                        *links[j].guid_mut() = value.1.to_owned();
                        vec_replaced[i].set_links(links);
                    }
                }
            }
        }   
    }
    pb.finish_and_clear();
}

/// This function push computer sid in domain GpoChanges
pub fn add_affected_computers(
    vec_domains: &mut Vec<Domain>,
    sid_type: &HashMap<String, String>
) {
    let mut vec_affected_computers: Vec<Member> = Vec::new();

    for value in sid_type
    {
        if value.1 == "Computer"
        {
            let mut json_template_object = Member::new();
            *json_template_object.object_type_mut() = "Computer".to_string();
            *json_template_object.object_identifier_mut() = value.0.to_owned().to_string();
            vec_affected_computers.push(json_template_object);
        }
    }
    let mut gpo_changes = GPOChange::new();
    *gpo_changes.affected_computers_mut() = vec_affected_computers;
    *vec_domains[0].gpo_changes_mut() = gpo_changes;
}


/// This function push computer sid in domain GpoChanges
pub fn add_affected_computers_for_ou(
    vec_ous: &mut Vec<Ou>,
    dn_sid: &HashMap<String, String>, 
    sid_type: &HashMap<String, String>
) {
    // All computers DN:SID
    let dn_sid_filtered = return_sid_dn_for_one_specific_type(&"Computer".to_string(), dn_sid, sid_type);
    
    // For OU by OU add affected computers
    for ou in vec_ous {
        let ou_dn: Option<String> = dn_sid.iter().find_map(|(key, value)| {
            if *value == ou.get_object_identifier().to_owned() {
                Some(key.clone())
            } else {
                None
            }
        });
        if let Some(ou_dn) = &ou_dn {
            let mut vec_affected_computers: Vec<Member> = Vec::new();
            for (dn, sid) in dn_sid_filtered.iter() {
                if get_contained_by_name_from_distinguishedname(&get_cn_object_name_from_full_distinguishedname(&dn), &dn) == ou_dn.to_owned() {
                    let mut member = Member::new();
                    *member.object_identifier_mut() = sid.to_owned();
                    *member.object_type_mut() = "Computer".to_owned();
                    vec_affected_computers.push(member);
                }
            }
            
            let mut gpo_changes = GPOChange::new();
            *gpo_changes.affected_computers_mut() = vec_affected_computers;
            *ou.gpo_changes_mut() = gpo_changes;
        }
    }
}


/// This function is to replace fqdn by sid in users SPNTargets:ComputerSID
pub fn replace_fqdn_by_sid<T: LdapObject>(
    object_type: Type,
    vec_src: &mut Vec<T>,
    fqdn_sid: &HashMap<String, String>
) {
    // Needed for progress bar stats
    let pb = ProgressBar::new(1);
    let mut count = 0;
    let total = vec_src.len();

    match object_type {
        Type::User => {
            for i in 0..vec_src.len()
            {
                // Manage progress bar
                count += 1;
                let pourcentage = 100 * count / total;
                progress_bar(pb.to_owned(),"Replacing FQDN by SID".to_string(),pourcentage.try_into().unwrap(),"%".to_string());
        
                let spn_targets_len = vec_src[i].get_spntargets().len();
                if spn_targets_len.to_owned() != 0 {
                    for j in 0..spn_targets_len.to_owned()
                    {
                        let default = &vec_src[i].get_spntargets()[j].computer_sid().to_string();
                        let sid = fqdn_sid.get(&vec_src[i].get_spntargets()[j].computer_sid().to_string()).unwrap_or(default);
                        let mut spn_targets = vec_src[i].get_spntargets().clone();
                        *spn_targets[j].computer_sid_mut() = sid.to_owned();
                        vec_src[i].set_spntargets(spn_targets);
        
                    }
                }
            }
        }
        Type::Computer => {
            for i in 0..vec_src.len()
            {
                // Manage progress bar
                count += 1;
                let pourcentage = 100 * count / total;
                progress_bar(pb.to_owned(),"Replacing FQDN by SID".to_string(),pourcentage.try_into().unwrap(),"%".to_string());
        
                let allowed_to_delegate_len = vec_src[i].get_allowed_to_delegate().len();
                if allowed_to_delegate_len.to_owned() != 0 {
                    for j in 0..allowed_to_delegate_len.to_owned()
                    {
                       let default = &vec_src[i].get_allowed_to_delegate()[j].object_identifier().to_string();
                       let sid = fqdn_sid.get(&vec_src[i].get_allowed_to_delegate()[j].object_identifier().to_string()).unwrap_or(default);
                       let mut allowed_to_delegate = vec_src[i].get_allowed_to_delegate().clone();
                       *allowed_to_delegate[j].object_identifier_mut() = sid.to_owned();
                       vec_src[i].set_allowed_to_delegate(allowed_to_delegate);
                    }
                }
            }
        }
        _ => { }
    }

    pb.finish_and_clear();
}

/// This function is to check and replace object name by SID in group members.
pub fn replace_sid_members(
    vec_groups: &mut Vec<Group>,
    dn_sid: &HashMap<String, String>,
    sid_type: &HashMap<String, String>,
    vec_trusts: &Vec<Trust>
) {
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

        let members_len = vec_groups[i].members().len();
        // MEMBER by MEMBER
        if members_len.to_owned() != 0 {
            for j in 0..members_len.to_owned()
            {
                let null: String = "NULL".to_string();
                let sid = dn_sid.get(&vec_groups[i].members()[j].object_identifier().to_string()).unwrap_or(&null);
                if sid.contains("NULL"){
                    let dn = &vec_groups[i].members()[j].object_identifier().to_string();
                    // Check if DN match trust domain to get SID and Type
                    let sid = sid_maker_from_another_domain(vec_trusts, &dn);
                    let type_object = "Group".to_string();
                    *vec_groups[i].members_mut()[j].object_identifier_mut() = sid.to_owned();
                    *vec_groups[i].members_mut()[j].object_type_mut() = type_object.to_owned();
                }
                else
                {
                    let default: String = "Group".to_string();
                    let type_object = sid_type.get(sid).unwrap_or(&default);
                    *vec_groups[i].members_mut()[j].object_identifier_mut() = sid.to_owned();
                    *vec_groups[i].members_mut()[j].object_type_mut() = type_object.to_owned();
                }

            }
        }
    }
    pb.finish_and_clear();
}

// Make the SID from domain present in trust
fn sid_maker_from_another_domain(
    vec_trusts: &Vec<Trust>,
    object_identifier: &String
) -> String {
    for i in 0..vec_trusts.len() {
        let ldap_dc = prepare_ldap_dc(&vec_trusts[i].target_domain_name().to_string());
        //trace!("LDAP_DC TRUSTED {:?}: {:?}", &i,&vec_trusts[i]);
        if object_identifier.contains(ldap_dc[0].as_str())
        {
            //trace!("object_identifier '{}' contains trust domain '{}'",&object_identifier, &ldap_dc);
            let id = get_id_from_objectidentifier(object_identifier);
            let sid = vec_trusts[i].target_domain_name().to_string() + id.as_str();
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
pub fn add_trustdomain(
    vec_domains: &mut Vec<Domain>,
    vec_trusts: &mut Vec<Trust>
) {
    if !&vec_trusts[0].target_domain_sid().to_string().contains("SID") {
        let mut trusts: Vec<Trust> = Vec::new();
        for trust in vec_trusts {
            trusts.push(trust.to_owned());
            let mut new_domain = Domain::new();
            *new_domain.object_identifier_mut() = trust.target_domain_sid().to_string();
            vec_domains.push(new_domain);
        }
        *vec_domains[0].trusts_mut() = trusts.to_owned();
    }
}

/// This function check PrincipalSID for all Ace and add the PrincipalType "Group","User","Computer"
pub fn add_type_for_ace<T: LdapObject>(
    object: &mut Vec<T>,
    sid_type: &HashMap<String, String>
) {
    // Needed for progress bar stats
    let pb = ProgressBar::new(1);
    let mut count = 0;
    let total = object.len();

    for i in 0..object.len()
    {
        // Manage progress bar
		count += 1;
        let pourcentage = 100 * count / total;
        progress_bar(pb.to_owned(),"Adding Type for ACE objects".to_string(),pourcentage.try_into().unwrap(),"%".to_string());

        // ACE by ACE
        if object[i].get_aces().len() != 0 {
            for j in 0..object[i].get_aces().len()
            {
                let group: String = "Group".to_string();
                let type_object = sid_type.get(&object[i].get_aces()[j].principal_sid().to_string()).unwrap_or(&group).to_owned();
                let mut aces = object[i].get_aces().to_owned();
                *aces[j].principal_type_mut() = type_object;
                object[i].set_aces(aces);
            }
        }
    }
    pb.finish_and_clear();
}

/// This function check PrincipalSID for all AllowedToAct object and add the PrincipalType "Group","User","Computer"
pub fn add_type_for_allowtedtoact(
    computer: &mut Vec<Computer>,
    sid_type: &HashMap<String, String>
) {
    // Needed for progress bar stats
    let pb = ProgressBar::new(1);
    let mut count = 0;
    let total = computer.len();

    for i in 0..computer.len()
    {
        // Manage progress bar
		count += 1;
        let pourcentage = 100 * count / total;
        progress_bar(pb.to_owned(),"Adding Type for AllowedToAct objects".to_string(),pourcentage.try_into().unwrap(),"%".to_string());

        let allowed_to_len = computer[i].allowed_to_act().len();
        if allowed_to_len.to_owned() != 0 {
            for j in 0..allowed_to_len.to_owned()
            {
                let default: String = "Computer".to_string();
                let type_object = sid_type.get(&computer[i].allowed_to_act()[j].object_identifier().to_string()).unwrap_or(&default);
                *computer[i].allowed_to_act_mut()[j].object_type_mut() = type_object.to_owned();
            }
        }
    }
    pb.finish_and_clear();
}

/// This function is to push user SID in ChildObjects for Ou
pub fn add_contained_by_for<T: LdapObject>(
    vec_replaced: &mut Vec<T>,
    dn_sid: &HashMap<String, String>, 
    sid_type: &HashMap<String, String>
) {
    // Needed for progress bar stats
    let pb = ProgressBar::new(1);
    let mut count = 0;
    let total = vec_replaced.len();
        
    for object in vec_replaced
    {
        // Manage progress bar
		count += 1;
        let pourcentage = 100 * count / total;
        progress_bar(pb.to_owned(),"Adding childobjects members".to_string(),pourcentage.try_into().unwrap(),"%".to_string());

        // Getting some vlaues: ObjectIdentifier / distinguishedname / ObjectType
        let sid = object.get_object_identifier().to_owned();
        let dn: Option<String> = dn_sid.iter().find_map(|(key, value)| {
            if *value == sid {
                Some(key.clone())
            } else {
                None
            }
        });
        let default: String = "Group".to_string();
        let otype = sid_type.get(&sid).unwrap_or(&default);

        if otype != "Domain"{
            if let Some(dn) = &dn {
                // Getting name from DN
                let cn_name = get_cn_object_name_from_full_distinguishedname(&dn);
                let contained_by_name = get_contained_by_name_from_distinguishedname(&cn_name,&dn);
                let dn_object = match dn_sid.get(&get_contained_by_name_from_distinguishedname(&cn_name,&dn)) {
                    Some(dn_object) => { dn_object.to_owned() }
                    None => { "NOT_FOUND".to_string() }
                };
                if !dn_object.contains("NOT_FOUND")
                {
                    let mut contained_by: Member = Member::new();
                    let sid_contained_by = dn_sid.get(&contained_by_name).unwrap();
                    let type_contained_by = sid_type.get(sid_contained_by).unwrap_or(&default);
                    *contained_by.object_identifier_mut() = sid_contained_by.to_owned();
                    *contained_by.object_type_mut() = type_contained_by.to_owned();
                    object.set_contained_by(Some(contained_by));
                }
            }
        }
    }
    pb.finish_and_clear();
}

/// Function to get name from DN
pub fn get_name_from_full_distinguishedname(dn_object: &String) -> String {
    // Example:
    // dn_object = CN=G0H4N,CN=USERS,DC=ESSOS,DC=LOCAL
    let split1 = dn_object.split(",");
    let vec1 = split1.collect::<Vec<&str>>();
    let split2 = vec1[0].split("=");
    let vec2 = split2.collect::<Vec<&str>>();
    let name = vec2[1].to_owned();
    // name = G0H4N
    name
}

/// Function to get CN=name from DN
fn get_cn_object_name_from_full_distinguishedname(dn_object: &String) -> String {
    // Example:
    // dn_object = CN=G0H4N,CN=USERS,DC=ESSOS,DC=LOCAL
    let name = dn_object.to_owned();
    let split = name.split(",");
    let vec = split.collect::<Vec<&str>>();
    let name = vec[0].to_owned();
    // name = CN=G0H4N
    name
}

/// Function to get first degree contained by name from DN
fn get_contained_by_name_from_distinguishedname(cn_name: &String, dn_object: &String) -> String {
    // Example:
    // dn_object = CN=G0H4N,CN=USERS,DC=ESSOS,DC=LOCAL
    let name = format!("{},",cn_name);
    let split = dn_object.split(&name);
    let vec = split.collect::<Vec<&str>>();
    let dn_contained_by = vec[1].to_owned();
    // dn_contained_by = CN=USERS,DC=ESSOS,DC=LOCAL
    dn_contained_by
}

/// Function to get only SID for one spécifique Type
fn return_sid_dn_for_one_specific_type(
    object_type: &String,
    dn_sid: &HashMap<String, String>,
    sid_type: &HashMap<String, String>
) -> HashMap<String, String> {
    let mut dn_sid_filtered: HashMap<String, String> = HashMap::new();
    for (sid, otype) in sid_type.iter() {
        if otype == object_type {
            let dn: Option<String> = dn_sid.iter().find_map(|(key, value)| {
                if *value == sid.to_owned() {
                    Some(key.clone())
                } else {
                    None
                }
            });
            if let Some(dn) = &dn {
                dn_sid_filtered.insert(
                    dn.to_owned(),
                    sid.to_owned(),
                );
            }
        }
    }
    dn_sid_filtered
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    
    use crate::json::checker::common::{
        get_name_from_full_distinguishedname,
        get_cn_object_name_from_full_distinguishedname,
        get_contained_by_name_from_distinguishedname
    };
    
    #[test]
    #[rustfmt::skip]
    pub fn test_get_name_from_full_distinguishedname() {
        // Example:
        // dn_object = CN=G0H4N,CN=USERS,DC=ESSOS,DC=LOCAL
        let dn_object = "CN=G0H4N,CN=USERS,DC=ESSOS,DC=LOCAL".to_string();
        let cn_name =  get_name_from_full_distinguishedname(&dn_object);
        println!("dn_object: {:?}",dn_object);
        println!("cn_name: {:?}",cn_name);
        assert_eq!(cn_name, "G0H4N".to_string());
    }

    #[test]
    #[rustfmt::skip]
    pub fn test_get_cn_object_name_from_full_distinguishedname() {
        // Example:
        // dn_object = CN=G0H4N,CN=USERS,DC=ESSOS,DC=LOCAL
        let dn_object = "CN=G0H4N,CN=USERS,DC=ESSOS,DC=LOCAL".to_string();
        let cn_name =  get_cn_object_name_from_full_distinguishedname(&dn_object);
        println!("dn_object: {:?}",dn_object);
        println!("cn_name: {:?}",cn_name);
        assert_eq!(cn_name, "CN=G0H4N".to_string());
    }
    
    #[test]
    #[rustfmt::skip]
    pub fn test_get_contained_by_name_from_name() {
        // Example:
        // dn_object = CN=G0H4N,CN=USERS,DC=ESSOS,DC=LOCAL
        let dn_object = "CN=G0H4N,CN=USERS,DC=ESSOS,DC=LOCAL".to_string();
        let cn_name = "CN=G0H4N".to_string();
        let contained_by_dn =  get_contained_by_name_from_distinguishedname(&cn_name, &dn_object);
        println!("dn_object: {:?}",dn_object);
        println!("contained_by_dn: {:?}",contained_by_dn);
        assert_eq!(contained_by_dn, "CN=USERS,DC=ESSOS,DC=LOCAL".to_string());
    }
}