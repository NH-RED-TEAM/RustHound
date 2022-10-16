use std::collections::HashMap;
use log::{info,debug};
use indicatif::ProgressBar;
use crate::banner::progress_bar;
use std::convert::TryInto;

pub mod bh_41;

/// Functions to replace and add missing values
pub fn check_all_result(
   domain: &String,
   
   vec_users: &mut Vec<serde_json::value::Value>,
   vec_groups: &mut Vec<serde_json::value::Value>,
   vec_computers: &mut Vec<serde_json::value::Value>,
   vec_ous: &mut Vec<serde_json::value::Value>,
   vec_domains: &mut Vec<serde_json::value::Value>,
   vec_gpos: &mut Vec<serde_json::value::Value>,
   _vec_fsps: &mut Vec<serde_json::value::Value>,
   vec_containers: &mut Vec<serde_json::value::Value>,
   vec_trusts: &mut Vec<serde_json::value::Value>,

   dn_sid: &mut HashMap<String, String>,
   sid_type: &mut HashMap<String, String>,
   fqdn_sid: &mut HashMap<String, String>,
   _fqdn_ip: &mut HashMap<String, String>,
)
{
    info!("Starting checker to replace some values...");
    debug!("Replace SID with checker.rs started");
    bh_41::replace_fqdn_by_sid(vec_users, &fqdn_sid);
    bh_41::replace_fqdn_by_sid(vec_computers, &fqdn_sid);
    bh_41::replace_sid_members(vec_groups, &dn_sid, &sid_type, &vec_trusts);
    debug!("Replace SID finished!");

    debug!("Adding defaults groups and default users");
    bh_41::add_default_groups(vec_groups, &vec_computers, domain.to_owned());
    bh_41::add_default_users(vec_users, domain.to_owned());
    debug!("Defaults groups and default users added!");

    debug!("Adding PrincipalType for ACEs started");
    add_type_for_ace(vec_users, &sid_type);
    add_type_for_ace(vec_groups, &sid_type);
    add_type_for_ace(vec_computers, &sid_type);
    add_type_for_ace(vec_gpos, &sid_type);
    add_type_for_ace(vec_ous, &sid_type);
    add_type_for_ace(vec_domains, &sid_type);
    add_type_for_ace(vec_containers, &sid_type);
    debug!("PrincipalType for ACEs added!");

    debug!("Adding ChildObject members started");
    bh_41::add_childobjects_members(vec_ous, &dn_sid, &sid_type);
    bh_41::add_childobjects_members(vec_domains, &dn_sid, &sid_type);
    bh_41::add_childobjects_members(vec_containers, &dn_sid, &sid_type);
    debug!("ChildObject members added!");

    debug!("Adding domainsid started");
    bh_41::add_domain_sid(vec_groups, &dn_sid);
    bh_41::add_domain_sid(vec_gpos, &dn_sid);
    bh_41::add_domain_sid(vec_ous, &dn_sid);
    bh_41::add_domain_sid(vec_containers, &dn_sid);
    debug!("domainsid added!");
        
    debug!("Adding affected computers in domain GpoChanges");
    bh_41::add_affected_computers(vec_domains, &sid_type);
    debug!("affected computers added!");

    debug!("Replacing guid for gplinks started");
    bh_41::replace_guid_gplink(vec_ous, &dn_sid);
    bh_41::replace_guid_gplink(vec_domains, &dn_sid);
    debug!("guid for gplinks added!");

    if vec_trusts.len() > 0 {
        debug!("Adding trust domain relation");
        bh_41::add_trustdomain(vec_domains, vec_trusts);
        debug!("Trust domain relation added!");
    }
    info!("Checking and replacing some values finished!");
}

/// This function check PrincipalSID for all Ace and add the PrincipalType "Group","User","Computer"
pub fn add_type_for_ace(vec_replaced: &mut Vec<serde_json::value::Value>, sid_type: &HashMap<String, String>)
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
        progress_bar(pb.to_owned(),"Adding Type for ACE objects".to_string(),pourcentage.try_into().unwrap(),"%".to_string());

        // ACE by ACE
        if vec_replaced[i]["Aces"].as_array().unwrap().len() != 0 {
            for j in 0..vec_replaced[i]["Aces"].as_array().unwrap().len()
            {
                let group: String = "Group".to_string();
                let type_object = sid_type.get(&vec_replaced[i]["Aces"][j]["PrincipalSID"].as_str().unwrap().to_string()).unwrap_or(&group);
                vec_replaced[i]["Aces"][j]["PrincipalType"] = type_object.to_owned().into();
            }
        }
    }
    pb.finish_and_clear();
}
