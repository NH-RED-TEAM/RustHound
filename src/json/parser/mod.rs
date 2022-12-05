use std::collections::HashMap;
use ldap3::SearchEntry;
use regex::Regex;
use indicatif::ProgressBar;
use std::convert::TryInto;

use log::info;
use crate::args::Options;
use crate::banner::progress_bar;
use crate::enums::ldaptype::*;
use crate::modules::adcs::parser::{parse_adcs_ca,parse_adcs_template};

pub mod bh_41;

/// Function to get type for object by object
pub fn parse_result_type(
    common_args: &Options, 
    result: Vec<SearchEntry>,
    vec_users: &mut Vec<serde_json::value::Value>,
    vec_groups: &mut Vec<serde_json::value::Value>,
    vec_computers: &mut Vec<serde_json::value::Value>,
    vec_ous: &mut Vec<serde_json::value::Value>,
    vec_domains: &mut Vec<serde_json::value::Value>,
    vec_gpos: &mut Vec<serde_json::value::Value>,
    vec_fsps: &mut Vec<serde_json::value::Value>,
    vec_containers: &mut Vec<serde_json::value::Value>,
    vec_trusts: &mut Vec<serde_json::value::Value>,
    vec_cas: &mut Vec<serde_json::value::Value>,
    vec_templates: &mut Vec<serde_json::value::Value>,

    dn_sid: &mut HashMap<String, String>,
    sid_type: &mut HashMap<String, String>,
    fqdn_sid: &mut HashMap<String, String>,
    fqdn_ip: &mut HashMap<String, String>,
    adcs_templates: &mut HashMap<String, Vec<String>>,
)
{
    // Domain name
    let domain = &common_args.domain;

    // Needed for progress bar stats
    let pb = ProgressBar::new(1);
    let mut count = 0;
    let total = result.len();

    info!("Starting the LDAP objects parsing...");
    for entry in result {
        // Start parsing with Type matching
        let cloneresult = entry.clone();
        //println!("{:?}",&entry);
        let atype = get_type(entry).unwrap_or(Type::Unknown);
        match atype {
            Type::User => {
                let user = parse_user(
                    cloneresult,
                    domain,
                    dn_sid,
                    sid_type,
                    common_args.adcs,
                );
                vec_users.push(user);
            }
            Type::Group => {
                let group = parse_group(
                    cloneresult,
                    domain,
                    dn_sid,
                    sid_type,
                );
                vec_groups.push(group);
            }
            Type::Computer => {
                let computer = parse_computer(
                    cloneresult,
                    domain,
                    dn_sid,
                    sid_type,
                    fqdn_sid,
                    fqdn_ip,
                );
                vec_computers.push(computer);
            }
            Type::Ou => {
                let ou = parse_ou(
                    cloneresult,
                    domain,
                    dn_sid,
                    sid_type,
                );
                vec_ous.push(ou);
            }
            Type::Domain => {
                let domain = parse_domain(
                    cloneresult,
                    domain,
                    dn_sid,
                    sid_type,
                );
                vec_domains.push(domain);
            }
            Type::Gpo => {
                let gpo = parse_gpo(
                    cloneresult,
                    domain,
                    dn_sid,
                    sid_type,
                );
                vec_gpos.push(gpo);
            }
            Type::ForeignSecurityPrincipal => {
                let security_principal = parse_fsp(
                    cloneresult,
                    domain,
                    dn_sid,
                    sid_type,
                );
                vec_fsps.push(security_principal);
            }
            Type::Container => {
                let re = Regex::new(r"[0-9a-z-A-Z]{1,}-[0-9a-z-A-Z]{1,}-[0-9a-z-A-Z]{1,}-[0-9a-z-A-Z]{1,}").unwrap();
                if re.is_match(&cloneresult.dn.to_uppercase()) 
                {
                    //trace!("Container not to add: {}",&cloneresult.dn.to_uppercase());
                    continue
                }
                let re = Regex::new(r"CN=DOMAINUPDATES,CN=SYSTEM,").unwrap();
                if re.is_match(&cloneresult.dn.to_uppercase()) 
                {
                    //trace!("Container not to add: {}",&cloneresult.dn.to_uppercase());
                    continue
                }
                //trace!("Container: {}",&cloneresult.dn.to_uppercase());
                let container = parse_container(
                    cloneresult,
                    domain,
                    dn_sid,
                    sid_type,
                );
                vec_containers.push(container);
            }
            Type::Trust => {
                let trust = parse_trust(
                    cloneresult,
                    domain
                );
                vec_trusts.push(trust);
            }
            Type::AdcsAuthority => {
                let adcs_ca = parse_adcs_ca(
                    cloneresult.to_owned(),
                    domain,
                    adcs_templates,
                    common_args.old_bloodhound,
                );
                vec_cas.push(adcs_ca); 
            }
            Type::AdcsTemplate => {
                let adcs_template = parse_adcs_template(
                    cloneresult.to_owned(),
                    domain,
                    common_args.old_bloodhound,
                );
                vec_templates.push(adcs_template);
            }
            Type::Unknown => {
                let _unknown = parse_unknown(cloneresult, domain);
            }
        }
        // Manage progress bar
        // Pourcentage (%) = 100 x Valeur partielle/Valeur totale
		count += 1;
        let pourcentage = 100 * count / total;
        progress_bar(pb.to_owned(),"Parsing LDAP objects".to_string(),pourcentage.try_into().unwrap(),"%".to_string());
    }
    pb.finish_and_clear();
    info!("Parsing LDAP objects finished!");
}


/// Parse user. Select parser based on BH version.
pub fn parse_user(
    result: SearchEntry,
    domain: &String,
    dn_sid: &mut HashMap<String, String>,
    sid_type: &mut HashMap<String, String>,
    adcs: bool,
) -> serde_json::value::Value {
    bh_41::parse_user(result, domain, dn_sid, sid_type, adcs)
}

/// Parse group. Select parser based on BH version.
pub fn parse_group(
    result: SearchEntry,
    domain: &String,
    dn_sid: &mut HashMap<String, String>,
    sid_type: &mut HashMap<String, String>,
) -> serde_json::value::Value {
    bh_41::parse_group(result, domain, dn_sid, sid_type)
}

/// Parse computer. Select parser based on BH version.
pub fn parse_computer(
    result: SearchEntry,
    domain: &String,
    dn_sid: &mut HashMap<String, String>,
    sid_type: &mut HashMap<String, String>,
    fqdn_sid: &mut HashMap<String, String>,
    fqdn_ip: &mut HashMap<String, String>,
) -> serde_json::value::Value {
    bh_41::parse_computer(result, domain, dn_sid, sid_type, fqdn_sid, fqdn_ip)
}

/// Parse ou. Select parser based on BH version.
pub fn parse_ou(
    result: SearchEntry,
    domain: &String,
    dn_sid: &mut HashMap<String, String>,
    sid_type: &mut HashMap<String, String>,
) -> serde_json::value::Value {
    bh_41::parse_ou(result, domain, dn_sid, sid_type)
}

/// Parse gpo. Select parser based on BH version.
pub fn parse_gpo(
    result: SearchEntry,
    domain: &String,
    dn_sid: &mut HashMap<String, String>,
    sid_type: &mut HashMap<String, String>,
) -> serde_json::value::Value {
    bh_41::parse_gpo(result, domain, dn_sid, sid_type)
}

/// Parse domain. Select parser based on BH version.
pub fn parse_domain(
    result: SearchEntry,
    domain: &String,
    dn_sid: &mut HashMap<String, String>,
    sid_type: &mut HashMap<String, String>,
) -> serde_json::value::Value {
    bh_41::parse_domain(result, domain, dn_sid, sid_type)
}

/// Parse ForeignSecurityPrincipal object. Select parser based on BH version.
pub fn parse_fsp(
    result: SearchEntry,
    domain: &String,
    dn_sid: &mut HashMap<String, String>,
    sid_type: &mut HashMap<String, String>,
) -> serde_json::value::Value {
    bh_41::parse_fsp(result, domain, dn_sid, sid_type)
}

/// Parse Containers object. Select parser based on BH version new in BH4.1+
pub fn parse_container(
    result: SearchEntry,
    domain: &String,
    dn_sid: &mut HashMap<String, String>,
    sid_type: &mut HashMap<String, String>,
) -> serde_json::value::Value {
    bh_41::parse_container(result, domain, dn_sid, sid_type)
}

/// Parse Trust domain object. Select parser based on BH version.
pub fn parse_trust(
    result: SearchEntry, 
    _domain: &String,
) -> serde_json::value::Value {
    bh_41::parse_trust(result, _domain)
}

/// Parse unknown object. Select parser based on BH version.
pub fn parse_unknown(
    result: SearchEntry, 
    _domain: &String,
) -> serde_json::value::Value {
    bh_41::parse_unknown(result, _domain)
}