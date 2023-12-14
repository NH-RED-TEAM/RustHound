use std::collections::HashMap;
use ldap3::SearchEntry;
use regex::Regex;
use indicatif::ProgressBar;
use crate::objects::common::parse_unknown;
use crate::objects::{
    user::User,
    computer::Computer,
    group::Group,
    ou::Ou,
    container::Container,
    gpo::Gpo,
    domain::Domain,
    fsp::Fsp,
    trust::Trust,
    ntauthstore::NtAuthStore,
    aiaca::AIACA,
    rootca::RootCA,
    enterpriseca::EnterpriseCA,
    certtemplate::CertTemplate,
};
use std::convert::TryInto;

use log::info;
use crate::args::Options;
use crate::banner::progress_bar;
use crate::enums::ldaptype::*;
// use crate::modules::adcs::parser::{parse_adcs_ca,parse_adcs_template};

/// Function to get type for object by object
pub fn parse_result_type(
    common_args:            &Options, 
    result:                 Vec<SearchEntry>,
    vec_users:              &mut Vec<User>,
    vec_groups:             &mut Vec<Group>,
    vec_computers:          &mut Vec<Computer>,
    vec_ous:                &mut Vec<Ou>,
    vec_domains:            &mut Vec<Domain>,
    vec_gpos:               &mut Vec<Gpo>,
    vec_fsps:               &mut Vec<Fsp>,
    vec_containers:         &mut Vec<Container>,
    vec_trusts:             &mut Vec<Trust>,
    vec_ntauthstore:        &mut Vec<NtAuthStore>,
    vec_aiacas:             &mut Vec<AIACA>,
    vec_rootcas:            &mut Vec<RootCA>,
    vec_enterprisecas:      &mut Vec<EnterpriseCA>,
    vec_certtemplates:      &mut Vec<CertTemplate>,

    dn_sid:             &mut HashMap<String, String>,
    sid_type:           &mut HashMap<String, String>,
    fqdn_sid:           &mut HashMap<String, String>,
    fqdn_ip:            &mut HashMap<String, String>,
    // adcs_templates: &mut HashMap<String, Vec<String>>,
)
{
    // Domain name
    let domain = &common_args.domain;

    // Needed for progress bar stats
    let pb = ProgressBar::new(1);
    let mut count = 0;
    let total = result.len();
    let mut domain_sid: String = "DOMAIN_SID".to_owned();

    info!("Starting the LDAP objects parsing...");
    for entry in result {
        // Start parsing with Type matching
        let cloneresult = entry.clone();
        //println!("{:?}",&entry);
        let atype = get_type(entry).unwrap_or(Type::Unknown);
        match atype {
            Type::User => {
                let mut user: User = User::new();
                user.parse(
                    cloneresult,
                    domain,
                    dn_sid,
                    sid_type,
                );
                vec_users.push(user);
            }
            Type::Group => {
                let mut group = Group::new();
                group.parse(
                    cloneresult,
                    domain,
                    dn_sid,
                    sid_type,
                    &domain_sid
                );
                vec_groups.push(group);
            }
            Type::Computer => {
                let mut computer = Computer::new();
                computer.parse(
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
                let mut ou = Ou::new();
                ou.parse(
                    cloneresult,
                    domain,
                    dn_sid,
                    sid_type,
                    &domain_sid
                );
                vec_ous.push(ou);
            }
            Type::Domain => {
                let mut domain_object = Domain::new();
                let domain_sid_from_domain = domain_object.parse(
                    cloneresult,
                    domain,
                    dn_sid,
                    sid_type,
                );
                domain_sid = domain_sid_from_domain;
                vec_domains.push(domain_object);
            }
            Type::Gpo => {
                let mut  gpo = Gpo::new();
                gpo.parse(
                    cloneresult,
                    domain,
                    dn_sid,
                    sid_type,
                    &domain_sid
                );
                vec_gpos.push(gpo);
            }
            Type::ForeignSecurityPrincipal => {
                let mut security_principal = Fsp::new();
                security_principal.parse(
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
                let mut container = Container::new();
                container.parse(
                    cloneresult,
                    domain,
                    dn_sid,
                    sid_type,
                    &domain_sid
                );
                vec_containers.push(container);
            }
            Type::Trust => {
                let mut trust = Trust::new();
                trust.parse(
                    cloneresult,
                    domain
                );
                vec_trusts.push(trust);
            }
            Type::NtAutStore => {
                let mut nt_auth_store = NtAuthStore::new();
                nt_auth_store.parse(
                    cloneresult,
                    domain,
                    dn_sid,
                    sid_type,
                    &domain_sid
                );
                vec_ntauthstore.push(nt_auth_store); 
            }
            Type::AIACA => {
                let mut aiaca = AIACA::new();
                aiaca.parse(
                    cloneresult,
                    domain,
                    dn_sid,
                    sid_type,
                    &domain_sid
                );
                vec_aiacas.push(aiaca); 
            }
            Type::RootCA => {
                let mut root_ca = RootCA::new();
                root_ca.parse(
                    cloneresult,
                    domain,
                    dn_sid,
                    sid_type,
                    &domain_sid
                );
                vec_rootcas.push(root_ca); 
            }
            Type::EnterpriseCA => {
                let mut enterprise_ca = EnterpriseCA::new();
                enterprise_ca.parse(
                    cloneresult,
                    domain,
                    dn_sid,
                    sid_type,
                    &domain_sid
                );
                vec_enterprisecas.push(enterprise_ca); 
            }
            Type::CertTemplate => {
                let mut cert_template = CertTemplate::new();
                cert_template.parse(
                    cloneresult,
                    domain,
                    dn_sid,
                    sid_type,
                    &domain_sid
                );
                vec_certtemplates.push(cert_template);
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