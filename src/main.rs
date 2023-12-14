pub mod modules;
pub mod enums;
pub mod json;

pub mod args;
pub mod objects;
pub mod utils;
pub mod banner;
pub mod errors;
pub mod ldap;

use log::{info,trace,error};
use env_logger::Builder;
use std::collections::HashMap;
use crate::errors::Result;

#[cfg(not(feature = "noargs"))]
use args::{Options,extract_args};
#[cfg(feature = "noargs")]
use args::auto_args;

use banner::{print_banner,print_end_banner};
use ldap::ldap_search;
use modules::run_modules;
use json::{
    parser::parse_result_type,
    checker::check_all_result,
    maker::make_result,
};
use objects::{
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

/// Main of RustHound
#[tokio::main]
async fn main() -> Result<()> {
    // Banner
    print_banner();

    // Get args
    #[cfg(not(feature = "noargs"))]
    let common_args: Options = extract_args();
    #[cfg(feature = "noargs")]
    let common_args = auto_args();

    // Build logger
    Builder::new()
        .filter(Some("rusthound"), common_args.verbose)
        .filter_level(log::LevelFilter::Error)
        .init();

    // Get verbose level
    info!("Verbosity level: {:?}", common_args.verbose);
    info!("Collection method: {:?}", common_args.collection_method);

    // LDAP request to get all informations in result
    let result = ldap_search(
        common_args.ldaps,
        &common_args.ip,
        &common_args.port,
        &common_args.domain,
        &common_args.ldapfqdn,
        &common_args.username,
        &common_args.password,
        common_args.kerberos,
    ).await?;

    // Vector for content all
    let mut vec_users:              Vec<User>           = Vec::new();
    let mut vec_groups:             Vec<Group>          = Vec::new();
    let mut vec_computers:          Vec<Computer>       = Vec::new();
    let mut vec_ous:                Vec<Ou>             = Vec::new();
    let mut vec_domains:            Vec<Domain>         = Vec::new();
    let mut vec_gpos:               Vec<Gpo>            = Vec::new();
    let mut vec_fsps:               Vec<Fsp>            = Vec::new();
    let mut vec_containers:         Vec<Container>      = Vec::new();
    let mut vec_trusts:             Vec<Trust>          = Vec::new();
    let mut vec_ntauthstores:       Vec<NtAuthStore>    = Vec::new();
    let mut vec_aiacas:             Vec<AIACA>          = Vec::new();
    let mut vec_rootcas:            Vec<RootCA>         = Vec::new();
    let mut vec_enterprisecas:      Vec<EnterpriseCA>   = Vec::new();
    let mut vec_certtemplates:      Vec<CertTemplate>   = Vec::new();

    // Hashmap to link DN to SID
    let mut dn_sid: HashMap<String, String> = HashMap::new();
    // Hashmap to link DN to Type
    let mut sid_type: HashMap<String, String> = HashMap::new();
    // Hashmap to link FQDN to SID
    let mut fqdn_sid: HashMap<String, String> = HashMap::new();
    // Hashmap to link fqdn to an ip address
    let mut fqdn_ip: HashMap<String, String> = HashMap::new();

    // Analyze object by object 
    // Get type and parse it to get values
    parse_result_type(
        &common_args,
        result,
        &mut vec_users,
        &mut vec_groups,
        &mut vec_computers,
        &mut vec_ous,
        &mut vec_domains,
        &mut vec_gpos,
        &mut vec_fsps,
        &mut vec_containers,
        &mut vec_trusts,
        &mut vec_ntauthstores,
        &mut vec_aiacas,
        &mut vec_rootcas,
        &mut vec_enterprisecas,
        &mut vec_certtemplates,
        &mut dn_sid,
        &mut sid_type,
        &mut fqdn_sid,
        &mut fqdn_ip,
    );
    
    // Functions to replace and add missing values
    check_all_result(
        &common_args,
        &mut vec_users,
        &mut vec_groups,
        &mut vec_computers,
        &mut vec_ous,
        &mut vec_domains,
        &mut vec_gpos,
        &mut vec_fsps,
        &mut vec_containers,
        &mut vec_trusts,
        &mut vec_ntauthstores,
        &mut vec_aiacas,
        &mut vec_rootcas,
        &mut vec_enterprisecas,
        &mut vec_certtemplates,
        &mut dn_sid,
        &mut sid_type,
        &mut fqdn_sid,
        &mut fqdn_ip,
     );

    // Running modules
    run_modules(
        &common_args,
        &mut fqdn_ip,
        &mut vec_computers,
    ).await;

    // Add all in json files
    match make_result(
        &common_args,
        vec_users,
        vec_groups,
        vec_computers,
        vec_ous,
        vec_domains,
        vec_gpos,
        vec_containers,
        vec_ntauthstores,
        vec_aiacas,
        vec_rootcas,
        vec_enterprisecas,
        vec_certtemplates,
    ) {
        Ok(_res) => trace!("Making json/zip files finished!"),
        Err(err) => error!("Error. Reason: {err}")
    }

    // End banner
    print_end_banner();
    Ok(())
}