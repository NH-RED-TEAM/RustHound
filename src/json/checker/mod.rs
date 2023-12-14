use std::collections::HashMap;
use log::{info,debug};
use crate::args::Options;
use crate::enums::{ldaptype::*, templates_enabled_change_displayname_to_sid};
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
pub mod common;

/// Functions to replace and add missing values
pub fn check_all_result(
    common_args:             &Options,
    vec_users:               &mut Vec<User>,
    vec_groups:              &mut Vec<Group>,
    vec_computers:           &mut Vec<Computer>,
    vec_ous:                 &mut Vec<Ou>,
    vec_domains:             &mut Vec<Domain>,
    vec_gpos:                &mut Vec<Gpo>,
    _vec_fsps:               &mut Vec<Fsp>,
    vec_containers:          &mut Vec<Container>,
    vec_trusts:              &mut Vec<Trust>,
    vec_ntauthstores:        &mut Vec<NtAuthStore>,
    vec_aiacas:              &mut Vec<AIACA>,
    vec_rootcas:             &mut Vec<RootCA>,
    vec_enterprisecas:       &mut Vec<EnterpriseCA>,
    vec_certtemplates:       &mut Vec<CertTemplate>,
    dn_sid:                  &mut HashMap<String, String>,
    sid_type:                &mut HashMap<String, String>,
    fqdn_sid:                &mut HashMap<String, String>,
    _fqdn_ip:                &mut HashMap<String, String>,
)
{
    let domain = &common_args.domain;
    info!("Starting checker to replace some values...");
    debug!("Replace SID with checker.rs started");
    common::replace_fqdn_by_sid(Type::User, vec_users, &fqdn_sid);
    common::replace_fqdn_by_sid(Type::Computer, vec_computers, &fqdn_sid);
    templates_enabled_change_displayname_to_sid(vec_certtemplates, vec_enterprisecas);
    common::replace_sid_members(vec_groups, &dn_sid, &sid_type, &vec_trusts);
    debug!("Replace SID finished!");

    debug!("Adding defaults groups and default users");
    common::add_default_groups(vec_groups, &vec_computers, domain.to_owned());
    common::add_default_users(vec_users, domain.to_owned());
    debug!("Defaults groups and default users added!");

    debug!("Adding PrincipalType for ACEs started");
    common::add_type_for_ace(vec_users, &sid_type);
    common::add_type_for_ace(vec_groups, &sid_type);
    common::add_type_for_ace(vec_computers, &sid_type);
    common::add_type_for_ace(vec_gpos, &sid_type);
    common::add_type_for_ace(vec_ous, &sid_type);
    common::add_type_for_ace(vec_domains, &sid_type);
    common::add_type_for_ace(vec_containers, &sid_type);
    common::add_type_for_ace(vec_ntauthstores, &sid_type);
    common::add_type_for_ace(vec_aiacas, &sid_type);
    common::add_type_for_ace(vec_rootcas, &sid_type);
    common::add_type_for_ace(vec_enterprisecas, &sid_type);
    common::add_type_for_ace(vec_certtemplates, &sid_type);

    common::add_type_for_allowtedtoact(vec_computers, &sid_type);
    debug!("PrincipalType for ACEs added!");

    debug!("Adding ChildObject members started");
    common::add_childobjects_members(vec_ous, &dn_sid, &sid_type);
    common::add_childobjects_members(vec_domains, &dn_sid, &sid_type);
    common::add_childobjects_members(vec_containers, &dn_sid, &sid_type);
    debug!("ChildObject members added!");

    debug!("Adding ContainedBy value started");
    common::add_contained_by_for(vec_users, &dn_sid, &sid_type);
    common::add_contained_by_for(vec_groups, &dn_sid, &sid_type);
    common::add_contained_by_for(vec_computers, &dn_sid, &sid_type);
    common::add_contained_by_for(vec_gpos, &dn_sid, &sid_type);
    common::add_contained_by_for(vec_ous, &dn_sid, &sid_type);
    common::add_contained_by_for(vec_containers, &dn_sid, &sid_type);
    common::add_contained_by_for(vec_ntauthstores, &dn_sid, &sid_type);
    common::add_contained_by_for(vec_aiacas, &dn_sid, &sid_type);
    common::add_contained_by_for(vec_rootcas, &dn_sid, &sid_type);
    common::add_contained_by_for(vec_enterprisecas, &dn_sid, &sid_type);
    common::add_contained_by_for(vec_certtemplates, &dn_sid, &sid_type);

    debug!("ContainedBy value added!");

    debug!("Adding affected computers in GpoChanges");
    common::add_affected_computers(vec_domains, &sid_type);
    common::add_affected_computers_for_ou(vec_ous, &dn_sid, &sid_type);
    debug!("Affected computers in GpoChanges added!");

    debug!("Replacing guid for gplinks started");
    common::replace_guid_gplink(vec_ous, &dn_sid);
    common::replace_guid_gplink(vec_domains, &dn_sid);
    debug!("guid for gplinks added!");

    if vec_trusts.len() > 0 {
        debug!("Adding trust domain relation");
        common::add_trustdomain(vec_domains, vec_trusts);
        debug!("Trust domain relation added!");
    }
    info!("Checking and replacing some values finished!");
}