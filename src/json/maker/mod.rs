use std::collections::HashMap;

extern crate zip;
use crate::args::Options;
use crate::utils::date::return_current_fulldate;
use crate::objects::{
   user::User,
   computer::Computer,
   group::Group,
   ou::Ou,
   container::Container,
   gpo::Gpo,
   domain::Domain,
   ntauthstore::NtAuthStore,
   aiaca::AIACA,
   rootca::RootCA,
   enterpriseca::EnterpriseCA,
   certtemplate::CertTemplate,
};
pub mod common;

/// This function will create json output and zip output
pub fn make_result(
   common_args:            &Options,
   vec_users:              Vec<User>,
   vec_groups:             Vec<Group>,
   vec_computers:          Vec<Computer>,
   vec_ous:                Vec<Ou>,
   vec_domains:            Vec<Domain>,
   vec_gpos:               Vec<Gpo>,
   vec_containers:         Vec<Container>,
   vec_ntauthstores:       Vec<NtAuthStore>,
   vec_aiacas:             Vec<AIACA>,
   vec_rootcas:            Vec<RootCA>,
   vec_enterprisecas:      Vec<EnterpriseCA>,
   vec_certtemplates:      Vec<CertTemplate>,
) -> std::io::Result<()>
{
   // Format domain name
   let filename = common_args.domain.replace(".", "-").to_lowercase();

   // Hashmap for json files
   let mut json_result: HashMap<String, String> = HashMap::new();

   // Datetime for output file
   let datetime = return_current_fulldate();

   // Add all in json files
   common::add_file(
      &datetime,
      "users".to_string(),
		&filename,
      vec_users,
      &mut json_result,
      common_args,
   )?;
   common::add_file(
      &datetime,
      "groups".to_string(),
		&filename,
      vec_groups,
      &mut json_result,
      common_args,
   )?;
   common::add_file(
      &datetime,
      "computers".to_string(),
		&filename,
      vec_computers,
      &mut json_result,
      common_args,
   )?;
   common::add_file(
      &datetime,
      "ous".to_string(),
		&filename,
      vec_ous,
      &mut json_result,
      common_args,
   )?;
   common::add_file(
      &datetime,
      "domains".to_string(),
		&filename,
      vec_domains,
      &mut json_result,
      common_args,
   )?;
   common::add_file(
      &datetime,
      "gpos".to_string(),
      &filename,
      vec_gpos,
      &mut json_result,
      common_args,
   )?;
   // }
   common::add_file(
      &datetime,
      "containers".to_string(),
		&filename,
      vec_containers,
      &mut json_result,
      common_args,
   )?;
   common::add_file(
      &datetime,
      "ntauthstores".to_string(),
		&filename,
      vec_ntauthstores,
      &mut json_result,
      common_args,
   )?;
   common::add_file(
      &datetime,
      "aiacas".to_string(),
		&filename,
      vec_aiacas,
      &mut json_result,
      common_args,
   )?;
   common::add_file(
      &datetime,
      "rootcas".to_string(),
		&filename,
      vec_rootcas,
      &mut json_result,
      common_args,
   )?;
   common::add_file(
      &datetime,
      "enterprisecas".to_string(),
		&filename,
      vec_enterprisecas,
      &mut json_result,
      common_args,
   )?;
   common::add_file(
      &datetime,
      "certtemplates".to_string(),
		&filename,
      vec_certtemplates,
      &mut json_result,
      common_args,
   )?;
   // All in zip file
   if common_args.zip {
      common::make_a_zip(
         &datetime,
         &filename,
         &common_args.path,
         &json_result);
   }
   Ok(())
}