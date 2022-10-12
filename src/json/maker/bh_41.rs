use std::fs;
use log::{info,debug};
use colored::Colorize;
use std::collections::HashMap;

use crate::json::templates::*;

/// Current Bloodhound version 4.2+
pub const BLOODHOUND_VERSION_4: i8 = 5;

/// Function to create the users.json file.
pub fn add_user(
	domain_format: &String,
   user: Vec<serde_json::value::Value>,
   path: &String,
   json_result: &mut HashMap<String, String>,
   zip: bool
) -> std::io::Result<()>
{
   debug!("Making users.json");

   // Prepare template and get result in const var
   let mut users_json = bh_41::prepare_final_json_file_template(BLOODHOUND_VERSION_4, "users".to_owned());
   // Add all users found
   users_json["data"] = user.into();
   // change count number
   let stream = users_json["data"].as_array().unwrap();
   let count = stream.len();

   users_json["meta"]["count"] = count.into();
   info!("{} users parsed!",count.to_string().bold());
    
   // result
   fs::create_dir_all(path)?;

   if ! zip 
   {
      let mut final_path = path.to_owned();
      final_path.push_str("/");
      final_path.push_str(domain_format);
      final_path.push_str("_users.json");
      fs::write(&final_path,&users_json.to_string())?;
      info!("{} created!",final_path.bold());
   }
   else
   {
      json_result.insert("users.json".to_string(),users_json.to_owned().to_string());
   }
    
   Ok(())
}


/// Function to create the groups.json file.
pub fn add_group(
	domain_format: &String,
   group: Vec<serde_json::value::Value>,
   path: &String,
   json_result: &mut HashMap<String, String>,
   zip: bool
) -> std::io::Result<()>
{
   debug!("Making groups.json");

   // Prepare template and get result in const var
   let mut groups_json = bh_41::prepare_final_json_file_template(BLOODHOUND_VERSION_4, "groups".to_owned());
   // Add all groups found
   groups_json["data"] = group.into();
   // change count number
   let stream = groups_json["data"].as_array().unwrap();
   let count = stream.len();

   groups_json["meta"]["count"] = count.into();
   info!("{} groups parsed!",count.to_string().bold());

   // result
   fs::create_dir_all(path)?;
    
   if ! zip 
   {
      let mut final_path = path.to_owned();
      final_path.push_str("/");
      final_path.push_str(domain_format);
      final_path.push_str("_groups.json");
      fs::write(&final_path, &groups_json.to_string())?;
      info!("{} created!",final_path.bold());
   }
   else
   {
      json_result.insert("groups.json".to_string(),groups_json.to_owned().to_string());
   }

   Ok(())
}

/// Function to create the computers.json file.
pub fn add_computer(
	domain_format: &String,
   computer: Vec<serde_json::value::Value>,
   path: &String, json_result: &mut HashMap<String, String>,
   zip: bool
) -> std::io::Result<()>
{
   debug!("Making computers.json");

   // Prepare template and get result in const var
   let mut computers_json = bh_41::prepare_final_json_file_template(BLOODHOUND_VERSION_4, "computers".to_owned());
   // Add all computers found
   computers_json["data"] = computer.into();
   // change count number
   let stream = computers_json["data"].as_array().unwrap();
   let count = stream.len();

   computers_json["meta"]["count"] = count.into();
   info!("{} computers parsed!",count.to_string().bold());

   // result
   fs::create_dir_all(path)?;

   if ! zip 
   {
      let mut final_path = path.to_owned();
      final_path.push_str("/");
      final_path.push_str(domain_format);
      final_path.push_str("_computers.json");    
      fs::write(&final_path, &computers_json.to_string())?;
      info!("{} created!",final_path.bold());
   }
   else
   {
      json_result.insert("computers.json".to_string(),computers_json.to_owned().to_string());
   }

   Ok(())
}


/// Function to create the ous.json file.
pub fn add_ou(
	domain_format: &String,
   ou: Vec<serde_json::value::Value>,
   path: &String,
   json_result: &mut HashMap<String, String>,
   zip: bool
) -> std::io::Result<()>
{
   debug!("Making ous.json");

   // Prepare template and get result in const var
   let mut ous_json = bh_41::prepare_final_json_file_template(BLOODHOUND_VERSION_4, "ous".to_owned());
   // Add all ous found
   ous_json["data"] = ou.into();
   // change count number
   let stream = ous_json["data"].as_array().unwrap();
   let count = stream.len();

   ous_json["meta"]["count"] = count.into();
   info!("{} ous parsed!",count.to_string().bold());

   // result
   fs::create_dir_all(path)?;

   if ! zip 
   {
      let mut final_path = path.to_owned();
      final_path.push_str("/");
      final_path.push_str(domain_format);
      final_path.push_str("_ous.json");
      fs::write(&final_path, &ous_json.to_string())?;
      info!("{} created!",final_path.bold());
   }
   else
   {
      json_result.insert("ous.json".to_string(),ous_json.to_owned().to_string());
   }

   Ok(())
}

/// Function to create the domains.json file.
pub fn add_domain(
	domain_format: &String,
   domain: Vec<serde_json::value::Value>,
   path: &String,
   json_result: &mut HashMap<String, String>,
   zip: bool
) -> std::io::Result<()>
{
   debug!("Making domains.json");

   // Prepare template and get result in const var
   let mut domains_json = bh_41::prepare_final_json_file_template(BLOODHOUND_VERSION_4, "domains".to_owned());
   // Add all domains found
   domains_json["data"] = domain.into();
   // change count number
   let stream = domains_json["data"].as_array().unwrap();
   let count = stream.len();

   domains_json["meta"]["count"] = count.into();
   info!("{} domains parsed!",count.to_string().bold());

   // result
   fs::create_dir_all(path)?;

   if ! zip 
   {
      let mut final_path = path.to_owned();
      final_path.push_str("/");
      final_path.push_str(domain_format);
      final_path.push_str("_domains.json");    
      fs::write(&final_path, &domains_json.to_string())?;
      info!("{} created!",final_path.bold());
   }
   else
   {
      json_result.insert("domains.json".to_string(),domains_json.to_owned().to_string());
   }

   Ok(())
}

/// Function to create the gpos.json file.
pub fn add_gpo(
	domain_format: &String,
   gpo: Vec<serde_json::value::Value>,
   path: &String,
   json_result: &mut HashMap<String, String>,
   zip: bool
) -> std::io::Result<()>
{
   debug!("Making gpos.json");

   // Prepare template and get result in const var
   let mut gpos_json = bh_41::prepare_final_json_file_template(BLOODHOUND_VERSION_4, "gpos".to_owned());
   // Add all gpos found
   gpos_json["data"] = gpo.into();
   // change count number
   let stream = gpos_json["data"].as_array().unwrap();
   let count = stream.len();

   gpos_json["meta"]["count"] = count.into();
   info!("{} gpos parsed!", count.to_string().bold());

   // result
   fs::create_dir_all(path)?;

   if ! zip 
   {
      let mut final_path = path.to_owned();
      final_path.push_str("/");
      final_path.push_str(domain_format);
      final_path.push_str("_gpos.json");    
      fs::write(&final_path, &gpos_json.to_string())?;
      info!("{} created!",final_path.bold());
   }
   else
   {
      json_result.insert("gpos.json".to_string(),gpos_json.to_owned().to_string());
   }

   Ok(())
}

/// Function to create the containers.json file.
pub fn add_container(
	domain_format: &String,
   container: Vec<serde_json::value::Value>,
   path: &String,
   json_result: &mut HashMap<String, String>,
   zip: bool
) -> std::io::Result<()>
{
   debug!("Making containers.json");

   // Prepare template and get result in const var
   let mut containers_json = bh_41::prepare_final_json_file_template(BLOODHOUND_VERSION_4, "containers".to_owned());
    
   // Add all containers found
   containers_json["data"] = container.into();
   // change count number
   let stream = containers_json["data"].as_array().unwrap();
   let count = stream.len();

   containers_json["meta"]["count"] = count.into();
   info!("{} containers parsed!", count.to_string().bold());

   // result
   fs::create_dir_all(path)?;

   if ! zip 
   {
      let mut final_path = path.to_owned();
      final_path.push_str("/");
      final_path.push_str(domain_format);
      final_path.push_str("_containers.json");    
      fs::write(&final_path, &containers_json.to_string())?;
      info!("{} created!",final_path.bold());
   }
   else
   {
      json_result.insert("containers.json".to_string(),containers_json.to_owned().to_string());
   }

   Ok(())
}