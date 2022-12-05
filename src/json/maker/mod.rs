use std::collections::HashMap;
use colored::Colorize;
use log::{info,debug,trace};

use std::fs;
use std::fs::File;
use std::io::{Seek, Write};
use zip::result::ZipResult;
use zip::write::{FileOptions, ZipWriter};

extern crate zip;
use crate::json::templates::*;
use crate::args::Options;

/// Current Bloodhound version 4.2+
pub const BLOODHOUND_VERSION_4: i8 = 5;

/// This function will create json output and zip output
pub fn make_result(
   common_args: &Options,
   vec_users: Vec<serde_json::value::Value>,
   vec_groups: Vec<serde_json::value::Value>,
   vec_computers: Vec<serde_json::value::Value>,
   vec_ous: Vec<serde_json::value::Value>,
   vec_domains: Vec<serde_json::value::Value>,
   vec_gpos: Vec<serde_json::value::Value>,
   vec_containers: Vec<serde_json::value::Value>,
   vec_cas: &mut Vec<serde_json::value::Value>,
   vec_templates: &mut Vec<serde_json::value::Value>,
) -> std::io::Result<()>
{
   // Format domain name
   let filename = common_args.domain.replace(".", "-").to_lowercase();

   // Hashmap for json files
   let mut json_result = HashMap::new();

   // Add all in json files
   add_file(
      "users".to_string(),
		&filename,
      vec_users,
      &mut json_result,
      common_args,
   )?;
   add_file(
      "groups".to_string(),
		&filename,
      vec_groups,
      &mut json_result,
      common_args,
   )?;
   add_file(
      "computers".to_string(),
		&filename,
      vec_computers,
      &mut json_result,
      common_args,
   )?;
   add_file(
      "ous".to_string(),
		&filename,
      vec_ous,
      &mut json_result,
      common_args,
   )?;
   add_file(
      "domains".to_string(),
		&filename,
      vec_domains,
      &mut json_result,
      common_args,
   )?;
   // Not @ly4k BloodHound version?
   if common_args.old_bloodhound {
      let mut _vec_gpos_cas_templates = vec_gpos.to_owned();
      info!("{} {} parsed!", &vec_cas.len().to_string().bold(),&"cas");
      _vec_gpos_cas_templates.append(vec_cas);
      info!("{} {} parsed!", &vec_templates.len().to_string().bold(),&"templates");
      _vec_gpos_cas_templates.append(vec_templates);
      info!("{} {} parsed!", &vec_gpos.len().to_string().bold(),&"gpos");
      add_file(
         "gpos".to_string(),
         &filename,
         _vec_gpos_cas_templates.to_vec(),
         &mut json_result,
         common_args,
      )?;
   } else {
      // Is @ly4k BloodHound version?
      add_file(
         "gpos".to_string(),
         &filename,
         vec_gpos,
         &mut json_result,
         common_args,
      )?;
   }
   add_file(
      "containers".to_string(),
		&filename,
      vec_containers,
      &mut json_result,
      common_args,
   )?;
   // ADCS and is @ly4k BloodHound version?
   if common_args.adcs && !common_args.old_bloodhound {
      add_file(
         "cas".to_string(),
         &filename,
         vec_cas.to_vec(),
         &mut json_result,
         common_args,
      )?;
      add_file(
         "templates".to_string(),
         &filename,
         vec_templates.to_vec(),
         &mut json_result,
         common_args,
      )?;
   }
   // All in zip file
   if common_args.zip {
      make_a_zip(
         &filename,
         &common_args.path,
         &json_result);
   }
   Ok(())
}

/// Function to create the .json file.
fn add_file(
   name: String,
	domain_format: &String,
   vec_json: Vec<serde_json::value::Value>,
   json_result: &mut HashMap<String, String>,
   common_args: &Options, 
) -> std::io::Result<()>
{
   debug!("Making {}.json",&name);

   let path = &common_args.path;
   let zip = common_args.zip;

   // Prepare template and get result in const var
   let mut final_json = bh_41::prepare_final_json_file_template(BLOODHOUND_VERSION_4, name.to_owned());
    
   // Add all object found
   final_json["data"] = vec_json.to_owned().into();
   // change count number
   let count = vec_json.len();
   final_json["meta"]["count"] = count.into();

   if &name != "gpos" || !common_args.old_bloodhound {
      info!("{} {} parsed!", count.to_string().bold(),&name);
   }

   // result
   fs::create_dir_all(path)?;

   // Create json file if isn't zip
   if ! zip 
   {
      let mut final_path = path.to_owned();
      final_path.push_str("/");
      final_path.push_str(domain_format);
      final_path.push_str(format!("_{}.json",&name).as_str());    
      fs::write(&final_path, &final_json.to_string())?;
      info!("{} created!",final_path.bold());
   }
   else
   {
      json_result.insert(format!("{}.json",name).to_string(),final_json.to_owned().to_string());
   }

   Ok(())
}

/// Function to compress the JSON files into a zip archive
fn make_a_zip(
   domain: &String,
   path: &String,
   json_result: &HashMap<String, String>
){
   let mut final_path = path.to_owned();
   final_path.push_str("/");
   final_path.push_str(domain);
   final_path.push_str("_rusthound_result.zip");

   let mut file = File::create(&final_path).expect("Couldn't create file");
   create_zip_archive(&mut file, json_result).expect("Couldn't create archive");

   info!("{} created!",&final_path.bold());
}


fn create_zip_archive<T: Seek + Write>(zip_filename: &mut T,json_result: &HashMap<String, String>) -> ZipResult<()> {
   let mut writer = ZipWriter::new(zip_filename);
   // json file by json file
   trace!("Making the ZIP file");

   for file in json_result
   {
      let filename = file.0;
      let content = file.1;
      trace!("Adding file {}",filename.bold());
      writer.start_file(filename, FileOptions::default())?;
      writer.write_all(content.as_bytes())?;
   }

   writer.finish()?;
   Ok(())
}