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

/// Current Bloodhound version 4.2+
pub const BLOODHOUND_VERSION_4: i8 = 5;

/// This function will create json output and zip output
pub fn make_result(
   zip: bool,
   path: &String,
   domain: &String,
   vec_users: Vec<serde_json::value::Value>,
   vec_groups: Vec<serde_json::value::Value>,
   vec_computers: Vec<serde_json::value::Value>,
   vec_ous: Vec<serde_json::value::Value>,
   vec_domains: Vec<serde_json::value::Value>,
   vec_gpos: Vec<serde_json::value::Value>,
   vec_containers: Vec<serde_json::value::Value>,
) -> std::io::Result<()>
{
   // Format domain name
   let filename = domain.replace(".", "-").to_lowercase();

   // Hashmap for json files
   let mut json_result = HashMap::new();

   // Add all in json files
   add_file(
      "users".to_string(),
		&filename,
      vec_users,
      path,&mut json_result,
      zip,
   )?;
   add_file(
      "groups".to_string(),
		&filename,
      vec_groups,
      path,
      &mut json_result,
      zip,
   )?;
   add_file(
      "computers".to_string(),
		&filename,
      vec_computers,
      path,
      &mut json_result,
      zip,
   )?;
   add_file(
      "ous".to_string(),
		&filename,
      vec_ous,
      path,
      &mut json_result,
      zip,
   )?;
   add_file(
      "domains".to_string(),
		&filename,
      vec_domains,
      path,
      &mut json_result,
      zip,
   )?;
   add_file(
      "gpos".to_string(),
		&filename,
      vec_gpos,
      path,
      &mut json_result,
      zip,
   )?;
   add_file(
      "containers".to_string(),
		&filename,
      vec_containers,
      path,
      &mut json_result,
      zip,
   )?;
   // All in zip file
   if zip {
      make_a_zip(
         &filename,
         path,
         &json_result);
   }
   Ok(())
}

/// Function to create the .json file.
fn add_file(
   name: String,
	domain_format: &String,
   vec_json: Vec<serde_json::value::Value>,
   path: &String,
   json_result: &mut HashMap<String, String>,
   zip: bool
) -> std::io::Result<()>
{
   debug!("Making {}.json",&name);

   // Prepare template and get result in const var
   let mut final_json = bh_41::prepare_final_json_file_template(BLOODHOUND_VERSION_4, name.to_owned());
    
   // Add all object found
   final_json["data"] = vec_json.into();
   // change count number
   let stream = final_json["data"].as_array().unwrap();
   let count = stream.len();

   final_json["meta"]["count"] = count.into();
   info!("{} {} parsed!", count.to_string().bold(),&name);

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