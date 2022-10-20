use std::collections::HashMap;
use colored::Colorize;
use log::{info,trace,error};

extern crate zip;
use std::fs::File;
use std::io::{Seek, Write};
use zip::result::ZipResult;
use zip::write::{FileOptions, ZipWriter};

pub mod bh_41;

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
   let domain_format = domain.replace(".", "-").to_lowercase();

   // Hashmap for json files
   let mut json_result = HashMap::new();

   // zip not really work on Windows / macOS yet
   let mut ziped = zip;
    if !cfg!(unix) && zip == true  {
      error!("Sorry but zip function doesn't really work for Windows/macOS yet.");
      ziped = false;
   }
   // Add all in json files
   bh_41::add_user(
		&domain_format,
      vec_users,
      path,&mut json_result,
      ziped,
   )?;
   bh_41::add_group(
		&domain_format,
      vec_groups,
      path,
      &mut json_result,
      ziped,
   )?;
   bh_41::add_computer(
		&domain_format,
      vec_computers,
      path,
      &mut json_result,
      ziped,
   )?;
   bh_41::add_ou(
		&domain_format,
      vec_ous,
      path,
      &mut json_result,
      ziped,
   )?;
   bh_41::add_domain(
		&domain_format,
      vec_domains,
      path,
      &mut json_result,
      ziped,
   )?;
   bh_41::add_gpo(
		&domain_format,
      vec_gpos,
      path,
      &mut json_result,
      ziped,
   )?;
   bh_41::add_container(
		&domain_format,
      vec_containers,
      path,
      &mut json_result,
      ziped,
   )?;
   // All in zip file
   if ziped {
      make_a_zip(
         &domain_format,
         path,
         &json_result);
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