use regex::Regex;
use crate::json::templates::bh_41::prepare_gplink_json_template;

/// Function to parse gplink and push it in json format
pub fn parse_gplink(all_link: String) -> Vec<serde_json::value::Value>
{
   let mut gplinks: Vec<serde_json::value::Value> = Vec::new();

   let re = Regex::new(r"[a-zA-Z0-9-]{36}").unwrap();
   let mut cpaths: Vec<String> = Vec::new();
   for cpath in re.captures_iter(&all_link)
   {
      cpaths.push(cpath[0].to_owned().to_string());
   }

   let re2 = Regex::new(r"[;][0-4]{1}").unwrap();
   let mut status: Vec<String> = Vec::new();
   for enforced in re2.captures_iter(&all_link){
      status.push(enforced[0].to_owned().to_string());
   }

   for i in 0..cpaths.len()
   {
      let mut gplink = prepare_gplink_json_template();
      gplink["GUID"] = cpaths[i].to_string().into();
      
      // Thanks to: https://techibee.com/group-policies/find-link-status-and-enforcement-status-of-group-policies-using-powershell/2424
      if status[i].to_string().contains(";2"){
         gplink["IsEnforced"] = true.into();
      }
      if status[i].to_string().contains(";3"){
         gplink["IsEnforced"] = true.into();
      }

      //trace!("gpo link: {:?}",cpaths[i]);
      gplinks.push(gplink);
   }

   return gplinks
}