use regex::Regex;
use crate::objects::common::Link;

/// Function to parse gplink and push it in json format
pub fn parse_gplink(all_link: String) -> Vec<Link>
{
   let mut gplinks: Vec<Link> = Vec::new();

   let re = Regex::new(r"[a-zA-Z0-9-]{36}").unwrap();
   let mut cpaths: Vec<String> = Vec::new();
   for cpath in re.captures_iter(&all_link)
   {
      cpaths.push(cpath[0].to_owned());
   }

   let re2 = Regex::new(r"[;][0-4]{1}").unwrap();
   let mut status: Vec<String> = Vec::new();
   for enforced in re2.captures_iter(&all_link){
      status.push(enforced[0].to_owned());
   }

   for i in 0..cpaths.len()
   {
      let mut gplink = Link::new(false, cpaths[i].to_string());
      
      // Thanks to: https://techibee.com/group-policies/find-link-status-and-enforcement-status-of-group-policies-using-powershell/2424
      if status[i].to_string().contains(";2") | status[i].to_string().contains(";3") {
         *gplink.is_enforced_mut() = true;
      }

      //trace!("gpo link: {:?}",cpaths[i]);
      gplinks.push(gplink);
   }

   return gplinks
}