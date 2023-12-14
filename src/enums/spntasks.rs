use crate::objects::common::SPNTarget;
//use log::trace;

/// Function to check if spns start with mssqlsvc to make SPNTargets
/// <https://github.com/BloodHoundAD/SharpHound3/blob/master/SharpHound3/Tasks/SPNTasks.cs#L22>
pub fn check_spn(serviceprincipalname: &String) -> Option<SPNTarget>
{
   if serviceprincipalname.to_lowercase().contains("mssqlsvc")
   {
      let mut mssqlsvc_spn = SPNTarget::new();

      //trace!("{:?}",serviceprincipalname);
      if serviceprincipalname.to_lowercase().contains(":")
      {
         let split = serviceprincipalname.split(":");
         let vec = split.collect::<Vec<&str>>();
         let mut fqdn = vec[0].to_owned();
         let value = vec[1].to_owned();

         //trace!("{:?}",value);
         let port = value.parse::<i32>().unwrap_or(1433);

         // I temporarily add the fqdn which will be replaced by the SID at the end of the parsing.
         // This avoids making a new request to the LDAP server and parsing off-line.
         let split = fqdn.split("/");
         let vec = split.collect::<Vec<&str>>();
         fqdn = vec[1].to_owned().to_uppercase();

         //trace!("{:?}",fqdn);
         *mssqlsvc_spn.computer_sid_mut() = fqdn;
         *mssqlsvc_spn.port_mut() = port;
      }
      else
      {
         // I temporarily add the fqdn which will be replaced by the SID at the end of the parsing.
         // This avoids making a new request to the LDAP server and parsing off-line.
         let split = serviceprincipalname.split("/");
         let vec = split.collect::<Vec<&str>>();
         let fqdn = vec[1].to_owned().to_uppercase();
         let port = 1433;
         
         //trace!("{:?}",fqdn);
         *mssqlsvc_spn.computer_sid_mut() = fqdn;
         *mssqlsvc_spn.port_mut() = port;
      }
      Some(mssqlsvc_spn)
   }
   else {
      None
   }
}