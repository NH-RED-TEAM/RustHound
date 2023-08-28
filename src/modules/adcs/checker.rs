use colored::Colorize;
use std::collections::HashMap;
use log::{info, debug, trace, error};

use std::io::prelude::*;
use std::net::TcpStream;
use std::str;

use crate::modules::resolver::resolv;

/// Check if template is enabled
pub fn check_enabled_template(
    vec_cas: &mut Vec<serde_json::value::Value>,
    vec_templates: &mut Vec<serde_json::value::Value>,
    adcs_templates: &mut HashMap<String, Vec<String>>,
    old_bloodhound: bool,
) {
    for i in 0..vec_templates.len() {
        for ca in adcs_templates.to_owned() {
            if ca.1.contains(&vec_templates[i]["Properties"]["Display Name"].as_str().unwrap().to_string()) {
                trace!("Certificate template {} enabled",&vec_templates[i]["Properties"]["Display Name"].as_str().unwrap().to_string().green().bold());
                vec_templates[i]["Properties"]["Enabled"] = true.into();
                
                // Is @ly4k BloodHound version?
                if !old_bloodhound {
                    let mut vcasids: Vec<String> = Vec::new();
                    vcasids.push(ca.0.to_string());
                    vec_templates[i]["cas_ids"] = vcasids.into();
                }

                // Push CANAME in the Template
                let mut caname = Vec::new();
                for j in 0..vec_cas.len() {
                    if ca.0.contains(&vec_cas[j]["ObjectIdentifier"].as_str().unwrap().to_string()) {
                        caname.push(vec_cas[j]["Properties"]["CA Name"].as_str().unwrap().to_string());
                    } else {
                        continue
                    }
                }
                vec_templates[i]["Properties"]["Certificate Authorities"] = caname.to_owned().into(); 
            }
        }
    }
}

/// Get web_enrollment, user_specified_san, request_disposition configuration
pub async fn get_conf(
    vec_cas: &mut Vec<serde_json::value::Value>,
    dc_only: bool,
    dns_tcp: bool,
    name_server: &String,
) {
    for i in 0..vec_cas.len() {
        if dc_only {
            vec_cas[i]["Properties"]["Web Enrollment"] = String::from("Unknown").into();
            vec_cas[i]["Properties"]["User Specified SAN"] = String::from("Unknown").into();
            vec_cas[i]["Properties"]["Request Disposition"] = String::from("Unknown").into();
        } else {
            // Checking if web enrollment is enabled
            let web_enrollment = web_enrollment(
                vec_cas[i]["Properties"]["DNS Name"].as_str().unwrap().to_string(),
                dns_tcp,
                name_server,
            ).await;
            vec_cas[i]["Properties"]["Web Enrollment"] = web_enrollment.to_owned().into(); 
            vec_cas[i]["Properties"]["User Specified SAN"] = String::from("Unknown").into();
            vec_cas[i]["Properties"]["Request Disposition"] = String::from("Unknown").into();
        }
    }
}


/// HEAD request on /certsrv/ to check web enrrollment
async fn web_enrollment(
    target: String,
    dns_tcp: bool,
    name_server: &String,
) -> String {

    debug!("Checking web enrollment on {}",&target);
    let ip = resolv::resolver(
        target.to_owned(),
        dns_tcp,
        name_server).await;
    let url = format!("http://{}/certsrv/",target);
    trace!("Resolved {} to {}",&target,&ip);

    if let Ok(mut stream) = TcpStream::connect(format!("{}:80",&ip)) 
    {
        trace!("Connected to the server {}",format!("http://{}/certsrv/",target.to_owned()).bold().green());
        // Send HTTP HEAD request
        stream.set_read_timeout(None).expect("set_read_timeout call failed");
        stream.write(format!("HEAD /certsrv/ HTTP/1.1\nHost: {}\r\n\n",target.to_owned()).as_bytes()).unwrap();

        // Waiting for response
        let mut buffer = [0; 256];
        let result = stream.read(&mut buffer[..]).unwrap();
        trace!("Result: {:?}", str::from_utf8(&buffer[..result][..]));

        // If response not contain 404 status code enrollment is enabled
        if !str::from_utf8(&buffer[..result][..]).unwrap_or("Error").contains(&"404".to_string()) 
        {
            info!("Web enrollment {} on {}","enabled".bold().green(),&url.bold());
            return "Enabled".to_string()
        } else {
            return "Disabled".to_string()
        }
    } else 
    {
        error!("Couldn't connect to server {}, please try manually and check for https access if EPA is enable.",format!("http://{}/certsrv/",target).bold().red());
    }
    return "Unknown".to_string()
}