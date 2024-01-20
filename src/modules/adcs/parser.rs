extern crate lazy_static;

use lazy_static::lazy_static;
use colored::Colorize;
use ldap3::SearchEntry;
use x509_parser::prelude::*;
use std::collections::HashMap;
use log::{info, debug, trace, error};

use crate::enums::sid::decode_guid;
use crate::enums::acl::parse_ntsecuritydescriptor;
use crate::json::templates::bh_41::{prepare_adcs_ca_json_template,prepare_adcs_template_json_template};
use crate::modules::adcs::utils::*;
use crate::modules::adcs::flags::*;

#[derive(Debug)]
pub struct CA {
    pub domain: String,
    pub name: String,
    pub dnshostname: String,
    pub object_id: String,
    pub user_specified_san: String,
    pub request_disposition: String,
    pub security: Vec<serde_json::value::Value>,
    pub web_enrollment: String,
    pub subject_name: String,
    pub serial_number: String,
    pub validity_start: String,
    pub validity_end: String,
    pub enabled_templates: Vec<String>
}

impl CA {
    pub fn new(domain: &String) -> CA {
        CA {
            domain: String::from(domain.to_uppercase()),
            name: String::from("name"),
            dnshostname: String::from("name"),
            object_id: String::from("object_id"),
            user_specified_san: String::from("Unknown"),
            request_disposition: String::from("Unknown"),
            security: Vec::new(),
            web_enrollment: String::from("Unknown"),
            subject_name: String::from("subject_name"),
            serial_number: String::from("serial_number"),
            validity_start: String::from("validity_start"),
            validity_end: String::from("validity_end"),
            enabled_templates: Vec::new(),
        }
    }
}

/// Function to parse and replace value in json template for Certificate Authority domain object.
pub fn parse_adcs_ca(
    result: SearchEntry,
    domain: &String,
    adcs_templates: &mut HashMap<String, Vec<String>>,
    old_bloodhound: bool,
) -> serde_json::value::Value  {

    let result_dn: String;
    result_dn = result.dn.to_uppercase();

    let result_attrs: HashMap<String, Vec<String>>;
    result_attrs = result.attrs;

    let result_bin: HashMap<String, Vec<Vec<u8>>>;
    result_bin = result.bin_attrs;

    let mut ca_json = prepare_adcs_ca_json_template();

    // Prepare struct for this CA
    let mut ca = CA::new(domain);

    // Debug for current object
    debug!("Parse (CA) Certificate Authority: {}", result_dn);
    //for (key, value) in &result_attrs {
    //    trace!("  {:?}:{:?}", key, value);
    //}
    ////trace result bin
    //for (key, value) in &result_bin {
    //    trace!("  {:?}:{:?}", key, value);
    //}

    // With a check
    for (key, value) in &result_attrs {
        match key.as_str() {
            "name" => {
                ca.name = value[0].to_owned().to_uppercase();
                ca_json["Properties"]["name"] = format!("{}@{}",ca.name,ca.domain).into();
                ca_json["Properties"]["CA Name"] = value[0].to_owned().to_uppercase().into();
                ca_json["Properties"]["domain"] = domain.to_owned().to_uppercase().into();
            }
            "cACertificateDN" => {
                ca.subject_name = value[0].to_owned();
                ca_json["Properties"]["Certificate Subject"] = ca.subject_name.to_owned().into();
                trace!("cACertificateDN: {}",&ca.subject_name);
            }
            "dNSHostName" => {
                ca.dnshostname = value[0].to_owned();
                ca_json["Properties"]["DNS Name"] = ca.dnshostname.to_owned().into();
            }
            "certificateTemplates" => {
                if value.len() <= 0 {
                    error!("No certificate templates enabled for {}",ca.name);
                } else {
                    ca.enabled_templates = value.to_vec();
                    info!("Found {} enabled certificate templates",value.len().to_string().bold());
                    trace!("Enabled certificate templates: {:?}",value);
                }
            }
            _ => {}
        }
    }
    // For all, bins attributs
    for (key, value) in &result_bin {
        match key.as_str() {
            "objectGUID" => {
                // objectGUID raw to string
                ca.object_id = decode_guid(&value[0]);
                ca_json["ObjectIdentifier"] = ca.object_id.to_owned().into();
            }
            "nTSecurityDescriptor" => {
                // Needed with acl
                let entry_type = "ca".to_string();
                // nTSecurityDescriptor raw to string
                let relations_ace = parse_ntsecuritydescriptor(
                    &mut ca_json,
                    &value[0],
                    entry_type,
                    &result_attrs,
                    &result_bin,
                    &domain,
                );
                ca.security = relations_ace.to_owned();
                ca_json["Aces"] = relations_ace.into();
            }
            "cACertificate" => {
                //info!("{:?}:{:?}", key,value[0].to_owned());
                // <https://docs.rs/x509-parser/latest/x509_parser/certificate/struct.X509Certificate.html>
                let res = X509Certificate::from_der(&value[0]);
                match res {
                    Ok((_rem, cert)) => {
                        //trace!("Certificate: {:?}",cert);
                        ca.serial_number = cert.tbs_certificate.raw_serial_as_string().replace(":","").to_uppercase();
                        ca_json["Properties"]["Certificate Serial Number"] = ca.serial_number.to_owned().to_uppercase().into();
                        trace!("Certificate Serial Number: {:?}",&ca.serial_number);

                        ca.validity_start = cert.validity().not_before.to_datetime().to_string();
                        ca_json["Properties"]["Certificate Validity Start"] = ca.validity_start.to_owned().into();
                        trace!("Certificate Validity Start: {:?}",&ca.validity_start);

                        ca.validity_end = cert.validity().not_after.to_datetime().to_string();
                        ca_json["Properties"]["Certificate Validity End"] = ca.validity_end.to_owned().into();
                        trace!("Certificate Validity End: {:?}",&ca.validity_end);

                    },
                    _ => error!("CA x509 certificate parsing failed: {:?}", res),
                }
            }
            _ => {}
        }
    }
    
    // Not @ly4k BloodHound version?
    if old_bloodhound {
        ca_json["Properties"]["type"] = "Enrollment Service".to_string().into();
    }

    // Push Certificate Template enable
    adcs_templates.insert(
            ca.object_id.to_owned(),
            ca.enabled_templates.to_owned(),
    );

    //trace!("CA VALUE: {:?}",ca_json);
    return ca_json
}


#[derive(Debug)]
pub struct Template {
    pub name: String,
    pub object_id: String,
    pub enrollment_agent: bool,
    pub certificate_name_flag: Vec<String>,
    pub enrollment_flag: Vec<String>,
    pub private_key_flag: Vec<String>,
    pub application_policies: Vec<String>,
    pub extended_key_usage: Vec<String>,
    pub any_purpose: bool,
    pub client_authentication: bool,
    pub requires_manager_approval: bool,
    pub enrollee_supplies_subject: bool,
    pub no_security_extension: bool,
    pub requires_key_archival: bool,
    pub authorized_signatures_required: u64,
    pub validity_period: String,
    pub renewal_period: String,
    pub domain: String,
}

impl Template {
    pub fn new(domain: &String) -> Template {
        Template {
            name: String::from("name"),
            object_id: String::from("object_id"),
            enrollment_agent: false,
            certificate_name_flag: Vec::new(),
            enrollment_flag: Vec::new(),
            private_key_flag: Vec::new(),
            application_policies: Vec::new(),
            extended_key_usage: Vec::new(),
            any_purpose: false,
            client_authentication: false,
            enrollee_supplies_subject: false,
            requires_manager_approval: false,
            no_security_extension: false,
            requires_key_archival: false,
            authorized_signatures_required: 0,
            validity_period: String::from("validity_period"),
            renewal_period: String::from("renewal_period"),
            domain: String::from(domain.to_uppercase()),
        }
    }
}

/// Function to parse and replace value in json for Certificate template object.
pub fn parse_adcs_template(
    result: SearchEntry,
    domain: &String,
    old_bloodhound: bool,
) -> serde_json::value::Value  {

    let result_dn: String = result.dn.to_uppercase();
    let result_attrs: HashMap<String, Vec<String>> = result.attrs;
    let result_bin: HashMap<String, Vec<Vec<u8>>> = result.bin_attrs;

    let mut template_json = prepare_adcs_template_json_template();

    // Debug for current object
    debug!("Parse Certificate Template: {}", result_dn);
    //for (key, value) in &result_attrs {
    //    trace!("att  {:?}:{:?}", key, value);
    //}
    ////trace result bin
    //for (key, value) in &result_bin {
    //    trace!("bin  {:?}:{:?}", key, value);
    //}

    // Prepare struct for this Template
    let mut template = Template::new(domain);

    // With a check
    for (key, value) in &result_attrs {
        match key.as_str() {
            "name" => {
                template.name = value[0].to_owned();
                template_json["Properties"]["name"] = format!("{}@{}",template.name.to_owned().to_uppercase(),template.domain.to_owned()).into();
                template_json["Properties"]["Template Name"] = template.name.to_owned().into();
                template_json["Properties"]["domain"] = domain.to_owned().to_uppercase().into();
            }
            "displayName" => {
                template_json["Properties"]["Display Name"] = value[0].to_owned().into();
            }
            "msPKI-Certificate-Name-Flag" => {
                if value.len() != 0 {
                    template.certificate_name_flag = get_pki_cert_name_flags(
                        &mut template,
                        &mut template_json,
                        value[0].parse::<i64>().unwrap_or(0) as u64
                    );
                    template_json["Properties"]["Certificate Name Flag"] = template.certificate_name_flag.to_owned().into();
                } else {
                    let mut res: Vec<String> = Vec::new();
                    res.push("None".to_string());
                    template.certificate_name_flag = res;
                    template_json["Properties"]["Certificate Name Flag"] = template.certificate_name_flag.to_owned().into();
                }
            }
            "msPKI-Enrollment-Flag" => {
                if value.len() != 0 {
                    template.enrollment_flag = get_pki_enrollment_flags(
                        &mut template,
                        &mut template_json,
                        value[0].parse::<i64>().unwrap_or(0) as u64
                    );
                    template_json["Properties"]["Enrollment Flag"] = template.enrollment_flag.to_owned().into();
                } else {
                    let mut res: Vec<String> = Vec::new();
                    res.push("None".to_string());
                    template.enrollment_flag = res;
                    template_json["Properties"]["Enrollment Flag"] = template.enrollment_flag.to_owned().into();
                }
            }
            "msPKI-Private-Key-Flag" => {
                if value.len() != 0 {
                    template.private_key_flag = get_pki_private_flags(
                        &mut template,
                        &mut template_json,
                        value[0].parse::<i64>().unwrap_or(0) as u64
                    );
                    template_json["Properties"]["Private Key Flag"] = template.private_key_flag.to_owned().into();
                } else {
                    let mut res: Vec<String> = Vec::new();
                    res.push("None".to_string());
                    template.private_key_flag = res;
                    template_json["Properties"]["Private Key Flag"] = template.private_key_flag.to_owned().into();
                }
            }
            "msPKI-RA-Signature" => {
                if value.len() != 0 {
                    template.authorized_signatures_required = value[0].parse::<i64>().unwrap_or(0) as u64;
                    template_json["Properties"]["Authorized Signatures Required"] = template.authorized_signatures_required.to_owned().into();
                } else {
                    template.authorized_signatures_required = 0;
                    template_json["Properties"]["Authorized Signatures Required"] = template.authorized_signatures_required.to_owned().into();
                }
            }
            "msPKI-RA-Application-Policies" => {
                // parsed but not use with ly4k BloodHound version
                if value.len() != 0 {
                    let application_policies = value;
                    let mut values = Vec::new();
                    for oid in application_policies {
                        if OID_TO_STR_MAP.contains_key(oid){
                            values.push(OID_TO_STR_MAP.get(oid).unwrap().to_string());
                        }
                        continue
                    }
                    template.application_policies = values;
                }
            }
            "pKIExtendedKeyUsage" => {
                if value.len() != 0 {
                    let eku = value;
                    let mut values = Vec::new();
                    for oid in eku {
                        if OID_TO_STR_MAP.contains_key(oid){
                            values.push(OID_TO_STR_MAP.get(oid).unwrap().to_string());
                        }
                        continue
                    }
                    template.extended_key_usage = values;
                    template_json["Properties"]["Extended Key Usage"] = template.extended_key_usage.to_owned().into();
                } 
            }
            _ => {}
        }
    }
    // For all, bins attributs
    for (key, value) in &result_bin {
        match key.as_str() {
            "objectGUID" => {
                // objectGUID raw to string
                template_json["ObjectIdentifier"] = decode_guid(&value[0]).to_owned().into();
            }
            "pKIExpirationPeriod" => {
                template.validity_period = span_to_string(filetime_to_span(value[0].to_owned()));
                template_json["Properties"]["Validity Period"] = template.validity_period.to_owned().into();
            }
            "pKIOverlapPeriod" => {
                template.renewal_period = span_to_string(filetime_to_span(value[0].to_owned()));
                template_json["Properties"]["Renewal Period"] = template.renewal_period.to_owned().into();
            }
            "nTSecurityDescriptor" => {
                // Needed with acl
                let entry_type = "template".to_string();
                // nTSecurityDescriptor raw to string
                let relations_ace = parse_ntsecuritydescriptor(
                    &mut template_json,
                    &value[0],
                    entry_type,
                    &result_attrs,
                    &result_bin,
                    &domain,
                );
                template_json["Aces"] = relations_ace.into();
            }
            _ => {}
        }
    }

    // Other values
    // Any Purpose
    if template.extended_key_usage.contains(&"Any Purpose".to_string()) || template.extended_key_usage.len() == 0 {
        template.any_purpose = true;
        template_json["Properties"]["Any purpose"] = template.any_purpose.to_owned().into();
    }
    
    // Client Authentification
    let mut isineku = false;
    for eku in &template.extended_key_usage {
        if vec!["Client Authentication","Smart Card Logon","PKINIT Client Authentication"].contains(&eku.as_str()) {
            isineku = true;
        }
    }
    template.client_authentication = template.any_purpose || isineku;
    template_json["Properties"]["Client Authentication"] = template.client_authentication.to_owned().into();

    // Enrollment Agent
    let mut isineku = false;
    for eku in &template.extended_key_usage {
        if vec!["Certificate Request Agent"].contains(&eku.as_str()) {
            isineku = true;
        }
    }
    template.enrollment_agent = template.any_purpose || isineku;
    template_json["Properties"]["Enrollment Agent"] = template.enrollment_agent.to_owned().into();

    // highvalue
    if template.enrollee_supplies_subject && !template.requires_manager_approval && template.client_authentication {
        template_json["Properties"]["highvalue"] = true.into();
    } else if template.enrollment_agent && !template.requires_manager_approval {
        template_json["Properties"]["highvalue"] = true.into();
    } else {
        template_json["Properties"]["highvalue"] = false.into();
    }

        
    // Not @ly4k BloodHound version?
    if old_bloodhound {
        template_json["Properties"]["type"] = "Certificate Template".to_string().into();
    }
    
    //trace!("TEMPLATE VALUE: {:?}",template_json);
    return template_json
}

// OID_TO_STR_MAP with all know guid
// <https://www.pkisolutions.com/object-identifiers-oid-in-pki/>
// <https://github.com/ly4k/Certipy/blob/main/certipy/lib/constants.py#L145>
lazy_static! {
    static ref OID_TO_STR_MAP: HashMap<String, String> = {
        let values = [
            ("1.3.6.1.4.1.311.76.6.1", "Windows Update"),
            ("1.3.6.1.4.1.311.10.3.11", "Key Recovery"),
            ("1.3.6.1.4.1.311.10.3.25", "Windows Third Party Application Component"),
            ("1.3.6.1.4.1.311.21.6", "Key Recovery Agent"),
            ("1.3.6.1.4.1.311.10.3.6", "Windows System Component Verification"),
            ("1.3.6.1.4.1.311.61.4.1", "Early Launch Antimalware Drive"),
            ("1.3.6.1.4.1.311.10.3.23", "Windows TCB Component"),
            ("1.3.6.1.4.1.311.61.1.1", "Kernel Mode Code Signing"),
            ("1.3.6.1.4.1.311.10.3.26", "Windows Software Extension Verification"),
            ("2.23.133.8.3", "Attestation Identity Key Certificate"),
            ("1.3.6.1.4.1.311.76.3.1", "Windows Store"),
            ("1.3.6.1.4.1.311.10.6.1", "Key Pack Licenses"),
            ("1.3.6.1.4.1.311.20.2.2", "Smart Card Logon"),
            ("1.3.6.1.5.2.3.5", "KDC Authentication"),
            ("1.3.6.1.5.5.7.3.7", "IP security use"),
            ("1.3.6.1.4.1.311.10.3.8", "Embedded Windows System Component Verification"),
            ("1.3.6.1.4.1.311.10.3.20", "Windows Kits Component"),
            ("1.3.6.1.5.5.7.3.6", "IP security tunnel termination"),
            ("1.3.6.1.4.1.311.10.3.5", "Windows Hardware Driver Verification"),
            ("1.3.6.1.5.5.8.2.2", "IP security IKE intermediate"),
            ("1.3.6.1.4.1.311.10.3.39", "Windows Hardware Driver Extended Verification"),
            ("1.3.6.1.4.1.311.10.6.2", "License Server Verification"),
            ("1.3.6.1.4.1.311.10.3.5.1", "Windows Hardware Driver Attested Verification"),
            ("1.3.6.1.4.1.311.76.5.1", "Dynamic Code Generato"),
            ("1.3.6.1.5.5.7.3.8", "Time Stamping"),
            ("1.3.6.1.4.1.311.10.3.4.1", "File Recovery"),
            ("1.3.6.1.4.1.311.2.6.1", "SpcRelaxedPEMarkerCheck"),
            ("2.23.133.8.1", "Endorsement Key Certificate"),
            ("1.3.6.1.4.1.311.2.6.2", "SpcEncryptedDigestRetryCount"),
            ("1.3.6.1.4.1.311.10.3.4", "Encrypting File System"),
            ("1.3.6.1.5.5.7.3.1", "Server Authentication"),
            ("1.3.6.1.4.1.311.61.5.1", "HAL Extension"),
            ("1.3.6.1.5.5.7.3.4", "Secure Email"),
            ("1.3.6.1.5.5.7.3.5", "IP security end system"),
            ("1.3.6.1.4.1.311.10.3.9", "Root List Signe"),
            ("1.3.6.1.4.1.311.10.3.30", "Disallowed List"),
            ("1.3.6.1.4.1.311.10.3.19", "Revoked List Signe"),
            ("1.3.6.1.4.1.311.10.3.21", "Windows RT Verification"),
            ("1.3.6.1.4.1.311.10.3.10", "Qualified Subordination"),
            ("1.3.6.1.4.1.311.10.3.12", "Document Signing"),
            ("1.3.6.1.4.1.311.10.3.24", "Protected Process Verification"),
            ("1.3.6.1.4.1.311.80.1", "Document Encryption"),
            ("1.3.6.1.4.1.311.10.3.22", "Protected Process Light Verification"),
            ("1.3.6.1.4.1.311.21.19", "Directory Service Email Replication"),
            ("1.3.6.1.4.1.311.21.5", "Private Key Archival"),
            ("1.3.6.1.4.1.311.10.5.1", "Digital Rights"),
            ("1.3.6.1.4.1.311.10.3.27", "Preview Build Signing"),
            ("1.3.6.1.4.1.311.20.2.1", "Certificate Request Agent"),
            ("2.23.133.8.2", "Platform Certificate"),
            ("1.3.6.1.4.1.311.20.1", "CTL Usage"),
            ("1.3.6.1.5.5.7.3.9", "OCSP Signing"),
            ("1.3.6.1.5.5.7.3.3", "Code Signing"),
            ("1.3.6.1.4.1.311.10.3.1", "Microsoft Trust List Signing"),
            ("1.3.6.1.4.1.311.10.3.2", "Microsoft Time Stamping"),
            ("1.3.6.1.4.1.311.76.8.1", "Microsoft Publishe"),
            ("1.3.6.1.5.5.7.3.2", "Client Authentication"),
            ("1.3.6.1.5.2.3.4", "PKIINIT Client Authentication"),
            ("1.3.6.1.4.1.311.10.3.13", "Lifetime Signing"),
            ("2.5.29.37.0", "Any Purpose"),
            ("1.3.6.1.4.1.311.64.1.1", "Server Trust"),
            ("1.3.6.1.4.1.311.10.3.7", "OEM Windows System Component Verification")
        ];

        values.iter().map(|&(k, v)| (k.to_string(), v.to_string())).collect::<HashMap<String, String>>()
    };
}
