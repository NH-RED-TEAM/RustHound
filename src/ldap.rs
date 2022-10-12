//! Run a ldap enumeration and parse results
//!
//! This module will prepare your connection and request the LDAP server to retrieve all the information needed to create the json files.
//!
//! rusthound sends only one request to the LDAP server, if the result of this one is higher than the limit of the LDAP server limit it will be split in several requests to avoid having an error 4 (LDAP_SIZELIMIT_EXCEED).
//!
//! Example in rust
//!
//! ```
//! let search = ldap_search(...)
//! ```
use crate::errors::{Result};
use colored::Colorize;
use ldap3::adapters::{Adapter, EntriesOnly};
use ldap3::{adapters::PagedResults, controls::RawControl, LdapConnAsync, LdapConnSettings};
use ldap3::{Scope, SearchEntry};
use log::{debug, error, info};
use std::process;

/// Function to request all AD values.
pub async fn ldap_search(
    ldaps: bool,
    ip: &String,
    port: &String,
    domain: &String,
    ldapfqdn: &String,
    username: &String,
    password: &String,
) -> Result<Vec<SearchEntry>> {
    // 0- Construct LDAP args
    let ldap_args = ldap_constructor(ldaps, ip, port, domain, ldapfqdn, username, password);

    // 1- LDAP connection
    let consettings = LdapConnSettings::new().set_no_tls_verify(true);
    let (conn, mut ldap) = LdapConnAsync::with_settings(consettings, &ldap_args.s_url).await?;
    ldap3::drive!(conn);


    if !&password.contains("not set") || !&username.contains("not set") {
        debug!("Trying to connect with simple_bind() function (username:password)");
        let res = ldap.simple_bind(&ldap_args.s_username, &ldap_args.s_password).await?.success();
        match res {
            Ok(_res) => {
                info!("Connected to {} Active Directory!", domain.to_uppercase().bold().green());
                info!("Starting data collection...");
            },
            Err(err) => {
                error!("Failed to authenticate to {} Active Directory. Reason: {err}\n", domain.to_uppercase().bold().red());
                process::exit(0x0100);
            }
        }
    }
    else
    {
        debug!("Trying to connect with sasl_gssapi_bind() function (kerberos session)");
        if !&ldapfqdn.contains("not set"){
            let res = ldap.sasl_gssapi_bind(ldapfqdn).await?.success();
            match res {
                Ok(_res) => {
                    info!("Connected to {} Active Directory!", domain.to_uppercase().bold().green());
                    info!("Starting data collection...");
                },
                Err(err) => {
                    error!("Failed to authenticate to {} Active Directory. Reason: {err}\n", domain.to_uppercase().bold().red());
                    process::exit(0x0100);
                }
            }
        }
        else
        {
            error!("Need Domain Controler FQDN to bind GSSAPI connection. Please use '{}'\n", "-f DC01.DOMAIN.LAB".bold());
            process::exit(0x0100);
        }
    }

    // 2- Set control LDAP_SERVER_SD_FLAGS_OID to get nTSecurityDescriptor
    // https://ldapwiki.com/wiki/LDAP_SERVER_SD_FLAGS_OID
    let ctrls = RawControl {
        ctype: String::from("1.2.840.113556.1.4.801"),
        crit: true,
        // flag to 7 or 5?
        val: Some(vec![48,132,00,00,00,3,2,1,7]),
    };
    ldap.with_controls(ctrls.to_owned());

    // 3- Prepare filter
    let s_filter: &str = "(objectClass=*)";

    // 4- Request LDAP
    let mut rs: Vec<SearchEntry> = Vec::new();
    // every 999 max value in ldap response (err 4 ldap)
    let adapters: Vec<Box<dyn Adapter<_,_>>> = vec![
        Box::new(EntriesOnly::new()),
        Box::new(PagedResults::new(999)),
    ];
    // streaming search with adaptaters and filters
    let mut search = ldap.streaming_search_with(
        adapters, // Adapter which fetches Search results with a Paged Results control.
        &ldap_args.s_dc, 
        Scope::Subtree,
        s_filter,
        vec!["*", "nTSecurityDescriptor"], 
        // Without the presence of this control, the server returns an SD only when the SD attribute name is explicitly mentioned in the requested attribute list.
        // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/932a7a8d-8c93-4448-8093-c79b7d9ba499
    ).await?;

    // wait and get next values
    while let Some(entry) = search.next().await? {
        let entry = SearchEntry::construct(entry);
        //trace!("{:?}", &entry);
        //push all result in rs vec()
        rs.push(entry);
    }

    let res = search.finish().await.success();
    match res {
        Ok(_res) => info!("All data collected!"),
        Err(err) => {
            error!("No data collected! Reason: {err}");
            process::exit(0x0100);
        }
    }

    // 5- Terminate the connection to the server
    ldap.unbind().await?;
    
    // 6- return the vector with the result
    return Ok(rs);
}

/// Structure containing the LDAP connection arguments.
struct LdapArgs {
    s_url: String,
    s_dc: String,
    _s_email: String,
    s_username: String,
    s_password: String,
}

/// Function to prepare LDAP arguments.
fn ldap_constructor(
    ldaps: bool,
    ip: &String,
    port: &String,
    domain: &String,
    ldapfqdn: &String,
    username: &String,
    password: &String,
) -> LdapArgs {
    // Prepare ldap url
    let s_url = prepare_ldap_url(ldaps, ip, port, domain);

    // Prepare full DC chain
    let s_dc = prepare_ldap_dc(domain);

    // Format username and password in str
    let s_username: &str = &username[..];
    let s_password: &str = &password[..];

    // Format email
    let mut _s_email: String = "".to_owned();
    if !username.contains("@") {
        _s_email.push_str(s_username);
        _s_email.push_str("@");
        _s_email.push_str(domain);
    } else {
        _s_email = username.to_string();
    }

    // Print infos if verbose mod is set
    debug!("IP: {}", ip);
    debug!("PORT: {}", port);
    debug!("FQDN: {}", ldapfqdn);
    debug!("Url: {}", s_url);
    debug!("Domain: {}", domain);
    debug!("Username: {}", s_username);
    debug!("Email: {}", _s_email.to_lowercase());
    debug!("Password: {}", s_password);
    debug!("DC: {}", s_dc);

    LdapArgs {
        s_url: s_url.to_string(),
        s_dc: s_dc.to_string(),
        _s_email: _s_email.to_string().to_lowercase(),
        s_username: s_username.to_string(),
        s_password: s_password.to_string(),
    }
}

/// Function to prepare LDAP url.
fn prepare_ldap_url(ldaps: bool, ip: &String, port: &String, domain: &String) -> String {
    let mut url: String = "".to_owned();

    // ldap or ldaps?
    if port.contains("636") || ldaps {
        url.push_str("ldaps://");
    }
    else
    {
        url.push_str("ldap://");
    }

    // If ldapip is set apply it to ldap url
    if ip.contains("not set") {
        url.push_str(&domain);
    } else {
        url.push_str(&ip);
    }

    // Push the port
    //trace!("port: {:?}", port);
    if port.contains("not set") || port == "636" || port == "389" {
        return url
    }
    else 
    {
        //trace!("port set");
        let mut final_port: String = ":".to_owned();
        final_port.push_str(&port);
        url.push_str(&final_port);
        return url
    }
}

/// Function to prepare LDAP DC from DOMAIN.LOCAL
pub fn prepare_ldap_dc(domain: &String) -> String {
    let mut dc: String = "".to_owned();

    // Format DC
    if !domain.contains(".") {
        dc.push_str("DC=");
        dc.push_str(&domain);
        return dc[..].to_string();
    }
    else 
    {
        let split = domain.split(".");
        let slen = split.to_owned().count();
        let mut cpt = 1;
        for s in split {
            if cpt < slen {
                dc.push_str("DC=");
                dc.push_str(&s);
                dc.push_str(",");
            }
            else
            {
                dc.push_str("DC=");
                dc.push_str(&s);
            }
            cpt += 1;
        }
        return dc[..].to_string();
    }
}