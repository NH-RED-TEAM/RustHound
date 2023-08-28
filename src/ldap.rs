//! Run a LDAP enumeration and parse results
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
use log::{info, debug, error};
use std::process;
use indicatif::ProgressBar;
use crate::banner::progress_bar;
use std::io::{self, Write, stdin};

/// Function to request all AD values.
pub async fn ldap_search(
    ldaps: bool,
    ip: &String,
    port: &String,
    domain: &String,
    ldapfqdn: &String,
    username: &String,
    password: &String,
    adcs: bool,
    kerberos: bool,
) -> Result<Vec<SearchEntry>> {
    // Construct LDAP args
    let ldap_args = ldap_constructor(ldaps, ip, port, domain, ldapfqdn, username, password, adcs, kerberos);

    // LDAP connection
    let consettings = LdapConnSettings::new().set_no_tls_verify(true);
    let (conn, mut ldap) = LdapConnAsync::with_settings(consettings, &ldap_args.s_url).await?;
    ldap3::drive!(conn);

    if !kerberos {
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
        if !&ldapfqdn.contains("not set") {
            #[cfg(not(feature = "nogssapi"))]
            gssapi_connection(&mut ldap,&ldapfqdn,&domain).await?;
            #[cfg(feature = "nogssapi")]{
                error!("Kerberos auth and GSSAPI not compatible with current os!");
                process::exit(0x0100);
            }
        } else {
            error!("Need Domain Controler FQDN to bind GSSAPI connection. Please use '{}'\n", "-f DC01.DOMAIN.LAB".bold());
            process::exit(0x0100);
        }
    }

    // Prepare LDAP result vector
    let mut rs: Vec<SearchEntry> = Vec::new();

    // For the following naming context 
    // namingContexts: DC=domain,DC=local
    // namingContexts: CN=Configuration,DC=domain,DC=local (needed for AD CS datas)
    for cn in &ldap_args.s_dc {
        // Set control LDAP_SERVER_SD_FLAGS_OID to get nTSecurityDescriptor
        // https://ldapwiki.com/wiki/LDAP_SERVER_SD_FLAGS_OID
        let ctrls = RawControl {
            ctype: String::from("1.2.840.113556.1.4.801"),
            crit: true,
            val: Some(vec![48,3,2,1,5]),
        };
        ldap.with_controls(ctrls.to_owned());

        // Prepare filter
        let mut _s_filter: &str = "";
        if cn.contains("Configuration") {
            _s_filter = "(|(objectclass=pKIEnrollmentService)(objectclass=pkicertificatetemplate)(objectclass=subschema))";
        } else {
            _s_filter = "(objectClass=*)";
        }

        // Every 999 max value in ldap response (err 4 ldap)
        let adapters: Vec<Box<dyn Adapter<_,_>>> = vec![
            Box::new(EntriesOnly::new()),
            Box::new(PagedResults::new(999)),
        ];

        // Streaming search with adaptaters and filters
        let mut search = ldap.streaming_search_with(
            adapters, // Adapter which fetches Search results with a Paged Results control.
            cn, 
            Scope::Subtree,
            _s_filter,
            vec!["*", "nTSecurityDescriptor"], 
            // Without the presence of this control, the server returns an SD only when the SD attribute name is explicitly mentioned in the requested attribute list.
            // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/932a7a8d-8c93-4448-8093-c79b7d9ba499
        ).await?;

        // Wait and get next values
        let pb = ProgressBar::new(1);
        let mut count = 0;	
        while let Some(entry) = search.next().await? {
            let entry = SearchEntry::construct(entry);
            //trace!("{:?}", &entry);
            // Manage progress bar
            count += 1;
            progress_bar(pb.to_owned(),"LDAP objects retreived".to_string(),count,"#".to_string());	
            // Push all result in rs vec()
            rs.push(entry);
        }
        pb.finish_and_clear();

        let res = search.finish().await.success();
        match res {
            Ok(_res) => info!("All data collected for NamingContext {}",&cn.bold()),
            Err(err) => {
                error!("No data collected on {}! Reason: {err}",&cn.bold().red());
            }
        }
    }
    // If no result exit program
    if rs.len() <= 0 {
        process::exit(0x0100);
    }

    // Terminate the connection to the server
    ldap.unbind().await?;
    
    // Return the vector with the result
    return Ok(rs);
}

/// Structure containing the LDAP connection arguments.
struct LdapArgs {
    s_url: String,
    s_dc: Vec<String>,
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
    adcs: bool,
    kerberos: bool,
) -> LdapArgs {
    // Prepare ldap url
    let s_url = prepare_ldap_url(ldaps, ip, port, domain);

    // Prepare full DC chain
    let s_dc = prepare_ldap_dc(domain,adcs);

    // Username prompt
    let mut s=String::new();
    let mut _s_username: String;
    if username.contains("not set") && !kerberos {
        print!("Username: ");
        io::stdout().flush().unwrap();
        stdin().read_line(&mut s).expect("Did not enter a correct username");
        io::stdout().flush().unwrap();
        if let Some('\n')=s.chars().next_back() {
            s.pop();
        }
        if let Some('\r')=s.chars().next_back() {
            s.pop();
        }
        _s_username = s.to_owned();
    } else {
        _s_username = username.to_owned();
    }

    // Format username and email
    let mut s_email: String = "".to_owned();
    if !_s_username.contains("@") {
        s_email.push_str(&_s_username.to_string());
        s_email.push_str("@");
        s_email.push_str(domain);
        _s_username = s_email.to_string();
    } else {
        s_email = _s_username.to_string().to_lowercase();
    }

    // Password prompt
    let mut _s_password: String = String::new();
    if !_s_username.contains("not set") && !kerberos {
        if password.contains("not set") {
            // Prompt for user password
            let rpass: String = rpassword::prompt_password("Password: ").unwrap_or("not set".to_string());
            _s_password = rpass;
        } else {
            _s_password = password.to_owned();
        }
    } else {
        _s_password = password.to_owned();
    }

    // Print infos if verbose mod is set
    debug!("IP: {}", ip);
    debug!("PORT: {}", port);
    debug!("FQDN: {}", ldapfqdn);
    debug!("Url: {}", s_url);
    debug!("Domain: {}", domain);
    debug!("Username: {}", _s_username);
    debug!("Email: {}", s_email.to_lowercase());
    debug!("Password: {}", _s_password);
    debug!("DC: {:?}", s_dc);
    debug!("ADCS: {:?}", adcs);
    debug!("Kerberos: {:?}", kerberos);

    LdapArgs {
        s_url: s_url.to_string(),
        s_dc: s_dc,
        _s_email: s_email.to_string().to_lowercase(),
        s_username: s_email.to_string().to_lowercase(),
        s_password: _s_password.to_string(),
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
pub fn prepare_ldap_dc(domain: &String, adcs: bool) -> Vec<String> {

    let mut dc: String = "".to_owned();
    let mut naming_context: Vec<String> = Vec::new();

    // Format DC
    if !domain.contains(".") {
        dc.push_str("DC=");
        dc.push_str(&domain);
        naming_context.push(dc[..].to_string());
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
        naming_context.push(dc[..].to_string());
    }

    if adcs {
        naming_context.push(format!("{}{}","CN=Configuration,",dc[..].to_string())); 
    }

    return naming_context
}

/// Function to make GSSAPI ldap connection.
#[cfg(not(feature = "nogssapi"))]
async fn gssapi_connection(
    ldap: &mut ldap3::Ldap,
    ldapfqdn: &String,
    domain: &String,
) -> Result<()> {
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
    Ok(())
}