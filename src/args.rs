//! Parsing arguments
#[cfg(not(feature = "noargs"))]
use clap::{Arg, ArgAction, value_parser, Command};

#[cfg(feature = "noargs")]
use winreg::{RegKey,{enums::*}};
#[cfg(feature = "noargs")]
use crate::exec::run;
#[cfg(feature = "noargs")]
use regex::Regex;

#[derive(Clone, Debug)]
pub struct Options {
    pub domain: String,
    pub username: String,
    pub password: String,
    pub ldapfqdn: String,
    pub ip: String,
    pub port: String,
    pub name_server: String,
    pub path: String,
    pub ldaps: bool,
    pub dns_tcp: bool,
    pub fqdn_resolver: bool,
    pub adcs: bool,
    pub old_bloodhound: bool,
    pub dc_only: bool,
    pub kerberos: bool,
    pub zip: bool,
    pub verbose: log::LevelFilter,
}

#[cfg(not(feature = "noargs"))]
fn cli() -> Command {
    Command::new("rusthound")
        .version("1.1.69")
        .about("Active Directory data collector for BloodHound.\ng0h4n <https://twitter.com/g0h4n_0>")
        .arg(Arg::new("v")
            .short('v')
            .help("Set the level of verbosity")
            .action(ArgAction::Count),
        )
        .next_help_heading("REQUIRED VALUES")
        .arg(Arg::new("domain")
                .short('d')
                .long("domain")
                .help("Domain name like: DOMAIN.LOCAL")
                .required(true)
                .value_parser(value_parser!(String))
            )
        .next_help_heading("OPTIONAL VALUES")
        .arg(Arg::new("ldapusername")
            .short('u')
            .long("ldapusername")
            .help("LDAP username, like: user@domain.local")
            .required(false)
            .value_parser(value_parser!(String))
        )
        .arg(Arg::new("ldappassword")
            .short('p')
            .long("ldappassword")
            .help("LDAP password")
            .required(false)
            .value_parser(value_parser!(String))
        )
        .arg(Arg::new("ldapfqdn")
            .short('f')
            .long("ldapfqdn")
            .help("Domain Controler FQDN like: DC01.DOMAIN.LOCAL or just DC01")
            .required(false)
            .value_parser(value_parser!(String))
        )
        .arg(Arg::new("ldapip")
            .short('i')
            .long("ldapip")
            .help("Domain Controller IP address like: 192.168.1.10")
            .required(false)
            .value_parser(value_parser!(String))
        )
        .arg(Arg::new("ldapport")
            .short('P')
            .long("ldapport")
            .help("LDAP port [default: 389]")
            .required(false)
            .value_parser(value_parser!(String))
        )
        .arg(Arg::new("name-server")
            .short('n')
            .long("name-server")
            .help("Alternative IP address name server to use for DNS queries")
            .required(false)
            .value_parser(value_parser!(String))
        )
        .arg(Arg::new("output")
            .short('o')
            .long("output")
            .help("Output directory where you would like to save JSON files [default: ./]")
            .required(false)
            .value_parser(value_parser!(String))
        )
        .next_help_heading("OPTIONAL FLAGS")
        .arg(Arg::new("ldaps")
            .long("ldaps")
            .help("Force LDAPS using for request like: ldaps://DOMAIN.LOCAL/")
            .required(false)
            .action(ArgAction::SetTrue)
            .global(false)
        )
        .arg(Arg::new("kerberos")
            .short('k')
            .long("kerberos")
            .help("Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters for Linux.")
            .required(false)
            .action(ArgAction::SetTrue)
            .global(false)
        )
        .arg(Arg::new("dns-tcp")
                .long("dns-tcp")
                .help("Use TCP instead of UDP for DNS queries")
                .required(false)
                .action(ArgAction::SetTrue)
                .global(false)
            )
        .arg(Arg::new("dc-only")
            .long("dc-only")
            .help("Collects data only from the domain controller. Will not try to retrieve CA security/configuration or check for Web Enrollment")
            .required(false)
            .action(ArgAction::SetTrue)
            .global(false)
        )
        .arg(Arg::new("old-bloodhound")
            .long("old-bloodhound")
            .help("For ADCS only. Output result as BloodHound data for the original BloodHound version from @BloodHoundAD without PKI support")
            .required(false)
            .action(ArgAction::SetTrue)
            .global(false)
        )
        .arg(Arg::new("zip")
            .long("zip")
            .short('z')
            .help("Compress the JSON files into a zip archive")
            .required(false)
            .action(ArgAction::SetTrue)
            .global(false)
        )
        .next_help_heading("OPTIONAL MODULES")
        .arg(Arg::new("fqdn-resolver")
            .long("fqdn-resolver")
            .help("Use fqdn-resolver module to get computers IP address")
            .required(false)
            .action(ArgAction::SetTrue)
            .global(false)
        )
        .arg(Arg::new("adcs")
            .long("adcs")
            .help("Use ADCS module to enumerate Certificate Templates, Certificate Authorities and other configurations.\n(For the custom-built BloodHound version from @ly4k with PKI support)")
            .required(false)
            .action(ArgAction::SetTrue)
            .global(false)
        )
}

#[cfg(not(feature = "noargs"))]
/// Function to extract all argument and put it in 'Options' structure.
pub fn extract_args() -> Options {

    // Get arguments
    let matches = cli().get_matches();

    // Now get values
    let d = matches.get_one::<String>("domain").map(|s| s.as_str()).unwrap();
    let u = matches.get_one::<String>("ldapusername").map(|s| s.as_str()).unwrap_or("not set");
    let p = matches.get_one::<String>("ldappassword").map(|s| s.as_str()).unwrap_or("not set");
    let f = matches.get_one::<String>("ldapfqdn").map(|s| s.as_str()).unwrap_or("not set");
    let ip = matches.get_one::<String>("ldapip").map(|s| s.as_str()).unwrap_or("not set");
    let port = matches.get_one::<String>("ldapport").map(|s| s.as_str()).unwrap_or("not set");
    let n = matches.get_one::<String>("name-server").map(|s| s.as_str()).unwrap_or("not set");
    let path = matches.get_one::<String>("output").map(|s| s.as_str()).unwrap_or("./");
    let ldaps = matches.get_one::<bool>("ldaps").map(|s| s.to_owned()).unwrap_or(false);
    let dns_tcp = matches.get_one::<bool>("dns-tcp").map(|s| s.to_owned()).unwrap_or(false);
    let dc_only = matches.get_one::<bool>("dc-only").map(|s| s.to_owned()).unwrap_or(false);
    let old_bh = matches.get_one::<bool>("old-bloodhound").map(|s| s.to_owned()).unwrap_or(false);
    let z = matches.get_one::<bool>("zip").map(|s| s.to_owned()).unwrap_or(false);
    let fqdn_resolver = matches.get_one::<bool>("fqdn-resolver").map(|s| s.to_owned()).unwrap_or(false);
    let adcs = matches.get_one::<bool>("adcs").map(|s| s.to_owned()).unwrap_or(false);
    let kerberos = matches.get_one::<bool>("kerberos").map(|s| s.to_owned()).unwrap_or(false);
    let v = match matches.get_count("v") {
        0 => log::LevelFilter::Info,
        1 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };

    // Return all
    Options {
        domain: d.to_string(),
        username: u.to_string(),
        password: p.to_string(),
        ldapfqdn: f.to_string(),
        ip: ip.to_string(),
        port: port.to_string(),
        name_server: n.to_string(),
        path: path.to_string(),
        ldaps: ldaps,
        dns_tcp: dns_tcp,
        dc_only: dc_only,
        old_bloodhound: old_bh,
        fqdn_resolver: fqdn_resolver,
        adcs: adcs,
        kerberos: kerberos,
        zip: z,
        verbose: v,
    }
}

#[cfg(feature = "noargs")]
/// Function to automatically get all informations needed and put it in 'Options' structure.
pub fn auto_args() -> Options {

    // Request registry key to get informations
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let cur_ver = hklm.open_subkey("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters").unwrap();
    //Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Domain
    let domain: String = match cur_ver.get_value("Domain") {
        Ok(domain) => domain,
        Err(err) => {
            panic!("Error: {:?}",err);
        }
    };
    
    // Get LDAP fqdn
    let _fqdn: String = run(&format!("nslookup -query=srv _ldap._tcp.{}",&domain));
    let re = Regex::new(r"hostname.*= (?<ldap_fqdn>[0-9a-zA-Z]{1,})").unwrap();
    let mut values =  re.captures_iter(&_fqdn);
    let caps = values.next().unwrap();
    let fqdn = caps["ldap_fqdn"].to_string();

    // Get LDAP port
    let re = Regex::new(r"port.*= (?<ldap_port>[0-9]{3,})").unwrap();
    let mut values =  re.captures_iter(&_fqdn);
    let caps = values.next().unwrap();
    let port = caps["ldap_port"].to_string();
    let mut ldaps: bool = false;
    if port == "636" {
        ldaps = true;
    }

    // Return all
    Options {
        domain: domain.to_string(),
        username: "not set".to_string(),
        password: "not set".to_string(),
        ldapfqdn: fqdn.to_string(),
        ip: "not set".to_string(),
        port: port.to_string(),
        name_server: "127.0.0.1".to_string(),
        path: "./output".to_string(),
        ldaps: ldaps,
        dns_tcp: false,
        dc_only: false,
        old_bloodhound: false,
        fqdn_resolver: false,
        adcs: true,
        kerberos: true,
        zip: true,
        verbose: log::LevelFilter::Info,
    }
}
