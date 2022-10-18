//! Parsing arguments
use clap::{App, Arg};

#[derive(Debug)]
pub struct Options {
    pub username: String,
    pub password: String,
    pub domain: String,
    pub ldapfqdn: String,
    pub ip: String,
    pub port: String,
    pub ldaps: bool,
    pub path: String,
    pub name_server: String,
    pub dns_tcp: bool,
    pub fqdn_resolver: bool,
    pub zip: bool,
    pub verbose: log::LevelFilter,
}

pub fn extract_args() -> Options {
    let matches = App::new("RustHound")
        .version("1.0.4")
        .author("g0h4n https://twitter.com/g0h4n_0")
        .about("Active Directory data collector for BloodHound.")
        .arg(
            Arg::with_name("ldapusername")
                .short("u")
                .long("ldapusername")
                .takes_value(true)
                .help("Ldap username to use")
                .required(false),
        )
        .arg(
            Arg::with_name("ldappassword")
                .short("p")
                .long("ldappassword")
                .takes_value(true)
                .help("Ldap password to use")
                .required(false),
        )
        .arg(
            Arg::with_name("domain")
                .short("d")
                .long("domain")
                .takes_value(true)
                .help("Domain name like: G0H4N.LAB")
                .required(true),
        )
        .arg(
            Arg::with_name("ldapfqdn")
                .short("f")
                .long("ldapfqdn")
                .takes_value(true)
                .help("Domain Controler FQDN like: DC01.G0H4N.LAB")
                .required(false),
        )
        .arg(
            Arg::with_name("ldapip")
                .short("i")
                .long("ldapip")
                .takes_value(true)
                .help("Domain Controller IP address")
                .required(false),
        )
        .arg(
            Arg::with_name("ldapport")
                .short("P")
                .long("ldapport")
                .takes_value(true)
                .help("Ldap port, default is 389")
                .required(false),
        )
        .arg(
            Arg::with_name("ldaps")
                .long("ldaps")
                .takes_value(false)
                .help("Prepare ldaps request. Like ldaps://G0H4N.LAB/")
                .required(false),
        )
        .arg(
            Arg::with_name("path")
                .short("o")
                .long("dirpath")
                .takes_value(true)
                .help("Path where you would like to save json files")
                .required(false),
        )
        .arg(
            Arg::with_name("name-server")
                .short("n")
                .long("name-server")
                .takes_value(true)
                .help("Alternative IP address name server to use for queries")
                .required(false),
        )
        .arg(
            Arg::with_name("dns-tcp")
                .long("dns-tcp")
                .takes_value(false)
                .help("Use TCP instead of UDP for DNS queries")
                .required(false),
        )
        .arg(
            Arg::with_name("fqdn-resolver")
                .long("fqdn-resolver")
                .takes_value(false)
                .help("[MODULE] Use fqdn-resolver module to get computers IP address")
                .required(false),
        )
        .arg(
            Arg::with_name("zip")
                .long("zip")
                .short("z")
                .takes_value(false)
                .help("RustHound will compress the JSON files into a zip archive (doesn't work with Windows)")
                .required(false),
        )
        .arg(
            Arg::with_name("v")
                .short("v")
                .multiple(true)
                .help("Sets the level of verbosity"),
        )
        .get_matches();

    let username = matches.value_of("ldapusername").unwrap_or("not set");
    let password = matches.value_of("ldappassword").unwrap_or("not set");
    let domain = matches.value_of("domain").unwrap_or("not set");
    let ldapfqdn = matches.value_of("ldapfqdn").unwrap_or("not set");
    let ip = matches.value_of("ldapip").unwrap_or("not set");
    let port = matches.value_of("ldapport").unwrap_or("not set");
    let ldaps = matches.is_present("ldaps");
    let path = matches.value_of("path").unwrap_or("./");
    let ns = matches.value_of("name-server").unwrap_or("127.0.0.1");
    let tcp = matches.is_present("dns-tcp");
    let fqdn_resolver = matches.is_present("fqdn-resolver");
    let zip = matches.is_present("zip");

    // Set log level
    let v = match matches.occurrences_of("v") {
        0 => log::LevelFilter::Info,
        1 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };

    Options {
        username: username.to_string(),
        password: password.to_string(),
        domain: domain.to_string(),
        ldapfqdn: ldapfqdn.to_string(),
        ip: ip.to_string(),
        port: port.to_string(),
        ldaps: ldaps,
        path: path.to_string(),
        name_server: ns.to_string(),
        dns_tcp: tcp,
        fqdn_resolver: fqdn_resolver,
        zip: zip,
        verbose: v,
    }
}
