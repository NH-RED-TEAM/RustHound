use ldap3::SearchEntry;
use std::collections::HashMap;
use std::fmt;
//use log::trace;

/// Enum to get ldap object type.
pub enum Type {
    User,
    Computer,
    Group,
    Ou,
    Domain,
    Gpo,
    ForeignSecurityPrincipal,
    Container,
    Trust,
    RootCA,
    NtAutStore,
    EnterpriseCA,
    AIACA,
    CertTemplate,
    Unknown
}

impl fmt::Debug for Type {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Get object type, like ("user","group","computer","ou", "container", "gpo", "domain" "trust").
pub fn get_type(result: SearchEntry) -> std::result::Result<Type, Type>
{
    let result_attrs: HashMap<String, Vec<String>>;
    result_attrs = result.attrs;

    //trace!("{:?}",&result_attrs);

    // For all entries I checked if is an user,group,computer,ou,domain
    for (key, value) in &result_attrs 
    {
        // Type is user
        if key == "objectClass" && value.contains(&String::from("person")) && value.contains(&String::from("user")) && !value.contains(&String::from("computer")) && !value.contains(&String::from("group"))
        {
            return Ok(Type::User)
        }
        // Type is user if is service-account
        if key == "objectClass" && value.contains(&String::from("msDS-GroupManagedServiceAccount"))
        {
            return Ok(Type::User)
        }
        // Type is group
        if key == "objectClass" && value.contains(&String::from("group"))
        {
            return Ok(Type::Group)
        }
        // Type is computer
        if key == "objectClass" && value.contains(&String::from("computer"))
        {
            return Ok(Type::Computer)
        }
        // Type is ou
        if key == "objectClass" && value.contains(&String::from("organizationalUnit"))
        {
            return Ok(Type::Ou)
        }
        // Type is domain
        if key == "objectClass" && value.contains(&String::from("domain"))
        {
            return Ok(Type::Domain)     
        }
        // Type is Gpo
        if key == "objectClass" && value.contains(&String::from("groupPolicyContainer"))
        {
            return Ok(Type::Gpo)
        }
        // Type is foreignSecurityPrincipal
        if key == "objectClass" && value.contains(&String::from("top")) && value.contains(&String::from("foreignSecurityPrincipal"))
        {
            return Ok(Type::ForeignSecurityPrincipal)
        }
        // Type is Container
        if key == "objectClass" && (value.contains(&String::from("top")) && value.contains(&String::from("container"))) && !value.contains(&String::from("groupPolicyContainer"))
        {
            return Ok(Type::Container)
        }
        // Type is Trust domain
        if key == "objectClass" && value.contains(&String::from("trustedDomain"))
        {
            return Ok(Type::Trust)
        }
        // Type is ADCS Certificate Authority
        if key == "objectClass" && value.contains(&String::from("certificationAuthority"))
        && result.dn.contains(DirectoryPaths::ROOT_CA_LOCATION) 
        {
            return Ok(Type::RootCA)
        }
        // Type is ADCS Certificate Authority
        if key == "objectClass" && value.contains(&String::from("pKIEnrollmentService"))
        && result.dn.contains(DirectoryPaths::ENTERPRISE_CA_LOCATION) 
        {
            return Ok(Type::EnterpriseCA)
        }
        // Type is ADCS Certificate Template
        if key == "objectClass" && value.contains(&String::from("pKICertificateTemplate"))
        && result.dn.contains(DirectoryPaths::CERT_TEMPLATE_LOCATION) 
        {
            return Ok(Type::CertTemplate)
        }
        // Type is AIACA
        if key == "objectClass" && value.contains(&String::from("certificationAuthority")) 
        && result.dn.contains(DirectoryPaths::AIA_CA_LOCATION) 
        {
            return Ok(Type::AIACA)
        }
        // Type is NtAuthStore for NTAUTHCERTIFICATES
        if key == "objectClass" && value.contains(&String::from("certificationAuthority")) 
        && result.dn.contains(DirectoryPaths::NT_AUTH_STORE_LOCATION) 
        {
            return Ok(Type::NtAutStore)
        }
    }
    return Err(Type::Unknown)
}


/// Ldap directory path.
pub struct DirectoryPaths;

impl DirectoryPaths {
    pub const ENTERPRISE_CA_LOCATION    : &'static str = "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration";
    pub const ROOT_CA_LOCATION          : &'static str = "CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration";
    pub const AIA_CA_LOCATION           : &'static str = "CN=AIA,CN=Public Key Services,CN=Services,CN=Configuration";
    pub const CERT_TEMPLATE_LOCATION    : &'static str = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration";
    pub const NT_AUTH_STORE_LOCATION    : &'static str = "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration";
    pub const PKI_LOCATION              : &'static str = "CN=Public Key Services,CN=Services,CN=Configuration";
    pub const CONFIG_LOCATION           : &'static str = "CN=Configuration";
}