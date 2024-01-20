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
    let result_attrs: HashMap<String, Vec<String>> = result.attrs;

    let contains = | values: &Vec<String>, to_find: &str | { 
        values.iter().any( |elem| elem == to_find ) 
    };

    //trace!("{:?}",&result_attrs);

    // For all entries I checked if is an user,group,computer,ou,domain
    for (key, vals) in &result_attrs 
    {
        // If key isn't objectClass, skip this key
        if key != "objectClass" {
            continue;
        }

        // Type is user
        if contains(vals, "person") && contains(vals, "user") && !contains(vals, "computer") && !contains(vals, "group")
        {
            return Ok(Type::User)
        }
        // Type is user if is service-account
        if contains(vals, "msDS-GroupManagedServiceAccount")
        {
            return Ok(Type::User)
        }
        // Type is group
        if contains(vals, "group")
        {
            return Ok(Type::Group)
        }
        // Type is computer
        if contains(vals, "computer")
        {
            return Ok(Type::Computer)
        }
        // Type is ou
        if contains(vals, "organizationalUnit")
        {
            return Ok(Type::Ou)
        }
        // Type is domain
        if contains(vals, "domain")
        {
            return Ok(Type::Domain)     
        }
        // Type is Gpo
        if contains(vals, "groupPolicyContainer")
        {
            return Ok(Type::Gpo)
        }
        // Type is foreignSecurityPrincipal
        if contains(vals, "top") && contains(vals, "foreignSecurityPrincipal")
        {
            return Ok(Type::ForeignSecurityPrincipal)
        }
        // Type is Container
        if (contains(vals, "top") && contains(vals, "container")) && !contains(vals, "groupPolicyContainer")
        {
            return Ok(Type::Container)
        }
        // Type is Trust domain
        if contains(vals, "trustedDomain")
        {
            return Ok(Type::Trust)
        }
        // Type is ADCS Certificate Authority
        if contains(vals, "certificationAuthority")
        && result.dn.contains(DirectoryPaths::ROOT_CA_LOCATION) 
        {
            return Ok(Type::RootCA)
        }
        // Type is ADCS Certificate Authority
        if contains(vals, "pKIEnrollmentService")
        && result.dn.contains(DirectoryPaths::ENTERPRISE_CA_LOCATION) 
        {
            return Ok(Type::EnterpriseCA)
        }
        // Type is ADCS Certificate Template
        if contains(vals, "pKICertificateTemplate")
        && result.dn.contains(DirectoryPaths::CERT_TEMPLATE_LOCATION) 
        {
            return Ok(Type::CertTemplate)
        }
        // Type is AIACA
        if contains(vals, "certificationAuthority")
        && result.dn.contains(DirectoryPaths::AIA_CA_LOCATION) 
        {
            return Ok(Type::AIACA)
        }
        // Type is NtAuthStore for NTAUTHCERTIFICATES
        if contains(vals, "certificationAuthority")
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