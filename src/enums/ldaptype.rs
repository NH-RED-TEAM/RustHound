use ldap3::SearchEntry;
use std::collections::HashMap;
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
    AdcsAuthority,
    AdcsTemplate,
    Unknown
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
        if key == "objectClass" && value.contains(&String::from("pKIEnrollmentService"))
        {
            return Ok(Type::AdcsAuthority)
        }
        // Type is ADCS Certificate Template
        if key == "objectClass" && value.contains(&String::from("pKICertificateTemplate"))
        {
            return Ok(Type::AdcsTemplate)
        }
    }
    return Err(Type::Unknown)
}