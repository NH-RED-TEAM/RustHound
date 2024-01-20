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

    let contains = | values: &Vec<String>, to_find: &str | { 
        values.iter().any( |elem| elem == to_find ) 
    };

    //trace!("{:?}",&result_attrs);

    // For all entries I checked if is an user,group,computer,ou,domain
    for (key, vals) in &result_attrs 
    {
        // If the key isn't an objectClass, then skip this attr
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
        if contains(vals, "pKIEnrollmentService")
        {
            return Ok(Type::AdcsAuthority)
        }
        // Type is ADCS Certificate Template
        if contains(vals, "pKICertificateTemplate")
        {
            return Ok(Type::AdcsTemplate)
        }
    }
    return Err(Type::Unknown)
}