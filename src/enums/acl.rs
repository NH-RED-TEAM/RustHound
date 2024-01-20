extern crate lazy_static;

use lazy_static::lazy_static;
use std::collections::HashMap;

use crate::objects::{
    user::User,
    common::{LdapObject,AceTemplate},
};
use crate::enums::constants::*;
use crate::enums::secdesc::*;
use crate::enums::sid::{bin_to_string, sid_maker};
use bitflags::bitflags;
use log::{trace,error};

/// This function allows to parse the attribut nTSecurityDescriptor from secdesc.rs
/// <http://www.selfadsi.org/deep-inside/ad-security-descriptors.htm#SecurityDescriptorStructure>
pub fn parse_ntsecuritydescriptor<T: LdapObject>(
    object: &mut T,
    nt: &Vec<u8>,
    entry_type: String,
    result_attrs: &HashMap<String, Vec<String>>,
    result_bin: &HashMap<String, Vec<Vec<u8>>>,
    domain: &String,
) -> Vec<AceTemplate> {
    let mut relations_dacl: Vec<AceTemplate> = Vec::new();
    let relations_sacl: Vec<AceTemplate> = Vec::new();
    let secdesc: SecurityDescriptor;
    let mut owner_sid: String = "".to_string();

    secdesc = SecurityDescriptor::parse(&nt).unwrap().1;
    trace!("SECURITY-DESCRIPTOR: {:?}", secdesc);

    // Check for ACL protected for Bloodhound4.1+
    // IsACLProtected
    let acl_is_protected = has_control(secdesc.control, SecurityDescriptorFlags::DACL_PROTECTED);
    //trace!("{} acl_is_protected: {:?}",object.properties().name,acl_is_protected);

    match entry_type.as_str()
    {
        "EnterpriseCA" | "RootCA" | "CertTemplate" => {
            object.set_is_acl_protected(acl_is_protected);
        }
        _ => {}
    }

    if secdesc.offset_owner as usize != 0 
    {
        owner_sid = sid_maker(LdapSid::parse(&nt[secdesc.offset_owner as usize..]).unwrap().1,domain);
        trace!("OWNER-SID: {:?}", owner_sid);
    }

    if secdesc.offset_group as usize != 0 
    {
        let group_sid = sid_maker(LdapSid::parse(&nt[secdesc.offset_group as usize..]).unwrap().1,domain);
        trace!("GROUP-SID: {:?}", group_sid);
    }

    if secdesc.offset_sacl as usize != 0 
    {
        let res = Acl::parse(&nt[secdesc.offset_sacl as usize..]);
        match res {
            Ok(_res) => {
                let sacl = _res.1;
                trace!("SACL: {:?}", sacl);
                //let aces = sacl.data;
                /*ace_maker(
                    object,
                    domain,
                    &mut relations_sacl,
                    &owner_sid,
                    aces,
                    &entry_type,
                    result_attrs,
                    result_bin,
                );*/
                trace!("RESULT: {:?}", relations_sacl);
            },
            Err(err) => error!("Error. Reason: {err}")
        }
        return relations_sacl;
    }

    if secdesc.offset_dacl as usize != 0 
    {
        let res = Acl::parse(&nt[secdesc.offset_dacl as usize..]);    
        match res {
            Ok(_res) => {
                let dacl = _res.1;
                trace!("DACL: {:?}", dacl);
                let aces = dacl.data;
                ace_maker(
                    object,
                    domain,
                    &mut relations_dacl,
                    &owner_sid,
                    aces,
                    &entry_type,
                    result_attrs,
                    result_bin,
                );
                trace!("RESULT: {:?}", relations_dacl);
            },
            Err(err) => error!("Error. Reason: {err}")
        }
        return relations_dacl;
    }
    return relations_dacl;
}

/// Parse ace in acl and get correct values (thanks fox-it for bloodhound.py works)
/// <https://github.com/fox-it/BloodHound.py/blob/master/bloodhound/enumeration/acls.py>
fn ace_maker<T: LdapObject>(
    object: &mut T,
    domain: &String,
    relations: &mut Vec<AceTemplate>,
    osid: &String,
    aces: Vec<Ace>,
    entry_type: &String,
    _result_attrs: &HashMap<String, Vec<String>>,
    _result_bin: &HashMap<String, Vec<Vec<u8>>>,
) {
    // trace!("ACL/ACE FOR ENTRY: {:?}",object.properties().name);
    // Ignore Creator Owner or Local System
    let ignoresids = [
        "S-1-3-0".to_string(),
        "S-1-5-18".to_string(),
        "S-1-5-10".to_string(),
    ]; //, "S-1-1-0".to_string(), "S-1-5-10".to_string(), "S-1-5-11".to_string()];
    if ignoresids.iter().any(|i| !osid.contains(i)) {
        relations.push(AceTemplate::new(
            osid.to_owned(),
            "Base".to_string(),
            "Owns".to_string(),
            false)
        );
    }

    for ace in aces {
        if ace.ace_type != 0x05 && ace.ace_type != 0x00
        {
            trace!("Don't care about acetype {:?}", ace.ace_type);
            continue
        }

        let sid = sid_maker(AceFormat::get_sid(ace.data.to_owned()).unwrap(), domain);
        trace!("SID for this ACE: {}", &sid);

        // Check if sid is in the ignored list
        if ignoresids.iter().any(|i| sid.contains(i))
        {
            continue
        }

        // https://github.com/fox-it/BloodHound.py/blob/645082e3462c93f31b571db945cde1fd7b837fb9/bloodhound/enumeration/acls.py#L74
        if ace.ace_type == 0x05 {
            trace!("TYPE: 0x05");
            // GUID : inherited_object_type
            let inherited_object_type = match AceFormat::get_inherited_object_type(ace.data.to_owned()) 
            {
                Some(inherited_object_type) => inherited_object_type,
                None => 0,
            };
            // GUID : object_type
            let object_type = match AceFormat::get_object_type(ace.data.to_owned()) 
            {
                Some(object_type) => object_type,
                None => 0,
            };
            // Get and check ace.ace_flags object content INHERITED_ACE and return boolean
            let is_inherited = ace.ace_flags & INHERITED_ACE == INHERITED_ACE;

            // Get the Flag for the ace.datas
            let flags = AceFormat::get_flags(ace.data.to_owned()).unwrap().bits();

            // https://github.com/fox-it/BloodHound.py/blob/645082e3462c93f31b571db945cde1fd7b837fb9/bloodhound/enumeration/acls.py#L77
            if (ace.ace_flags & INHERITED_ACE != INHERITED_ACE)
            && (ace.ace_flags & INHERIT_ONLY_ACE == INHERIT_ONLY_ACE) 
            {
                // ACE is set on this object, but only inherited, so not applicable to us
                continue
            }

            // https://github.com/fox-it/BloodHound.py/blob/645082e3462c93f31b571db945cde1fd7b837fb9/bloodhound/enumeration/acls.py#L82
            if (ace.ace_flags & INHERITED_ACE == INHERITED_ACE) 
            && (&flags & ACE_INHERITED_OBJECT_TYPE_PRESENT == ACE_INHERITED_OBJECT_TYPE_PRESENT)
            {
                // ACE is set on this object, but only inherited, so not applicable to us
                // need to verify if the ACE applies to this object type #todo
                // Verify if the ACE applies to this object type
                // if not ace_applies(ace_object.acedata.get_inherited_object_type().lower(), entrytype, objecttype_guid_map):
                // continue
                // https://github.com/fox-it/BloodHound.py/blob/645082e3462c93f31b571db945cde1fd7b837fb9/bloodhound/enumeration/acls.py#L85
                let ace_guid = bin_to_string(&inherited_object_type.to_be_bytes().to_vec()).to_lowercase();
                if !(ace_applies(&ace_guid, &entry_type)) 
                {
                    continue
                }
            }

            let mask = match AceFormat::get_mask(ace.data.to_owned()) {
                Some(mask) => mask,
                None => continue,
            };
            trace!("ACE MASK for ACETYPE 0x05: {:?}", mask);

            let ace_guid = bin_to_string(&object_type.to_be_bytes().to_vec()).to_lowercase();
            trace!("ACE GUID for ACETYPE 0x05: {:?}", ace_guid);

            // https://github.com/fox-it/BloodHound.py/blob/645082e3462c93f31b571db945cde1fd7b837fb9/bloodhound/enumeration/acls.py#L92
            if ((MaskFlags::GENERIC_ALL.bits() | mask) == mask)
            || ((MaskFlags::WRITE_DACL.bits() | mask) == mask)
            || ((MaskFlags::WRITE_OWNER.bits() | mask) == mask)
            || ((MaskFlags::GENERIC_WRITE.bits() | mask) == mask)
            {
                trace!("ACE MASK contain: GENERIC_ALL or WRITE_DACL or WRITE_OWNER or GENERIC_WRITE");
                if (&flags & ACE_OBJECT_TYPE_PRESENT == ACE_OBJECT_TYPE_PRESENT) && !(ace_applies(&ace_guid, &entry_type))
                {
                    continue
                }
                if (MaskFlags::GENERIC_ALL.bits() | mask) == mask 
                {
                    if entry_type == "Computer" && (&flags & ACE_OBJECT_TYPE_PRESENT == ACE_OBJECT_TYPE_PRESENT)
                    && object.get_haslaps().to_owned()
                    {
                        if &ace_guid == OBJECTTYPE_GUID_HASHMAP.get("ms-mcs-admpwd").unwrap_or(&String::from("GUID-NOT-FOUND")) {
                            relations.push(AceTemplate::new(
                                sid.to_owned(),
                                "".to_string(),
                                "ReadLAPSPassword".to_string(),
                                is_inherited)
                            );
                        }
                    } else {
                        relations.push(AceTemplate::new(
                            sid.to_owned(),
                            "".to_string(),
                            "GenericAll".to_string(),
                            is_inherited)
                        );
                    }
                    continue
                }
                if (MaskFlags::GENERIC_WRITE.bits() | mask) == mask {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "GenericWrite".to_string(),
                        is_inherited)
                    );
                    if (entry_type != "Domain") && (entry_type != "Computer") 
                    {
                        continue
                    }
                }
                if (MaskFlags::WRITE_DACL.bits() | mask) == mask {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "WriteDacl".to_string(),
                        is_inherited)
                    );
                }
                if (MaskFlags::WRITE_OWNER.bits() | mask) == mask {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "WriteOwner".to_string(),
                        is_inherited)
                    );
                }
            }

            // Property write privileges
            // https://github.com/fox-it/BloodHound.py/blob/645082e3462c93f31b571db945cde1fd7b837fb9/bloodhound/enumeration/acls.py#L126
            if (MaskFlags::ADS_RIGHT_DS_WRITE_PROP.bits() | mask) == mask {

                if ((entry_type == "User") || (entry_type == "Group") || (entry_type == "Computer"))
                && !(&flags & ACE_OBJECT_TYPE_PRESENT == ACE_OBJECT_TYPE_PRESENT)
                {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "GenericWrite".to_string(),
                        is_inherited)
                    );
                }
                if entry_type == "Group" && can_write_property(&ace, WRITE_MEMBER)
                {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "AddMember".to_string(),
                        is_inherited)
                    );
                }
                if entry_type == "Computer" && can_write_property(&ace, ALLOWED_TO_ACT)
                {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "AddAllowedToAct".to_string(),
                        is_inherited)
                    );
                }
                if entry_type == "Computer" && can_write_property(&ace, USER_ACCOUNT_RESTRICTIONS_SET) && !&sid.ends_with("-512")
                {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "WriteAccountRestrictions".to_string(),
                        is_inherited)
                    );
                }

                // Since BloodHound 4.1
                // AddKeyCredentialLink write access
                if ((entry_type == "User") || (entry_type == "Computer"))
                && (&flags & ACE_OBJECT_TYPE_PRESENT == ACE_OBJECT_TYPE_PRESENT)
                && (&ace_guid == OBJECTTYPE_GUID_HASHMAP.get("ms-ds-key-credential-link").unwrap_or(&String::from("GUID-NOT-FOUND")))
                {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "AddKeyCredentialLink".to_string(),
                        is_inherited)
                    );
                }
                if (entry_type == "User")
                && (&flags & ACE_OBJECT_TYPE_PRESENT == ACE_OBJECT_TYPE_PRESENT) 
                && (&ace_guid == OBJECTTYPE_GUID_HASHMAP.get("service-principal-name").unwrap_or(&String::from("GUID-NOT-FOUND")))
                {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "WriteSPN".to_string(),
                        is_inherited)
                    );
                }
            } 
            else if (MaskFlags::ADS_RIGHT_DS_SELF.bits() | mask) == mask 
            {
                if (entry_type == "Group") && (&ace_guid == WRITE_MEMBER)
                {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "AddSelf".to_string(),
                        is_inherited)
                    );
                }
            }

            // Property read privileges
            // https://github.com/fox-it/BloodHound.py/blob/645082e3462c93f31b571db945cde1fd7b837fb9/bloodhound/enumeration/acls.py#L138
            if (MaskFlags::ADS_RIGHT_DS_READ_PROP.bits() | mask) == mask 
            {
                if (entry_type == "Computer")
                && (&flags & ACE_OBJECT_TYPE_PRESENT == ACE_OBJECT_TYPE_PRESENT)
                && object.get_haslaps().to_owned()
                {
                    if &ace_guid == OBJECTTYPE_GUID_HASHMAP.get("ms-mcs-admpwd").unwrap_or(&String::from("GUID-NOT-FOUND"))
                    {
                        relations.push(AceTemplate::new(
                            sid.to_owned(),
                            "".to_string(),
                            "ReadLAPSPassword".to_string(),
                            is_inherited)
                        );
                    }
                }
            }

            // Extended rights
            // https://github.com/fox-it/BloodHound.py/blob/645082e3462c93f31b571db945cde1fd7b837fb9/bloodhound/enumeration/acls.py#L146
            if (MaskFlags::ADS_RIGHT_DS_CONTROL_ACCESS.bits() | mask) == mask 
            {
                // All Extended
                if vec!["User","Domain"].contains(&entry_type.as_str()) && !(&flags & ACE_OBJECT_TYPE_PRESENT == ACE_OBJECT_TYPE_PRESENT)
                {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "AllExtendedRights".to_string(),
                        is_inherited)
                    );
                }
                if (entry_type == "Computer")
                && !(&flags & ACE_OBJECT_TYPE_PRESENT == ACE_OBJECT_TYPE_PRESENT)
                && false
                {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "AllExtendedRights".to_string(),
                        is_inherited)
                    );
                }
                if (entry_type == "Domain") && has_extended_right(&ace, GET_CHANGES) 
                {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "GetChanges".to_string(),
                        is_inherited)
                    );
                }
                if (entry_type == "Domain") && has_extended_right(&ace, GET_CHANGES_ALL) 
                {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "GetChangesAll".to_string(),
                        is_inherited)
                    );
                }
                if (entry_type == "Domain") && has_extended_right(&ace, GET_CHANGES_IN_FILTERED_SET)
                {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "GetChangesInFilteredSet".to_string(),
                        is_inherited)
                    );
                }
                if (entry_type == "User") && has_extended_right(&ace, USER_FORCE_CHANGE_PASSWORD)
                {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "ForceChangePassword".to_string(),
                        is_inherited)
                    );
                }
                if vec!["EnterpriseCA","RootCA","CertTemplate"].contains(&entry_type.as_str()) && has_extended_right(&ace, ENROLL)
                {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "Enroll".to_string(),
                        is_inherited)
                    );
                }
                if vec!["EnterpriseCA","RootCA","CertTemplate"].contains(&entry_type.as_str()) && has_extended_right(&ace, AUTO_ENROLL)
                {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "AutoEnroll".to_string(),
                        is_inherited)
                    );
                }
            }
        }

        // For AceType == 0x00
        // https://github.com/fox-it/BloodHound.py/blob/645082e3462c93f31b571db945cde1fd7b837fb9/bloodhound/enumeration/acls.py#L162
        if ace.ace_type == 0x00 {
            trace!("TYPE: 0x00");
            let is_inherited = ace.ace_flags & INHERITED_ACE == INHERITED_ACE;

            let mask = match AceFormat::get_mask(ace.data.to_owned()) {
                Some(mask) => mask,
                None => continue,
            };
            trace!("ACE MASK for ACETYPE 0x00: {:?}", mask);

            if (MaskFlags::GENERIC_ALL.bits() | mask) == mask 
            {
                relations.push(AceTemplate::new(
                    sid.to_owned(),
                    "".to_string(),
                    "GenericAll".to_string(),
                    is_inherited)
                );
                continue
            }
            if (MaskFlags::ADS_RIGHT_DS_WRITE_PROP.bits() | mask) == mask 
            {
                relations.push(AceTemplate::new(
                    sid.to_owned(),
                    "".to_string(),
                    "GenericWrite".to_string(),
                    is_inherited)
                );
            }
            if (MaskFlags::WRITE_OWNER.bits() | mask) == mask
            {
                relations.push(AceTemplate::new(
                    sid.to_owned(),
                    "".to_string(),
                    "WriteOwner".to_string(),
                    is_inherited)
                );
            }
            // For users and domain, check extended rights
            if ((entry_type == "User") || (entry_type == "Domain"))
                && ((MaskFlags::ADS_RIGHT_DS_CONTROL_ACCESS.bits() | mask) == mask)
            {
                relations.push(AceTemplate::new(
                    sid.to_owned(),
                    "".to_string(),
                    "AllExtendedRights".to_string(),
                    is_inherited)
                );
            }
            // For computer
            if (entry_type == "Computer")
                && ((MaskFlags::ADS_RIGHT_DS_CONTROL_ACCESS.bits() | mask) == mask)
                && false
            {
                relations.push(AceTemplate::new(
                    sid.to_owned(),
                    "".to_string(),
                    "AllExtendedRights".to_string(),
                    is_inherited)
                );
            }
            if (MaskFlags::WRITE_DACL.bits() | mask) == mask 
            {
                relations.push(AceTemplate::new(
                    sid.to_owned(),
                    "".to_string(),
                    "WriteDacl".to_string(),
                    is_inherited)
                );
            }
            // Self add, also possible ad ACCESS_ALLOWED_ACE
            // Thanks to bh-py: <https://github.com/dirkjanm/BloodHound.py/blob/d47e765fd3d0356e2e4b48d0d9a0841525194c64/bloodhound/enumeration/acls.py#L221C1-L225C97>
            if (MaskFlags::ADS_RIGHT_DS_SELF.bits() | mask) == mask
            && sid != "S-1-5-32-544" && sid.ends_with("-512") && sid.ends_with("-519") 
            {
                relations.push(AceTemplate::new(
                    sid.to_owned(),
                    "".to_string(),
                    "AddSelf".to_string(),
                    is_inherited)
                );
            }
            if vec!["EnterpriseCA","RootCA"].contains(&entry_type.as_str())
            && (MaskFlags::MANAGE_CA.bits() | mask) == mask
            {
                relations.push(AceTemplate::new(
                    sid.to_owned(),
                    "".to_string(),
                    "ManageCA".to_string(),
                    is_inherited)
                );
            }
            if vec!["EnterpriseCA","RootCA"].contains(&entry_type.as_str())
            && (MaskFlags::MANAGE_CERTIFICATES.bits() | mask) == mask
            {
                relations.push(AceTemplate::new(
                    sid.to_owned(),
                    "".to_string(),
                    "ManageCertificates".to_string(),
                    is_inherited)
                );
            }
        }
    }
}

/// Make Relation
/// <https://github.com/fox-it/BloodHound.py/blob/645082e3462c93f31b571db945cde1fd7b837fb9/bloodhound/enumeration/acls.py#L240>
// fn build_relation(
//     sid: &String,
//     relation: String,
//     acetype: String,
//     inherited: bool,
// ) -> serde_json::value::Value {
//     let mut relation_builded = bh_41::prepare_acl_relation_template();

//     relation_builded["RightName"] = relation.to_owned().into();
//     relation_builded["IsInherited"] = inherited.to_owned().into();
//     relation_builded["PrincipalType"] = acetype.to_owned().into();
//     relation_builded["PrincipalSID"] = sid.to_owned().into();

//     return relation_builded;
// }

/// Checks if the access is sufficient to write to a specific property.
/// <https://github.com/fox-it/BloodHound.py/blob/645082e3462c93f31b571db945cde1fd7b837fb9/bloodhound/enumeration/acls.py#L193>
fn can_write_property(ace: &Ace, bin_property: &str) -> bool {
    // This can either be because we have the right ADS_RIGHT_DS_WRITE_PROP and the correct GUID
    // is set in ObjectType, or if we have the ADS_RIGHT_DS_WRITE_PROP right and the ObjectType
    // is empty, in which case we can write to any property. This is documented in
    // [MS-ADTS] section 5.1.3.2: https://msdn.microsoft.com/en-us/library/cc223511.aspx

    // If not found, then assume can't write. Should not happen, but missing some parsers.
    let mask = match AceFormat::get_mask(ace.data.to_owned()) {
        Some(mask) => mask,
        None => return false,
    };

    if (MaskFlags::ADS_RIGHT_DS_WRITE_PROP.bits() | mask) != mask {
        //if not ace_object.acedata.mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_WRITE_PROP):
        return false;
    }

    // Get the Flag for the ace.datas
    let flags = AceFormat::get_flags(ace.data.to_owned()).unwrap().bits();

    if !((&flags & ACE_OBJECT_TYPE_PRESENT) == ACE_OBJECT_TYPE_PRESENT)
    {
        return true;
    }

    let typea = match AceFormat::get_object_type(ace.data.to_owned()) {
        Some(typea) => typea,
        None => 0,
    };

    trace!("AceFormat::get_object_type {}",bin_to_string(&typea.to_be_bytes().to_vec()));
    trace!("bin_property_guid_string {}", bin_property.to_uppercase());

    if bin_to_string(&typea.to_be_bytes().to_vec()) == bin_property.to_uppercase()
    {
        trace!("MATCHED AceFormat::get_object_type with bin_property!");
        return true;
    }

    return false;
}

/// Checks if the access is sufficient to control the right with the given GUID.
/// <https://github.com/fox-it/BloodHound.py/blob/645082e3462c93f31b571db945cde1fd7b837fb9/bloodhound/enumeration/acls.py#L211>
fn has_extended_right(ace: &Ace, bin_right_guid: &str) -> bool {
    // This can either be because we have the right ADS_RIGHT_DS_CONTROL_ACCESS and the correct GUID
    // is set in ObjectType, or if we have the ADS_RIGHT_DS_CONTROL_ACCESS right and the ObjectType
    // is empty, in which case we have all extended rights. This is documented in
    // [MS-ADTS] section 5.1.3.2: https://msdn.microsoft.com/en-us/library/cc223511.aspx

    let mask = match AceFormat::get_mask(ace.data.to_owned()) {
        Some(mask) => mask,
        None => return false,
    };
    if (MaskFlags::ADS_RIGHT_DS_CONTROL_ACCESS.bits() | mask) != mask {
        // if not ace_object.acedata.mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_CONTROL_ACCESS):
        trace!("has_extended_right : return false for ADS_RIGHT_DS_CONTROL_ACCESS != mask");
        return false;
    }
    // Get the Flag for the ace.datas
    let flags = AceFormat::get_flags(ace.data.to_owned()).unwrap().bits();

    if !((&flags & ACE_OBJECT_TYPE_PRESENT) == ACE_OBJECT_TYPE_PRESENT) {
        // if not ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT):
        trace!("has_extended_right : return true for ACE_OBJECT_TYPE_PRESENT != ace_flags");
        return true;
    }

    let typea = match AceFormat::get_object_type(ace.data.to_owned()) {
        Some(typea) => typea,
        None => 0,
    };

    trace!("AceFormat::get_object_type {}",
        bin_to_string(&typea.to_be_bytes().to_vec())
    );
    trace!("bin_right_guid {}", bin_right_guid.to_uppercase());

    if bin_to_string(&typea.to_be_bytes().to_vec()) == bin_right_guid.to_uppercase() {
        trace!("MATCHED AceFormat::get_object_type with bin_right_guid!");
        return true;
    }

    return false;
}

/// Check if an ACE applies to this object.
/// <https://github.com/fox-it/BloodHound.py/blob/645082e3462c93f31b571db945cde1fd7b837fb9/bloodhound/enumeration/acls.py#L229>
fn ace_applies(ace_guid: &String, entry_type: &String) -> bool {
    // Checks if an ACE applies to this object (based on object classes).
    // Note that this function assumes you already verified that InheritedObjectType is set (via the flag).
    // If this is not set, the ACE applies to all object types.
    trace!("ACE GUID: {}", &ace_guid);
    trace!("OBJECTTYPE_GUID_HASHMAP: {}",OBJECTTYPE_GUID_HASHMAP.get(entry_type).unwrap_or(&String::from("GUID-NOT-FOUND")));

    return &ace_guid == &OBJECTTYPE_GUID_HASHMAP.get(entry_type).unwrap_or(&String::from("GUID-NOT-FOUND"))
}

/// Function to check the user can read Service Account password
pub fn parse_gmsa(
    processed_aces: &mut Vec<AceTemplate>,
    user: &mut User
) {
    for i in 0..processed_aces.len()
    {
        match processed_aces[i].right_name().as_str() {
            "Owns" | "Owner" => {},
            _ => {
                *processed_aces[i].right_name_mut() = "ReadGMSAPassword".to_string();
                let mut aces = user.aces().to_owned();
                aces.push(processed_aces[i].to_owned());
                *user.aces_mut() = aces;
            }
        }
    }
}


/// Function to get relations for CASecurity from LDAP attribute.
pub fn parse_ca_security(
    nt: &Vec<u8>,
    hosting_computer_sid: &String,
    domain: &String,
) -> Vec<AceTemplate> {
    // The CASecurity exist in the AD object DACL and in registry of the CA server.
    // SharpHound prefer to use the values from registry as they are the ground truth.
    // If changes are made on the CA server, registry and the AD object is updated.
    // If changes are made directly on the AD object, the CA server registry is not updated.
    // For RustHound, we need to use AD object DACL because we dont have RPC to read registry yet.
    let blacklist_sid = vec![
        // <https://learn.microsoft.com/fr-fr/windows-server/identity/ad-ds/manage/understand-security-identifiers>
        "-544", // Administrators
        "-519", // Enterprise Administrators
        "-512", // Domain Admins
    ];
    let mut relations:  Vec<AceTemplate> = Vec::new();
    // Hosting Computer local administrator group is the owner.
    relations.push(AceTemplate::new(
        hosting_computer_sid.to_owned() + "-544",
        "LocalGroup".to_string(),
        "Owns".to_string(),
        false)
    );
    let secdesc: SecurityDescriptor = SecurityDescriptor::parse(&nt).unwrap().1;
    if secdesc.offset_dacl as usize != 0 
    {
        let res = Acl::parse(&nt[secdesc.offset_dacl as usize..]);    
        match res {
            Ok(_res) => {
                let dacl = _res.1;
                let aces = dacl.data;
                for ace in aces {
                    let sid = sid_maker(AceFormat::get_sid(ace.data.to_owned()).unwrap(), domain);
                    let mask = match AceFormat::get_mask(ace.data.to_owned()) {
                        Some(mask) => mask,
                        None => continue,
                    };
                    if ace.ace_type == 0x05 {
                        if has_extended_right(&ace, ENROLL)
                        {
                            relations.push(AceTemplate::new(
                                sid.to_owned(),
                                "".to_string(),
                                "Enroll".to_string(),
                                false)
                            );
                        }
                    }
                    if ace.ace_type == 0x00 {
                        if (MaskFlags::MANAGE_CERTIFICATES.bits() | mask) == mask
                        {
                            // trace!("SID: {:?}\nMASK: ManageCertificates",&sid);
                            if !blacklist_sid.iter().any(|blacklisted| sid.ends_with(blacklisted)) {
                                // HostingComputer SID, need to add -544 for LocalGroup
                                relations.push(AceTemplate::new(
                                    sid.to_owned() + "-544",
                                    "LocalGroup".to_string(),
                                    "ManageCertificates".to_string(),
                                    false)
                                );
                            } else {
                                relations.push(AceTemplate::new(
                                    sid.to_owned(),
                                    "Group".to_string(),
                                    "ManageCertificates".to_string(),
                                    false)
                                );
                            }
                        }
                        if (MaskFlags::MANAGE_CA.bits() | mask) == mask
                        {
                            // trace!("SID: {:?}\nMASK: ManageCA",&sid);
                            if !blacklist_sid.iter().any(|blacklisted| sid.ends_with(blacklisted)) {
                                // HostingComputer SID, need to add -544 for LocalGroup
                                relations.push(AceTemplate::new(
                                    sid.to_owned() + "-544",
                                    "LocalGroup".to_string(),
                                    "ManageCA".to_string(),
                                    false)
                                );
                            } else {
                                relations.push(AceTemplate::new(
                                    sid.to_owned(),
                                    "Group".to_string(),
                                    "ManageCA".to_string(),
                                    false)
                                );
                            }
                        }
                    }
                }
            },
            Err(err) => { error!("Error. Reason: {err}") }
        }
    }
    return relations
}

// Access Mask contain value?
bitflags! {
    pub struct MaskFlags: u32 {
        // These constants are only used when WRITING
        // and are then translated into their actual rights
        const SET_GENERIC_READ        = 0x80000000;
        const SET_GENERIC_WRITE       = 0x04000000;
        const SET_GENERIC_EXECUTE     = 0x20000000;
        const SET_GENERIC_ALL         = 0x10000000;
        // When reading, these constants are actually represented by
        // the following for Active Directory specific Access Masks
        // Reference: https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2
        const GENERIC_READ            = 0x00020094;
        const GENERIC_WRITE           = 0x00020028;
        const GENERIC_EXECUTE         = 0x00020004;
        const GENERIC_ALL             = 0x000F01FF;

        // These are actual rights (for all ACE types)
        const MAXIMUM_ALLOWED         = 0x02000000;
        const ACCESS_SYSTEM_SECURITY  = 0x01000000;
        const SYNCHRONIZE             = 0x00100000;
        const WRITE_OWNER             = 0x00080000;
        const WRITE_DACL              = 0x00040000;
        const READ_CONTROL            = 0x00020000;
        const DELETE                  = 0x00010000;

        // ACE type specific mask constants (for ACCESS_ALLOWED_OBJECT_ACE)
        // Note that while not documented, these also seem valid
        // for ACCESS_ALLOWED_ACE types
        const ADS_RIGHT_DS_CONTROL_ACCESS         = 0x00000100;
        const ADS_RIGHT_DS_CREATE_CHILD           = 0x00000001;
        const ADS_RIGHT_DS_DELETE_CHILD           = 0x00000002;
        const ADS_RIGHT_DS_READ_PROP              = 0x00000010;
        const ADS_RIGHT_DS_WRITE_PROP             = 0x00000020;
        const ADS_RIGHT_DS_SELF                   = 0x00000008;
        
        // ADCS
        const MANAGE_CA = 1;
        const MANAGE_CERTIFICATES = 2;
    }
}

bitflags! {
    struct SecurityDescriptorFlags: u16 {
        const SELF_RELATIVE = 0b1000000000000000;
        const RM_CONTROL_VALID = 0b0100000000000000;
        const SACL_PROTECTED = 0b0010000000000000;
        const DACL_PROTECTED = 0b0001000000000000;
        const SACL_INHERITED = 0b0000100000000000;
        const DACL_INHERITED = 0b0000010000000000;
        const SACL_COMPUTED_INHERITANCE_REQUIRED = 0b0000001000000000;
        const DACL_COMPUTED_INHERITANCE_REQUIRED = 0b0000000100000000;
        const SERVER_SECURITY = 0b0000000010000000;
        const DACL_TRUSTED = 0b0000000001000000;
        const SACL_DEFAULT = 0b0000000000100000;
        const SACL_PRESENT = 0b0000000000010000;
        const DACL_DEFAULT = 0b0000000000001000;
        const DACL_PRESENT = 0b0000000000000100;
        const GROUP_DEFAULT = 0b0000000000000010;
        const OWNER_DEFAULT = 0b0000000000000001;
    }
}

fn has_control(secdesc_control: u16, flag: SecurityDescriptorFlags) -> bool {
    let flags = SecurityDescriptorFlags::from_bits(secdesc_control).unwrap();
    flags.contains(flag)
}

// OBJECTTYPE_GUID_HASHMAP with all know guid
lazy_static! {
    static ref OBJECTTYPE_GUID_HASHMAP: HashMap<String, String> = {
        let values = [
            ("ms-mcs-admpwdexpirationtime", "2bb09a7b-9acd-4082-9b51-104bb7f6a01e"),
            ("ms-mcs-admpwd", "a740f691-b206-4baa-9ab1-559f8985523f"),
            ("ms-ds-key-credential-link", "5b47d60f-6090-40b2-9f37-2a4de88f3063"),
            ("service-principal-name", "f3a64788-5306-11d1-a9c5-0000f80367c1"),
            ("ms-ds-sitename", "98a7f36d-3595-448a-9e6f-6b8965baed9c"),
            ("frs-staging-path", "1be8f175-a9ff-11d0-afe2-00c04fd930c9"),
            ("account-name-history", "031952ec-3b72-11d2-90cc-00c04fd91ab1"),
            ("ms-ts-property01", "faaea977-9655-49d7-853d-f27bb7aaca0f"),
            ("registered-address", "bf967a10-0de6-11d0-a285-00aa003049e2"),
            ("msi-script-path", "bf967937-0de6-11d0-a285-00aa003049e2"),
            ("ms-ds-promotion-settings", "c881b4e2-43c0-4ebe-b9bb-5250aa9b434c"),
            ("frs-service-command-status", "2a132582-9373-11d1-aebc-0000f80367c1"),
            ("attribute-schema", "bf967a80-0de6-11d0-a285-00aa003049e2"),
            ("ntfrs-member", "2a132586-9373-11d1-aebc-0000f80367c1"),
            ("configuration", "bf967a87-0de6-11d0-a285-00aa003049e2"),
            ("ms-ts-secondary-desktop-bl", "34b107af-a00a-455a-b139-dd1a1b12d8af"),
            ("rdn-att-id", "bf967a0f-0de6-11d0-a285-00aa003049e2"),
            ("msi-script-name", "96a7dd62-9118-11d1-aebc-0000f80367c1"),
            ("ms-ds-hab-seniority-index", "def449f1-fd3b-4045-98cf-d9658da788b5"),
            ("frs-service-command", "ddac0cee-af8f-11d0-afeb-00c04fd930c9"),
            ("account-expires", "bf967915-0de6-11d0-a285-00aa003049e2"),
            ("ms-ts-primary-desktop-bl", "9daadc18-40d1-4ed1-a2bf-6b9bf47d3daa"),
            ("rdn", "bf967a0e-0de6-11d0-a285-00aa003049e2"),
            ("msi-script", "d9e18313-8939-11d1-aebc-0000f80367c1"),
            ("ms-ds-phonetic-display-name", "e21a94e4-2d66-4ce5-b30d-0ef87a776ff0"),
            ("frs-root-security", "5245801f-ca6a-11d0-afff-0000f80367c1"),
            ("subschema", "5a8b3261-c38d-11d1-bbc9-0080c76670c0"),
            ("ntds-site-settings", "19195a5d-6da0-11d0-afd3-00c04fd930c9"),
            ("computer", "bf967a86-0de6-11d0-a285-00aa003049e2"),
            ("ms-ts-secondary-desktops", "f63aa29a-bb31-48e1-bfab-0a6c5a1d39c2"),
            ("range-upper", "bf967a0d-0de6-11d0-a285-00aa003049e2"),
            ("msi-file-list", "7bfdcb7d-4807-11d1-a9c3-0000f80367c1"),
            ("ms-ds-phonetic-company-name", "5bd5208d-e5f4-46ae-a514-543bc9c47659"),
            ("frs-root-path", "1be8f174-a9ff-11d0-afe2-00c04fd930c9"),
            ("ms-ts-primary-desktop", "29259694-09e4-4237-9f72-9306ebe63ab2"),
            ("range-lower", "bf967a0c-0de6-11d0-a285-00aa003049e2"),
            ("mscope-id", "963d2751-48be-11d1-a9c3-0000f80367c1"),
            ("ms-ds-phonetic-department", "6cd53daf-003e-49e7-a702-6fa896e7a6ef"),
            ("frs-replica-set-type", "26d9736b-6070-11d1-a9c6-0000f80367c1"),
            ("dmd", "bf967a8f-0de6-11d0-a285-00aa003049e2"),
            ("ntds-service", "19195a5f-6da0-11d0-afd3-00c04fd930c9"),
            ("com-connection-point", "bf967a85-0de6-11d0-a285-00aa003049e2"),
            ("ms-ts-endpoint-plugin", "3c08b569-801f-4158-b17b-e363d6ae696a"),
            ("querypoint", "7bfdcb86-4807-11d1-a9c3-0000f80367c1"),
            ("ms-wmi-targettype", "ca2a281e-262b-4ff7-b419-bc123352a4e9"),
            ("ms-ds-phonetic-last-name", "f217e4ec-0836-4b90-88af-2f5d4bbda2bc"),
            ("frs-replica-set-guid", "5245801a-ca6a-11d0-afff-0000f80367c1"),
            ("ms-ts-endpoint-type", "377ade80-e2d8-46c5-9bcd-6d9dec93b35e"),
            ("query-policy-object", "e1aea403-cd5b-11d0-afff-0000f80367c1"),
            ("ms-wmi-targetpath", "5006a79a-6bfe-4561-9f52-13cf4dd3e560"),
            ("ms-ds-phonetic-first-name", "4b1cba4e-302f-4134-ac7c-f01f6c797843"),
            ("frs-primary-member", "2a132581-9373-11d1-aebc-0000f80367c1"),
            ("ntds-dsa", "f0f8ffab-1191-11d0-a060-00aa006c33ed"),
            ("ntds-dsa-ro", "85d16ec1-0791-4bc8-8ab3-70980602ff8c"),
            ("class-store", "bf967a84-0de6-11d0-a285-00aa003049e2"),
            ("ms-ts-endpoint-data", "40e1c407-4344-40f3-ab43-3625a34a63a2"),
            ("query-policy-bl", "e1aea404-cd5b-11d0-afff-0000f80367c1"),
            ("ms-wmi-targetobject", "c44f67a5-7de5-4a1f-92d9-662b57364b77"),
            ("ms-ds-non-members-bl", "2a8c68fc-3a7a-4e87-8720-fe77c51cbe74"),
            ("frs-partner-auth-level", "2a132580-9373-11d1-aebc-0000f80367c1"),
            ("ms-ts-initial-program", "9201ac6f-1d69-4dfb-802e-d95510109599"),
            ("query-filter", "cbf70a26-7e78-11d2-9921-0000f87a57d4"),
            ("ms-wmi-targetnamespace", "1c4ab61f-3420-44e5-849d-8b5dbf60feb7"),
            ("ms-ds-non-members", "cafcb1de-f23c-46b5-adf7-1e64957bd5db"),
            ("frs-member-reference-bl", "2a13257f-9373-11d1-aebc-0000f80367c1"),
            ("organization", "bf967aa3-0de6-11d0-a285-00aa003049e2"),
            ("ms-ts-work-directory", "a744f666-3d3c-4cc8-834b-9d4f6f687b8b"),
            ("quality-of-service", "80a67e4e-9f22-11d0-afdd-00c04fd930c9"),
            ("ms-wmi-targetclass", "95b6d8d6-c9e8-4661-a2bc-6a5cabc04c62"),
            ("ms-ds-nc-type", "5a2eacd7-cc2b-48cf-9d9a-b6f1a0024de9"),
            ("frs-member-reference", "2a13257e-9373-11d1-aebc-0000f80367c1"),
            ("ntds-connection", "19195a60-6da0-11d0-afd3-00c04fd930c9"),
            ("class-registration", "bf967a82-0de6-11d0-a285-00aa003049e2"),
            ("ms-ts-default-to-main-printer", "c0ffe2bd-cacf-4dc7-88d5-61e9e95766f6"),
            ("pwd-properties", "bf967a0b-0de6-11d0-a285-00aa003049e2"),
            ("ms-wmi-stringvalidvalues", "37609d31-a2bf-4b58-8f53-2b64e57a076d"),
            ("ms-ds-members-for-az-role-bl", "ececcd20-a7e0-4688-9ccf-02ece5e287f5"),
            ("frs-level-limit", "5245801e-ca6a-11d0-afff-0000f80367c1"),
            ("ms-ts-connect-printer-drives", "8ce6a937-871b-4c92-b285-d99d4036681c"),
            ("pwd-last-set", "bf967a0a-0de6-11d0-a285-00aa003049e2"),
            ("ms-wmi-stringdefault", "152e42b6-37c5-4f55-ab48-1606384a9aea"),
            ("ms-ds-members-for-az-role", "cbf7e6cd-85a4-4314-8939-8bfe80597835"),
            ("frs-flags", "2a13257d-9373-11d1-aebc-0000f80367c1"),
            ("msmq-site-link", "9a0dc346-c100-11d1-bbc5-0080c76670c0"),
            ("certification-authority", "3fdfee50-47f4-11d1-a9c3-0000f80367c1"),
            ("ms-ts-connect-client-drives", "23572aaf-29dd-44ea-b0fa-7e8438b9a4a3"),
            ("pwd-history-length", "bf967a09-0de6-11d0-a285-00aa003049e2"),
            ("ms-wmi-sourceorganization", "34f7ed6c-615d-418d-aa00-549a7d7be03e"),
            ("ms-ds-max-values", "d1e169a4-ebe9-49bf-8fcb-8aef3874592d"),
            ("frs-file-filter", "1be8f170-a9ff-11d0-afe2-00c04fd930c9"),
            ("ms-ts-broken-connection-action", "1cf41bba-5604-463e-94d6-1a1287b72ca3"),
            ("purported-search", "b4b54e50-943a-11d1-aebd-0000f80367c1"),
            ("ms-wmi-scopeguid", "87b78d51-405f-4b7f-80ed-2bd28786f48d"),
            ("ms-ds-password-settings-precedence", "456374ac-1f0a-4617-93cf-bc55a7c9d341"),
            ("frs-fault-condition", "1be8f178-a9ff-11d0-afe2-00c04fd930c9"),
            ("msmq-settings", "9a0dc347-c100-11d1-bbc5-0080c76670c0"),
            ("category-registration", "7d6c0e9d-7e20-11d0-afd6-00c04fd930c9"),
            ("ms-ts-reconnection-action", "366ed7ca-3e18-4c7f-abae-351a01e4b4f7"),
            ("public-key-policy", "80a67e28-9f22-11d0-afdd-00c04fd930c9"),
            ("ms-wmi-querylanguage", "7d3cfa98-c17b-4254-8bd7-4de9b932a345"),
            ("ms-ds-resultant-pso", "b77ea093-88d0-4780-9a98-911f8e8b1dca"),
            ("frs-extensions", "52458020-ca6a-11d0-afff-0000f80367c1"),
            ("msmq-foreign", "9a0dc32f-c100-11d1-bbc5-0080c76670c0"),
            ("ms-ds-quota-amount", "fbb9a00d-3a8c-4233-9cf9-7189264903a1"),
            ("gp-link", "f30e3bbe-9ff0-11d1-b603-0000f80367c1"),
            ("acs-max-duration-per-flow", "7f56127e-5301-11d1-a9c5-0000f80367c1"),
            ("ms-tsls-property01", "87e53590-971d-4a52-955b-4794d15a84ae"),
            ("retired-repl-dsa-signatures", "7bfdcb7f-4807-11d1-a9c3-0000f80367c1"),
            ("msmq-encrypt-key", "9a0dc331-c100-11d1-bbc5-0080c76670c0"),
            ("ms-ds-principal-name", "564e9325-d057-c143-9e3b-4f9e5ef46f93"),
            ("governs-id", "bf96797d-0de6-11d0-a285-00aa003049e2"),
            ("acs-max-aggregate-peak-rate-per-user", "f072230c-aef5-11d1-bdcf-0000f80367c1"),
            ("organizational-unit", "bf967aa5-0de6-11d0-a285-00aa003049e2"),
            ("cross-ref", "bf967a8d-0de6-11d0-a285-00aa003049e2"),
            ("ms-ts-managingls4", "f7a3b6a0-2107-4140-b306-75cb521731e5"),
            ("required-categories", "7d6c0e93-7e20-11d0-afd6-00c04fd930c9"),
            ("msmq-ds-services", "2df90d78-009f-11d2-aa4c-00c04fd7d83a"),
            ("ms-ds-other-settings", "79d2f34c-9d7d-42bb-838f-866b3e4400e2"),
            ("global-address-list", "f754c748-06f4-11d2-aa53-00c04fd7d83a"),
            ("acs-identity-name", "dab029b6-ddf7-11d1-90a5-00c04fd91ab1"),
            ("ms-ts-managingls3", "fad5dcc1-2130-4c87-a118-75322cd67050"),
            ("reps-to", "bf967a1e-0de6-11d0-a285-00aa003049e2"),
            ("msmq-ds-service", "2df90d82-009f-11d2-aa4c-00c04fd7d83a"),
            ("ms-ds-operations-for-az-task-bl", "a637d211-5739-4ed1-89b2-88974548bc59"),
            ("given-name", "f0f8ff8e-1191-11d0-a060-00aa006c33ed"),
            ("acs-event-log-level", "7f561286-5301-11d1-a9c5-0000f80367c1"),
            ("organizational-role", "a8df74bf-c5ea-11d1-bbcb-0080c76670c0"),
            ("crl-distribution-point", "167758ca-47f3-11d1-a9c3-0000f80367c1"),
            ("ms-ts-managingls2", "349f0757-51bd-4fc8-9d66-3eceea8a25be"),
            ("reps-from", "bf967a1d-0de6-11d0-a285-00aa003049e2"),
            ("msmq-digests-mig", "0f71d8e0-da3b-11d1-90a5-00c04fd91ab1"),
            ("ms-ds-operations-for-az-task", "1aacb436-2e9d-44a9-9298-ce4debeb6ebf"),
            ("generation-qualifier", "16775804-47f3-11d1-a9c3-0000f80367c1"),
            ("acs-enable-rsvp-message-logging", "7f561285-5301-11d1-a9c5-0000f80367c1"),
            ("ms-ts-managingls", "f3bcc547-85b0-432c-9ac0-304506bf2c83"),
            ("repl-interval", "45ba9d1a-56fa-11d2-90d0-00c04fd91ab1"),
            ("msmq-digests", "9a0dc33c-c100-11d1-bbc5-0080c76670c0"),
            ("ms-ds-operations-for-az-role-bl", "f85b6228-3734-4525-b6b7-3f3bb220902c"),
            ("generated-connection", "bf96797a-0de6-11d0-a285-00aa003049e2"),
            ("acs-enable-rsvp-accounting", "f072230e-aef5-11d1-bdcf-0000f80367c1"),
            ("organizational-person", "bf967aa4-0de6-11d0-a285-00aa003049e2"),
            ("country", "bf967a8c-0de6-11d0-a285-00aa003049e2"),
            ("ms-ts-licenseversion4", "70ca5d97-2304-490a-8a27-52678c8d2095"),
            ("reports", "bf967a1c-0de6-11d0-a285-00aa003049e2"),
            ("msmq-dependent-client-services", "2df90d76-009f-11d2-aa4c-00c04fd7d83a"),
            ("ms-ds-operations-for-az-role", "93f701be-fa4c-43b6-bc2f-4dbea718ffab"),
            ("garbage-coll-period", "5fd424a1-1262-11d0-a060-00aa006c33ed"),
            ("acs-enable-acs-service", "7f561287-5301-11d1-a9c5-0000f80367c1"),
            ("ms-ts-licenseversion3", "f8ba8f81-4cab-4973-a3c8-3a6da62a5e31"),
            ("replica-source", "bf967a18-0de6-11d0-a285-00aa003049e2"),
            ("msmq-dependent-client-service", "2df90d83-009f-11d2-aa4c-00c04fd7d83a"),
            ("ms-ds-object-reference-bl", "2b702515-c1f7-4b3b-b148-c0e4c6ceecb4"),
            ("fsmo-role-owner", "66171887-8f3c-11d0-afda-00c04fd930c9"),
            ("acs-dsbm-refresh", "1cb3559f-56d0-11d1-a9c6-0000f80367c1"),
            ("ntfrs-subscriptions", "2a132587-9373-11d1-aebc-0000f80367c1"),
            ("control-access-right", "8297931e-86d3-11d0-afda-00c04fd930c9"),
            ("ms-ts-licenseversion2", "4b0df103-8d97-45d9-ad69-85c3080ba4e7"),
            ("repl-uptodate-vector", "bf967a16-0de6-11d0-a285-00aa003049e2"),
            ("msmq-csp-name", "9a0dc334-c100-11d1-bbc5-0080c76670c0"),
            ("ms-ds-object-reference", "638ec2e8-22e7-409c-85d2-11b21bee72de"),
            ("frs-working-path", "1be8f173-a9ff-11d0-afe2-00c04fd930c9"),
            ("acs-dsbm-priority", "1cb3559e-56d0-11d1-a9c6-0000f80367c1"),
            ("ms-ts-licenseversion", "0ae94a89-372f-4df2-ae8a-c64a2bc47278"),
            ("repl-topology-stay-of-execution", "7bfdcb83-4807-11d1-a9c3-0000f80367c1"),
            ("msmq-cost", "9a0dc33a-c100-11d1-bbc5-0080c76670c0"),
            ("ms-ds-machine-account-quota", "d064fb68-1480-11d3-91c1-0000f87a57d4"),
            ("frs-version-guid", "26d9736c-6070-11d1-a9c6-0000f80367c1"),
            ("acs-dsbm-deadtime", "1cb355a0-56d0-11d1-a9c6-0000f80367c1"),
            ("ntfrs-subscriber", "2a132588-9373-11d1-aebc-0000f80367c1"),
            ("container", "bf967a8b-0de6-11d0-a285-00aa003049e2"),
            ("ms-ts-expiredate4", "5e11dc43-204a-4faf-a008-6863621c6f5f"),
            ("repl-property-meta-data", "281416c0-1968-11d0-a28f-00aa003049e2"),
            ("msmq-computer-type-ex", "18120de8-f4c4-4341-bd95-32eb5bcf7c80"),
            ("ms-ds-top-quota-usage", "7b7cce4f-f1f5-4bb6-b7eb-23504af19e75"),
            ("frs-version", "2a132585-9373-11d1-aebc-0000f80367c1"),
            ("acs-direction", "7f56127a-5301-11d1-a9c5-0000f80367c1"),
            ("ms-ts-expiredate3", "41bc7f04-be72-4930-bd10-1f3439412387"),
            ("remote-storage-guid", "2a39c5b0-8960-11d1-aebc-0000f80367c1"),
            ("msmq-computer-type", "9a0dc32e-c100-11d1-bbc5-0080c76670c0"),
            ("ms-ds-tombstone-quota-factor", "461744d7-f3b6-45ba-8753-fb9552a5df32"),
            ("frs-update-timeout", "1be8f172-a9ff-11d0-afe2-00c04fd930c9"),
            ("acs-cache-timeout", "1cb355a1-56d0-11d1-a9c6-0000f80367c1"),
            ("ntfrs-settings", "f780acc2-56f0-11d1-a9c6-0000f80367c1"),
            ("person", "bf967aa7-0de6-11d0-a285-00aa003049e2"),
            ("ms-ts-expiredate2", "54dfcf71-bc3f-4f0b-9d5a-4b2476bb8925"),
            ("remote-source-type", "bf967a15-0de6-11d0-a285-00aa003049e2"),
            ("msmq-base-priority", "9a0dc323-c100-11d1-bbc5-0080c76670c0"),
            ("ms-ds-trust-forest-trust-info", "29cc866e-49d3-4969-942e-1dbc0925d183"),
            ("frs-time-last-config-change", "2a132584-9373-11d1-aebc-0000f80367c1"),
            ("acs-allocable-rsvp-bandwidth", "7f561283-5301-11d1-a9c5-0000f80367c1"),
            ("contact", "5cb41ed0-0e4c-11d0-a286-00aa003049e2"),
            ("ms-ts-expiredate", "70004ef5-25c3-446a-97c8-996ae8566776"),
            ("remote-source", "bf967a14-0de6-11d0-a285-00aa003049e2"),
            ("msmq-authenticate", "9a0dc326-c100-11d1-bbc5-0080c76670c0"),
            ("ms-ds-supported-encryption-types", "20119867-1d04-4ab7-9371-cfc3d5df0afd"),
            ("frs-time-last-command", "2a132583-9373-11d1-aebc-0000f80367c1"),
            ("acs-aggregate-token-rate-per-user", "7f56127d-5301-11d1-a9c5-0000f80367c1"),
            ("ntfrs-replica-set", "5245803a-ca6a-11d0-afff-0000f80367c1"),
            ("connection-point", "5cb41ecf-0e4c-11d0-a286-00aa003049e2"),
            ("ms-ts-property02", "3586f6ac-51b7-4978-ab42-f936463198e7"),
            ("remote-server-name", "bf967a12-0de6-11d0-a285-00aa003049e2"),
            ("msi-script-size", "96a7dd63-9118-11d1-aebc-0000f80367c1"),
            ("ms-dfs-link-security-descriptor-v2", "57cf87f7-3426-4841-b322-02b3b6e9eba8"),
            ("roomnumber", "81d7f8c2-e327-4a0d-91c6-b42d4009115f"),
            ("msmq-os-type", "9a0dc330-c100-11d1-bbc5-0080c76670c0"),
            ("ms-ds-repl-attribute-meta-data", "d7c53242-724e-4c39-9d4c-2df8c9d66c7a"),
            ("help-data16", "5fd424a7-1262-11d0-a060-00aa006c33ed"),
            ("acs-non-reserved-min-policed-size", "b6873917-3b90-11d2-90cc-00c04fd91ab1"),
            ("query-policy", "83cc7075-cca7-11d0-afff-0000f80367c1"),
            ("dns-node", "e0fa1e8c-9b45-11d0-afdd-00c04fd930c9"),
            ("ms-dfs-link-path-v2", "86b021f6-10ab-40a2-a252-1dc0cc3be6a9"),
            ("role-occupant", "a8df7465-c5ea-11d1-bbcb-0080c76670c0"),
            ("msmq-nt4-stub", "6f914be6-d57e-11d1-90a2-00c04fd91ab1"),
            ("ms-ds-preferred-gc-site", "d921b50a-0ab2-42cd-87f6-09cf83a91854"),
            ("has-partial-replica-ncs", "bf967981-0de6-11d0-a285-00aa003049e2"),
            ("acs-non-reserved-max-sdu-size", "aec2cfe3-3b90-11d2-90cc-00c04fd91ab1"),
            ("ms-dfs-link-identity-guid-v2", "edb027f3-5726-4dee-8d4e-dbf07e1ad1f1"),
            ("rights-guid", "8297931c-86d3-11d0-afda-00c04fd930c9"),
            ("msmq-nt4-flags", "eb38a158-d57f-11d1-90a2-00c04fd91ab1"),
            ("ms-ds-per-user-trust-tombstones-quota", "8b70a6c6-50f9-4fa3-a71e-1ce03040449b"),
            ("has-master-ncs", "bf967982-0de6-11d0-a285-00aa003049e2"),
            ("acs-minimum-policed-size", "8d0e7195-3b90-11d2-90cc-00c04fd91ab1"),
            ("print-queue", "bf967aa8-0de6-11d0-a285-00aa003049e2"),
            ("ms-dfs-last-modified-v2", "3c095e8a-314e-465b-83f5-ab8277bcf29b"),
            ("rid-used-pool", "6617188b-8f3c-11d0-afda-00c04fd930c9"),
            ("msmq-name-style", "9a0dc333-c100-11d1-bbc5-0080c76670c0"),
            ("ms-ds-per-user-trust-quota", "d161adf0-ca24-4993-a3aa-8b2c981302e8"),
            ("groups-to-ignore", "eea65904-8ac6-11d0-afda-00c04fd930c9"),
            ("acs-minimum-latency", "9517fefb-3b90-11d2-90cc-00c04fd91ab1"),
            ("display-template", "5fd4250c-1262-11d0-a060-00aa006c33ed"),
            ("ms-dfs-generation-guid-v2", "35b8b3d9-c58f-43d6-930e-5040f2f1a781"),
            ("rid-set-references", "7bfdcb7b-4807-11d1-a9c3-0000f80367c1"),
            ("msmq-multicast-address", "1d2f4412-f10d-4337-9b48-6e5b125cd265"),
            ("ms-ds-non-security-group-extra-classes", "2de144fc-1f52-486f-bdf4-16fcc3084e54"),
            ("group-type", "9a9a021e-4a5b-11d1-a9c3-0000f80367c1"),
            ("acs-minimum-delay-variation", "9c65329b-3b90-11d2-90cc-00c04fd91ab1"),
            ("ms-pki-private-key-recovery-agent", "1562a632-44b9-4a7e-a2d3-e426c96a3acc"),
            ("ms-dfs-comment-v2", "b786cec9-61fd-4523-b2c1-5ceb3860bb32"),
            ("rid-previous-allocation-pool", "6617188a-8f3c-11d0-afda-00c04fd930c9"),
            ("msmq-migrated", "9a0dc33f-c100-11d1-bbc5-0080c76670c0"),
            ("ms-ds-nc-ro-replica-locations-bl", "f547511c-5b2a-44cc-8358-992a88258164"),
            ("group-priority", "eea65905-8ac6-11d0-afda-00c04fd930c9"),
            ("acs-maximum-sdu-size", "87a2d8f9-3b90-11d2-90cc-00c04fd91ab1"),
            ("display-specifier", "e0fa1e8a-9b45-11d0-afdd-00c04fd930c9"),
            ("ms-dfsr-stagingcleanuptriggerinpercent", "d64b9c23-e1fa-467b-b317-6964d744d633"),
            ("rid-next-rid", "6617188c-8f3c-11d0-afda-00c04fd930c9"),
            ("msmq-long-lived", "9a0dc335-c100-11d1-bbc5-0080c76670c0"),
            ("ms-ds-nc-ro-replica-locations", "3df793df-9858-4417-a701-735a1ecebf74"),
            ("group-membership-sam", "bf967980-0de6-11d0-a285-00aa003049e2"),
            ("acs-max-token-rate-per-flow", "7f56127b-5301-11d1-a9c5-0000f80367c1"),
            ("pki-enrollment-service", "ee4aa692-3bba-11d2-90cc-00c04fd91ab1"),
            ("ms-dfsr-commonstagingsizeinmb", "135eb00e-4846-458b-8ea2-a37559afd405"),
            ("rid-manager-reference", "66171886-8f3c-11d0-afda-00c04fd930c9"),
            ("msmq-label-ex", "4580ad25-d407-48d2-ad24-43e6e56793d7"),
            ("ms-ds-nc-replica-locations", "97de9615-b537-46bc-ac0f-10720f3909f3"),
            ("group-attributes", "bf96797e-0de6-11d0-a285-00aa003049e2"),
            ("acs-max-token-bucket-per-flow", "81f6e0df-3b90-11d2-90cc-00c04fd91ab1"),
            ("dhcp-class", "963d2756-48be-11d1-a9c3-0000f80367c1"),
            ("ms-dfsr-commonstagingpath", "936eac41-d257-4bb9-bd55-f310a3cf09ad"),
            ("rid-available-pool", "66171888-8f3c-11d0-afda-00c04fd930c9"),
            ("msmq-label", "9a0dc325-c100-11d1-bbc5-0080c76670c0"),
            ("ms-ds-nc-repl-outbound-neighbors", "855f2ef5-a1c5-4cc4-ba6d-32522848b61f"),
            ("gpc-wql-filter", "7bd4c7a6-1add-4436-8c04-3999a880154c"),
            ("acs-max-size-of-rsvp-log-file", "1cb3559d-56d0-11d1-a9c6-0000f80367c1"),
            ("pki-certificate-template", "e5209ca2-3bba-11d2-90cc-00c04fd91ab1"),
            ("ms-dfsr-options2", "11e24318-4ca6-4f49-9afe-e5eb1afa3473"),
            ("rid-allocation-pool", "66171889-8f3c-11d0-afda-00c04fd930c9"),
            ("msmq-journal-quota", "9a0dc324-c100-11d1-bbc5-0080c76670c0"),
            ("ms-ds-nc-repl-inbound-neighbors", "9edba85a-3e9e-431b-9b1a-a5b6e9eda796"),
            ("gpc-user-extension-names", "42a75fc6-783f-11d2-9916-0000f87a57d4"),
            ("acs-max-size-of-rsvp-account-file", "f0722311-aef5-11d1-bdcf-0000f80367c1"),
            ("dfs-configuration", "8447f9f2-1027-11d0-a05f-00aa006c33ed"),
            ("ms-dfsr-ondemandexclusiondirectoryfilter", "7d523aff-9012-49b2-9925-f922a0018656"),
            ("rid", "bf967a22-0de6-11d0-a285-00aa003049e2"),
            ("msmq-journal", "9a0dc321-c100-11d1-bbc5-0080c76670c0"),
            ("ms-ds-nc-repl-cursors", "8a167ce4-f9e8-47eb-8d78-f7fe80abb2cc"),
            ("gpc-machine-extension-names", "32ff8ecc-783f-11d2-9916-0000f87a57d4"),
            ("acs-max-peak-bandwidth-per-flow", "7f56127c-5301-11d1-a9c5-0000f80367c1"),
            ("physical-location", "b7b13122-b82e-11d0-afee-0000f80367c1"),
            ("ms-dfsr-ondemandexclusionfilefilter", "a68359dc-a581-4ee6-9015-5382c60f0fb4"),
            ("revision", "bf967a21-0de6-11d0-a285-00aa003049e2"),
            ("msmq-interval2", "99b88f52-3b7b-11d2-90cc-00c04fd91ab1"),
            ("ms-ds-quota-used", "b5a84308-615d-4bb7-b05f-2f1746aa439f"),
            ("gpc-functionality-version", "f30e3bc0-9ff0-11d1-b603-0000f80367c1"),
            ("acs-max-peak-bandwidth", "7f561284-5301-11d1-a9c5-0000f80367c1"),
            ("device", "bf967a8e-0de6-11d0-a285-00aa003049e2"),
            ("ms-dfsr-defaultcompressionexclusionfilter", "87811bd5-cd8b-45cb-9f5d-980f3a9e0c97"),
            ("token-groups-no-gc-acceptable", "040fc392-33df-11d2-98b2-0000f87a57d4"),
            ("msmq-interval1", "8ea825aa-3b7b-11d2-90cc-00c04fd91ab1"),
            ("ms-ds-quota-trustee", "16378906-4ea5-49be-a8d1-bfd41dff4f65"),
            ("gpc-file-sys-path", "f30e3bc1-9ff0-11d1-b603-0000f80367c1"),
            ("acs-max-no-of-log-files", "1cb3559c-56d0-11d1-a9c6-0000f80367c1"),
            ("ms-dfsr-disablepacketprivacy", "6a84ede5-741e-43fd-9dd6-aa0f61578621"),
            ("token-groups-global-and-universal", "46a9b11d-60ae-405a-b7e8-ff8a58d456d2"),
            ("msmq-in-routing-servers", "9a0dc32c-c100-11d1-bbc5-0080c76670c0"),
            ("ms-ds-quota-effective", "6655b152-101c-48b4-b347-e1fcebc60157"),
            ("gp-options", "f30e3bbf-9ff0-11d1-b603-0000f80367c1"),
            ("acs-max-no-of-account-files", "f0722310-aef5-11d1-bdcf-0000f80367c1"),
            ("package-registration", "bf967aa6-0de6-11d0-a285-00aa003049e2"),
            ("cross-ref-container", "ef9e60e0-56f7-11d1-a9c6-0000f80367c1"),
            ("ms-tsls-property02", "47c77bb0-316e-4e2f-97f1-0d4c48fca9dd"),
            ("token-groups", "b7c69e6d-2cc7-11d2-854e-00a0c983f608"),
            ("additional-trusted-service-names", "032160be-9824-11d1-aec0-0000f80367c1"),
            ("ds-ui-settings", "09b10f14-6f93-11d2-9905-0000f87a57d4"),
            ("ms-ds-claim-shares-possible-values-with", "52c8d13a-ce0b-4f57-892b-18f5a43a2400"),
            ("sam-domain-updates", "04d2d114-f799-4e9b-bcdc-90e8f5ba7ebe"),
            ("msmq-secured-source", "8bf0221b-7a06-4d63-91f0-1499941813d3"),
            ("ms-ds-tasks-for-az-role-bl", "a0dcd536-5158-42fe-8c40-c00a7ad37959"),
            ("install-ui-level", "96a7dd64-9118-11d1-aebc-0000f80367c1"),
            ("additional-information", "6d05fb41-246b-11d0-a9c8-00aa006c33ed"),
            ("room", "7860e5d2-c8b0-4cbb-bd45-d9455beb9206"),
            ("ms-ds-claim-type-applies-to-class", "6afb0e4c-d876-437c-aeb6-c3e41454c272"),
            ("sam-account-type", "6e7b626c-64f2-11d0-afd2-00c04fd930c9"),
            ("msmq-routing-services", "2df90d77-009f-11d2-aa4c-00c04fd7d83a"),
            ("ms-ds-tasks-for-az-role", "35319082-8c4a-4646-9386-c2949d49894d"),
            ("initials", "f0f8ff90-1191-11d0-a060-00aa006c33ed"),
            ("acs-server-list", "7cbd59a5-3b90-11d2-90cc-00c04fd91ab1"),
            ("domainrelatedobject", "8bfd2d3d-efda-4549-852c-f85e137aedc6"),
            ("ms-ds-claim-attribute-source", "eebc123e-bae6-4166-9e5b-29884a8b76b0"),
            ("sam-account-name", "3e0abfd0-126a-11d0-a060-00aa006c33ed"),
            ("msmq-routing-service", "2df90d81-009f-11d2-aa4c-00c04fd7d83a"),
            ("ms-ds-spn-suffixes", "789ee1eb-8c8e-4e4c-8cec-79b31b7617b5"),
            ("initial-auth-outgoing", "52458024-ca6a-11d0-afff-0000f80367c1"),
            ("acs-total-no-of-flows", "7f561280-5301-11d1-a9c5-0000f80367c1"),
            ("rid-set", "7bfdcb89-4807-11d1-a9c3-0000f80367c1"),
            ("ms-ds-claim-value-type", "c66217b9-e48e-47f7-b7d5-6552b8afd619"),
            ("rpc-ns-transfer-syntax", "29401c4a-7a27-11d0-afd6-00c04fd930c9"),
            ("msmq-recipient-formatname", "3bfe6748-b544-485a-b067-1b310c4334bf"),
            ("ms-ds-site-affinity", "c17c5602-bcb7-46f0-9656-6370ca884b72"),
            ("initial-auth-incoming", "52458023-ca6a-11d0-afff-0000f80367c1"),
            ("acs-time-of-day", "7f561279-5301-11d1-a9c5-0000f80367c1"),
            ("domain-policy", "bf967a99-0de6-11d0-a285-00aa003049e2"),
            ("ms-ds-claim-possible-values", "2e28edee-ed7c-453f-afe4-93bd86f2174f"),
            ("rpc-ns-profile-entry", "bf967a28-0de6-11d0-a285-00aa003049e2"),
            ("msmq-quota", "9a0dc322-c100-11d1-bbc5-0080c76670c0"),
            ("ms-ds-settings", "0e1b47d7-40a3-4b48-8d1b-4cac0c1cdf21"),
            ("indexedscopes", "7bfdcb87-4807-11d1-a9c3-0000f80367c1"),
            ("acs-service-type", "7f56127f-5301-11d1-a9c5-0000f80367c1"),
            ("rid-manager", "6617188d-8f3c-11d0-afda-00c04fd930c9"),
            ("ms-ds-is-used-as-resource-security-attribute", "51c9f89d-4730-468d-a2b5-1d493212d17e"),
            ("rpc-ns-priority", "bf967a27-0de6-11d0-a285-00aa003049e2"),
            ("msmq-queue-type", "9a0dc320-c100-11d1-bbc5-0080c76670c0"),
            ("ms-ds-security-group-extra-classes", "4f146ae8-a4fe-4801-a731-f51848a4f4e4"),
            ("implemented-categories", "7d6c0e92-7e20-11d0-afd6-00c04fd930c9"),
            ("acs-rsvp-log-files-location", "1cb3559b-56d0-11d1-a9c6-0000f80367c1"),
            ("ms-ds-bridgehead-servers-used", "3ced1465-7b71-2541-8780-1e1ea6243a82"),
            ("rpc-ns-object-id", "29401c48-7a27-11d0-afd6-00c04fd930c9"),
            ("msmq-queue-quota", "3f6b8e12-d57f-11d1-90a2-00c04fd91ab1"),
            ("ms-ds-sd-reference-domain", "4c51e316-f628-43a5-b06b-ffb695fcb4f3"),
            ("icon-path", "f0f8ff83-1191-11d0-a060-00aa006c33ed"),
            ("acs-rsvp-account-files-location", "f072230f-aef5-11d1-bdcf-0000f80367c1"),
            ("rfc822localpart", "b93e3a78-cbae-485e-a07b-5ef4ae505686"),
            ("domain-dns", "19195a5b-6da0-11d0-afd3-00c04fd930c9"),
            ("ms-dfs-ttl-v2", "ea944d31-864a-4349-ada5-062e2c614f5e"),
            ("rpc-ns-interface-id", "bf967a25-0de6-11d0-a285-00aa003049e2"),
            ("msmq-queue-name-ext", "2df90d87-009f-11d2-aa4c-00c04fd7d83a"),
            ("ms-ds-schema-extensions", "b39a61be-ed07-4cab-9a4a-4963ed0141e1"),
            ("host", "6043df71-fa48-46cf-ab7c-cbd54644b22d"),
            ("acs-priority", "7f561281-5301-11d1-a9c5-0000f80367c1"),
            ("domain", "19195a5a-6da0-11d0-afd3-00c04fd930c9"),
            ("ms-dfs-target-list-v2", "6ab126c6-fa41-4b36-809e-7ca91610d48f"),
            ("rpc-ns-group", "bf967a24-0de6-11d0-a285-00aa003049e2"),
            ("msmq-queue-journal-quota", "8e441266-d57f-11d1-90a2-00c04fd91ab1"),
            ("ms-ds-retired-repl-nc-signatures", "d5b35506-19d6-4d26-9afb-11357ac99b5e"),
            ("houseidentifier", "a45398b7-c44a-4eb6-82d3-13c10946dbfe"),
            ("acs-policy-name", "1cb3559a-56d0-11d1-a9c6-0000f80367c1"),
            ("residential-person", "a8df74d6-c5ea-11d1-bbcb-0080c76670c0"),
            ("documentseries", "7a2be07c-302f-4b96-bc90-0795d66885f8"),
            ("ms-dfs-short-name-link-path-v2", "2d7826f0-4cf7-42e9-a039-1110e0d9ca99"),
            ("rpc-ns-entry-flags", "80212841-4bdc-11d1-a9c4-0000f80367c1"),
            ("msmq-qm-id", "9a0dc33e-c100-11d1-bbc5-0080c76670c0"),
            ("ms-ds-replicationepoch", "08e3aa79-eb1c-45b5-af7b-8f94246c8e41"),
            ("home-drive", "bf967986-0de6-11d0-a285-00aa003049e2"),
            ("acs-permission-bits", "7f561282-5301-11d1-a9c5-0000f80367c1"),
            ("ms-dfs-schema-minor-version", "fef9a725-e8f1-43ab-bd86-6a0115ce9e38"),
            ("rpc-ns-codeset", "7a0ba0e0-8e98-11d0-afda-00c04fd930c9"),
            ("msmq-privacy-level", "9a0dc327-c100-11d1-bbc5-0080c76670c0"),
            ("ms-ds-replication-notify-subsequent-dsa-delay", "d63db385-dd92-4b52-b1d8-0d3ecc0e86b6"),
            ("home-directory", "bf967985-0de6-11d0-a285-00aa003049e2"),
            ("acs-non-reserved-tx-size", "f072230d-aef5-11d1-bdcf-0000f80367c1"),
            ("remote-storage-service-point", "2a39c5bd-8960-11d1-aebc-0000f80367c1"),
            ("document", "39bad96d-c2d6-4baf-88ab-7e4207600117"),
            ("ms-dfs-schema-major-version", "ec6d7855-704a-4f61-9aa6-c49a7c1d54c7"),
            ("rpc-ns-bindings", "bf967a23-0de6-11d0-a285-00aa003049e2"),
            ("msmq-prev-site-gates", "2df90d75-009f-11d2-aa4c-00c04fd7d83a"),
            ("ms-ds-replication-notify-first-dsa-delay", "85abd4f4-0a89-4e49-bdec-6f35bb2562ba"),
            ("hide-from-ab", "ec05b750-a977-4efe-8e8d-ba6c1a6e33a8"),
            ("acs-non-reserved-tx-limit", "1cb355a2-56d0-11d1-a9c6-0000f80367c1"),
            ("ms-dfs-properties-v2", "0c3e5bc5-eb0e-40f5-9b53-334e958dffdb"),
            ("rpc-ns-annotation", "88611bde-8cf4-11d0-afda-00c04fd930c9"),
            ("msmq-owner-id", "9a0dc328-c100-11d1-bbc5-0080c76670c0"),
            ("ms-ds-replicates-nc-reason", "0ea12b84-08b3-11d3-91bc-0000f87a57d4"),
            ("help-file-name", "5fd424a9-1262-11d0-a060-00aa006c33ed"),
            ("acs-non-reserved-token-size", "a916d7c9-3b90-11d2-90cc-00c04fd91ab1"),
            ("remote-mail-recipient", "bf967aa9-0de6-11d0-a285-00aa003049e2"),
            ("dns-zone", "e0fa1e8b-9b45-11d0-afdd-00c04fd930c9"),
            ("ms-dfs-namespace-identity-guid-v2", "200432ce-ec5f-4931-a525-d7f4afe34e68"),
            ("root-trust", "7bfdcb80-4807-11d1-a9c3-0000f80367c1"),
            ("msmq-out-routing-servers", "9a0dc32b-c100-11d1-bbc5-0080c76670c0"),
            ("ms-ds-repl-value-meta-data", "2f5c8145-e1bd-410b-8957-8bfa81d5acfd"),
            ("help-data32", "5fd424a8-1262-11d0-a060-00aa006c33ed"),
            ("acs-non-reserved-peak-rate", "a331a73f-3b90-11d2-90cc-00c04fd91ab1"),
            ("ms-ds-is-full-replica-for", "c8bc72e0-a6b4-48f0-94a5-fd76a88c9987"),
            ("ipsec-negotiation-policy-type", "07383074-91df-11d1-aebc-0000f80367c1"),
            ("allowed-attributes", "9a7ad940-ca53-11d1-bbd0-0080c76670c0"),
            ("ft-dfs", "8447f9f3-1027-11d0-a05f-00aa006c33ed"),
            ("ms-tpm-srk-pub-thumbprint", "19d706eb-4d76-44a2-85d6-1c342be3be37"),
            ("see-also", "bf967a31-0de6-11d0-a285-00aa003049e2"),
            ("msmq-sites", "9a0dc32a-c100-11d1-bbc5-0080c76670c0"),
            ("ms-ds-krbtgt-link-bl", "5dd68c41-bfdf-438b-9b5d-39d9618bf260"),
            ("ipsec-negotiation-policy-reference", "b40ff822-427a-11d1-a9c2-0000f80367c1"),
            ("admin-property-pages", "52458038-ca6a-11d0-afff-0000f80367c1"),
            ("rpc-server-element", "f29653d0-7ad0-11d0-afd6-00c04fd930c9"),
            ("ms-spp-issuance-license", "1075b3a1-bbaf-49d2-ae8d-c4f25c823303"),
            ("security-identifier", "bf967a2f-0de6-11d0-a285-00aa003049e2"),
            ("msmq-site-name-ex", "422144fa-c17f-4649-94d6-9731ed2784ed"),
            ("ms-ds-revealed-dsas", "94f6f2ac-c76d-4b5e-b71f-f332c3e93c22"),
            ("ipsec-negotiation-policy-action", "07383075-91df-11d1-aebc-0000f80367c1"),
            ("admin-multiselect-property-pages", "18f9b67d-5ac6-4b3b-97db-d0a406afb7ba"),
            ("friendlycountry", "c498f152-dc6b-474a-9f52-7cdba3d7d351"),
            ("ms-spp-config-license", "0353c4b5-d199-40b0-b3c5-deb32fd9ec06"),
            ("secretary", "01072d9a-98ad-4a53-9744-e83e287278fb"),
            ("msmq-site-name", "ffadb4b2-de39-11d1-90a5-00c04fd91ab1"),
            ("ms-ds-secondary-krbtgt-number", "aa156612-2396-467e-ad6a-28d23fdb1865"),
            ("ipsec-name", "b40ff81c-427a-11d1-a9c2-0000f80367c1"),
            ("admin-display-name", "bf96791a-0de6-11d0-a285-00aa003049e2"),
            ("rpc-server", "88611be0-8cf4-11d0-afda-00c04fd930c9"),
            ("ms-spp-phone-license", "67e4d912-f362-4052-8c79-42f45ba7b221"),
            ("search-guide", "bf967a2e-0de6-11d0-a285-00aa003049e2"),
            ("msmq-site-id", "9a0dc340-c100-11d1-bbc5-0080c76670c0"),
            ("ms-ds-reveal-ondemand-group", "303d9f4a-1dd6-4b38-8fc5-33afe8c988ad"),
            ("ipsec-isakmp-reference", "b40ff820-427a-11d1-a9c2-0000f80367c1"),
            ("admin-description", "bf967919-0de6-11d0-a285-00aa003049e2"),
            ("foreign-security-principal", "89e31c12-8530-11d0-afda-00c04fd930c9"),
            ("ms-spp-online-license", "098f368e-4812-48cd-afb7-a136b96807ed"),
            ("search-flags", "bf967a2d-0de6-11d0-a285-00aa003049e2"),
            ("msmq-site-gates-mig", "e2704852-3b7b-11d2-90cc-00c04fd91ab1"),
            ("ms-ds-never-reveal-group", "15585999-fd49-4d66-b25d-eeb96aba8174"),
            ("ipsec-id", "b40ff81d-427a-11d1-a9c2-0000f80367c1"),
            ("admin-count", "bf967918-0de6-11d0-a285-00aa003049e2"),
            ("rpc-profile-element", "f29653cf-7ad0-11d0-afd6-00c04fd930c9"),
            ("ms-spp-confirmation-id", "6e8797c4-acda-4a49-8740-b0bd05a9b831"),
            ("sd-rights-effective", "c3dbafa6-33df-11d2-98b2-0000f87a57d4"),
            ("msmq-site-gates", "9a0dc339-c100-11d1-bbc5-0080c76670c0"),
            ("ms-ds-has-full-replica-ncs", "1d3c2d18-42d0-4868-99fe-0eca1e6fa9f3"),
            ("ipsec-filter-reference", "b40ff823-427a-11d1-a9c2-0000f80367c1"),
            ("admin-context-menu", "553fd038-f32e-11d0-b0bc-00c04fd8dca6"),
            ("file-link-tracking-entry", "8e4eb2ed-4712-11d0-a1a0-00c04fd930c9"),
            ("ms-spp-installation-id", "69bfb114-407b-4739-a213-c663802b3e37"),
            ("script-path", "bf9679a8-0de6-11d0-a285-00aa003049e2"),
            ("msmq-site-foreign", "fd129d8a-d57e-11d1-90a2-00c04fd91ab1"),
            ("ms-ds-revealed-users", "185c7821-3749-443a-bd6a-288899071adb"),
            ("ipsec-data-type", "b40ff81e-427a-11d1-a9c2-0000f80367c1"),
            ("address-type", "5fd42464-1262-11d0-a060-00aa006c33ed"),
            ("rpc-profile", "88611be1-8cf4-11d0-afda-00c04fd930c9"),
            ("ms-spp-kms-ids", "9b663eda-3542-46d6-9df0-314025af2bac"),
            ("scope-flags", "16f3a4c2-7e79-11d2-9921-0000f87a57d4"),
            ("msmq-site-2", "9a0dc338-c100-11d1-bbc5-0080c76670c0"),
            ("ms-ds-krbtgt-link", "778ff5c9-6f4e-4b74-856a-d68383313910"),
            ("ipsec-data", "b40ff81f-427a-11d1-a9c2-0000f80367c1"),
            ("address-syntax", "5fd42463-1262-11d0-a060-00aa006c33ed"),
            ("file-link-tracking", "dd712229-10e4-11d0-a05f-00aa006c33ed"),
            ("ms-spp-csvlk-sku-id", "9684f739-7b78-476d-8d74-31ad7692eef4"),
            ("schema-version", "bf967a2c-0de6-11d0-a285-00aa003049e2"),
            ("msmq-site-1", "9a0dc337-c100-11d1-bbc5-0080c76670c0"),
            ("ms-ds-source-object-dn", "773e93af-d3b4-48d4-b3f9-06457602d3d0"),
            ("invocation-id", "bf96798e-0de6-11d0-a285-00aa003049e2"),
            ("address-home", "16775781-47f3-11d1-a9c3-0000f80367c1"),
            ("rpc-group", "88611bdf-8cf4-11d0-afda-00c04fd930c9"),
            ("ms-spp-csvlk-partial-product-key", "a601b091-8652-453a-b386-87ad239b7c08"),
            ("schema-update", "1e2d06b4-ac8f-11d0-afe3-00c04fd930c9"),
            ("msmq-sign-key", "9a0dc332-c100-11d1-bbc5-0080c76670c0"),
            ("ms-ds-updatescript", "146eb639-bb9f-4fc1-a825-e29e00c77920"),
            ("international-isdn-number", "bf96798d-0de6-11d0-a285-00aa003049e2"),
            ("address-entry-display-table-msdos", "5fd42462-1262-11d0-a060-00aa006c33ed"),
            ("dynamic-object", "66d51249-3355-4c1f-b24e-81f252aca23b"),
            ("ms-spp-csvlk-pid", "b47f510d-6b50-47e1-b556-772c79e4ffc4"),
            ("schema-info", "f9fb64ae-93b4-11d2-9945-0000f87a57d4"),
            ("msmq-sign-certificates-mig", "3881b8ea-da3b-11d1-90a5-00c04fd91ab1"),
            ("ms-ds-user-password-expiry-time-computed", "add5cf10-7b09-4449-9ae6-2534148f8a72"),
            ("inter-site-topology-renew", "b7c69e5f-2cc7-11d2-854e-00a0c983f608"),
            ("address-entry-display-table", "5fd42461-1262-11d0-a060-00aa006c33ed"),
            ("rpc-entry", "bf967aac-0de6-11d0-a285-00aa003049e2"),
            ("ms-ds-members-of-resource-property-list-bl", "7469b704-edb0-4568-a5a5-59f4862c75a7"),
            ("schema-id-guid", "bf967923-0de6-11d0-a285-00aa003049e2"),
            ("msmq-sign-certificates", "9a0dc33b-c100-11d1-bbc5-0080c76670c0"),
            ("ms-ds-user-account-control-computed", "2cc4b836-b63f-4940-8d23-ea7acf06af56"),
            ("inter-site-topology-generator", "b7c69e5e-2cc7-11d2-854e-00a0c983f608"),
            ("address-book-roots", "f70b6e48-06f4-11d2-aa53-00c04fd7d83a"),
            ("dsa", "3fdfee52-47f4-11d1-a9c3-0000f80367c1"),
            ("ms-ds-members-of-resource-property-list", "4d371c11-4cad-4c41-8ad2-b180ab2bd13c"),
            ("schema-flags-ex", "bf967a2b-0de6-11d0-a285-00aa003049e2"),
            ("msmq-services", "9a0dc33d-c100-11d1-bbc5-0080c76670c0"),
            ("ms-ds-tasks-for-az-task-bl", "df446e52-b5fa-4ca2-a42f-13f98a526c8f"),
            ("inter-site-topology-failover", "b7c69e60-2cc7-11d2-854e-00a0c983f608"),
            ("address", "f0f8ff84-1191-11d0-a060-00aa006c33ed"),
            ("rpc-container", "80212842-4bdc-11d1-a9c4-0000f80367c1"),
            ("ms-ds-claim-shares-possible-values-with-bl", "54d522db-ec95-48f5-9bbd-1880ebbb2180"),
            ("schedule", "dd712224-10e4-11d0-a05f-00aa006c33ed"),
            ("msmq-service-type", "9a0dc32d-c100-11d1-bbc5-0080c76670c0"),
            ("ms-ds-tasks-for-az-task", "b11c8ee2-5fcd-46a7-95f0-f38333f096cf"),
            ("instance-type", "bf96798c-0de6-11d0-a285-00aa003049e2"),
            ("must-contain", "bf9679d3-0de6-11d0-a285-00aa003049e2"),
            ("ms-ds-token-group-names", "65650576-4699-4fc9-8d18-26e0cd0137a6"),
            ("keywords", "bf967993-0de6-11d0-a285-00aa003049e2"),
            ("attributecertificateattribute", "fa4693bb-7bc2-4cb9-81a8-c99c43b7905e"),
            ("ms-dns-dnskey-record-set-ttl", "8f4e317f-28d7-442c-a6df-1f491f97b326"),
            ("service-instance-version", "bf967a37-0de6-11d0-a285-00aa003049e2"),
            ("msrassavedframedroute", "db0c90c7-c1f2-11d1-bbc5-0080c76670c0"),
            ("ms-ds-optional-feature-flags", "8a0560c1-97b9-4811-9db7-dc061598965b"),
            ("jpegphoto", "bac80572-09c4-4fa9-9ae6-7628d7adbe0e"),
            ("associatedname", "f7fbfc45-85ab-42a4-a435-780e62f7858b"),
            ("security-object", "bf967aaf-0de6-11d0-a285-00aa003049e2"),
            ("infrastructure-update", "2df90d89-009f-11d2-aa4c-00c04fd7d83a"),
            ("ms-dns-nsec3-iterations", "80b70aab-8959-4ec0-8e93-126e76df3aca"),
            ("service-dns-name-type", "28630eba-41d5-11d1-a9c1-0000f80367c1"),
            ("msrassavedframedipaddress", "db0c90c6-c1f2-11d1-bbc5-0080c76670c0"),
            ("ms-ds-value-type-reference-bl", "ab5543ad-23a1-3b45-b937-9b313d5474a8"),
            ("is-single-valued", "bf967992-0de6-11d0-a285-00aa003049e2"),
            ("associateddomain", "3320fc38-c379-4c17-a510-1bdf6133c5da"),
            ("ms-dns-nsec3-random-salt-length", "13361665-916c-4de7-a59d-b1ebbd0de129"),
            ("service-dns-name", "28630eb8-41d5-11d1-a9c1-0000f80367c1"),
            ("msrassavedcallbacknumber", "db0c90c5-c1f2-11d1-bbc5-0080c76670c0"),
            ("ms-ds-value-type-reference", "78fc5d84-c1dc-3148-8984-58f792d41d3e"),
            ("is-recycled", "8fb59256-55f1-444b-aacb-f5b482fe3459"),
            ("assoc-nt-account", "398f63c0-ca60-11d1-bbd1-0000f81f10c0"),
            ("secret", "bf967aae-0de6-11d0-a285-00aa003049e2"),
            ("inetorgperson", "4828cc14-1437-45bc-9b07-ad6f015e5f28"),
            ("ms-dns-nsec3-hash-algorithm", "ff9e5552-7db7-4138-8888-05ce320a0323"),
            ("service-class-name", "b7b1311d-b82e-11d0-afee-0000f80367c1"),
            ("msradiusservicetype", "db0c90b6-c1f2-11d1-bbc5-0080c76670c0"),
            ("ms-ds-usn-last-sync-success", "31f7b8b6-c9f8-4f2d-a37b-58a823030331"),
            ("is-privilege-holder", "19405b9c-3cfa-11d1-a9c0-0000f80367c1"),
            ("assistant", "0296c11c-40da-11d1-a9c0-0000f80367c1"),
            ("index-server-catalog", "7bfdcb8a-4807-11d1-a9c3-0000f80367c1"),
            ("ms-dns-rfc5011-key-rollovers", "27d93c40-065a-43c0-bdd8-cdf2c7d120aa"),
            ("service-class-info", "bf967a36-0de6-11d0-a285-00aa003049e2"),
            ("msradiusframedroute", "db0c90a9-c1f2-11d1-bbc5-0080c76670c0"),
            ("ms-ds-failed-interactive-logon-count-at-last-successful-logon", "c5d234e5-644a-4403-a665-e26e0aef5e98"),
            ("is-member-of-partial-attribute-set", "19405b9d-3cfa-11d1-a9c0-0000f80367c1"),
            ("asset-number", "ba305f75-47e3-11d0-a1a6-00c04fd930c9"),
            ("sam-server", "bf967aad-0de6-11d0-a285-00aa003049e2"),
            ("ms-dns-ds-record-algorithms", "5c5b7ad2-20fa-44bb-beb3-34b9c0f65579"),
            ("service-class-id", "bf967a35-0de6-11d0-a285-00aa003049e2"),
            ("msradiusframedipaddress", "db0c90a4-c1f2-11d1-bbc5-0080c76670c0"),
            ("ms-ds-failed-interactive-logon-count", "dc3ca86f-70ad-4960-8425-a4d6313d93dd"),
            ("is-member-of-dl", "bf967991-0de6-11d0-a285-00aa003049e2"),
            ("applies-to", "8297931d-86d3-11d0-afda-00c04fd930c9"),
            ("group-policy-container", "f30e3bc2-9ff0-11d1-b603-0000f80367c1"),
            ("ms-dns-maintain-trust-anchor", "0dc063c1-52d9-4456-9e15-9c2434aafd94"),
            ("service-binding-information", "b7b1311c-b82e-11d0-afee-0000f80367c1"),
            ("msradiuscallbacknumber", "db0c909c-c1f2-11d1-bbc5-0080c76670c0"),
            ("ms-ds-last-failed-interactive-logon-time", "c7e7dafa-10c3-4b8b-9acd-54f11063742e"),
            ("is-ephemeral", "f4c453f0-c5f1-11d1-bbcb-0080c76670c0"),
            ("application-name", "dd712226-10e4-11d0-a05f-00aa006c33ed"),
            ("sam-domain-base", "bf967a91-0de6-11d0-a285-00aa003049e2"),
            ("ms-dns-nsec3-optout", "7bea2088-8ce2-423c-b191-66ec506b1595"),
            ("server-state", "bf967a34-0de6-11d0-a285-00aa003049e2"),
            ("msnpsavedcallingstationid", "db0c908e-c1f2-11d1-bbc5-0080c76670c0"),
            ("ms-ds-last-successful-interactive-logon-time", "011929e6-8b5d-4258-b64a-00b0b4949747"),
            ("is-deleted", "bf96798f-0de6-11d0-a285-00aa003049e2"),
            ("app-schema-version", "96a7dd65-9118-11d1-aebc-0000f80367c1"),
            ("groupofuniquenames", "0310a911-93a3-4e21-a7a3-55d85ab2c48b"),
            ("ms-dns-sign-with-nsec3", "c79f2199-6da1-46ff-923c-1f3f800c721e"),
            ("server-role", "bf967a33-0de6-11d0-a285-00aa003049e2"),
            ("msnpcallingstationid", "db0c908a-c1f2-11d1-bbc5-0080c76670c0"),
            ("ms-ds-revealed-list-bl", "aa1c88fd-b0f6-429f-b2ca-9d902266e808"),
            ("is-defunct", "28630ebe-41d5-11d1-a9c1-0000f80367c1"),
            ("anr", "45b01500-c419-11d1-bbc9-0080c76670c0"),
            ("sam-domain", "bf967a90-0de6-11d0-a285-00aa003049e2"),
            ("ms-dns-is-signed", "aa12854c-d8fc-4d5e-91ca-368b8d829bee"),
            ("server-reference-bl", "26d9736e-6070-11d1-a9c6-0000f80367c1"),
            ("msnpcalledstationid", "db0c9089-c1f2-11d1-bbc5-0080c76670c0"),
            ("ms-ds-revealed-list", "cbdad11c-7fec-387b-6219-3a0627d9af81"),
            ("is-critical-system-object", "00fbf30d-91fe-11d1-aebc-0000f80367c1"),
            ("alt-security-identities", "00fbf30c-91fe-11d1-aebc-0000f80367c1"),
            ("group-of-names", "bf967a9d-0de6-11d0-a285-00aa003049e2"),
            ("ms-dns-keymaster-zones", "0be0dd3b-041a-418c-ace9-2f17d23e9d42"),
            ("server-reference", "26d9736d-6070-11d1-a9c6-0000f80367c1"),
            ("msnpallowdialin", "db0c9085-c1f2-11d1-bbc5-0080c76670c0"),
            ("ms-ds-is-user-cachable-at-rodc", "fe01245a-341f-4556-951f-48c033a89050"),
            ("ipsec-policy-reference", "b7b13118-b82e-11d0-afee-0000f80367c1"),
            ("allowed-child-classes-effective", "9a7ad943-ca53-11d1-bbd0-0080c76670c0"),
            ("rras-administration-dictionary", "f39b98ae-938d-11d1-aebd-0000f80367c1"),
            ("ms-tpm-tpm-information-for-computer-bl", "14fa84c9-8ecd-4348-bc91-6d3ced472ab7"),
            ("server-name", "09dcb7a0-165f-11d0-a064-00aa006c33ed"),
            ("msmq-version", "9a0dc336-c100-11d1-bbc5-0080c76670c0"),
            ("ms-ds-is-partial-replica-for", "37c94ff6-c6d4-498f-b2f9-c6f7f8647809"),
            ("ipsec-owners-reference", "b40ff824-427a-11d1-a9c2-0000f80367c1"),
            ("allowed-child-classes", "9a7ad942-ca53-11d1-bbd0-0080c76670c0"),
            ("group", "bf967a9c-0de6-11d0-a285-00aa003049e2"),
            ("ms-tpm-tpm-information-for-computer", "ea1b7b93-5e48-46d5-bc6c-4df4fda78a35"),
            ("serial-number", "bf967a32-0de6-11d0-a285-00aa003049e2"),
            ("msmq-user-sid", "c58aae32-56f9-11d2-90d0-00c04fd91ab1"),
            ("ms-ds-is-domain-for", "ff155a2a-44e5-4de0-8318-13a58988de4f"),
            ("ipsec-nfa-reference", "b40ff821-427a-11d1-a9c2-0000f80367c1"),
            ("allowed-attributes-effective", "9a7ad941-ca53-11d1-bbd0-0080c76670c0"),
            ("rras-administration-connection-point", "2a39c5be-8960-11d1-aebc-0000f80367c1"),
            ("ms-tpm-owner-information-temp", "c894809d-b513-4ff8-8811-f4f43f5ac7bc"),
            ("seq-notification", "ddac0cf2-af8f-11d0-afeb-00c04fd930c9"),
            ("msmq-transactional", "9a0dc329-c100-11d1-bbc5-0080c76670c0"),
            ("ipsec-negotiation-policy", "b40ff827-427a-11d1-a9c2-0000f80367c1"),
            ("ms-authz-central-access-policy-id", "62f29b60-be74-4630-9456-2f6691993a86"),
            ("site-server", "1be8f17c-a9ff-11d0-afe2-00c04fd930c9"),
            ("netboot-machine-file-path", "3e978923-8c01-11d0-afda-00c04fd930c9"),
            ("ms-dfsr-stagingsizeinmb", "250a8f20-f6fc-4559-ae65-e4b24c67aebe"),
            ("legacy-exchange-dn", "28630ebc-41d5-11d1-a9c1-0000f80367c1"),
            ("bridgehead-server-list-bl", "d50c2cdb-8951-11d1-aebc-0000f80367c1"),
            ("ms-authz-resource-condition", "80997877-f874-4c68-864d-6e508a83bdbd"),
            ("site-object-bl", "3e10944d-c354-11d0-aff8-0000f80367c1"),
            ("netboot-locally-installed-oses", "07383080-91df-11d1-aebc-0000f80367c1"),
            ("ms-dfsr-stagingpath", "86b9a69e-f0a6-405d-99bb-77d977992c2a"),
            ("ldap-ipdeny-list", "7359a353-90f7-11d1-aebc-0000f80367c1"),
            ("birth-location", "1f0075f9-7e40-11d0-afd6-00c04fd930c9"),
            ("service-instance", "bf967ab2-0de6-11d0-a285-00aa003049e2"),
            ("ipsec-isakmp-policy", "b40ff828-427a-11d1-a9c2-0000f80367c1"),
            ("ms-authz-last-effective-security-policy", "8e1685c6-3e2f-48a2-a58d-5af0ea789fa0"),
            ("site-object", "3e10944c-c354-11d0-aff8-0000f80367c1"),
            ("netboot-limit-clients", "07383077-91df-11d1-aebc-0000f80367c1"),
            ("ms-dfsr-rootsizeinmb", "90b769ac-4413-43cf-ad7a-867142e740a3"),
            ("ldap-display-name", "bf96799a-0de6-11d0-a285-00aa003049e2"),
            ("bad-pwd-count", "bf96792e-0de6-11d0-a285-00aa003049e2"),
            ("ms-authz-proposed-security-policy", "b946bece-09b5-4b6a-b25a-4b63a330e80e"),
            ("site-list", "d50c2cdc-8951-11d1-aebc-0000f80367c1"),
            ("netboot-intellimirror-oses", "0738307e-91df-11d1-aebc-0000f80367c1"),
            ("ms-dfsr-rootpath", "d7d5e8c1-e61f-464f-9fcf-20bbe0a2ec54"),
            ("ldap-admin-limits", "7359a352-90f7-11d1-aebc-0000f80367c1"),
            ("bad-password-time", "bf96792d-0de6-11d0-a285-00aa003049e2"),
            ("service-connection-point", "28630ec1-41d5-11d1-a9c1-0000f80367c1"),
            ("ipsec-filter", "b40ff826-427a-11d1-a9c2-0000f80367c1"),
            ("ms-authz-effective-security-policy", "07831919-8f94-4fb6-8a42-91545dccdad3"),
            ("site-link-list", "d50c2cdd-8951-11d1-aebc-0000f80367c1"),
            ("netboot-initialization", "3e978920-8c01-11d0-afda-00c04fd930c9"),
            ("ms-dfsr-extension", "78f011ec-a766-4b19-adcf-7b81ed781a4d"),
            ("last-update-sequence", "7d6c0e9c-7e20-11d0-afd6-00c04fd930c9"),
            ("auxiliary-class", "bf96792c-0de6-11d0-a285-00aa003049e2"),
            ("ms-dns-nsec3-current-salt", "387d9432-a6d1-4474-82cd-0a89aae084ae"),
            ("site-guid", "3e978924-8c01-11d0-afda-00c04fd930c9"),
            ("netboot-duid", "532570bd-3d77-424f-822f-0d636dc6daad"),
            ("ms-dfsr-version", "1a861408-38c3-49ea-ba75-85481a77c655"),
            ("last-set-time", "bf967998-0de6-11d0-a285-00aa003049e2"),
            ("authority-revocation-list", "1677578d-47f3-11d1-a9c3-0000f80367c1"),
            ("service-class", "bf967ab1-0de6-11d0-a285-00aa003049e2"),
            ("ipsec-base", "b40ff825-427a-11d1-a9c2-0000f80367c1"),
            ("ms-dns-nsec3-user-salt", "aff16770-9622-4fbc-a128-3088777605b9"),
            ("signature-algorithms", "2a39c5b2-8960-11d1-aebc-0000f80367c1"),
            ("netboot-guid", "3e978921-8c01-11d0-afda-00c04fd930c9"),
            ("ms-frs-topology-pref", "92aa27e0-5c50-402d-9ec1-ee847def9788"),
            ("last-logon-timestamp", "c0e20a04-0e5a-4ff3-9482-5efeaecd7060"),
            ("authentication-options", "bf967928-0de6-11d0-a285-00aa003049e2"),
            ("ms-dns-propagation-time", "ba340d47-2181-4ca0-a2f6-fae4479dab2a"),
            ("sid-history", "17eb4278-d167-11d0-b002-0000f80367c1"),
            ("netboot-current-client-count", "07383079-91df-11d1-aebc-0000f80367c1"),
            ("ms-frs-hub-member", "5643ff81-35b6-4ca9-9512-baf0bd0a2772"),
            ("last-logon", "bf967997-0de6-11d0-a285-00aa003049e2"),
            ("auditing-policy", "6da8a4fe-0e52-11d0-a286-00aa003049e2"),
            ("service-administration-point", "b7b13123-b82e-11d0-afee-0000f80367c1"),
            ("inter-site-transport-container", "26d97375-6070-11d1-a9c6-0000f80367c1"),
            ("ms-dns-parent-has-secure-delegation", "285c6964-c11a-499e-96d8-bf7c75a223c6"),
            ("show-in-advanced-view-only", "bf967984-0de6-11d0-a285-00aa003049e2"),
            ("netboot-answer-requests", "0738307a-91df-11d1-aebc-0000f80367c1"),
            ("ms-exch-owner-bl", "bf9679f4-0de6-11d0-a285-00aa003049e2"),
            ("last-logoff", "bf967996-0de6-11d0-a285-00aa003049e2"),
            ("audio", "d0e1d224-e1a0-42ce-a2da-793ba5244f35"),
            ("ms-dns-dnskey-records", "28c458f5-602d-4ac9-a77c-b3f1be503a7e"),
            ("show-in-address-book", "3e74f60e-3e73-11d1-a9c0-0000f80367c1"),
            ("netboot-answer-only-valid-clients", "0738307b-91df-11d1-aebc-0000f80367c1"),
            ("ms-exch-labeleduri", "16775820-47f3-11d1-a9c3-0000f80367c1"),
            ("last-known-parent", "52ab8670-5709-11d1-a9c6-0000f80367c1"),
            ("attribute-types", "9a7ad944-ca53-11d1-bbd0-0080c76670c0"),
            ("servers-container", "f780acc0-56f0-11d1-a9c6-0000f80367c1"),
            ("inter-site-transport", "26d97376-6070-11d1-a9c6-0000f80367c1"),
            ("ms-dns-signing-keys", "b7673e6d-cad9-4e9e-b31a-63e8098fdd63"),
            ("short-server-name", "45b01501-c419-11d1-bbc9-0080c76670c0"),
            ("netboot-allow-new-clients", "07383076-91df-11d1-aebc-0000f80367c1"),
            ("ms-exch-house-identifier", "a8df7407-c5ea-11d1-bbcb-0080c76670c0"),
            ("last-content-indexed", "bf967995-0de6-11d0-a285-00aa003049e2"),
            ("attribute-syntax", "bf967925-0de6-11d0-a285-00aa003049e2"),
            ("ms-dns-signing-key-descriptors", "3443d8cd-e5b6-4f3b-b098-659a0214a079"),
            ("shell-property-pages", "52458039-ca6a-11d0-afff-0000f80367c1"),
            ("netbios-name", "bf9679d8-0de6-11d0-a285-00aa003049e2"),
            ("ms-exch-assistant-name", "a8df7394-c5ea-11d1-bbcb-0080c76670c0"),
            ("last-backup-restoration-time", "1fbb0be8-ba63-11d0-afef-0000f80367c1"),
            ("attribute-security-guid", "bf967924-0de6-11d0-a285-00aa003049e2"),
            ("server", "bf967a92-0de6-11d0-a285-00aa003049e2"),
            ("intellimirror-scp", "07383085-91df-11d1-aebc-0000f80367c1"),
            ("ms-dns-secure-delegation-polling-period", "f6b0f0be-a8e4-4468-8fd9-c3c47b8722f9"),
            ("shell-context-menu", "553fd039-f32e-11d0-b0bc-00c04fd8dca6"),
            ("nc-name", "bf9679d6-0de6-11d0-a285-00aa003049e2"),
            ("ms-ds-token-group-names-no-gc-acceptable", "523fc6c8-9af4-4a02-9cd7-3dea129eeb27"),
            ("labeleduri", "c569bb46-c680-44bc-a273-e6c227d71b45"),
            ("attribute-id", "bf967922-0de6-11d0-a285-00aa003049e2"),
            ("ms-dns-signature-inception-offset", "03d4c32e-e217-4a61-9699-7bbc4729a026"),
            ("setup-command", "7d6c0e97-7e20-11d0-afd6-00c04fd930c9"),
            ("name-service-flags", "80212840-4bdc-11d1-a9c4-0000f80367c1"),
            ("ms-ds-token-group-names-global-and-universal", "fa06d1f4-7922-4aad-b79c-b2201f54417c"),
            ("knowledge-information", "1677581f-47f3-11d1-a9c3-0000f80367c1"),
            ("attribute-display-names", "cb843f80-48d9-11d1-a9c3-0000f80367c1"),
            ("security-principal", "bf967ab0-0de6-11d0-a285-00aa003049e2"),
            ("intellimirror-group", "07383086-91df-11d1-aebc-0000f80367c1"),
            ("ms-dns-ds-record-set-ttl", "29869b7c-64c4-42fe-97d5-fbc2fa124160"),
            ("catalogs", "7bfdcb81-4807-11d1-a9c3-0000f80367c1"),
            ("subnet-container", "b7b13125-b82e-11d0-afee-0000f80367c1"),
            ("link-track-vol-entry", "ddac0cf6-af8f-11d0-afeb-00c04fd930c9"),
            ("ms-kds-publickey-length", "e338f470-39cd-4549-ab5b-f69f9e583fe0"),
            ("surname", "bf967a41-0de6-11d0-a285-00aa003049e2"),
            ("notification-list", "19195a56-6da0-11d0-afd3-00c04fd930c9"),
            ("ms-dfsr-rdcminfilesizeinkb", "f402a330-ace5-4dc1-8cc9-74d900bf8ae0"),
            ("lockout-time", "28630ebf-41d5-11d1-a9c1-0000f80367c1"),
            ("carlicense", "d4159c92-957d-4a87-8a67-8d2934e01649"),
            ("ms-kds-secretagreement-param", "30b099d9-edfe-7549-b807-eba444da79e9"),
            ("supported-application-context", "1677588f-47f3-11d1-a9c3-0000f80367c1"),
            ("non-security-member-bl", "52458019-ca6a-11d0-afff-0000f80367c1"),
            ("ms-dfsr-rdcenabled", "e3b44e05-f4a7-4078-a730-f48670a743f8"),
            ("lockout-threshold", "bf9679a6-0de6-11d0-a285-00aa003049e2"),
            ("canonical-name", "9a7ad945-ca53-11d1-bbd0-0080c76670c0"),
            ("subnet", "b7b13124-b82e-11d0-afee-0000f80367c1"),
            ("link-track-omt-entry", "ddac0cf7-af8f-11d0-afeb-00c04fd930c9"),
            ("ms-kds-secretagreement-algorithmid", "1702975d-225e-cb4a-b15d-0daea8b5e990"),
            ("supplemental-credentials", "bf967a3f-0de6-11d0-a285-00aa003049e2"),
            ("non-security-member", "52458018-ca6a-11d0-afff-0000f80367c1"),
            ("ms-dfsr-contentsetguid", "1035a8e1-67a8-4c21-b7bb-031cdf99d7a0"),
            ("lockout-duration", "bf9679a5-0de6-11d0-a285-00aa003049e2"),
            ("can-upgrade-script", "d9e18314-8939-11d1-aebc-0000f80367c1"),
            ("ms-kds-kdf-param", "8a800772-f4b8-154f-b41c-2e4271eff7a7"),
            ("superior-dns-root", "5245801d-ca6a-11d0-afff-0000f80367c1"),
            ("next-rid", "bf9679db-0de6-11d0-a285-00aa003049e2"),
            ("ms-dfsr-options", "d6d67084-c720-417d-8647-b696237a114c"),
            ("lock-out-observation-window", "bf9679a4-0de6-11d0-a285-00aa003049e2"),
            ("ca-web-url", "963d2736-48be-11d1-a9c3-0000f80367c1"),
            ("storage", "bf967ab5-0de6-11d0-a285-00aa003049e2"),
            ("link-track-object-move-table", "ddac0cf5-af8f-11d0-afeb-00c04fd930c9"),
            ("ms-kds-kdf-algorithmid", "db2c48b2-d14d-ec4e-9f58-ad579d8b440e"),
            ("super-scopes", "963d274b-48be-11d1-a9c3-0000f80367c1"),
            ("next-level-store", "bf9679da-0de6-11d0-a285-00aa003049e2"),
            ("ms-dfsr-flags", "fe515695-3f61-45c8-9bfa-19c148c57b09"),
            ("location", "09dcb79f-165f-11d0-a064-00aa006c33ed"),
            ("ca-usages", "963d2738-48be-11d1-a9c3-0000f80367c1"),
            ("ms-ds-is-primary-computer-for", "998c06ac-3f87-444e-a5df-11b03dc8a50c"),
            ("super-scope-description", "963d274c-48be-11d1-a9c3-0000f80367c1"),
            ("network-address", "bf9679d9-0de6-11d0-a285-00aa003049e2"),
            ("ms-dfsr-keywords", "048b4692-6227-4b67-a074-c4437083e14b"),
            ("localization-display-id", "a746f0d1-78d0-11d2-9916-0000f87a57d4"),
            ("ca-connect", "963d2735-48be-11d1-a9c3-0000f80367c1"),
            ("sites-container", "7a4117da-cd67-11d0-afff-0000f80367c1"),
            ("licensing-site-settings", "1be8f17d-a9ff-11d0-afe2-00c04fd930c9"),
            ("ms-ds-primary-computer", "a13df4e2-dbb0-4ceb-828b-8b2e143e9e81"),
            ("subschemasubentry", "9a7ad94d-ca53-11d1-bbd0-0080c76670c0"),
            ("netboot-tools", "0738307f-91df-11d1-aebc-0000f80367c1"),
            ("ms-dfsr-schedule", "4699f15f-a71f-48e2-9ff5-5897c0759205"),
            ("localized-description", "d9e18316-8939-11d1-aebc-0000f80367c1"),
            ("ca-certificate-dn", "963d2740-48be-11d1-a9c3-0000f80367c1"),
            ("ms-ds-generation-id", "1e5d393d-8cb7-4b4f-840a-973b36cc09c3"),
            ("sub-refs", "bf967a3c-0de6-11d0-a285-00aa003049e2"),
            ("netboot-sif-file", "2df90d84-009f-11d2-aa4c-00c04fd7d83a"),
            ("ms-dfsr-directoryfilter", "93c7b477-1f2e-4b40-b7bf-007e8d038ccf"),
            ("locality-name", "bf9679a2-0de6-11d0-a285-00aa003049e2"),
            ("ca-certificate", "bf967932-0de6-11d0-a285-00aa003049e2"),
            ("site-link-bridge", "d50c2cdf-8951-11d1-aebc-0000f80367c1"),
            ("leaf", "bf967a9e-0de6-11d0-a285-00aa003049e2"),
            ("ms-ds-claim-is-single-valued", "cd789fb9-96b4-4648-8219-ca378161af38"),
            ("sub-class-of", "bf967a3b-0de6-11d0-a285-00aa003049e2"),
            ("netboot-server", "07383081-91df-11d1-aebc-0000f80367c1"),
            ("ms-dfsr-filefilter", "d68270ac-a5dc-4841-a6ac-cd68be38c181"),
            ("locale-id", "bf9679a1-0de6-11d0-a285-00aa003049e2"),
            ("bytes-per-minute", "ba305f76-47e3-11d0-a1a6-00c04fd930c9"),
            ("ms-ds-claim-is-value-space-restricted", "0c2ce4c7-f1c3-4482-8578-c60d4bb74422"),
            ("structural-object-class", "3860949f-f6a8-4b38-9950-81ecb6bc2982"),
            ("netboot-scp-bl", "07383082-91df-11d1-aebc-0000f80367c1"),
            ("ms-dfsr-tombstoneexpiryinmin", "23e35d4c-e324-4861-a22f-e199140dae00"),
            ("local-policy-reference", "80a67e4d-9f22-11d0-afdd-00c04fd930c9"),
            ("business-category", "bf967931-0de6-11d0-a285-00aa003049e2"),
            ("site-link", "d50c2cde-8951-11d1-aebc-0000f80367c1"),
            ("ipsec-policy", "b7b13121-b82e-11d0-afee-0000f80367c1"),
            ("ms-ds-claim-source-type", "92f19c05-8dfa-4222-bbd1-2c4f01487754"),
            ("street-address", "bf967a3a-0de6-11d0-a285-00aa003049e2"),
            ("netboot-new-machine-ou", "0738307d-91df-11d1-aebc-0000f80367c1"),
            ("ms-dfsr-replicationgrouptype", "eeed0fc8-1001-45ed-80cc-bbf744930720"),
            ("local-policy-flags", "bf96799e-0de6-11d0-a285-00aa003049e2"),
            ("builtin-modified-count", "bf967930-0de6-11d0-a285-00aa003049e2"),
            ("ms-ds-claim-source", "fa32f2a6-f28b-47d0-bf91-663e8f910a72"),
            ("state-or-province-name", "bf967a39-0de6-11d0-a285-00aa003049e2"),
            ("netboot-new-machine-naming-policy", "0738307c-91df-11d1-aebc-0000f80367c1"),
            ("ms-dfsr-enabled", "03726ae7-8e7d-4446-8aae-a91657c00993"),
            ("lm-pwd-history", "bf96799d-0de6-11d0-a285-00aa003049e2"),
            ("builtin-creation-time", "bf96792f-0de6-11d0-a285-00aa003049e2"),
            ("site", "bf967ab3-0de6-11d0-a285-00aa003049e2"),
            ("ipsec-nfa", "b40ff829-427a-11d1-a9c2-0000f80367c1"),
            ("ms-authz-member-rules-in-central-access-policy-bl", "516e67cf-fedd-4494-bb3a-bc506a948891"),
            ("spn-mappings", "2ab0e76c-7041-11d2-9905-0000f87a57d4"),
            ("netboot-mirror-data-file", "2df90d85-009f-11d2-aa4c-00c04fd7d83a"),
            ("ms-dfsr-conflictsizeinmb", "9ad33fc9-aacf-4299-bb3e-d1fc6ea88e49"),
            ("link-track-secret", "2ae80fe2-47b4-11d0-a1a4-00c04fd930c9"),
            ("buildingname", "f87fa54b-b2c5-4fd7-88c0-daccb21d93c5"),
            ("ms-authz-member-rules-in-central-access-policy", "57f22f7a-377e-42c3-9872-cec6f21d2e3e"),
            ("smtp-mail-address", "26d9736f-6070-11d1-a9c6-0000f80367c1"),
            ("netboot-max-clients", "07383078-91df-11d1-aebc-0000f80367c1"),
            ("ms-dfsr-conflictpath", "5cf0bcc8-60f7-4bff-bda6-aea0344eb151"),
            ("link-id", "bf96799b-0de6-11d0-a285-00aa003049e2"),
            ("bridgehead-transport-list", "d50c2cda-8951-11d1-aebc-0000f80367c1"),
            ("simplesecurityobject", "5fe69b0b-e146-4f15-b0ab-c1e5d488e094"),
            ("ms-dfsr-maxageincacheinmin", "2ab0e48d-ac4e-4afc-83e5-a34240db6198"),
            ("marshalled-interface", "bf9679b9-0de6-11d0-a285-00aa003049e2"),
            ("com-typelib-id", "281416de-1968-11d0-a28f-00aa003049e2"),
            ("shadowaccount", "5b6d8467-1a18-4174-b350-9cc6e7b4ac8d"),
            ("ms-com-partitionset", "250464ab-c417-497a-975a-9e0d459a7ca1"),
            ("ms-ds-groupmsamembership", "888eedd6-ce04-df40-b462-b8a50e41ba38"),
            ("telex-primary", "0296c121-40da-11d1-a9c0-0000f80367c1"),
            ("oem-information", "bf9679ea-0de6-11d0-a285-00aa003049e2"),
            ("ms-dfsr-mindurationcacheinmin", "4c5d607a-ce49-444a-9862-82a95f5d1fcc"),
            ("mapi-id", "bf9679b7-0de6-11d0-a285-00aa003049e2"),
            ("com-treat-as-class-id", "281416db-1968-11d0-a28f-00aa003049e2"),
            ("ms-ds-managedpasswordinterval", "f8758ef7-ac76-8843-a2ee-a26b4dcaf409"),
            ("telex-number", "bf967a4b-0de6-11d0-a285-00aa003049e2"),
            ("object-version", "16775848-47f3-11d1-a9c3-0000f80367c1"),
            ("ms-dfsr-cachepolicy", "db7a08e7-fc76-4569-a45f-f5ecb66a88b5"),
            ("manager", "bf9679b5-0de6-11d0-a285-00aa003049e2"),
            ("com-progid", "bf96793d-0de6-11d0-a285-00aa003049e2"),
            ("posixaccount", "ad44bb41-67d5-4d88-b575-7b20674e76d8"),
            ("ms-com-partition", "c9010e74-4e58-49f7-8a89-5e3e2340fcf8"),
            ("ms-ds-managedpasswordpreviousid", "d0d62131-2d4a-d04f-99d9-1c63646229a4"),
            ("teletex-terminal-identifier", "bf967a4a-0de6-11d0-a285-00aa003049e2"),
            ("object-sid", "bf9679e8-0de6-11d0-a285-00aa003049e2"),
            ("ms-dfsr-readonly", "5ac48021-e447-46e7-9d23-92c0c6a90dfb"),
            ("managed-objects", "0296c124-40da-11d1-a9c0-0000f80367c1"),
            ("com-other-prog-id", "281416dd-1968-11d0-a28f-00aa003049e2"),
            ("ms-ds-managedpasswordid", "0e78295a-c6d3-0a40-b491-d62251ffa0a6"),
            ("telephone-number", "bf967a49-0de6-11d0-a285-00aa003049e2"),
            ("object-guid", "bf9679e7-0de6-11d0-a285-00aa003049e2"),
            ("ms-dfsr-deletedsizeinmb", "53ed9ad1-9975-41f4-83f5-0c061a12553a"),
            ("managed-by", "0296c120-40da-11d1-a9c0-0000f80367c1"),
            ("com-interfaceid", "bf96793c-0de6-11d0-a285-00aa003049e2"),
            ("volume", "bf967abb-0de6-11d0-a285-00aa003049e2"),
            ("meeting", "11b6cc94-48c4-11d1-a9c3-0000f80367c1"),
            ("ms-ds-managedpassword", "e362ed86-b728-0842-b27d-2dea7a9df218"),
            ("system-poss-superiors", "bf967a47-0de6-11d0-a285-00aa003049e2"),
            ("object-count", "34aaa216-b699-11d0-afee-0000f80367c1"),
            ("ms-dfsr-deletedpath", "817cf0b8-db95-4914-b833-5a079ef65764"),
            ("machine-wide-policy", "80a67e4f-9f22-11d0-afdd-00c04fd930c9"),
            ("com-clsid", "281416d9-1968-11d0-a28f-00aa003049e2"),
            ("ms-ds-allowed-to-act-on-behalf-of-other-identity", "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79"),
            ("system-only", "bf967a46-0de6-11d0-a285-00aa003049e2"),
            ("object-classes", "9a7ad94b-ca53-11d1-bbd0-0080c76670c0"),
            ("ms-dfsr-priority", "eb20e7d6-32ad-42de-b141-16ad2631b01b"),
            ("machine-role", "bf9679b2-0de6-11d0-a285-00aa003049e2"),
            ("com-classid", "bf96793b-0de6-11d0-a285-00aa003049e2"),
            ("user", "bf967aba-0de6-11d0-a285-00aa003049e2"),
            ("mail-recipient", "bf967aa1-0de6-11d0-a285-00aa003049e2"),
            ("ms-imaging-hash-algorithm", "8ae70db5-6406-4196-92fe-f3bb557520a7"),
            ("system-must-contain", "bf967a45-0de6-11d0-a285-00aa003049e2"),
            ("object-class-category", "bf9679e6-0de6-11d0-a285-00aa003049e2"),
            ("ms-dfsr-computerreferencebl", "5eb526d7-d71b-44ae-8cc6-95460052e6ac"),
            ("machine-password-change-interval", "c9b6358e-bb38-11d0-afef-0000f80367c1"),
            ("code-page", "bf967938-0de6-11d0-a285-00aa003049e2"),
            ("type-library", "281416e2-1968-11d0-a28f-00aa003049e2"),
            ("ms-imaging-thumbprint-hash", "9cdfdbc5-0304-4569-95f6-c4f663fe5ae6"),
            ("system-may-contain", "bf967a44-0de6-11d0-a285-00aa003049e2"),
            ("object-class", "bf9679e5-0de6-11d0-a285-00aa003049e2"),
            ("ms-dfsr-memberreferencebl", "adde62c6-1880-41ed-bd3c-30b7d25e14f0"),
            ("machine-architecture", "bf9679af-0de6-11d0-a285-00aa003049e2"),
            ("class-display-name", "548e1c22-dea6-11d0-b010-0000f80367c1"),
            ("lost-and-found", "52ab8671-5709-11d1-a9c6-0000f80367c1"),
            ("ms-kds-createtime", "ae18119f-6390-0045-b32d-97dbc701aef7"),
            ("system-flags", "e0fa1e62-9b45-11d0-afdd-00c04fd930c9"),
            ("object-category", "26d97369-6070-11d1-a9c6-0000f80367c1"),
            ("ms-dfsr-computerreference", "6c7b5785-3d21-41bf-8a8a-627941544d5a"),
            ("lsa-modified-count", "bf9679ae-0de6-11d0-a285-00aa003049e2"),
            ("certificate-templates", "2a39c5b1-8960-11d1-aebc-0000f80367c1"),
            ("trusted-domain", "bf967ab8-0de6-11d0-a285-00aa003049e2"),
            ("ms-kds-usestarttime", "6cdc047f-f522-b74a-9a9c-d95ac8cdfda2"),
            ("system-auxiliary-class", "bf967a43-0de6-11d0-a285-00aa003049e2"),
            ("obj-dist-name", "bf9679e4-0de6-11d0-a285-00aa003049e2"),
            ("ms-dfsr-memberreference", "261337aa-f1c3-44b2-bbea-c88d49e6f0c7"),
            ("lsa-creation-time", "bf9679ad-0de6-11d0-a285-00aa003049e2"),
            ("certificate-revocation-list", "1677579f-47f3-11d1-a9c3-0000f80367c1"),
            ("locality", "bf967aa0-0de6-11d0-a285-00aa003049e2"),
            ("ms-kds-domainid", "96400482-cf07-e94c-90e8-f2efc4f0495e"),
            ("sync-with-sid", "037651e5-441d-11d1-a9c3-0000f80367c1"),
            ("nt-security-descriptor", "bf9679e3-0de6-11d0-a285-00aa003049e2"),
            ("ms-dfsr-dfslinktarget", "f7b85ba9-3bf9-428f-aab4-2eee6d56f063"),
            ("logon-workstation", "bf9679ac-0de6-11d0-a285-00aa003049e2"),
            ("certificate-authority-object", "963d2732-48be-11d1-a9c3-0000f80367c1"),
            ("top", "bf967ab7-0de6-11d0-a285-00aa003049e2"),
            ("ms-kds-version", "d5f07340-e6b0-1e4a-97be-0d3318bd9db1"),
            ("sync-with-object", "037651e2-441d-11d1-a9c3-0000f80367c1"),
            ("nt-pwd-history", "bf9679e2-0de6-11d0-a285-00aa003049e2"),
            ("ms-dfsr-replicationgroupguid", "2dad8796-7619-4ff8-966e-0a5cc67b287f"),
            ("logon-hours", "bf9679ab-0de6-11d0-a285-00aa003049e2"),
            ("category-id", "7d6c0e94-7e20-11d0-afd6-00c04fd930c9"),
            ("link-track-volume-table", "ddac0cf4-af8f-11d0-afeb-00c04fd930c9"),
            ("ms-kds-rootkeydata", "26627c27-08a2-0a40-a1b1-8dce85b42993"),
            ("sync-membership", "037651e3-441d-11d1-a9c3-0000f80367c1"),
            ("nt-mixed-domain", "3e97891f-8c01-11d0-afda-00c04fd930c9"),
            ("ms-dfsr-rootfence", "51928e94-2cd8-4abe-b552-e50412444370"),
            ("logon-count", "bf9679aa-0de6-11d0-a285-00aa003049e2"),
            ("categories", "7bfdcb7e-4807-11d1-a9c3-0000f80367c1"),
            ("ms-kds-privatekey-length", "615f42a1-37e7-1148-a0dd-3007e09cfc81"),
            ("sync-attributes", "037651e4-441d-11d1-a9c3-0000f80367c1"),
            ("nt-group-members", "bf9679df-0de6-11d0-a285-00aa003049e2"),
            ("ms-dfsr-dfspath", "2cc903e2-398c-443b-ac86-ff6b01eac7ba"),
            ("logo", "bf9679a9-0de6-11d0-a285-00aa003049e2"),
            ("trust-auth-incoming", "bf967a59-0de6-11d0-a285-00aa003049e2"),
            ("organizationalstatus", "28596019-7349-4d2f-adff-5a629961f942"),
            ("ms-net-ieee-80211-gp-policydata", "9c1495a5-4d76-468e-991e-1433b0a67855"),
            ("meetingid", "11b6cc7c-48c4-11d1-a9c3-0000f80367c1"),
            ("creation-time", "bf967946-0de6-11d0-a285-00aa003049e2"),
            ("nisnetgroup", "72efbf84-6e7b-4a5c-a8db-8a75a7cad254"),
            ("ms-ds-az-scope", "4feae054-ce55-47bb-860e-5b12063a51de"),
            ("ms-ds-cloudextensionattribute3", "82f6c81a-fada-4a0d-b0f7-706d46838eb5"),
            ("trust-attributes", "80a67e5a-9f22-11d0-afdd-00c04fd930c9"),
            ("organizational-unit-name", "bf9679f0-0de6-11d0-a285-00aa003049e2"),
            ("ms-net-ieee-80211-gp-policyguid", "35697062-1eaf-448b-ac1e-388e0be4fdee"),
            ("meetingendtime", "11b6cc91-48c4-11d1-a9c3-0000f80367c1"),
            ("create-wizard-ext", "2b09958b-8931-11d1-aebc-0000f80367c1"),
            ("ms-ds-cloudextensionattribute2", "f34ee0ac-c0c1-4ba9-82c9-1a90752f16a5"),
            ("tree-name", "28630ebd-41d5-11d1-a9c1-0000f80367c1"),
            ("organization-name", "bf9679ef-0de6-11d0-a285-00aa003049e2"),
            ("ms-imaging-psp-string", "7b6760ae-d6ed-44a6-b6be-9de62c09ec67"),
            ("meetingdescription", "11b6cc7e-48c4-11d1-a9c3-0000f80367c1"),
            ("create-time-stamp", "2df90d73-009f-11d2-aa4c-00c04fd7d83a"),
            ("ipnetwork", "d95836c3-143e-43fb-992a-b057f1ecadf9"),
            ("ms-ds-az-role", "8213eac9-9d55-44dc-925c-e9a52b927644"),
            ("ms-ds-cloudextensionattribute1", "9709eaaf-49da-4db2-908a-0446e5eab844"),
            ("treat-as-leaf", "8fd044e3-771f-11d1-aeae-0000f80367c1"),
            ("options-location", "963d274e-48be-11d1-a9c3-0000f80367c1"),
            ("ms-imaging-psp-identifier", "51583ce9-94fa-4b12-b990-304c35b18595"),
            ("meetingcontactinfo", "11b6cc87-48c4-11d1-a9c3-0000f80367c1"),
            ("create-dialog", "2b09958a-8931-11d1-aebc-0000f80367c1"),
            ("ms-ds-rid-pool-allocation-enabled", "24977c8c-c1b7-3340-b4f6-2b375eb711d7"),
            ("transport-type", "26d97374-6070-11d1-a9c6-0000f80367c1"),
            ("options", "19195a53-6da0-11d0-afd3-00c04fd930c9"),
            ("ms-iis-ftp-root", "2a7827a4-1483-49a5-9d84-52e3812156b4"),
            ("meetingblob", "11b6cc93-48c4-11d1-a9c3-0000f80367c1"),
            ("country-name", "bf967945-0de6-11d0-a285-00aa003049e2"),
            ("iphost", "ab911646-8827-4f95-8780-5a8f008eb68f"),
            ("ms-ds-az-operation", "860abe37-9a9b-4fa4-b3d2-b8ace5df9ec5"),
            ("ms-ds-applies-to-resource-types", "693f2006-5764-3d4a-8439-58f04aab4b59"),
            ("transport-dll-name", "26d97372-6070-11d1-a9c6-0000f80367c1"),
            ("option-description", "963d274d-48be-11d1-a9c3-0000f80367c1"),
            ("ms-iis-ftp-dir", "8a5c99e9-2230-46eb-b8e8-e59d712eb9ee"),
            ("meetingbandwidth", "11b6cc92-48c4-11d1-a9c3-0000f80367c1"),
            ("country-code", "5fd42471-1262-11d0-a060-00aa006c33ed"),
            ("ms-ds-transformation-rules-compiled", "0bb49a10-536b-bc4d-a273-0bab0dd4bd10"),
            ("transport-address-attribute", "c1dc867c-a261-11d1-b606-0000f80367c1"),
            ("operator-count", "bf9679ee-0de6-11d0-a285-00aa003049e2"),
            ("ms-ieee-80211-id", "7f73ef75-14c9-4c23-81de-dd07a06f9e8b"),
            ("meetingapplication", "11b6cc83-48c4-11d1-a9c3-0000f80367c1"),
            ("cost", "bf967944-0de6-11d0-a285-00aa003049e2"),
            ("oncrpc", "cadd1e5e-fefc-4f3f-b5a9-70e994204303"),
            ("ms-ds-az-application", "ddf8de9b-cba5-4e12-842e-28d8b66f75ec"),
            ("ms-ds-tdo-ingress-bl", "5a5661a1-97c6-544b-8056-e430fe7bc554"),
            ("tombstone-lifetime", "16c3a860-1273-11d0-a060-00aa006c33ed"),
            ("operating-system-version", "3e978926-8c01-11d0-afda-00c04fd930c9"),
            ("ms-ieee-80211-data-type", "6558b180-35da-4efe-beed-521f8f48cafb"),
            ("meetingadvertisescope", "11b6cc8b-48c4-11d1-a9c3-0000f80367c1"),
            ("control-access-rights", "6da8a4fc-0e52-11d0-a286-00aa003049e2"),
            ("ms-ds-tdo-egress-bl", "d5006229-9913-2242-8b17-83761d1e0e5b"),
            ("title", "bf967a55-0de6-11d0-a285-00aa003049e2"),
            ("operating-system-service-pack", "3e978927-8c01-11d0-afda-00c04fd930c9"),
            ("ms-ieee-80211-data", "0e0d0938-2658-4580-a9f6-7a0ac7b566cb"),
            ("may-contain", "bf9679bf-0de6-11d0-a285-00aa003049e2"),
            ("context-menu", "4d8601ee-ac85-11d0-afe3-00c04fd930c9"),
            ("ipprotocol", "9c2dcbd2-fbf0-4dc7-ace0-8356dcd0f013"),
            ("ms-ds-az-admin-manager", "cfee1051-5f28-4bae-a863-5d0cc18a8ed1"),
            ("ms-ds-egress-claims-transformation-policy", "c137427e-9a73-b040-9190-1b095bb43288"),
            ("time-vol-change", "ddac0cf0-af8f-11d0-afeb-00c04fd930c9"),
            ("operating-system-hotfix", "bd951b3c-9c96-11d0-afdd-00c04fd930c9"),
            ("ms-tpm-ownerinformation", "aa4e1a6d-550d-4e05-8c35-4afcb917a9fe"),
            ("max-ticket-age", "bf9679be-0de6-11d0-a285-00aa003049e2"),
            ("content-indexing-allowed", "bf967943-0de6-11d0-a285-00aa003049e2"),
            ("ms-ds-ingress-claims-transformation-policy", "86284c08-0c6e-1540-8b15-75147d23d20d"),
            ("time-refresh", "ddac0cf1-af8f-11d0-afeb-00c04fd930c9"),
            ("operating-system", "3e978925-8c01-11d0-afda-00c04fd930c9"),
            ("ms-fve-recoveryguid", "f76909bc-e678-47a0-b0b3-f86a0044c06d"),
            ("max-storage", "bf9679bd-0de6-11d0-a285-00aa003049e2"),
            ("company", "f0f8ff88-1191-11d0-a060-00aa006c33ed"),
            ("ipservice", "2517fadf-fa97-48ad-9de6-79ac5721f864"),
            ("ms-ds-app-data", "9e67d761-e327-4d55-bc95-682f875e2f8e"),
            ("ms-ds-transformation-rules", "55872b71-c4b2-3b48-ae51-4095f91ec600"),
            ("text-encoded-or-address", "a8df7489-c5ea-11d1-bbcb-0080c76670c0"),
            ("omt-indx-guid", "1f0075fa-7e40-11d0-afd6-00c04fd930c9"),
            ("ms-fve-keypackage", "1fd55ea8-88a7-47dc-8129-0daa97186a54"),
            ("max-renew-age", "bf9679bc-0de6-11d0-a285-00aa003049e2"),
            ("common-name", "bf96793f-0de6-11d0-a285-00aa003049e2"),
            ("ms-ds-geocoordinates-longitude", "94c42110-bae4-4cea-8577-af813af5da25"),
            ("text-country", "f0f8ffa7-1191-11d0-a060-00aa006c33ed"),
            ("omt-guid", "ddac0cf3-af8f-11d0-afeb-00c04fd930c9"),
            ("ms-fve-volumeguid", "85e5a5cf-dcee-4075-9cfd-ac9db6a2f245"),
            ("max-pwd-age", "bf9679bb-0de6-11d0-a285-00aa003049e2"),
            ("comment", "bf96793e-0de6-11d0-a285-00aa003049e2"),
            ("posixgroup", "2a9350b8-062c-4ed0-9903-dde10d06deba"),
            ("ms-ds-app-configuration", "90df3c3e-1854-4455-a5d7-cad40d56657a"),
            ("ms-ds-geocoordinates-latitude", "dc66d44e-3d43-40f5-85c5-3c12e169927e"),
            ("terminal-server", "6db69a1c-9422-11d1-aebd-0000f80367c1"),
            ("om-syntax", "bf9679ed-0de6-11d0-a285-00aa003049e2"),
            ("ms-fve-recoverypassword", "43061ac1-c8ad-4ccc-b785-2bfac20fc60a"),
            ("mastered-by", "e48e64e0-12c9-11d3-9102-00c04fd91ab1"),
            ("com-unique-libid", "281416da-1968-11d0-a28f-00aa003049e2"),
            ("ms-ds-geocoordinates-altitude", "a11703b7-5641-4d9c-863e-5fb3325e74e0"),
            ("template-roots", "ed9de9a0-7041-11d2-9905-0000f87a57d4"),
            ("om-object-class", "bf9679ec-0de6-11d0-a285-00aa003049e2"),
            ("default-object-category", "26d97367-6070-11d1-a9c6-0000f80367c1"),
            ("ms-ds-cloudextensionattribute18", "88e73b34-0aa6-4469-9842-6eb01b32a5b5"),
            ("unstructuredname", "9c8ef177-41cf-45c9-9673-7716c0c8901b"),
            ("partial-attribute-deletion-list", "28630ec0-41d5-11d1-a9c1-0000f80367c1"),
            ("ms-pki-oid-cps", "5f49940e-a79f-4a51-bb6f-3d446a54dc6b"),
            ("meetingstarttime", "11b6cc90-48c4-11d1-a9c3-0000f80367c1"),
            ("default-local-policy-object", "bf96799f-0de6-11d0-a285-00aa003049e2"),
            ("mssfu-30-domain-info", "36297dce-656b-4423-ab65-dabb2770819e"),
            ("ms-ds-managed-service-account", "ce206244-5827-4a86-ba1c-1c0c386c1b64"),
            ("ms-ds-cloudextensionattribute17", "3d3c6dda-6be8-4229-967e-2ff5bb93b4ce"),
            ("unstructuredaddress", "50950839-cc4c-4491-863a-fcf942d684b7"),
            ("parent-guid", "2df90d74-009f-11d2-aa4c-00c04fd7d83a"),
            ("ms-pki-oid-attribute", "8c9e1288-5028-4f4f-a704-76d026f246ef"),
            ("meetingscope", "11b6cc8a-48c4-11d1-a9c3-0000f80367c1"),
            ("default-hiding-value", "b7b13116-b82e-11d0-afee-0000f80367c1"),
            ("ms-ds-cloudextensionattribute16", "9581215b-5196-4053-a11e-6ffcafc62c4d"),
            ("uniquemember", "8f888726-f80a-44d7-b1ee-cb9df21392c8"),
            ("parent-ca-certificate-chain", "963d2733-48be-11d1-a9c3-0000f80367c1"),
            ("ms-pki-minimal-key-size", "e96a63f5-417f-46d3-be52-db7703c503df"),
            ("meetingrecurrence", "11b6cc8f-48c4-11d1-a9c3-0000f80367c1"),
            ("default-group", "720bc4e2-a54a-11d0-afdf-00c04fd930c9"),
            ("mssfu-30-net-id", "e263192c-2a02-48df-9792-94f2328781a0"),
            ("ms-ds-quota-control", "de91fc26-bd02-4b52-ae26-795999e96fc7"),
            ("ms-ds-cloudextensionattribute15", "aae4d537-8af0-4daa-9cc6-62eadb84ff03"),
            ("uniqueidentifier", "ba0184c7-38c5-4bed-a526-75421470580c"),
            ("parent-ca", "5245801b-ca6a-11d0-afff-0000f80367c1"),
            ("ms-pki-enrollment-servers", "f22bd38f-a1d0-4832-8b28-0331438886a6"),
            ("meetingrating", "11b6cc8d-48c4-11d1-a9c3-0000f80367c1"),
            ("default-class-store", "bf967948-0de6-11d0-a285-00aa003049e2"),
            ("ms-ds-cloudextensionattribute14", "cebcb6ba-6e80-4927-8560-98feca086a9f"),
            ("unicode-pwd", "bf9679e1-0de6-11d0-a285-00aa003049e2"),
            ("package-type", "7d6c0e96-7e20-11d0-afd6-00c04fd930c9"),
            ("ms-pki-enrollment-flag", "d15ef7d8-f226-46db-ae79-b34e560bd12c"),
            ("meetingprotocol", "11b6cc81-48c4-11d1-a9c3-0000f80367c1"),
            ("dbcs-pwd", "bf96799c-0de6-11d0-a285-00aa003049e2"),
            ("mssfu-30-mail-aliases", "d6710785-86ff-44b7-85b5-f1f8689522ce"),
            ("ms-ds-quota-container", "da83fc4f-076f-4aea-b4dc-8f4dab9b5993"),
            ("ms-ds-cloudextensionattribute13", "28be464b-ab90-4b79-a6b0-df437431d036"),
            ("unc-name", "bf967a64-0de6-11d0-a285-00aa003049e2"),
            ("package-name", "7d6c0e98-7e20-11d0-afd6-00c04fd930c9"),
            ("ms-pki-credential-roaming-tokens", "b7ff5a38-0818-42b0-8110-d3d154c97f24"),
            ("meetingowner", "11b6cc88-48c4-11d1-a9c3-0000f80367c1"),
            ("current-value", "bf967947-0de6-11d0-a285-00aa003049e2"),
            ("ms-ds-cloudextensionattribute12", "3c01c43d-e10b-4fca-92b2-4cf615d5b09a"),
            ("uid", "0bb0fca0-1e89-429f-901a-1413894d9f59"),
            ("package-flags", "7d6c0e99-7e20-11d0-afd6-00c04fd930c9"),
            ("ms-pki-certificate-policy", "38942346-cc5b-424b-a7d8-6ffd12029c5f"),
            ("meetingoriginator", "11b6cc86-48c4-11d1-a9c3-0000f80367c1"),
            ("current-parent-ca", "963d273f-48be-11d1-a9c3-0000f80367c1"),
            ("bootabledevice", "4bcb2477-4bb3-4545-a9fc-fb66e136b435"),
            ("ms-ds-password-settings-container", "5b06b06a-4cf3-44c0-bd16-43bc10a987da"),
            ("ms-ds-cloudextensionattribute11", "9e9ebbc8-7da5-42a6-8925-244e12a56e24"),
            ("uas-compat", "bf967a61-0de6-11d0-a285-00aa003049e2"),
            ("owner", "bf9679f3-0de6-11d0-a285-00aa003049e2"),
            ("ms-pki-certificate-name-flag", "ea1dddc4-60ff-416e-8cc0-17cee534bce7"),
            ("meetingname", "11b6cc7d-48c4-11d1-a9c3-0000f80367c1"),
            ("current-location", "1f0075fc-7e40-11d0-afd6-00c04fd930c9"),
            ("ms-ds-cloudextensionattribute10", "670afcb3-13bd-47fc-90b3-0a527ed81ab7"),
            ("trust-type", "bf967a60-0de6-11d0-a285-00aa003049e2"),
            ("other-well-known-objects", "1ea64e5d-ac0f-11d2-90df-00c04fd91ab1"),
            ("ms-pki-certificate-application-policy", "dbd90548-aa37-4202-9966-8c537ba5ce32"),
            ("meetingmaxparticipants", "11b6cc85-48c4-11d1-a9c3-0000f80367c1"),
            ("curr-machine-id", "1f0075fe-7e40-11d0-afd6-00c04fd930c9"),
            ("ieee802device", "a699e529-a637-4b7d-a0fb-5dc466a0b8a7"),
            ("ms-ds-password-settings", "3bcd9db8-f84b-451c-952f-6c52b81f9ec6"),
            ("ms-ds-cloudextensionattribute9", "0a63e12c-3040-4441-ae26-cd95af0d247e"),
            ("trust-posix-offset", "bf967a5e-0de6-11d0-a285-00aa003049e2"),
            ("other-name", "bf9679f2-0de6-11d0-a285-00aa003049e2"),
            ("ms-pki-cert-template-oid", "3164c36a-ba26-468c-8bda-c1e5cc256728"),
            ("meetinglocation", "11b6cc80-48c4-11d1-a9c3-0000f80367c1"),
            ("cross-certificate-pair", "167757b2-47f3-11d1-a9c3-0000f80367c1"),
            ("ms-ds-cloudextensionattribute8", "3cd1c514-8449-44ca-81c0-021781800d2a"),
            ("trust-partner", "bf967a5d-0de6-11d0-a285-00aa003049e2"),
            ("other-mailbox", "0296c123-40da-11d1-a9c0-0000f80367c1"),
            ("ms-net-ieee-8023-gp-policyreserved", "d3c527c7-2606-4deb-8cfd-18426feec8ce"),
            ("meetinglanguage", "11b6cc84-48c4-11d1-a9c3-0000f80367c1"),
            ("crl-partitioned-revocation-list", "963d2731-48be-11d1-a9c3-0000f80367c1"),
            ("nisobject", "904f8a93-4954-4c5f-b1e1-53c097a31e13"),
            ("ms-ds-optional-feature", "44f00041-35af-468b-b20a-6ce8737c580b"),
            ("ms-ds-cloudextensionattribute7", "4a7c1319-e34e-40c2-9d00-60ff7890f207"),
            ("trust-parent", "b000ea7a-a086-11d0-afdd-00c04fd930c9"),
            ("other-login-workstations", "bf9679f1-0de6-11d0-a285-00aa003049e2"),
            ("ms-net-ieee-8023-gp-policydata", "8398948b-7457-4d91-bd4d-8d7ed669c9f7"),
            ("meetingkeyword", "11b6cc7f-48c4-11d1-a9c3-0000f80367c1"),
            ("crl-object", "963d2737-48be-11d1-a9c3-0000f80367c1"),
            ("ms-ds-cloudextensionattribute6", "60452679-28e1-4bec-ace3-712833361456"),
            ("trust-direction", "bf967a5c-0de6-11d0-a285-00aa003049e2"),
            ("original-display-table-msdos", "5fd424cf-1262-11d0-a060-00aa006c33ed"),
            ("ms-net-ieee-8023-gp-policyguid", "94a7b05a-b8b2-4f59-9c25-39e69baa1684"),
            ("meetingisencrypted", "11b6cc8e-48c4-11d1-a9c3-0000f80367c1"),
            ("creator", "7bfdcb85-4807-11d1-a9c3-0000f80367c1"),
            ("nismap", "7672666c-02c1-4f33-9ecf-f649c1dd9b7c"),
            ("ms-ds-az-task", "1ed3a473-9b1b-418a-bfa0-3a37b95a5306"),
            ("ms-ds-cloudextensionattribute5", "2915e85b-e347-4852-aabb-22e5a651c864"),
            ("trust-auth-outgoing", "bf967a5f-0de6-11d0-a285-00aa003049e2"),
            ("original-display-table", "5fd424ce-1262-11d0-a060-00aa006c33ed"),
            ("ms-net-ieee-80211-gp-policyreserved", "0f69c62e-088e-4ff5-a53a-e923cec07c0a"),
            ("meetingip", "11b6cc89-48c4-11d1-a9c3-0000f80367c1"),
            ("creation-wizard", "4d8601ed-ac85-11d0-afe3-00c04fd930c9"),
            ("ms-ds-cloudextensionattribute4", "9cbf3437-4e6e-485b-b291-22b02554273f"),
            ("dhcp-obj-description", "963d2744-48be-11d1-a9c3-0000f80367c1"),
            ("ms-ds-device-id", "c30181c7-6342-41fb-b279-f7c566cbe0a7"),
            ("user-workstations", "bf9679d7-0de6-11d0-a285-00aa003049e2"),
            ("phone-isdn-primary", "0296c11f-40da-11d1-a9c0-0000f80367c1"),
            ("ms-rras-attribute", "f39b98ad-938d-11d1-aebd-0000f80367c1"),
            ("ms-com-defaultpartitionlink", "998b10f7-aa1a-4364-b867-753d197fe670"),
            ("dhcp-maxkey", "963d2754-48be-11d1-a9c3-0000f80367c1"),
            ("ms-dfs-link-v2", "7769fb7a-1159-4e96-9ccd-68bc487073eb"),
            ("ms-dfsr-content", "64759b35-d3a1-42e4-b5f1-a3de162109b3"),
            ("ms-ds-device-physical-ids", "90615414-a2a0-4447-a993-53409599b74e"),
            ("user-smime-certificate", "e16a9db2-403c-11d1-a9c0-0000f80367c1"),
            ("phone-ip-primary", "4d146e4a-48d4-11d1-a9c3-0000f80367c1"),
            ("ms-pki-accountcredentials", "b8dfa744-31dc-4ef1-ac7c-84baf7ef9da7"),
            ("move-tree-state", "1f2ac2c8-3b71-11d2-90cc-00c04fd91ab1"),
            ("dhcp-mask", "963d2747-48be-11d1-a9c3-0000f80367c1"),
            ("ms-ds-device-os-version", "70fb8c63-5fab-4504-ab9d-14b329a8a7f8"),
            ("user-shared-folder-other", "9a9a0220-4a5b-11d1-a9c3-0000f80367c1"),
            ("phone-ip-other", "4d146e4b-48d4-11d1-a9c3-0000f80367c1"),
            ("ms-pki-dpapimasterkeys", "b3f93023-9239-4f7c-b99c-6745d87adbc2"),
            ("moniker-display-name", "bf9679c8-0de6-11d0-a285-00aa003049e2"),
            ("dhcp-identification", "963d2742-48be-11d1-a9c3-0000f80367c1"),
            ("ms-dfs-deleted-link-v2", "25173408-04ca-40e8-865e-3f9ce9bf1bd3"),
            ("ms-dfsr-replicationgroup", "1c332fe0-0c2a-4f32-afca-23c5e45a9e77"),
            ("ms-ds-device-os-type", "100e454d-f3bb-4dcb-845f-8d5edc471c59"),
            ("user-shared-folder", "9a9a021f-4a5b-11d1-a9c3-0000f80367c1"),
            ("phone-home-primary", "f0f8ffa1-1191-11d0-a060-00aa006c33ed"),
            ("ms-pki-roamingtimestamp", "6617e4ac-a2f1-43ab-b60c-11fbd1facf05"),
            ("moniker", "bf9679c7-0de6-11d0-a285-00aa003049e2"),
            ("dhcp-flags", "963d2741-48be-11d1-a9c3-0000f80367c1"),
            ("ms-ds-is-enabled", "22a95c0e-1f83-4c82-94ce-bea688cfc871"),
            ("user-principal-name", "28630ebb-41d5-11d1-a9c1-0000f80367c1"),
            ("phone-home-other", "f0f8ffa2-1191-11d0-a060-00aa006c33ed"),
            ("ms-pki-ra-signature", "fe17e04b-937d-4f7e-8e0e-9292c8d5683e"),
            ("modify-time-stamp", "9a7ad94a-ca53-11d1-bbd0-0080c76670c0"),
            ("dhcp-classes", "963d2750-48be-11d1-a9c3-0000f80367c1"),
            ("ms-fve-recoveryinformation", "ea715d30-8f53-40d0-bd1e-6109186d782c"),
            ("ms-dfsr-globalsettings", "7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6"),
            ("ms-ds-approximate-last-logon-time-stamp", "a34f983b-84c6-4f0c-9050-a3a14a1d35a4"),
            ("userpkcs12", "23998ab5-70f8-4007-a4c1-a84a38311f9a"),
            ("phone-fax-other", "0296c11d-40da-11d1-a9c0-0000f80367c1"),
            ("ms-pki-ra-policies", "d546ae22-0951-4d47-817e-1c9f96faad46"),
            ("modified-count-at-last-prom", "bf9679c6-0de6-11d0-a285-00aa003049e2"),
            ("destination-indicator", "bf967951-0de6-11d0-a285-00aa003049e2"),
            ("ms-ds-registered-users", "0449160c-5a8e-4fc8-b052-01c0f6e48f02"),
            ("userclass", "11732a8a-e14d-4cc5-b92f-d93f51c6d8e4"),
            ("personal-title", "16775858-47f3-11d1-a9c3-0000f80367c1"),
            ("ms-pki-ra-application-policies", "3c91fbbf-4773-4ccd-a87b-85d53e7bcf6a"),
            ("modified-count", "bf9679c5-0de6-11d0-a285-00aa003049e2"),
            ("desktop-profile", "eea65906-8ac6-11d0-afda-00c04fd930c9"),
            ("ms-net-ieee-8023-grouppolicy", "99a03a6a-ab19-4446-9350-0cb878ed2d9b"),
            ("ms-dfsr-subscription", "67212414-7bcc-4609-87e0-088dad8abdee"),
            ("ms-ds-registered-owner", "617626e9-01eb-42cf-991f-ce617982237e"),
            ("user-password", "bf967a6e-0de6-11d0-a285-00aa003049e2"),
            ("per-recip-dialog-display-table", "5fd424d4-1262-11d0-a060-00aa006c33ed"),
            ("ms-pki-template-schema-version", "0c15e9f5-491d-4594-918f-32813a091da9"),
            ("min-ticket-age", "bf9679c4-0de6-11d0-a285-00aa003049e2"),
            ("description", "bf967950-0de6-11d0-a285-00aa003049e2"),
            ("ms-ds-device-location", "e3fb56c8-5de8-45f5-b1b1-d2b6cd31e762"),
            ("user-parameters", "bf967a6d-0de6-11d0-a285-00aa003049e2"),
            ("per-msg-dialog-display-table", "5fd424d3-1262-11d0-a060-00aa006c33ed"),
            ("ms-pki-template-minor-revision", "13f5236c-1884-46b1-b5d0-484e38990d58"),
            ("min-pwd-length", "bf9679c3-0de6-11d0-a285-00aa003049e2"),
            ("departmentnumber", "be9ef6ee-cbc7-4f22-b27b-96967e7ee585"),
            ("ms-net-ieee-80211-grouppolicy", "1cb81863-b822-4379-9ea2-5ff7bdc6386d"),
            ("ms-dfsr-subscriber", "e11505d7-92c4-43e7-bf5c-295832ffc896"),
            ("ms-ds-maximum-registration-inactivity-period", "0a5caa39-05e6-49ca-b808-025b936610e7"),
            ("user-comment", "bf967a6a-0de6-11d0-a285-00aa003049e2"),
            ("pending-parent-ca", "963d273e-48be-11d1-a9c3-0000f80367c1"),
            ("ms-pki-supersede-templates", "9de8ae7d-7a5b-421d-b5e4-061f79dfd5d7"),
            ("min-pwd-age", "bf9679c2-0de6-11d0-a285-00aa003049e2"),
            ("department", "bf96794f-0de6-11d0-a285-00aa003049e2"),
            ("ms-ds-registration-quota", "ca3286c2-1f64-4079-96bc-e62b610e730f"),
            ("user-cert", "bf967a69-0de6-11d0-a285-00aa003049e2"),
            ("pending-ca-certificates", "963d273c-48be-11d1-a9c3-0000f80367c1"),
            ("ms-pki-site-name", "0cd8711f-0afc-4926-a4b1-09b08d3d436c"),
            ("mhs-or-address", "0296c122-40da-11d1-a9c0-0000f80367c1"),
            ("delta-revocation-list", "167757b5-47f3-11d1-a9c3-0000f80367c1"),
            ("mssfu-30-nis-map-config", "faf733d0-f8eb-4dcf-8d75-f1753af6a50b"),
            ("ms-dfsr-localsettings", "fa85c591-197f-477e-83bd-ea5a43df2239"),
            ("ms-ds-issuer-certificates", "6b3d6fda-0893-43c4-89fb-1fb52a6616a9"),
            ("user-account-control", "bf967a68-0de6-11d0-a285-00aa003049e2"),
            ("pek-list", "07383083-91df-11d1-aebc-0000f80367c1"),
            ("ms-pki-private-key-flag", "bab04ac2-0435-4709-9307-28380e7c7001"),
            ("member", "bf9679c0-0de6-11d0-a285-00aa003049e2"),
            ("default-security-descriptor", "807a6d30-1669-11d0-a064-00aa006c33ed"),
            ("ms-ds-cloudextensionattribute20", "f5446328-8b6e-498d-95a8-211748d5acdc"),
            ("upn-suffixes", "032160bf-9824-11d1-aec0-0000f80367c1"),
            ("pek-key-change-interval", "07383084-91df-11d1-aebc-0000f80367c1"),
            ("ms-pki-oid-user-notice", "04c4da7a-e114-4e69-88de-e293f2d3b395"),
            ("meetingurl", "11b6cc8c-48c4-11d1-a9c3-0000f80367c1"),
            ("default-priority", "281416c8-1968-11d0-a28f-00aa003049e2"),
            ("mssfu-30-network-user", "e15334a3-0bf0-4427-b672-11f5d84acc92"),
            ("ms-exch-configuration-container", "d03d6858-06f4-11d2-aa53-00c04fd7d83a"),
            ("ms-ds-cloudextensionattribute19", "0975fe99-9607-468a-8e18-c800d3387395"),
            ("upgrade-product-code", "d9e18312-8939-11d1-aebc-0000f80367c1"),
            ("partial-attribute-set", "19405b9e-3cfa-11d1-a9c0-0000f80367c1"),
            ("ms-pki-oid-localizedname", "7d59a816-bb05-4a72-971f-5c1331f67559"),
            ("meetingtype", "11b6cc82-48c4-11d1-a9c3-0000f80367c1"),
            ("display-name-printable", "bf967954-0de6-11d0-a285-00aa003049e2"),
            ("ms-ds-claim-type", "81a3857c-5469-4d8f-aae6-c27699762604"),
            ("ms-ds-user-allowed-to-authenticate-to", "de0caa7f-724e-4286-b179-192671efc664"),
            ("volume-count", "34aaa217-b699-11d0-afee-0000f80367c1"),
            ("pki-expiration-period", "041570d2-3b9e-11d2-90cc-00c04fd91ab1"),
            ("ms-sql-serviceaccount", "64933a3e-ccee-11d2-9993-0000f87a57d4"),
            ("ms-ds-authenticatedat-dc", "3e1ee99c-6604-4489-89d9-84798a89515a"),
            ("display-name", "bf967953-0de6-11d0-a285-00aa003049e2"),
            ("ms-imaging-postscanprocess", "1f7c257c-b8a3-4525-82f8-11ccc7bee36e"),
            ("ms-ds-syncserverurl", "b7acc3d2-2a74-4fa4-ac25-e63fe8b61218"),
            ("vol-table-idx-guid", "1f0075fb-7e40-11d0-afd6-00c04fd930c9"),
            ("pki-enrollment-access", "926be278-56f9-11d2-90d0-00c04fd91ab1"),
            ("ms-sql-build", "603e94c4-ccee-11d2-9993-0000f87a57d4"),
            ("ms-ds-approx-immed-subordinates", "e185d243-f6ce-4adb-b496-b0c005d7823c"),
            ("dhcp-update-time", "963d2755-48be-11d1-a9c3-0000f80367c1"),
            ("ms-ds-resource-properties", "7a4a4584-b350-478f-acd6-b4b852d82cc0"),
            ("ms-ds-cloud-isenabled", "89848328-7c4e-4f6f-a013-28ce3ad282dc"),
            ("vol-table-guid", "1f0075fd-7e40-11d0-afd6-00c04fd930c9"),
            ("pki-default-key-spec", "426cae6e-3b9d-11d2-90cc-00c04fd91ab1"),
            ("ms-sql-memory", "5b5d448c-ccee-11d2-9993-0000f87a57d4"),
            ("ms-ds-auxiliary-classes", "c4af1073-ee50-4be0-b8c0-89a41fe99abe"),
            ("dhcp-unique-key", "963d273a-48be-11d1-a9c3-0000f80367c1"),
            ("ms-imaging-psps", "a0ed2ac1-970c-4777-848e-ec63a0ec44fc"),
            ("ms-ds-cloud-issuer-public-certificates", "a1e8b54f-4bd6-4fd2-98e2-bcee92a55497"),
            ("version-number-lo", "7d6c0e9b-7e20-11d0-afd6-00c04fd930c9"),
            ("pki-default-csps", "1ef6336e-3b9e-11d2-90cc-00c04fd91ab1"),
            ("ms-sql-location", "561c9644-ccee-11d2-9993-0000f87a57d4"),
            ("ms-ds-allowed-to-delegate-to", "800d94d7-b7a1-42a1-b14d-7cae1423d07f"),
            ("dhcp-type", "963d273b-48be-11d1-a9c3-0000f80367c1"),
            ("ms-ds-claim-types", "36093235-c715-4821-ab6a-b56fb2805a58"),
            ("ms-ds-cloud-anchor", "78565e80-03d4-4fe3-afac-8c3bca2f3653"),
            ("version-number-hi", "7d6c0e9a-7e20-11d0-afd6-00c04fd930c9"),
            ("pki-critical-extensions", "fc5a9106-3b9d-11d2-90cc-00c04fd91ab1"),
            ("ms-sql-contact", "4f6cbdd8-ccee-11d2-9993-0000f87a57d4"),
            ("ms-ds-allowed-dns-suffixes", "8469441b-9ac4-4e45-8205-bd219dbf672d"),
            ("dhcp-subnets", "963d2746-48be-11d1-a9c3-0000f80367c1"),
            ("ms-ieee-80211-policy", "7b9a2d92-b7eb-4382-9772-c3e0f9baaf94"),
            ("ms-ds-cloud-ismanaged", "5315ba8e-958f-4b52-bd38-1349a304dd63"),
            ("version-number", "bf967a76-0de6-11d0-a285-00aa003049e2"),
            ("picture", "8d3bca50-1d7e-11d0-a081-00aa006c33ed"),
            ("ms-sql-registeredowner", "48fd44ea-ccee-11d2-9993-0000f87a57d4"),
            ("ms-ds-all-users-trust-quota", "d3aa4a5c-4e03-4810-97aa-2b339e7a434b"),
            ("dhcp-state", "963d2752-48be-11d1-a9c3-0000f80367c1"),
            ("ms-ds-claim-type-property-base", "b8442f58-c490-4487-8a9d-d80b883271ad"),
            ("ms-ds-ismanaged", "60686ace-6c27-43de-a4e5-f00c2f8d3309"),
            ("vendor", "281416df-1968-11d0-a28f-00aa003049e2"),
            ("physical-location-object", "b7b13119-b82e-11d0-afee-0000f80367c1"),
            ("ms-sql-name", "3532dfd8-ccee-11d2-9993-0000f87a57d4"),
            ("ms-ds-additional-sam-account-name", "975571df-a4d5-429a-9f59-cdc6581d91e6"),
            ("dhcp-sites", "963d2749-48be-11d1-a9c3-0000f80367c1"),
            ("ms-dfsr-connection", "e58f972e-64b5-46ef-8d8b-bbc3e1897eab"),
            ("ms-ds-issuer-public-certificates", "b5f1edfe-b4d2-4076-ab0f-6148342b0bf6"),
            ("valid-accesses", "4d2fa380-7f54-11d2-992a-0000f87a57d4"),
            ("physical-delivery-office-name", "bf9679f7-0de6-11d0-a285-00aa003049e2"),
            ("ms-radius-savedframedipv6route", "9666bb5c-df9d-4d41-b437-2eec7e27c9b3"),
            ("ms-ds-additional-dns-host-name", "80863791-dbe9-4eb8-837e-7f0ab55d9ac7"),
            ("dhcp-servers", "963d2745-48be-11d1-a9c3-0000f80367c1"),
            ("template-roots2", "b1cba91a-0682-4362-a659-153e201ef069"),
            ("ms-ds-drs-farm-id", "6055f766-202e-49cd-a8be-e52bb159edfb"),
            ("usn-source", "167758ad-47f3-11d1-a9c3-0000f80367c1"),
            ("photo", "9c979768-ba1a-4c08-9632-c6a5c1ed649a"),
            ("ms-radius-framedipv6route", "5a5aa804-3083-4863-94e5-018a79a22ec0"),
            ("ms-drm-identity-certificate", "e85e1204-3434-41ad-9b56-e2901228fff0"),
            ("dhcp-reservations", "963d274a-48be-11d1-a9c3-0000f80367c1"),
            ("global-address-list2", "4898f63d-4112-477c-8826-3ca00bd8277d"),
            ("ms-dfsr-member", "4229c897-c211-437c-a5ae-dbf705b696e5"),
            ("ms-ds-repl-value-meta-data-ext", "1e02d2ef-44ad-46b2-a67d-9fd18d780bca"),
            ("usn-last-obj-rem", "bf967a73-0de6-11d0-a285-00aa003049e2"),
            ("phone-pager-primary", "f0f8ffa6-1191-11d0-a060-00aa006c33ed"),
            ("ms-radius-savedframedipv6prefix", "0965a062-b1e1-403b-b48d-5c0eb0e952cc"),
            ("ms-com-userpartitionsetlink", "8e940c8a-e477-4367-b08d-ff2ff942dcd7"),
            ("dhcp-ranges", "963d2748-48be-11d1-a9c3-0000f80367c1"),
            ("address-book-roots2", "508ca374-a511-4e4e-9f4f-856f61a6b7e4"),
            ("ms-ds-parent-dist-name", "b918fe7d-971a-f404-9e21-9261abec970b"),
            ("usn-intersite", "a8df7498-c5ea-11d1-bbcb-0080c76670c0"),
            ("phone-pager-other", "f0f8ffa4-1191-11d0-a060-00aa006c33ed"),
            ("ms-radius-framedipv6prefix", "f63ed610-d67c-494d-87be-cd1e24359a38"),
            ("ms-com-userlink", "9e6f3a4d-242c-4f37-b068-36b57f9fc852"),
            ("dhcp-properties", "963d2753-48be-11d1-a9c3-0000f80367c1"),
            ("ms-dfs-namespace-v2", "21cb8628-f3c3-4bbf-bff6-060b2d8f299a"),
            ("ms-dfsr-topology", "04828aa9-6e42-4e80-b962-e2fe00754d17"),
            ("ms-ds-member-transitive", "e215395b-9104-44d9-b894-399ec9e21dfc"),
            ("usn-dsa-last-obj-removed", "bf967a71-0de6-11d0-a285-00aa003049e2"),
            ("phone-office-other", "f0f8ffa5-1191-11d0-a060-00aa006c33ed"),
            ("ms-radius-savedframedinterfaceid", "a4da7289-92a3-42e5-b6b6-dad16d280ac9"),
            ("ms-com-partitionsetlink", "67f121dc-7d02-4c7d-82f5-9ad4c950ac34"),
            ("dhcp-options", "963d274f-48be-11d1-a9c3-0000f80367c1"),
            ("ms-ds-is-member-of-dl-transitive", "862166b6-c941-4727-9565-48bfff2941de"),
            ("usn-created", "bf967a70-0de6-11d0-a285-00aa003049e2"),
            ("phone-mobile-primary", "f0f8ffa3-1191-11d0-a060-00aa006c33ed"),
            ("ms-radius-framedinterfaceid", "a6f24a23-d65c-4d65-a64f-35fb6873c2b9"),
            ("ms-com-partitionlink", "09abac62-043f-4702-ac2b-6ca15eee5754"),
            ("dhcp-obj-name", "963d2743-48be-11d1-a9c3-0000f80367c1"),
            ("ms-dfs-namespace-anchor", "da73a085-6e64-4d61-b064-015d04164795"),
            ("ms-dfsr-contentset", "4937f40d-a6dc-4d48-97ca-06e5fbfd3f16"),
            ("ms-ds-device-object-version", "ef65695a-f179-4e6a-93de-b01e06681cfb"),
            ("usn-changed", "bf967a6f-0de6-11d0-a285-00aa003049e2"),
            ("phone-mobile-other", "0296c11e-40da-11d1-a9c0-0000f80367c1"),
            ("ms-rras-vendor-attribute-entry", "f39b98ac-938d-11d1-aebd-0000f80367c1"),
            ("ms-com-objectid", "430f678b-889f-41f2-9843-203b5a65572f"),
            ("ms-sql-publicationurl", "ae0c11b8-ccee-11d2-9993-0000f87a57d4"),
            ("ms-ds-az-scope-name", "515a6b06-2617-4173-8099-d5605df043c6"),
            ("dns-tombstoned", "d5eb2eb7-be4e-463b-a214-634a44d7392e"),
            ("ms-dns-server-settings", "ef2fc3ed-6e18-415b-99e4-3114a8cb124b"),
            ("ms-ds-computer-authn-policy", "afb863c9-bea3-440f-a9f3-6153cc668929"),
            ("gecos", "a3e03f1f-1d55-4253-a0af-30c2a784e46e"),
            ("preferred-delivery-method", "bf9679fe-0de6-11d0-a285-00aa003049e2"),
            ("ms-sql-connectionurl", "a92d23da-ccee-11d2-9993-0000f87a57d4"),
            ("ms-ds-az-operation-id", "a5f3b553-5d76-4cbe-ba3f-4312152cab18"),
            ("dns-secure-secondaries", "e0fa1e67-9b45-11d0-afdd-00c04fd930c9"),
            ("ms-sql-sqlpublication", "17c2f64e-ccef-11d2-9993-0000f87a57d4"),
            ("ms-ds-user-authn-policy-bl", "2f17faa9-5d47-4b1f-977e-aa52fabe65c8"),
            ("gidnumber", "c5b95f0c-ec9e-41c4-849c-b46597ed6696"),
            ("postal-code", "bf9679fd-0de6-11d0-a285-00aa003049e2"),
            ("ms-sql-informationurl", "a42cd510-ccee-11d2-9993-0000f87a57d4"),
            ("ms-ds-az-minor-version", "ee85ed93-b209-4788-8165-e702f51bfbf3"),
            ("dns-root", "bf967959-0de6-11d0-a285-00aa003049e2"),
            ("ms-tpm-information-object", "85045b6a-47a6-4243-a7cc-6890701f662c"),
            ("ms-ds-user-authn-policy", "cd26b9f3-d415-442a-8f78-7c61523ee95b"),
            ("uidnumber", "850fcc8f-9c6b-47e1-b671-7c654be4d5b3"),
            ("postal-address", "bf9679fc-0de6-11d0-a285-00aa003049e2"),
            ("ms-sql-lastupdateddate", "9fcc43d4-ccee-11d2-9993-0000f87a57d4"),
            ("ms-ds-az-major-version", "cfb9adb7-c4b7-4059-9568-1ed9db6b7248"),
            ("dns-record", "e0fa1e69-9b45-11d0-afdd-00c04fd930c9"),
            ("ms-sql-sqlrepository", "11d43c5c-ccef-11d2-9993-0000f87a57d4"),
            ("ms-ds-authn-policy-silo-members-bl", "11fccbc7-fbe4-4951-b4b7-addf6f9efd44"),
            ("unixuserpassword", "612cb747-c0e8-4f92-9221-fdd5f15b550d"),
            ("post-office-box", "bf9679fb-0de6-11d0-a285-00aa003049e2"),
            ("ms-sql-status", "9a7d4770-ccee-11d2-9993-0000f87a57d4"),
            ("ms-ds-az-ldap-query", "5e53368b-fc94-45c8-9d7d-daf31ee7112d"),
            ("dns-property", "675a15fe-3b70-11d2-90cc-00c04fd91ab1"),
            ("ms-tpm-information-objects-container", "e027a8bd-6456-45de-90a3-38593877ee74"),
            ("ms-ds-authn-policy-silo-members", "164d1e05-48a6-4886-a8e9-77a2006e3c77"),
            ("x509-cert", "bf967a7f-0de6-11d0-a285-00aa003049e2"),
            ("possible-inferiors", "9a7ad94c-ca53-11d1-bbd0-0080c76670c0"),
            ("ms-sql-vines", "94c56394-ccee-11d2-9993-0000f87a57d4"),
            ("ms-ds-az-last-imported-biz-rule-path", "665acb5c-bb92-4dbc-8c59-b3638eab09b3"),
            ("dns-notify-secondaries", "e0fa1e68-9b45-11d0-afdd-00c04fd930c9"),
            ("ms-sql-olapserver", "0c7e18ea-ccef-11d2-9993-0000f87a57d4"),
            ("ms-ds-assigned-authn-policy-silo-bl", "33140514-f57a-47d2-8ec4-04c4666600c7"),
            ("x500uniqueidentifier", "d07da11f-8a3d-42b6-b0aa-76c962be719a"),
            ("poss-superiors", "bf9679fa-0de6-11d0-a285-00aa003049e2"),
            ("ms-sql-appletalk", "8fda89f4-ccee-11d2-9993-0000f87a57d4"),
            ("ms-ds-az-generate-audits", "f90abab0-186c-4418-bb85-88447c87222a"),
            ("dns-host-name", "72e39547-7b18-11d1-adef-00c04fd8d5cd"),
            ("ms-spp-activation-object", "51a0e68c-0dc5-43ca-935d-c1c911bf2ee5"),
            ("ms-ds-assigned-authn-policy-silo", "b23fc141-0df5-4aea-b33d-6cf493077b3f"),
            ("x121-address", "bf967a7b-0de6-11d0-a285-00aa003049e2"),
            ("port-name", "281416c4-1968-11d0-a28f-00aa003049e2"),
            ("ms-sql-tcpip", "8ac263a6-ccee-11d2-9993-0000f87a57d4"),
            ("ms-ds-az-domain-timeout", "6448f56a-ca70-4e2e-b0af-d20e4ce653d0"),
            ("dns-allow-xfr", "e0fa1e66-9b45-11d0-afdd-00c04fd930c9"),
            ("ms-sql-sqlserver", "05f6c878-ccef-11d2-9993-0000f87a57d4"),
            ("ms-ds-service-tgt-lifetime", "5dfe3c20-ca29-407d-9bab-8421e55eb75c"),
            ("www-page-other", "9a9a0221-4a5b-11d1-a9c3-0000f80367c1"),
            ("policy-replication-flags", "19405b96-3cfa-11d1-a9c0-0000f80367c1"),
            ("ms-sql-spx", "86b08004-ccee-11d2-9993-0000f87a57d4"),
            ("ms-ds-az-class-id", "013a7277-5c2d-49ef-a7de-b765b36a3f6f"),
            ("dns-allow-dynamic", "e0fa1e65-9b45-11d0-afdd-00c04fd930c9"),
            ("ms-spp-activation-objects-container", "b72f862b-bb25-4d5d-aa51-62c59bdf90ae"),
            ("ms-ds-service-allowed-to-authenticate-from", "97da709a-3716-4966-b1d1-838ba53c3d89"),
            ("www-home-page", "bf967a7a-0de6-11d0-a285-00aa003049e2"),
            ("pkt-guid", "8447f9f0-1027-11d0-a05f-00aa006c33ed"),
            ("ms-sql-multiprotocol", "8157fa38-ccee-11d2-9993-0000f87a57d4"),
            ("ms-ds-az-biz-rule-language", "52994b56-0e6c-4e07-aa5c-ef9d7f5a0e25"),
            ("dn-reference-update", "2df90d86-009f-11d2-aa4c-00c04fd7d83a"),
            ("ms-pki-key-recovery-agent", "26ccf238-a08e-4b86-9a82-a8c9ac7ee5cb"),
            ("ms-ds-service-allowed-to-authenticate-to", "f2973131-9b4d-4820-b4de-0474ef3b849f"),
            ("winsock-addresses", "bf967a79-0de6-11d0-a285-00aa003049e2"),
            ("pkt", "8447f9f1-1027-11d0-a05f-00aa006c33ed"),
            ("ms-sql-namedpipe", "7b91c840-ccee-11d2-9993-0000f87a57d4"),
            ("ms-ds-az-biz-rule", "33d41ea8-c0c9-4c92-9494-f104878413fd"),
            ("dmd-name", "167757b9-47f3-11d1-a9c3-0000f80367c1"),
            ("ms-ds-resource-property-list", "72e3d47a-b342-4d45-8f56-baff803cabf9"),
            ("ms-ds-computer-tgt-lifetime", "2e937524-dfb9-4cac-a436-a5b7da64fd66"),
            ("when-created", "bf967a78-0de6-11d0-a285-00aa003049e2"),
            ("pki-overlap-period", "1219a3ec-3b9e-11d2-90cc-00c04fd91ab1"),
            ("ms-sql-clustered", "7778bd90-ccee-11d2-9993-0000f87a57d4"),
            ("ms-ds-az-application-version", "7184a120-3ac4-47ae-848f-fe0ab20784d4"),
            ("dmd-location", "f0f8ff8b-1191-11d0-a060-00aa006c33ed"),
            ("ms-pki-enterprise-oid", "37cfd85c-6719-4ad8-8f9e-8678ba627563"),
            ("ms-ds-computer-allowed-to-authenticate-to", "105babe9-077e-4793-b974-ef0410b62573"),
            ("when-changed", "bf967a77-0de6-11d0-a285-00aa003049e2"),
            ("pki-max-issuing-depth", "f0bfdefa-3b9d-11d2-90cc-00c04fd91ab1"),
            ("ms-sql-unicodesortorder", "72dc918a-ccee-11d2-9993-0000f87a57d4"),
            ("ms-ds-az-application-name", "db5b0728-6208-4876-83b7-95d3e5695275"),
            ("division", "fe6136a0-2073-11d0-a9c2-00aa006c33ed"),
            ("ms-ds-resource-property", "5b283d5e-8404-4195-9339-8450188c501a"),
            ("ms-ds-user-tgt-lifetime", "8521c983-f599-420f-b9ab-b1222bdf95c1"),
            ("well-known-objects", "05308983-7688-11d1-aded-00c04fd8d5cd"),
            ("pki-key-usage", "e9b0a87e-3b9d-11d2-90cc-00c04fd91ab1"),
            ("ms-sql-sortorder", "6ddc42c0-ccee-11d2-9993-0000f87a57d4"),
            ("ms-ds-az-application-data", "503fc3e8-1cc6-461a-99a3-9eee04f402a7"),
            ("dit-content-rules", "9a7ad946-ca53-11d1-bbd0-0080c76670c0"),
            ("ms-print-connectionpolicy", "a16f33c7-7fd6-4828-9364-435138fda08d"),
            ("ms-ds-user-allowed-to-authenticate-from", "2c4c9600-b0e1-447d-8dda-74902257bdb5"),
            ("wbem-path", "244b2970-5abd-11d0-afd2-00c04fd930c9"),
            ("pki-extended-key-usage", "18976af6-3b9e-11d2-90cc-00c04fd91ab1"),
            ("ms-sql-characterset", "696177a6-ccee-11d2-9993-0000f87a57d4"),
            ("ms-ds-authenticatedto-accountlist", "e8b2c971-a6df-47bc-8d6f-62770d527aa5"),
            ("ipprotocolnumber", "ebf5c6eb-0e2d-4415-9670-1081993b4211"),
            ("print-form-name", "281416cb-1968-11d0-a28f-00aa003049e2"),
            ("ms-sql-lastbackupdate", "f2b6abca-ccee-11d2-9993-0000f87a57d4"),
            ("ms-ds-default-quota", "6818f726-674b-441b-8a3a-f40596374cea"),
            ("domain-replica", "bf96795e-0de6-11d0-a285-00aa003049e2"),
            ("ms-ds-group-managed-service-account", "7b8b558a-93a5-4af7-adca-c017e67f1057"),
            ("ms-ds-key-principal", "bd61253b-9401-4139-a693-356fc400f3ea"),
            ("ipserviceprotocol", "cd96ec0b-1ed6-43b4-b26b-f170b645883f"),
            ("print-end-time", "281416ca-1968-11d0-a28f-00aa003049e2"),
            ("ms-sql-creationdate", "ede14754-ccee-11d2-9993-0000f87a57d4"),
            ("ms-ds-date-time", "234fcbd8-fb52-4908-a328-fd9f6e58e403"),
            ("domain-policy-reference", "80a67e2a-9f22-11d0-afdd-00c04fd930c9"),
            ("ms-wmi-intsetparam", "292f0d9a-cf76-42b0-841f-b650f331df62"),
            ("ms-ds-key-usage", "de71b44c-29ba-4597-9eca-c3348ace1917"),
            ("ipserviceport", "ff2daebf-f463-495a-8405-3e483641eaa2"),
            ("print-duplex-supported", "281416cc-1968-11d0-a28f-00aa003049e2"),
            ("ms-sql-size", "e9098084-ccee-11d2-9993-0000f87a57d4"),
            ("ms-ds-creator-sid", "c5e60132-1480-11d3-91c1-0000f87a57d4"),
            ("domain-policy-object", "bf96795d-0de6-11d0-a285-00aa003049e2"),
            ("ms-kds-prov-rootkey", "aa02fd41-17e0-4f18-8687-b2239649736b"),
            ("ms-ds-key-material", "a12e0e9f-dedb-4f31-8f21-1311b958182f"),
            ("nisnetgrouptriple", "a8032e74-30ef-4ff5-affc-0fc217783fec"),
            ("print-color", "281416d3-1968-11d0-a28f-00aa003049e2"),
            ("ms-sql-alias", "e0c6baae-ccee-11d2-9993-0000f87a57d4"),
            ("ms-ds-consistency-child-count", "178b7bc2-b63a-11d2-90e1-00c04fd91ab1"),
            ("domain-identifier", "7f561278-5301-11d1-a9c5-0000f80367c1"),
            ("ms-wmi-intrangeparam", "50ca5d7d-5c8b-4ef3-b9df-5b66d491e526"),
            ("ms-ds-key-id", "c294f84b-2fad-4b71-be4c-9fc5701f60ba"),
            ("membernisnetgroup", "0f6a17dc-53e5-4be8-9442-8f3ce2f9012a"),
            ("print-collate", "281416d2-1968-11d0-a28f-00aa003049e2"),
            ("ms-sql-allowanonymoussubscription", "db77be4a-ccee-11d2-9993-0000f87a57d4"),
            ("ms-ds-consistency-guid", "23773dc2-b63a-11d2-90e1-00c04fd91ab1"),
            ("domain-id", "963d2734-48be-11d1-a9c3-0000f80367c1"),
            ("ms-kds-prov-serverconfiguration", "5ef243a8-2a25-45a6-8b73-08a71ae677ce"),
            ("ms-ds-is-compliant", "59527d0f-b7c0-4ce2-a1dd-71cef6963292"),
            ("memberuid", "03dab236-672e-4f61-ab64-f77d2dc2ffab"),
            ("print-bin-names", "281416cd-1968-11d0-a28f-00aa003049e2"),
            ("ms-sql-database", "d5a0dbdc-ccee-11d2-9993-0000f87a57d4"),
            ("ms-ds-cached-membership-time-stamp", "3566bf1f-beee-4dcb-8abe-ef89fcfec6c1"),
            ("domain-cross-ref", "b000ea7b-a086-11d0-afdd-00c04fd930c9"),
            ("ms-tapi-rt-person", "53ea1cb5-b704-4df9-818f-5cb4ec86cac1"),
            ("ms-ds-external-directory-object-id", "bd29bf90-66ad-40e1-887b-10df070419a6"),
            ("shadowflag", "8dfeb70d-c5db-46b6-b15e-a4389e6cee9b"),
            ("print-attributes", "281416d7-1968-11d0-a28f-00aa003049e2"),
            ("ms-sql-informationdirectory", "d0aedb2e-ccee-11d2-9993-0000f87a57d4"),
            ("ms-ds-cached-membership", "69cab008-cdd4-4bc9-bab8-0ff37efe1b20"),
            ("domain-component", "19195a55-6da0-11d0-afd3-00c04fd930c9"),
            ("ms-authz-central-access-policy", "a5679cb0-6f9d-432c-8b75-1e3e834f02aa"),
            ("ms-ds-device-mdmstatus", "f60a8f96-57c4-422c-a3ad-9e2fa09ce6f7"),
            ("shadowexpire", "75159a00-1fff-4cf4-8bff-4ef2695cf643"),
            ("primary-group-token", "c0ed8738-7efd-4481-84d9-66d2db8be369"),
            ("ms-sql-type", "ca48eba8-ccee-11d2-9993-0000f87a57d4"),
            ("ms-ds-byte-array", "f0d8972e-dd5b-40e5-a51d-044c7c17ece7"),
            ("domain-certificate-authorities", "7bfdcb7a-4807-11d1-a9c3-0000f80367c1"),
            ("ms-tapi-rt-conference", "ca7b9735-4b2a-4e49-89c3-99025334dc94"),
            ("ms-ds-authn-policy-silo-enforced", "f2f51102-6be0-493d-8726-1546cdbc8771"),
            ("shadowinactive", "86871d1f-3310-4312-8efd-af49dcfb2671"),
            ("primary-group-id", "bf967a00-0de6-11d0-a285-00aa003049e2"),
            ("ms-sql-description", "8386603c-ccef-11d2-9993-0000f87a57d4"),
            ("ms-ds-behavior-version", "d31a8757-2447-4545-8081-3bb610cacbf2"),
            ("documentversion", "94b3a8a9-d613-4cec-9aad-5fbcc1046b43"),
            ("ms-authz-central-access-rule", "5b4a06dc-251c-4edb-8813-0bdd71327226"),
            ("ms-ds-authn-policy-enforced", "7a560cc2-ec45-44ba-b2d7-21236ad59fd5"),
            ("shadowwarning", "7ae89c9c-2976-4a46-bb8a-340f88560117"),
            ("previous-parent-ca", "963d273d-48be-11d1-a9c3-0000f80367c1"),
            ("ms-sql-language", "c57f72f4-ccee-11d2-9993-0000f87a57d4"),
            ("ms-ds-az-generic-data", "b5f7e349-7a5b-407c-a334-a31c3f538b98"),
            ("documenttitle", "de265a9c-ff2c-47b9-91dc-6e6fe2c43062"),
            ("ms-sql-olapcube", "09f0506a-cd28-11d2-9993-0000f87a57d4"),
            ("ms-ds-assigned-authn-policy-bl", "2d131b3c-d39f-4aee-815e-8db4bc1ce7ac"),
            ("shadowmax", "f285c952-50dd-449e-9160-3b880d99988d"),
            ("previous-ca-certificates", "963d2739-48be-11d1-a9c3-0000f80367c1"),
            ("ms-sql-version", "c07cc1d0-ccee-11d2-9993-0000f87a57d4"),
            ("ms-ds-az-object-guid", "8491e548-6c38-4365-a732-af041569b02c"),
            ("documentpublisher", "170f09d7-eb69-448a-9a30-f1afecfd32d7"),
            ("ms-authz-central-access-rules", "99bb1b7a-606d-4f8b-800e-e15be554ca8d"),
            ("ms-ds-assigned-authn-policy", "b87a0ad8-54f7-49c1-84a0-e64d12853588"),
            ("shadowmin", "a76b8737-e5a1-4568-b057-dc12e04be4b2"),
            ("presentation-address", "a8df744b-c5ea-11d1-bbcb-0080c76670c0"),
            ("ms-sql-gpsheight", "bcdd4f0e-ccee-11d2-9993-0000f87a57d4"),
            ("ms-ds-az-task-is-role-definition", "7b078544-6c82-4fe9-872f-ff48ad2b2e26"),
            ("documentlocation", "b958b14e-ac6d-4ec4-8892-be70b69f7281"),
            ("ms-sql-olapdatabase", "20af031a-ccef-11d2-9993-0000f87a57d4"),
            ("ms-ds-service-authn-policy-bl", "2c1128ec-5aa2-42a3-b32d-f0979ca9fcd2"),
            ("shadowlastchange", "f8f2689c-29e8-4843-8177-e8b98e15eeac"),
            ("prefix-map", "52458022-ca6a-11d0-afff-0000f80367c1"),
            ("ms-sql-gpslongitude", "b7577c94-ccee-11d2-9993-0000f87a57d4"),
            ("ms-ds-az-script-timeout", "87d0fb41-2c8b-41f6-b972-11fdfd50d6b0"),
            ("documentidentifier", "0b21ce82-ff63-46d9-90fb-c8b9f24e97b9"),
            ("ms-authz-central-access-policies", "555c21c3-a136-455a-9397-796bbd358e25"),
            ("ms-ds-service-authn-policy", "2a6a6d95-28ce-49ee-bb24-6d1fc01e3111"),
            ("loginshell", "a553d12c-3231-4c5e-8adf-8d189697721e"),
            ("preferred-ou", "bf9679ff-0de6-11d0-a285-00aa003049e2"),
            ("ms-sql-gpslatitude", "b222ba0e-ccee-11d2-9993-0000f87a57d4"),
            ("ms-ds-az-script-engine-cache-max", "2629f66a-1f95-4bf3-a296-8e9d7b9e30c8"),
            ("documentauthor", "f18a8e19-af5f-4478-b096-6f35c27eb83f"),
            ("ms-sql-sqldatabase", "1d08694a-ccef-11d2-9993-0000f87a57d4"),
            ("ms-ds-computer-authn-policy-bl", "2bef6232-30a1-457e-8604-7af6dbf131b8"),
            ("unixhomedirectory", "bc2dba12-000f-464d-bf1d-0808465d8843"),
            ("preferredlanguage", "856be0d0-18e7-46e1-8f5f-7ee4d9020e0d"),
            ("ms-wmi-shadowobject", "f1e44bdf-8dd3-4235-9c86-f91f31f5b569"),
            ("ms-ds-object-soa", "34f6bdf5-2e79-4c3b-8e14-3d93b75aab89"),
            ("mssfu-30-search-attributes", "ef9a2df0-2e57-48c8-8950-0cc674004733"),
            ("print-notify", "ba305f6a-47e3-11d0-a1a6-00c04fd930c9"),
            ("ms-wmi-author", "6366c0c1-6972-4e66-b3a5-1d52ad0c0547"),
            ("ms-ds-host-service-account", "80641043-15a2-40e1-92a2-8ca866f70776"),
            ("employee-id", "bf967962-0de6-11d0-a285-00aa003049e2"),
            ("ms-ds-device-container", "7c9e8c58-901b-4ea8-b6ec-4eb9e9fc0e11"),
            ("ms-ds-source-anchor", "b002f407-1340-41eb-bca0-bd7d938e25a9"),
            ("mssfu-30-intra-field-separator", "95b2aef0-27e4-4cb9-880a-a2d9a9ea23b8"),
            ("print-network-address", "ba305f79-47e3-11d0-a1a6-00c04fd930c9"),
            ("ms-tapi-unique-identifier", "70a4e7ea-b3b9-4643-8918-e6dd2471bfd4"),
            ("ms-ds-has-master-ncs", "ae2de0e2-59d7-4d47-8d47-ed4dfe4357ad"),
            ("efspolicy", "8e4eb2ec-4712-11d0-a1a0-00c04fd930c9"),
            ("ms-wmi-rule", "3c7e6f83-dd0e-481b-a0c2-74cd96ef2a66"),
            ("ms-ds-strong-ntlm-policy", "aacd2170-482a-44c6-b66e-42c2f66a285c"),
            ("mssfu-30-field-separator", "a2e11a42-e781-4ca1-a7fa-ec307f62b6a1"),
            ("print-min-y-extent", "ba305f72-47e3-11d0-a1a6-00c04fd930c9"),
            ("ms-tapi-protocol-id", "89c1ebcf-7a5f-41fd-99ca-c900b32299ab"),
            ("ms-ds-has-domain-ncs", "6f17e347-a842-4498-b8b3-15e007da4fed"),
            ("e-mail-addresses", "bf967961-0de6-11d0-a285-00aa003049e2"),
            ("ms-ds-device-registration-service", "96bc3a1a-e3d2-49d3-af11-7b0df79d67f5"),
            ("ms-ds-service-allowed-ntlm-network-authentication", "278947b9-5222-435e-96b7-1503858c2b48"),
            ("mssfu-30-key-attributes", "32ecd698-ce9e-4894-a134-7ad76b082e83"),
            ("print-min-x-extent", "ba305f71-47e3-11d0-a1a6-00c04fd930c9"),
            ("ms-tapi-ip-address", "efd7d7f7-178e-4767-87fa-f8a16b840544"),
            ("ms-ds-has-instantiated-ncs", "11e9a5bc-4517-4049-af9c-51554fb0fc09"),
            ("dynamic-ldap-server", "52458021-ca6a-11d0-afff-0000f80367c1"),
            ("ms-wmi-realrangeparam", "6afe8fe2-70bc-4cce-b166-a96f7359c514"),
            ("ms-ds-user-allowed-ntlm-network-authentication", "7ece040f-9327-4cdc-aad3-037adfe62639"),
            ("mssfu-30-search-container", "27eebfa2-fbeb-4f8e-aad6-c50247994291"),
            ("print-memory", "ba305f74-47e3-11d0-a1a6-00c04fd930c9"),
            ("ms-tapi-conference-blob", "4cc4601e-7201-4141-abc8-3e529ae88863"),
            ("ms-ds-filter-containers", "fb00dcdf-ac37-483a-9c12-ac53a6603033"),
            ("dsa-signature", "167757bc-47f3-11d1-a9c3-0000f80367c1"),
            ("ms-ds-device-registration-service-container", "310b55ce-3dcd-4392-a96d-c9e35397c24f"),
            ("ms-ds-expire-passwords-on-smart-card-only-accounts", "3417ab48-df24-4fb1-80b0-0fcb367e25e3"),
            ("nismapentry", "4a95216e-fcc0-402e-b57f-5971626148a9"),
            ("print-media-supported", "244b296f-5abd-11d0-afd2-00c04fd930c9"),
            ("ms-sql-thirdparty", "c4e311fc-d34b-11d2-999a-0000f87a57d4"),
            ("ms-ds-optional-feature-guid", "9b88bda8-dd82-4998-a91d-5f2d2baf1927"),
            ("ds-ui-shell-maximum", "fcca766a-6f91-11d2-9905-0000f87a57d4"),
            ("ms-wmi-rangeparam", "45fb5a57-5018-4d0f-9056-997c8c9122d9"),
            ("ms-ds-key-credential-link-bl", "938ad788-225f-4eee-93b9-ad24a159e1db"),
            ("nismapname", "969d3c79-0e9a-4d95-b0ac-bdde7ff8f3a1"),
            ("print-media-ready", "3bcbfcf5-4d3d-11d0-a1a6-00c04fd930c9"),
            ("ms-sql-allowsnapshotfilesftpdownloading", "c49b8be8-d34b-11d2-999a-0000f87a57d4"),
            ("ms-ds-external-store", "604877cd-9cdb-47c7-b03d-3daadb044910"),
            ("ds-ui-admin-notification", "f6ea0a94-6f91-11d2-9905-0000f87a57d4"),
            ("ms-ds-cloud-extensions", "641e87a4-8326-4771-ba2d-c706df35e35a"),
            ("bootfile", "e3f3cb4e-0f20-42eb-9703-d2ff26e52667"),
            ("print-max-y-extent", "ba305f70-47e3-11d0-a1a6-00c04fd930c9"),
            ("ms-sql-allowqueuedupdatingsubscription", "c458ca80-d34b-11d2-999a-0000f87a57d4"),
            ("ms-ds-external-key", "b92fd528-38ac-40d4-818d-0433380837c1"),
            ("ds-ui-admin-maximum", "ee8d0ae0-6f91-11d2-9905-0000f87a57d4"),
            ("ms-wmi-policytype", "595b2613-4109-4e77-9013-a3bb4ef277c7"),
            ("ms-ds-shadow-principal-sid", "1dcc0722-aab0-4fef-956f-276fe19de107"),
            ("bootparameter", "d72a0750-8c7c-416e-8714-e65f11e908be"),
            ("print-max-x-extent", "ba305f6f-47e3-11d0-a1a6-00c04fd930c9"),
            ("ms-sql-allowimmediateupdatingsubscription", "c4186b6e-d34b-11d2-999a-0000f87a57d4"),
            ("ms-ds-executescriptpassword", "9d054a5a-d187-46c1-9d85-42dfc44a56dd"),
            ("ds-heuristics", "f0f8ff86-1191-11d0-a060-00aa006c33ed"),
            ("ms-ds-claims-transformation-policies", "c8fca9b1-7d88-bb4f-827a-448927710762"),
            ("ms-ds-device-trust-type", "c4a46807-6adc-4bbb-97de-6bed181a1bfe"),
            ("macaddress", "e6a522dd-9770-43e1-89de-1de5044328f7"),
            ("print-max-resolution-supported", "281416cf-1968-11d0-a28f-00aa003049e2"),
            ("ms-sql-allowknownpullsubscription", "c3bb7054-d34b-11d2-999a-0000f87a57d4"),
            ("ms-ds-entry-time-to-die", "e1e9bad7-c6dd-4101-a843-794cec85b038"),
            ("ds-core-propagation-data", "d167aa4b-8b08-11d2-9939-0000f87a57d4"),
            ("ms-wmi-policytemplate", "e2bc80f1-244a-4d59-acc6-ca5c4f82e6e1"),
            ("ms-ds-key-approximate-last-logon-time-stamp", "649ac98d-9b9a-4d41-af6b-f616f2a62e4a"),
            ("ipnetmasknumber", "6ff64fcd-462e-4f62-b44a-9a5347659eb9"),
            ("print-max-copies", "281416d1-1968-11d0-a28f-00aa003049e2"),
            ("ms-sql-publisher", "c1676858-d34b-11d2-999a-0000f87a57d4"),
            ("ms-ds-enabled-feature-bl", "ce5b01bc-17c6-44b8-9dc1-a9668b00901b"),
            ("driver-version", "ba305f6e-47e3-11d0-a1a6-00c04fd930c9"),
            ("ms-ds-claims-transformation-policy-type", "2eeb62b3-1373-fe45-8101-387f1676edc7"),
            ("ms-ds-custom-key-information", "b6e5e988-e5e4-4c86-a2ae-0dacb970a0e1"),
            ("ipnetworknumber", "4e3854f4-3087-42a4-a813-bb0c528958d3"),
            ("print-mac-address", "ba305f7a-47e3-11d0-a1a6-00c04fd930c9"),
            ("ms-sql-keywords", "01e9a98a-ccef-11d2-9993-0000f87a57d4"),
            ("ms-ds-enabled-feature", "5706aeaf-b940-4fb2-bcfc-5268683ad9fe"),
            ("driver-name", "281416c5-1968-11d0-a28f-00aa003049e2"),
            ("ms-wmi-objectencoding", "55dd81c9-c312-41f9-a84d-c6adbdf1e8e1"),
            ("ms-ds-computer-sid", "dffbd720-0872-402e-9940-fcd78db049ba"),
            ("iphostnumber", "de8bb721-85dc-4fde-b687-9657688e667e"),
            ("print-language", "281416d6-1968-11d0-a28f-00aa003049e2"),
            ("ms-sql-applications", "fbcda2ea-ccee-11d2-9993-0000f87a57d4"),
            ("ms-ds-dnsrootalias", "2143acca-eead-4d29-b591-85fa49ce9173"),
            ("drink", "1a1aa5b5-262e-4df6-af04-2cf6b0d80048"),
            ("ms-ds-value-type", "e3c27fdf-b01d-4f4e-87e7-056eef0eb922"),
            ("ms-ds-device-dn", "642c1129-3899-4721-8e21-4839e3988ce5"),
            ("oncrpcnumber", "966825f5-01d9-4a5c-a011-d15ae84efa55"),
            ("print-keep-printed-jobs", "ba305f6d-47e3-11d0-a1a6-00c04fd930c9"),
            ("ms-sql-lastdiagnosticdate", "f6d6dd88-ccee-11d2-9993-0000f87a57d4"),
            ("ms-ds-deleted-object-lifetime", "a9b38cb6-189a-4def-8a70-0fcfa158148e"),
            ("domain-wide-policy", "80a67e29-9f22-11d0-afdd-00c04fd930c9"),
            ("ms-wmi-mergeablepolicytemplate", "07502414-fdca-4851-b04a-13645b11d226"),
            ("ms-ds-key-principal-bl", "d1328fbc-8574-4150-881d-0b1088827878"),
            ("ms-ds-password-history-length", "fed81bb7-768c-4c2f-9641-2245de34794d"),
            ("force-logoff", "bf967977-0de6-11d0-a285-00aa003049e2"),
            ("ms-ds-shadow-principal", "770f4cb3-1643-469c-b766-edd77aa75e14"),
            ("application-entity", "3fdfee4f-47f4-11d1-a9c3-0000f80367c1"),
            ("mssfu-30-posix-member-of", "7bd76b92-3244-438a-ada6-24f5ea34381e"),
            ("prior-value", "bf967a02-0de6-11d0-a285-00aa003049e2"),
            ("ms-wmi-int8default", "f4d8085a-8c5b-4785-959b-dc585566e445"),
            ("ms-ds-oidtogroup-link-bl", "1a3d0d20-5844-4199-ad25-0f5039a76ada"),
            ("flat-name", "b7b13117-b82e-11d0-afee-0000f80367c1"),
            ("ms-wmi-wmigpo", "05630000-3927-4ede-bf27-ca91f275c26f"),
            ("mssfu-30-posix-member", "c875d82d-2848-4cec-bb50-3c5486d09d57"),
            ("prior-set-time", "bf967a01-0de6-11d0-a285-00aa003049e2"),
            ("ms-wmi-intvalidvalues", "6af565f6-a749-4b72-9634-3c5d47e6b4e0"),
            ("ms-ds-oidtogroup-link", "f9c9a57c-3941-438d-bebf-0edaf2aca187"),
            ("flags", "bf967976-0de6-11d0-a285-00aa003049e2"),
            ("ms-ds-shadow-principal-container", "11f95545-d712-4c50-b847-d2781537c633"),
            ("address-template", "5fd4250a-1262-11d0-a060-00aa006c33ed"),
            ("mssfu-30-nsmap-field-position", "585c9d5e-f599-4f07-9cf9-4373af4b89d3"),
            ("printer-name", "244b296e-5abd-11d0-afd2-00c04fd930c9"),
            ("ms-wmi-intmin", "68c2e3ba-9837-4c70-98e0-f0c33695d023"),
            ("ms-ds-minimum-password-length", "b21b3439-4c3a-441c-bb5f-08f20e9b315e"),
            ("file-ext-priority", "d9e18315-8939-11d1-aebc-0000f80367c1"),
            ("ms-wmi-unknownrangeparam", "b82ac26b-c6db-4098-92c6-49c18a3336e1"),
            ("mssfu-30-max-uid-number", "ec998437-d944-4a28-8500-217588adfc75"),
            ("print-status", "ba305f6b-47e3-11d0-a1a6-00c04fd930c9"),
            ("ms-wmi-intmax", "fb920c2c-f294-4426-8ac1-d24b42aa2bce"),
            ("ms-ds-minimum-password-age", "2a74f878-4d9c-49f9-97b3-6767d1cbd9a3"),
            ("facsimile-telephone-number", "bf967974-0de6-11d0-a285-00aa003049e2"),
            ("ms-ds-key-credential", "ee1f5543-7c2e-476a-8b3f-e11f4af6c498"),
            ("address-book-container", "3e74f60f-3e73-11d1-a9c0-0000f80367c1"),
            ("mssfu-30-max-gid-number", "04ee6aa6-f83b-469a-bf5a-3c00d3634669"),
            ("print-start-time", "281416c9-1968-11d0-a28f-00aa003049e2"),
            ("ms-wmi-intflags4", "bd74a7ac-c493-4c9c-bdfa-5c7b119ca6b2"),
            ("ms-ds-maximum-password-age", "fdd337f5-4999-4fce-b252-8ff9c9b43875"),
            ("extra-columns", "d24e2846-1dd9-4bcf-99d7-a6227cc86da7"),
            ("ms-wmi-uintsetparam", "8f4beb31-4e19-46f5-932e-5fa03c339b1d"),
            ("mssfu-30-yp-servers", "084a944b-e150-4bfe-9345-40e1aedaebba"),
            ("print-stapling-supported", "ba305f73-47e3-11d0-a1a6-00c04fd930c9"),
            ("ms-wmi-intflags3", "f29fa736-de09-4be4-b23a-e734c124bacc"),
            ("ms-ds-mastered-by", "60234769-4819-4615-a1b2-49d2f119acb5"),
            ("extension-name", "bf967972-0de6-11d0-a285-00aa003049e2"),
            ("ms-ds-authn-policy", "ab6a1156-4dc7-40f5-9180-8e4ce42fe5cd"),
            ("acs-subnet", "7f561289-5301-11d1-a9c5-0000f80367c1"),
            ("mssfu-30-domains", "93095ed3-6f30-4bdd-b734-65d569f5f7c9"),
            ("print-spooling", "ba305f6c-47e3-11d0-a1a6-00c04fd930c9"),
            ("ms-wmi-intflags2", "075a42c9-c55a-45b1-ac93-eb086b31f610"),
            ("ms-ds-logon-time-sync-interval", "ad7940f8-e43a-4a42-83bc-d688e59ea605"),
            ("extended-class-info", "9a7ad948-ca53-11d1-bbd0-0080c76670c0"),
            ("ms-wmi-uintrangeparam", "d9a799b2-cef3-48b3-b5ad-fb85f8dd3214"),
            ("mssfu-30-nis-domain", "9ee3b2e3-c7f3-45f8-8c9f-1382be4984d2"),
            ("print-share-name", "ba305f68-47e3-11d0-a1a6-00c04fd930c9"),
            ("ms-wmi-intflags1", "18e006b9-6445-48e3-9dcf-b5ecfbc4df8e"),
            ("ms-ds-keyversionnumber", "c523e9c0-33b5-4ac8-8923-b57b927f42f6"),
            ("extended-chars-allowed", "bf967966-0de6-11d0-a285-00aa003049e2"),
            ("ms-ds-authn-policy-silo", "f9f0461e-697d-4689-9299-37e61d617b0d"),
            ("acs-resource-limits", "2e899b04-2834-11d3-91d4-0000f87a57d4"),
            ("mssfu-30-key-values", "37830235-e5e9-46f2-922b-d8d44f03e7ae"),
            ("print-separator-file", "281416c6-1968-11d0-a28f-00aa003049e2"),
            ("ms-wmi-intdefault", "1b0c07f8-76dd-4060-a1e1-70084619dc90"),
            ("ms-ds-last-known-rdn", "8ab15858-683e-466d-877f-d640e1f9a611"),
            ("extended-attribute-info", "9a7ad947-ca53-11d1-bbd0-0080c76670c0"),
            ("ms-wmi-stringsetparam", "0bc579a2-1da7-4cea-b699-807f3b9d63a4"),
            ("mssfu-30-aliases", "20ebf171-c69a-4c31-b29d-dcb837d8912d"),
            ("print-rate-unit", "ba305f78-47e3-11d0-a1a6-00c04fd930c9"),
            ("ms-wmi-id", "9339a803-94b8-47f7-9123-a853b9ff7e45"),
            ("ms-ds-isrodc", "a8e8aa23-3e67-4af1-9d7a-2f1a1d633ac9"),
            ("entry-ttl", "d213decc-d81a-4384-aac2-dcfcfd631cf8"),
            ("ms-ds-authn-policies", "3a9adf5d-7b97-4f7e-abb4-e5b55c1c06b4"),
            ("acs-policy", "7f561288-5301-11d1-a9c5-0000f80367c1"),
            ("mssfu-30-name", "16c5d1d3-35c2-4061-a870-a5cefda804f0"),
            ("print-rate", "ba305f77-47e3-11d0-a1a6-00c04fd930c9"),
            ("ms-wmi-genus", "50c8673a-8f56-4614-9308-9e1340fb9af3"),
            ("ms-ds-isgc", "1df5cf33-0fe5-499e-90e1-e94b42718a46"),
            ("enrollment-providers", "2a39c5b3-8960-11d1-aebc-0000f80367c1"),
            ("ms-wmi-som", "ab857078-0142-4406-945b-34c9b6b13372"),
            ("mssfu-30-order-number", "02625f05-d1ee-4f9f-b366-55266becb95c"),
            ("print-pages-per-minute", "19405b97-3cfa-11d1-a9c0-0000f80367c1"),
            ("ms-wmi-creationdate", "748b0a2e-3351-4b3f-b171-2f17414ea779"),
            ("ms-ds-is-possible-values-present", "6fabdcda-8c53-204f-b1a4-9df0c67c1eb4"),
            ("enabled-connection", "bf967963-0de6-11d0-a285-00aa003049e2"),
            ("ms-ds-authn-policy-silos", "d2b1470a-8f84-491e-a752-b401ee00fe5c"),
            ("class-schema", "bf967a83-0de6-11d0-a285-00aa003049e2"),
            ("mssfu-30-master-server-name", "4cc908a2-9e18-410e-8459-f17cc422020a"),
            ("print-owner", "ba305f69-47e3-11d0-a1a6-00c04fd930c9"),
            ("ms-wmi-classdefinition", "2b9c0ebc-c272-45cb-99d2-4d0e691632e0"),
            ("ms-ds-intid", "bc60096a-1b47-4b30-8877-602c93f56532"),
            ("enabled", "a8df73f2-c5ea-11d1-bbcb-0080c76670c0"),
            ("ms-wmi-simplepolicytemplate", "6cc8b2b5-12df-44f6-8307-e74f5cdee369"),
            ("account", "2628a46a-a6ad-4ae0-b854-2b12d9fe6f9e"),
            ("mssfu-30-map-filter", "b7b16e01-024f-4e23-ad0d-71f1a406b684"),
            ("print-orientations-supported", "281416d0-1968-11d0-a28f-00aa003049e2"),
            ("ms-wmi-class", "90c1925f-4a24-4b07-b202-be32eb3c8b74"),
            ("ms-ds-integer", "7bc64cea-c04e-4318-b102-3e0729371a65"),
            ("employee-type", "a8df73f0-c5ea-11d1-bbcb-0080c76670c0"),
            ("ms-ds-device", "5df2b673-6d41-4774-b3e8-d52e8ee9ff99"),
            ("mssfu-30-result-attributes", "e167b0b6-4045-4433-ac35-53f972d45cba"),
            ("print-number-up", "3bcbfcf4-4d3d-11d0-a1a6-00c04fd930c9"),
            ("ms-wmi-changedate", "f9cdf7a0-ec44-4937-a79b-cd91522b3aa8"),
            ("ms-ds-host-service-account-bl", "79abe4eb-88f3-48e7-89d6-f4bc7e98c331"),
            ("employee-number", "a8df73ef-c5ea-11d1-bbcb-0080c76670c0"),
            ("ms-ts-max-idle-time", "ff739e9c-6bb7-460e-b221-e250f3de0f95"),
            ("proxy-lifetime", "bf967a07-0de6-11d0-a285-00aa003049e2"),
            ("ms-wmi-query", "65fff93e-35e3-45a3-85ae-876c6718297f"),
            ("ms-ds-required-forest-behavior-version", "4beca2e8-a653-41b2-8fee-721575474bec"),
            ("frs-ds-poll", "1be8f177-a9ff-11d0-afe2-00c04fd930c9"),
            ("msmq-queue", "9a0dc343-c100-11d1-bbc5-0080c76670c0"),
            ("builtin-domain", "bf967a81-0de6-11d0-a285-00aa003049e2"),
            ("ms-ts-max-connection-time", "1d960ee2-6464-4e95-a781-e3b5cd5f9588"),
            ("proxy-generation-enabled", "5fd424d6-1262-11d0-a060-00aa006c33ed"),
            ("ms-wmi-propertyname", "ab920883-e7f8-4d72-b4a0-c0449897509d"),
            ("ms-ds-required-domain-behavior-version", "eadd3dfe-ae0e-4cc2-b9b9-5fe5b6ed2dd2"),
            ("frs-directory-filter", "1be8f171-a9ff-11d0-afe2-00c04fd930c9"),
            ("ms-ts-max-disconnection-time", "326f7089-53d8-4784-b814-46d8535110d2"),
            ("proxy-addresses", "bf967a06-0de6-11d0-a285-00aa003049e2"),
            ("ms-wmi-parm4", "3800d5a3-f1ce-4b82-a59a-1528ea795f59"),
            ("ms-ds-pso-applied", "5e6cf031-bda8-43c8-aca4-8fee4127005b"),
            ("frs-control-outbound-backlog", "2a13257c-9373-11d1-aebc-0000f80367c1"),
            ("msmq-migrated-user", "50776997-3c3d-11d2-90cc-00c04fd91ab1"),
            ("ms-ts-remote-control", "15177226-8642-468b-8c48-03ddfd004982"),
            ("proxied-object-name", "e1aea402-cd5b-11d0-afff-0000f80367c1"),
            ("ms-wmi-parm3", "45958fb6-52bd-48ce-9f9f-c2712d9f2bfc"),
            ("ms-ds-pso-applies-to", "64c80f48-cdd2-4881-a86d-4e97b6f561fc"),
            ("frs-control-inbound-backlog", "2a13257b-9373-11d1-aebc-0000f80367c1"),
            ("application-version", "ddc790ac-af4d-442a-8f0f-a1d4caa7dd92"),
            ("ms-ts-allow-logon", "3a0cd464-bc54-40e7-93ae-a646a6ecc4b4"),
            ("profile-path", "bf967a05-0de6-11d0-a285-00aa003049e2"),
            ("ms-wmi-parm2", "0003508e-9c42-4a76-a8f4-38bf64bab0de"),
            ("ms-ds-lockout-threshold", "b8c8c35e-4a19-4a95-99d0-69fe4446286f"),
            ("frs-control-data-creation", "2a13257a-9373-11d1-aebc-0000f80367c1"),
            ("msmq-group", "46b27aac-aafa-4ffb-b773-e5bf621ee87b"),
            ("ms-ts-home-drive", "5f0a24d9-dffa-4cd9-acbf-a0680c03731e"),
            ("product-code", "d9e18317-8939-11d1-aebc-0000f80367c1"),
            ("ms-wmi-parm1", "27e81485-b1b0-4a8b-bedd-ce19a837e26e"),
            ("ms-ds-lockout-duration", "421f889a-472e-4fe4-8eb9-e1d0bc6071b2"),
            ("frs-computer-reference-bl", "2a132579-9373-11d1-aebc-0000f80367c1"),
            ("application-site-settings", "19195a5c-6da0-11d0-afd3-00c04fd930c9"),
            ("ms-ts-home-directory", "5d3510f0-c4e7-4122-b91f-a20add90e246"),
            ("privilege-value", "19405b99-3cfa-11d1-a9c0-0000f80367c1"),
            ("ms-wmi-normalizedclass", "eaba628f-eb8e-4fe9-83fc-693be695559b"),
            ("ms-ds-lockout-observation-window", "b05bda89-76af-468a-b892-1be55558ecc8"),
            ("frs-computer-reference", "2a132578-9373-11d1-aebc-0000f80367c1"),
            ("msmq-enterprise-settings", "9a0dc345-c100-11d1-bbc5-0080c76670c0"),
            ("ms-ts-profile-path", "e65c30db-316c-4060-a3a0-387b083f09cd"),
            ("privilege-holder", "19405b9b-3cfa-11d1-a9c0-0000f80367c1"),
            ("ms-wmi-name", "c6c8ace5-7e81-42af-ad72-77412c5941c4"),
            ("ms-ds-local-effective-recycle-time", "4ad6016b-b0d2-4c9b-93b6-5964b17b968c"),
            ("from-server", "bf967979-0de6-11d0-a285-00aa003049e2"),
            ("dns-zone-scope", "696f8a61-2d3f-40ce-a4b3-e275dfcc49c5"),
            ("application-settings", "f780acc1-56f0-11d1-a9c6-0000f80367c1"),
            ("mssfu-30-crypt-method", "4503d2a3-3d70-41b8-b077-dff123c15865"),
            ("privilege-display-name", "19405b98-3cfa-11d1-a9c0-0000f80367c1"),
            ("ms-wmi-mof", "6736809f-2064-443e-a145-81262b1f1366"),
            ("ms-ds-local-effective-deletion-time", "94f2800c-531f-4aeb-975d-48ac39fd8ca4"),
            ("from-entry", "9a7ad949-ca53-11d1-bbd0-0080c76670c0"),
            ("msmq-custom-recipient", "876d6817-35cc-436c-acea-5ef7174dd9be"),
            ("mssfu-30-is-valid-container", "0dea42f5-278d-4157-b4a7-49b59664915b"),
            ("privilege-attributes", "19405b9a-3cfa-11d1-a9c0-0000f80367c1"),
            ("ms-wmi-int8validvalues", "103519a9-c002-441b-981a-b0b3e012c803"),
            ("ms-ds-password-reversible-encryption-enabled", "75ccdd8f-af6c-4487-bb4b-69e4d38a959c"),
            ("friendly-names", "7bfdcb88-4807-11d1-a9c3-0000f80367c1"),
            ("dns-zone-scope-container", "f2699093-f25a-4220-9deb-03df4cc4a9c5"),
            ("application-process", "5fd4250b-1262-11d0-a060-00aa006c33ed"),
            ("mssfu-30-netgroup-user-at-domain", "a9e84eed-e630-4b67-b4b3-cad2a82d345e"),
            ("private-key", "bf967a03-0de6-11d0-a285-00aa003049e2"),
            ("ms-wmi-int8min", "ed1489d1-54cc-4066-b368-a00daa2664f1"),
            ("ms-ds-password-complexity-enabled", "db68054b-c9c3-4bf0-b15b-0fb52552a610"),
            ("foreign-identifier", "3e97891e-8c01-11d0-afda-00c04fd930c9"),
            ("msmq-configuration", "9a0dc344-c100-11d1-bbc5-0080c76670c0"),
            ("mssfu-30-netgroup-host-at-domain", "97d2bf65-0466-4852-a25a-ec20f57ee36c"),
            ("priority", "281416c7-1968-11d0-a28f-00aa003049e2"),
            ("ms-wmi-int8max", "e3d8b547-003d-4946-a32b-dc7cedc96b74"),
        ];

        values.iter().map(|&(k, v)| (k.to_string(), v.to_string())).collect::<HashMap<String, String>>()
    };
}
