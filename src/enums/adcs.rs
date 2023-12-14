use bitflags::bitflags;
use std::collections::HashMap;

use crate::objects::{
    certtemplate::CertTemplate,
    enterpriseca::EnterpriseCA, common::Member,
};

bitflags! {
    struct PkiCertificateNameFlag: u64 {
        const NONE = 0x00000000;
        const ENROLLEE_SUPPLIES_SUBJECT = 0x00000001;
        const ADD_EMAIL = 0x00000002;
        const ADD_OBJ_GUID = 0x00000004;
        const OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME = 0x00000008;
        const ADD_DIRECTORY_PATH = 0x00000100;
        const ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x00010000;
        const SUBJECT_ALT_REQUIRE_DOMAIN_DNS = 0x00400000;
        const SUBJECT_ALT_REQUIRE_SPN = 0x00800000;
        const SUBJECT_ALT_REQUIRE_DIRECTORY_GUID = 0x01000000;
        const SUBJECT_ALT_REQUIRE_UPN = 0x02000000;
        const SUBJECT_ALT_REQUIRE_EMAIL = 0x04000000;
        const SUBJECT_ALT_REQUIRE_DNS = 0x08000000;
        const SUBJECT_REQUIRE_DNS_AS_CN = 0x10000000;
        const SUBJECT_REQUIRE_EMAIL = 0x20000000;
        const SUBJECT_REQUIRE_COMMON_NAME = 0x40000000;
        const SUBJECT_REQUIRE_DIRECTORY_PATH = 0x80000000;
    }
}

/// Get the PKI flags from "msPKI-Certificate-Name-Flag" LDAP attribut.
/// MS: <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/1192823c-d839-4bc3-9b6b-fa8c53507ae1>
pub fn get_pki_cert_name_flags(value: u64) -> String
{
    let mut flags: Vec<String> = Vec::new();

    if (PkiCertificateNameFlag::NONE.bits() | value) == value
    {
        //nothing
    }
    if (PkiCertificateNameFlag::ENROLLEE_SUPPLIES_SUBJECT.bits() | value) == value
    {
        flags.push("ENROLLEE_SUPPLIES_SUBJECT".to_string());
        // template.enrollee_supplies_subject = true;
        // template_json["Properties"]["Enrollee Supplies Subject"] = template.enrollee_supplies_subject.to_owned().into();
    }
    if (PkiCertificateNameFlag::ADD_EMAIL.bits() | value) == value
    {
        flags.push("ADD_EMAIL".to_string());
    }
    if (PkiCertificateNameFlag::ADD_OBJ_GUID.bits() | value) == value
    {
        flags.push("ADD_OBJ_GUID".to_string());
    }
    if (PkiCertificateNameFlag::OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME.bits() | value) == value
    {
        flags.push("OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME".to_string());
    }
    if (PkiCertificateNameFlag::ADD_DIRECTORY_PATH.bits() | value) == value
    {
        flags.push("ADD_DIRECTORY_PATH".to_string());
    }
    if (PkiCertificateNameFlag::ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME.bits() | value) == value
    {
        flags.push("ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME".to_string());
    }
    if (PkiCertificateNameFlag::SUBJECT_ALT_REQUIRE_DOMAIN_DNS.bits() | value) == value
    {
        flags.push("SUBJECT_ALT_REQUIRE_DOMAIN_DNS".to_string());
    }
    if (PkiCertificateNameFlag::SUBJECT_ALT_REQUIRE_SPN.bits() | value) == value
    {
        flags.push("SUBJECT_ALT_REQUIRE_SPN".to_string());
    }
    if (PkiCertificateNameFlag::SUBJECT_ALT_REQUIRE_DIRECTORY_GUID.bits() | value) == value
    {
        flags.push("SUBJECT_ALT_REQUIRE_DIRECTORY_GUID".to_string());
    }
    if (PkiCertificateNameFlag::SUBJECT_ALT_REQUIRE_UPN.bits() | value) == value
    {
        flags.push("SUBJECT_ALT_REQUIRE_UPN".to_string());
    }
    if (PkiCertificateNameFlag::SUBJECT_ALT_REQUIRE_EMAIL.bits() | value) == value
    {
        flags.push("SUBJECT_ALT_REQUIRE_EMAIL".to_string());
    }
    if (PkiCertificateNameFlag::SUBJECT_ALT_REQUIRE_DNS.bits() | value) == value
    {
        flags.push("SUBJECT_ALT_REQUIRE_DNS".to_string());
    }
    if (PkiCertificateNameFlag::SUBJECT_REQUIRE_DNS_AS_CN.bits() | value) == value
    {
        flags.push("SUBJECT_REQUIRE_DNS_AS_CN".to_string());
    }
    if (PkiCertificateNameFlag::SUBJECT_REQUIRE_EMAIL.bits() | value) == value
    {
        flags.push("SUBJECT_REQUIRE_EMAIL".to_string());
    }
    if (PkiCertificateNameFlag::SUBJECT_REQUIRE_COMMON_NAME.bits() | value) == value
    {
        flags.push("SUBJECT_REQUIRE_COMMON_NAME".to_string());
    }
    if (PkiCertificateNameFlag::SUBJECT_REQUIRE_DIRECTORY_PATH.bits() | value) == value
    {
        flags.push("SUBJECT_REQUIRE_DIRECTORY_PATH".to_string());
    }
    return flags.join(", ")
}


bitflags! {
    struct PkiEnrollmentFlag: u64 {
        const NONE = 0x00000000;
        const INCLUDE_SYMMETRIC_ALGORITHMS = 0x00000001;
        const PEND_ALL_REQUESTS = 0x00000002;
        const PUBLISH_TO_KRA_CONTAINER = 0x00000004;
        const PUBLISH_TO_DS = 0x00000008;
        const AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE = 0x00000010;
        const AUTO_ENROLLMENT = 0x00000020;
        const CT_FLAG_DOMAIN_AUTHENTICATION_NOT_REQUIRED = 0x80;
        const PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT = 0x00000040;
        const USER_INTERACTION_REQUIRED = 0x00000100;
        const ADD_TEMPLATE_NAME = 0x200;
        const REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE = 0x00000400;
        const ALLOW_ENROLL_ON_BEHALF_OF = 0x00000800;
        const ADD_OCSP_NOCHECK = 0x00001000;
        const ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL = 0x00002000;
        const NOREVOCATIONINFOINISSUEDCERTS = 0x00004000;
        const INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS = 0x00008000;
        const ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT = 0x00010000;
        const ISSUANCE_POLICIES_FROM_REQUEST = 0x00020000;
        const SKIP_AUTO_RENEWAL = 0x00040000;
        const NO_SECURITY_EXTENSION = 0x00080000;
    }
}

/// Get the PKI flags from "msPKI-Enrollment-Flag" LDAP attribut.
/// MS: <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/ec71fd43-61c2-407b-83c9-b52272dec8a1>
pub fn get_pki_enrollment_flags(value: u64) -> String
{
    let mut flags: Vec<String> = Vec::new();

    if (PkiEnrollmentFlag::NONE.bits() | value) == value
    {
        //nothing
    }
    if (PkiEnrollmentFlag::INCLUDE_SYMMETRIC_ALGORITHMS.bits() | value) == value
    {
        flags.push("INCLUDE_SYMMETRIC_ALGORITHMS".to_string());
    }
    if (PkiEnrollmentFlag::PEND_ALL_REQUESTS.bits() | value) == value
    {
        flags.push("PEND_ALL_REQUESTS".to_string());
        // template.requires_manager_approval = true;
        // template_json["Properties"]["Requires Manager Approval"] = template.requires_manager_approval.to_owned().into();
    }
    if (PkiEnrollmentFlag::PUBLISH_TO_KRA_CONTAINER.bits() | value) == value
    {
        flags.push("PUBLISH_TO_KRA_CONTAINER".to_string());
    }
    if (PkiEnrollmentFlag::PUBLISH_TO_DS.bits() | value) == value
    {
        flags.push("PUBLISH_TO_DS".to_string());
    }
    if (PkiEnrollmentFlag::AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE.bits() | value) == value
    {
        flags.push("AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE".to_string());
    }
    if (PkiEnrollmentFlag::AUTO_ENROLLMENT.bits() | value) == value
    {
        flags.push("AUTO_ENROLLMENT".to_string());
    }
    if (PkiEnrollmentFlag::CT_FLAG_DOMAIN_AUTHENTICATION_NOT_REQUIRED.bits() | value) == value
    {
        flags.push("CT_FLAG_DOMAIN_AUTHENTICATION_NOT_REQUIRED".to_string());
    }
    if (PkiEnrollmentFlag::PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT.bits() | value) == value
    {
        flags.push("PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT".to_string());
    }
    if (PkiEnrollmentFlag::USER_INTERACTION_REQUIRED.bits() | value) == value
    {
        flags.push("USER_INTERACTION_REQUIRED".to_string());
    }
    if (PkiEnrollmentFlag::ADD_TEMPLATE_NAME.bits() | value) == value
    {
        flags.push("ADD_TEMPLATE_NAME".to_string());
    }
    if (PkiEnrollmentFlag::REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE.bits() | value) == value
    {
        flags.push("REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE".to_string());
    }
    if (PkiEnrollmentFlag::ALLOW_ENROLL_ON_BEHALF_OF.bits() | value) == value
    {
        flags.push("ALLOW_ENROLL_ON_BEHALF_OF".to_string());
    }
    if (PkiEnrollmentFlag::ADD_OCSP_NOCHECK.bits() | value) == value
    {
        flags.push("ADD_OCSP_NOCHECK".to_string());
    }
    if (PkiEnrollmentFlag::ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL.bits() | value) == value
    {
        flags.push("ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL".to_string());
    }
    if (PkiEnrollmentFlag::NOREVOCATIONINFOINISSUEDCERTS.bits() | value) == value
    {
        flags.push("NOREVOCATIONINFOINISSUEDCERTS".to_string());
    }
    if (PkiEnrollmentFlag::INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS.bits() | value) == value
    {
        flags.push("INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS".to_string());
    }
    if (PkiEnrollmentFlag::ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT.bits() | value) == value
    {
        flags.push("ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT".to_string());
    }
    if (PkiEnrollmentFlag::ISSUANCE_POLICIES_FROM_REQUEST.bits() | value) == value
    {
        flags.push("ISSUANCE_POLICIES_FROM_REQUEST".to_string());
    }
    if (PkiEnrollmentFlag::SKIP_AUTO_RENEWAL.bits() | value) == value
    {
        flags.push("SKIP_AUTO_RENEWAL".to_string());
    }
    if (PkiEnrollmentFlag::NO_SECURITY_EXTENSION.bits() | value) == value
    {
        flags.push("NO_SECURITY_EXTENSION".to_string());
        // template.no_security_extension = true;
    }
    return flags.join(", ")
}

bitflags! {
    struct PkiPrivateKeyFlag: u64 {
        const REQUIRE_PRIVATE_KEY_ARCHIVAL = 0x00000001;
        const EXPORTABLE_KEY = 0x00000010;
        const STRONG_KEY_PROTECTION_REQUIRED = 0x00000020;
        const REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM = 0x00000040;
        const REQUIRE_SAME_KEY_RENEWAL = 0x00000080;
        const USE_LEGACY_PROVIDER = 0x00000100;
        const ATTEST_NONE = 0x00000000;
        const ATTEST_REQUIRED = 0x00002000;
        const ATTEST_PREFERRED = 0x00001000;
        const ATTESTATION_WITHOUT_POLICY = 0x00004000;
        const EK_TRUST_ON_USE = 0x00000200;
        const EK_VALIDATE_CERT = 0x00000400;
        const EK_VALIDATE_KEY = 0x00000800;
        const HELLO_LOGON_KEY = 0x00200000;
    }
}

/// Get the PKI flags from "msPKI-Private-Key-Flag" LDAP attribut.
/// MS: <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/f6122d87-b999-4b92-bff8-f465e8949667>
pub fn get_pki_private_flags(value: u64) -> String
{
    let mut flags: Vec<String> = Vec::new();

    if (PkiPrivateKeyFlag::REQUIRE_PRIVATE_KEY_ARCHIVAL.bits() | value) == value
    {
        flags.push("REQUIRE_PRIVATE_KEY_ARCHIVAL".to_string());
        // template.requires_key_archival = true;
        // template_json["Properties"]["Requires Key Archival"] = template.requires_key_archival.to_owned().into();
    }
    if (PkiPrivateKeyFlag::EXPORTABLE_KEY.bits() | value) == value
    {
        flags.push("EXPORTABLE_KEY".to_string());
    }
    if (PkiPrivateKeyFlag::STRONG_KEY_PROTECTION_REQUIRED.bits() | value) == value
    {
        flags.push("STRONG_KEY_PROTECTION_REQUIRED".to_string());
    }
    if (PkiPrivateKeyFlag::REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM.bits() | value) == value
    {
        flags.push("REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM".to_string());
    }
    if (PkiPrivateKeyFlag::REQUIRE_SAME_KEY_RENEWAL.bits() | value) == value
    {
        flags.push("REQUIRE_SAME_KEY_RENEWAL".to_string());
    }
    if (PkiPrivateKeyFlag::USE_LEGACY_PROVIDER.bits() | value) == value
    {
        flags.push("USE_LEGACY_PROVIDER".to_string());
    }
    if (PkiPrivateKeyFlag::ATTEST_NONE.bits() | value) == value
    {
        flags.push("ATTEST_NONE".to_string());
    }
    if (PkiPrivateKeyFlag::ATTEST_REQUIRED.bits() | value) == value
    {
        flags.push("ATTEST_REQUIRED".to_string());
    }
    if (PkiPrivateKeyFlag::ATTEST_PREFERRED.bits() | value) == value
    {
        flags.push("ATTEST_PREFERRED".to_string());
    }
    if (PkiPrivateKeyFlag::ATTESTATION_WITHOUT_POLICY.bits() | value) == value
    {
        flags.push("ATTESTATION_WITHOUT_POLICY".to_string());
    }
    if (PkiPrivateKeyFlag::EK_TRUST_ON_USE.bits() | value) == value
    {
        flags.push("EK_TRUST_ON_USE".to_string());
    }
    if (PkiPrivateKeyFlag::EK_VALIDATE_CERT.bits() | value) == value
    {
        flags.push("EK_VALIDATE_CERT".to_string());
    }
    if (PkiPrivateKeyFlag::EK_VALIDATE_KEY.bits() | value) == value
    {
        flags.push("EK_VALIDATE_KEY".to_string());
    }
    if (PkiPrivateKeyFlag::HELLO_LOGON_KEY.bits() | value) == value
    {
        flags.push("HELLO_LOGON_KEY".to_string());
    }
    return flags.join(", ")
}


/// Function to replace displayname by SID in enabled cert templates.
pub fn templates_enabled_change_displayname_to_sid(
    vec_certtemplates: &mut Vec<CertTemplate>,
    vec_enterprisecas: &mut Vec<EnterpriseCA>,
) {
    let mut name_sid: HashMap<String, String> = HashMap::new();
    for certtemplate in vec_certtemplates {
        name_sid.insert(
            certtemplate.properties().name().to_owned(),
            certtemplate.object_identifier().to_owned(),
         );
    }
    // println!("{:?}",&name_sid);

    for enterprise_ca in vec_enterprisecas {
        let templates = enterprise_ca.enabled_cert_templates();
        let mut enabled_cert_templates: Vec<Member> = Vec::new();
        for template in templates {
            let mut member = Member::new();
            // println!("{:?}",&template.object_identifier());
            if let Some(value) = name_sid.keys()
            .find(|&key| key.contains(&template.object_identifier().to_uppercase()))
            .and_then(|key| name_sid.get(key))
            {
                *member.object_identifier_mut() = value.to_owned();
                *member.object_type_mut() = template.object_type().to_owned();
                enabled_cert_templates.push(member);
            }
        }
        // Fixe values in enterprise CA
        *enterprise_ca.enabled_cert_templates_mut() = enabled_cert_templates;
    }
}