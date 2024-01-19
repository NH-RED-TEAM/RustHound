use bitflags::bitflags;
use crate::modules::adcs::parser::Template;

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

/// Get the PKI flags from "msPKI-Certificate-Name-Flag" LDAP attribute.
/// MS: <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/1192823c-d839-4bc3-9b6b-fa8c53507ae1>
pub fn get_pki_cert_name_flags(
    template: &mut Template,
    template_json: &mut serde_json::value::Value,
    value: u64,
) -> Vec<String>
{
    let mut flags: Vec<&str> = Vec::new();

    if (PkiCertificateNameFlag::NONE.bits() | value) == value
    {
        //nothing
    }
    if (PkiCertificateNameFlag::ENROLLEE_SUPPLIES_SUBJECT.bits() | value) == value
    {
        flags.push("EnrolleeSuppliesSubject");
        template.enrollee_supplies_subject = true;
        template_json["Properties"]["Enrollee Supplies Subject"] = template.enrollee_supplies_subject.to_owned().into();
    }
    if (PkiCertificateNameFlag::ADD_EMAIL.bits() | value) == value
    {
        flags.push("AddEmail");
    }
    if (PkiCertificateNameFlag::ADD_OBJ_GUID.bits() | value) == value
    {
        flags.push("AddObjGuid");
    }
    if (PkiCertificateNameFlag::OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME.bits() | value) == value
    {
        flags.push("OldCertSuppliesSubjectAndAltName");
    }
    if (PkiCertificateNameFlag::ADD_DIRECTORY_PATH.bits() | value) == value
    {
        flags.push("AddDirectoryPath");
    }
    if (PkiCertificateNameFlag::ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME.bits() | value) == value
    {
        flags.push("EnrolleeSuppliesSubjectAltName");
    }
    if (PkiCertificateNameFlag::SUBJECT_ALT_REQUIRE_DOMAIN_DNS.bits() | value) == value
    {
        flags.push("SubjectAltRequireDomainDns");
    }
    if (PkiCertificateNameFlag::SUBJECT_ALT_REQUIRE_SPN.bits() | value) == value
    {
        flags.push("SubjectAltRequireSpn");
    }
    if (PkiCertificateNameFlag::SUBJECT_ALT_REQUIRE_DIRECTORY_GUID.bits() | value) == value
    {
        flags.push("SubjectAltRequireGuid");
    }
    if (PkiCertificateNameFlag::SUBJECT_ALT_REQUIRE_UPN.bits() | value) == value
    {
        flags.push("SubjectAltRequireUpn");
    }
    if (PkiCertificateNameFlag::SUBJECT_ALT_REQUIRE_EMAIL.bits() | value) == value
    {
        flags.push("SubjectAltRequireEmail");
    }
    if (PkiCertificateNameFlag::SUBJECT_ALT_REQUIRE_DNS.bits() | value) == value
    {
        flags.push("SubjectAltRequireDns");
    }
    if (PkiCertificateNameFlag::SUBJECT_REQUIRE_DNS_AS_CN.bits() | value) == value
    {
        flags.push("SubjectRequireDnsAsCn");
    }
    if (PkiCertificateNameFlag::SUBJECT_REQUIRE_EMAIL.bits() | value) == value
    {
        flags.push("SubjectRequireEmail");
    }
    if (PkiCertificateNameFlag::SUBJECT_REQUIRE_COMMON_NAME.bits() | value) == value
    {
        flags.push("SubjectRequireCommonName");
    }
    if (PkiCertificateNameFlag::SUBJECT_REQUIRE_DIRECTORY_PATH.bits() | value) == value
    {
        flags.push("SubjectRequireDirectoryPath");
    }

    return flags.iter().map(|x| x.to_string()).collect::<Vec<String>>();
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

/// Get the PKI flags from "msPKI-Enrollment-Flag" LDAP attribute.
/// MS: <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/ec71fd43-61c2-407b-83c9-b52272dec8a1>
pub fn get_pki_enrollment_flags(
    template: &mut Template,
    template_json: &mut serde_json::value::Value,
    value: u64,
) -> Vec<String>
{
    let mut flags: Vec<&str> = Vec::new();

    if (PkiEnrollmentFlag::NONE.bits() | value) == value
    {
        //nothing
    }
    if (PkiEnrollmentFlag::INCLUDE_SYMMETRIC_ALGORITHMS.bits() | value) == value
    {
        flags.push("IncludeSymmetricAlgorithms");
    }
    if (PkiEnrollmentFlag::PEND_ALL_REQUESTS.bits() | value) == value
    {
        flags.push("PendAllRequests");
        template.requires_manager_approval = true;
        template_json["Properties"]["Requires Manager Approval"] = template.requires_manager_approval.to_owned().into();
    }
    if (PkiEnrollmentFlag::PUBLISH_TO_KRA_CONTAINER.bits() | value) == value
    {
        flags.push("PublishToKraContainer");
    }
    if (PkiEnrollmentFlag::PUBLISH_TO_DS.bits() | value) == value
    {
        flags.push("PublishToDs");
    }
    if (PkiEnrollmentFlag::AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE.bits() | value) == value
    {
        flags.push("AutoEnrollmentCheckUserDsCertificate");
    }
    if (PkiEnrollmentFlag::AUTO_ENROLLMENT.bits() | value) == value
    {
        flags.push("AutoEnrollment");
    }
    if (PkiEnrollmentFlag::CT_FLAG_DOMAIN_AUTHENTICATION_NOT_REQUIRED.bits() | value) == value
    {
        flags.push("CtFlagDomainAuthentificationNotRequired");
    }
    if (PkiEnrollmentFlag::PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT.bits() | value) == value
    {
        flags.push("PreviousApprovalValidateReenrollment");
    }
    if (PkiEnrollmentFlag::USER_INTERACTION_REQUIRED.bits() | value) == value
    {
        flags.push("UserInteractionRequired");
    }
    if (PkiEnrollmentFlag::ADD_TEMPLATE_NAME.bits() | value) == value
    {
        flags.push("AddTemplateName");
    }
    if (PkiEnrollmentFlag::REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE.bits() | value) == value
    {
        flags.push("RemoveInvalidCertificateFromPersonalStore");
    }
    if (PkiEnrollmentFlag::ALLOW_ENROLL_ON_BEHALF_OF.bits() | value) == value
    {
        flags.push("AllowEnrollOnBehalfOf");
    }
    if (PkiEnrollmentFlag::ADD_OCSP_NOCHECK.bits() | value) == value
    {
        flags.push("AddOcspNocheck");
    }
    if (PkiEnrollmentFlag::ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL.bits() | value) == value
    {
        flags.push("EnbaleKeyReuseOnNtTokenKeysetStorageFull");
    }
    if (PkiEnrollmentFlag::NOREVOCATIONINFOINISSUEDCERTS.bits() | value) == value
    {
        flags.push("NorevocationInforInIssuedCerts");
    }
    if (PkiEnrollmentFlag::INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS.bits() | value) == value
    {
        flags.push("IncludeBasicConstraintsForEeCerts");
    }
    if (PkiEnrollmentFlag::ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT.bits() | value) == value
    {
        flags.push("AllowPreviousApprovalKeybasedrenewalValidateReenrollment");
    }
    if (PkiEnrollmentFlag::ISSUANCE_POLICIES_FROM_REQUEST.bits() | value) == value
    {
        flags.push("IssuancePoliciesFromRequest");
    }
    if (PkiEnrollmentFlag::SKIP_AUTO_RENEWAL.bits() | value) == value
    {
        flags.push("SkipAutoRenewal");
    }
    if (PkiEnrollmentFlag::NO_SECURITY_EXTENSION.bits() | value) == value
    {
        flags.push("NoSecurityExtension");
        template.no_security_extension = true;
    }

    return flags.iter().map(|x| x.to_string()).collect::<Vec<String>>();
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

/// Get the PKI flags from "msPKI-Private-Key-Flag" LDAP attribute.
/// MS: <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/f6122d87-b999-4b92-bff8-f465e8949667>
pub fn get_pki_private_flags(
    template: &mut Template,
    template_json: &mut serde_json::value::Value,
    value: u64,
) -> Vec<String>
{
    let mut flags: Vec<&str> = Vec::new();

    if (PkiPrivateKeyFlag::REQUIRE_PRIVATE_KEY_ARCHIVAL.bits() | value) == value
    {
        flags.push("RequirePrivateKeyArchival");
        template.requires_key_archival = true;
        template_json["Properties"]["Requires Key Archival"] = template.requires_key_archival.to_owned().into();
    }
    if (PkiPrivateKeyFlag::EXPORTABLE_KEY.bits() | value) == value
    {
        flags.push("ExportableKey");
    }
    if (PkiPrivateKeyFlag::STRONG_KEY_PROTECTION_REQUIRED.bits() | value) == value
    {
        flags.push("StringKeyProtectionRequired");
    }
    if (PkiPrivateKeyFlag::REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM.bits() | value) == value
    {
        flags.push("RequireAlternateSignatureAlgorithm");
    }
    if (PkiPrivateKeyFlag::REQUIRE_SAME_KEY_RENEWAL.bits() | value) == value
    {
        flags.push("RequireSameKeyRenewal");
    }
    if (PkiPrivateKeyFlag::USE_LEGACY_PROVIDER.bits() | value) == value
    {
        flags.push("UseLegacyProvider");
    }
    if (PkiPrivateKeyFlag::ATTEST_NONE.bits() | value) == value
    {
        flags.push("AttestNone");
    }
    if (PkiPrivateKeyFlag::ATTEST_REQUIRED.bits() | value) == value
    {
        flags.push("AttestRequired");
    }
    if (PkiPrivateKeyFlag::ATTEST_PREFERRED.bits() | value) == value
    {
        flags.push("AttestPrefeered");
    }
    if (PkiPrivateKeyFlag::ATTESTATION_WITHOUT_POLICY.bits() | value) == value
    {
        flags.push("AttestationWithoutPolicy");
    }
    if (PkiPrivateKeyFlag::EK_TRUST_ON_USE.bits() | value) == value
    {
        flags.push("EkTrustOnUse");
    }
    if (PkiPrivateKeyFlag::EK_VALIDATE_CERT.bits() | value) == value
    {
        flags.push("EkValidateCert");
    }
    if (PkiPrivateKeyFlag::EK_VALIDATE_KEY.bits() | value) == value
    {
        flags.push("EkValidateKey");
    }
    if (PkiPrivateKeyFlag::HELLO_LOGON_KEY.bits() | value) == value
    {
        flags.push("HelloLogonKey");
    }
    return flags.iter().map(|x| x.to_string()).collect::<Vec<String>>();
}