use bitflags::bitflags;

bitflags! {
    struct Flags: u32 {
        const SCRIPT = 0x0001;
        const ACCOUNT_DISABLE = 0x0002;
        const HOME_DIR_REQUIRED = 0x0008;
        const LOCKOUT = 0x0010;
        const PASSWORD_NOT_REQUIRED = 0x0020;
        const PASSWORD_CANT_CHANGE = 0x0040;
        const ENCRYPTED_TEXT_PWD_ALLOWED = 0x0080;
        const TEMP_DUPLICATE_ACCOUNT = 0x0100;
        const NORMAL_ACCOUNT = 0x0200;
        const INTER_DOMAIN_TRUST_ACCOUNT = 0x0800;
        const WORKSTATION_TRUST_ACCOUNT = 0x1000;
        const SERVER_TRUST_ACCOUNT = 0x2000;
        const DONT_EXPIRE_PASSWORD = 0x10000;
        const MNS_LOGON_ACCOUNT = 0x20000;
        const SMART_CARD_REQUIRED = 0x40000;
        const TRUSTED_FOR_DELEGATION = 0x80000;
        const NOT_DELEGATED = 0x100000;
        const USE_DES_KEY_ONLY = 0x200000;
        const DONT_REQ_PRE_AUTH = 0x400000;
        const PASSWORD_EXPIRED = 0x800000;
        const TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000;
        const PARTIAL_SECRETS_ACCOUNT = 0x04000000;
    }
}

/// Get the UAC flags from "userAccountControl" LDAP attribut.
pub fn get_flag(uac: u32) -> Vec<String>
{
    let mut uac_flags: Vec<String> = Vec::new();

    if (Flags::SCRIPT.bits() | uac) == uac
    {
        uac_flags.push("Script".to_string());
    }
    if (Flags::ACCOUNT_DISABLE.bits() | uac) == uac
    {
        uac_flags.push("AccountDisable".to_string());
    }
    if (Flags::HOME_DIR_REQUIRED.bits() | uac) == uac
    {
        uac_flags.push("HomeDirRequired".to_string());
    }
    if (Flags::LOCKOUT.bits() | uac) == uac
    {
        uac_flags.push("Lockout".to_string());
    }
    if (Flags::PASSWORD_NOT_REQUIRED.bits() | uac) == uac
    {
        uac_flags.push("PasswordNotRequired".to_string());
    }
    if (Flags::PASSWORD_CANT_CHANGE.bits() | uac) == uac
    {
        uac_flags.push("PasswordCantChange".to_string());
    }
    if (Flags::ENCRYPTED_TEXT_PWD_ALLOWED.bits() | uac) == uac
    {
        uac_flags.push("EncryptedTextPwdAllowed".to_string());
    }
    if (Flags::TEMP_DUPLICATE_ACCOUNT.bits() | uac) == uac
    {
        uac_flags.push("TempDuplicateAccount".to_string());
    }
    if (Flags::NORMAL_ACCOUNT.bits() | uac) == uac
    {
        uac_flags.push("NormalAccount".to_string());
    }
    if (Flags::INTER_DOMAIN_TRUST_ACCOUNT.bits() | uac) == uac
    {
        uac_flags.push("InterdomainTrustAccount".to_string());
    }
    if (Flags::WORKSTATION_TRUST_ACCOUNT.bits() | uac) == uac
    {
        uac_flags.push("WorkstationTrustAccount".to_string());
    }
    if (Flags::SERVER_TRUST_ACCOUNT.bits() | uac) == uac
    {
        uac_flags.push("ServerTrustAccount".to_string());
    }
    if (Flags::DONT_EXPIRE_PASSWORD.bits() | uac) == uac
    {
        uac_flags.push("DontExpirePassword".to_string());
    }
    if (Flags::MNS_LOGON_ACCOUNT.bits() | uac) == uac
    {
        uac_flags.push("MnsLogonAccount".to_string());
    }
    if (Flags::SMART_CARD_REQUIRED.bits() | uac) == uac
    {
        uac_flags.push("SmartcardRequired".to_string());
    }
    if (Flags::TRUSTED_FOR_DELEGATION.bits() | uac) == uac
    {
        uac_flags.push("TrustedForDelegation".to_string());
    }
    if (Flags::NOT_DELEGATED.bits() | uac) == uac
    {
        uac_flags.push("NotDelegated".to_string());
    }
    if (Flags::USE_DES_KEY_ONLY.bits() | uac) == uac
    {
        uac_flags.push("UseDesKeyOnly".to_string());
    }
    if (Flags::DONT_REQ_PRE_AUTH.bits() | uac) == uac
    {
        uac_flags.push("DontReqPreauth".to_string());
    }
    if (Flags::PASSWORD_EXPIRED.bits() | uac) == uac
    {
        uac_flags.push("PasswordExpired".to_string());
    }
    if (Flags::TRUSTED_TO_AUTH_FOR_DELEGATION.bits() | uac) == uac
    {
        uac_flags.push("TrustedToAuthForDelegation".to_string());
    }
    if (Flags::PARTIAL_SECRETS_ACCOUNT.bits() | uac) == uac
    {
        uac_flags.push("PartialSecretsAccount".to_string());
    }
    return uac_flags
}