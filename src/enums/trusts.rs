use bitflags::bitflags;

bitflags! {
   struct Flags: u32 {
      // TRUST FLAG
      // From: https://msdn.microsoft.com/en-us/library/cc223779.aspx
      const NON_TRANSITIVE= 0x00000001;
      const UPLEVEL_ONLY= 0x00000002;
      const QUARANTINED_DOMAIN= 0x00000004;
      const FOREST_TRANSITIVE= 0x00000008;
      const CROSS_ORGANIZATION= 0x00000010;
      const WITHIN_FOREST= 0x00000020;
      const TREAT_AS_EXTERNAL= 0x00000040;
      const USES_RC4_ENCRYPTION= 0x00000080;
      const CROSS_ORGANIZATION_NO_TGT_DELEGATION= 0x00000200;
      const CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION= 0x00000800;
      const PIM_TRUST= 0x00000400;
   }
}

/// Get the trust flags from "trustDomain".
pub fn get_trust_flag(trustflag: u32, trust_json: &mut serde_json::value::Value)
{
   let mut is_transitive = false;
   let mut sid_filtering = false;

   if (Flags::WITHIN_FOREST.bits() | trustflag) == trustflag
   {
      let trust_type = "ParentChild"; //0 = ParentChild
      trust_json["TrustType"] = trust_type.into();
      is_transitive = true;
      if (Flags::QUARANTINED_DOMAIN.bits() | trustflag) == trustflag {
         sid_filtering = true;
      }
   }
   else if (Flags::FOREST_TRANSITIVE.bits() | trustflag) == trustflag
   {
      let trust_type = "Forest"; //2 = Forest
      trust_json["TrustType"] = trust_type.into();
      is_transitive = true;
      sid_filtering = true;
   }
   else if (Flags::TREAT_AS_EXTERNAL.bits() | trustflag) == trustflag || (Flags::CROSS_ORGANIZATION.bits() | trustflag) == trustflag
   {
      let trust_type = "External"; //3 = External
      trust_json["TrustType"] = trust_type.into();
      is_transitive = false;
      sid_filtering = true;
   }
   else
   {
      let trust_type = "Unknown"; //4 = Unknown
      trust_json["TrustType"] = trust_type.into();
      if (Flags::NON_TRANSITIVE.bits() | trustflag) != trustflag {
         is_transitive = true;
      }
      sid_filtering = true;
   }

   // change value in mut vec json
   trust_json["SidFilteringEnabled"] = sid_filtering.into();
   trust_json["IsTransitive"] = is_transitive.into();
}