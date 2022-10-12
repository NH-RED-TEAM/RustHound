/// Get the forest level from "msDS-Behavior-Version" LDAP attribut.
pub fn get_forest_level(level: String) -> String
{
    match level.as_str() {
        "7" => { return "2016".to_string(); },
        "6" => { return "2012 R2".to_string(); },
        "5" => { return "2012".to_string(); },
        "4" => { return "2008 R2".to_string(); },
        "3" => { return "2008".to_string(); },
        "2" => { return "2003".to_string(); },
        "1" => { return "2003 Interim".to_string(); },
        "0" => { return "2000 Mixed/Native".to_string(); },
        _ => { return "Unknown".to_string(); },
    }
}