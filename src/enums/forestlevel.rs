/// Get the forest level from "msDS-Behavior-Version" LDAP attribute.
pub fn get_forest_level(level: String) -> String
{
    match level.as_str() {
        "7" => "2016",
        "6" => "2012 R2",
        "5" => "2012",
        "4" => "2008 R2",
        "3" => "2008",
        "2" => "2003",
        "1" => "2003 Interim",
        "0" => "2000 Mixed/Native",
        _   => "Unknown",
    }.to_string()
}