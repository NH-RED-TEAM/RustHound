use chrono::{NaiveDateTime, Local};
//use log::trace;

/// Change date timestamp format to epoch format.
pub fn convert_timestamp(timestamp: i64) -> i64
{
    let offset: i64 = 134774*24*60*60;
    let epoch: i64 = timestamp/10000000-offset;
    return epoch
}

pub fn string_to_epoch(date: &String) -> i64 {
    // yyyyMMddHHmmss.0z to epoch format
    let str_representation = date.split(".").next().unwrap();
    let date = NaiveDateTime::parse_from_str(&str_representation, "%Y%m%d%H%M%S").unwrap();
    //trace!("whencreated timestamp: {:?}", date.timestamp());
    return date.timestamp()
}

/// Function to return current hours.
pub fn return_current_time() -> String
{
    return Local::now().format("%T").to_string()
}

/// Function to return current date.
pub fn return_current_date() -> String
{
    return Local::now().format("%D").to_string()
}

/// Function to return current date.
pub fn return_current_fulldate() -> String
{
    return Local::now().format("%Y%m%d%H%M%S").to_string()
}