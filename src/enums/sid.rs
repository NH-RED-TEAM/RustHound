use crate::enums::secdesc::LdapSid;
use log::{trace,error};

/// Function to make SID String from ldap_sid struct
pub fn sid_maker(sid: LdapSid, domain: &String) -> String {
    let mut sub: String = "".to_owned();
    trace!("sid_maker before: {:?}",&sid);
    for v in &sid.sub_authority {
        sub.push_str(&"-".to_owned());
        sub.push_str(&v.to_string());
    }

    let mut result: String = "S-".to_owned();
    result.push_str(&sid.revision.to_string());
    result.push_str(&"-");
    result.push_str(&sid.identifier_authority.value[5].to_string());
    result.push_str(&sub);

    let mut final_sid: String = "".to_owned();
    if result.len() <= 16 {
        final_sid.push_str(&domain.to_uppercase());
        final_sid.push_str(&"-".to_owned());
        final_sid.push_str(&result.to_owned());
    } else {
        final_sid = result;
    }
    trace!("sid_maker value: {}",final_sid);
    if final_sid.contains("S-0-0"){
        error!("SID contains null bytes!\n[INPUT: {:?}]\n[OUTPUT: {}]", &sid, final_sid);
    }
    return final_sid;
}

/// Change SID value to correct format.
pub fn objectsid_to_vec8(sid: &String) -> Vec<u8>
{
    // \u{1} to vec parsable 
    let mut vec_sid: Vec<u8> = Vec::new();
    for value in sid.as_bytes() {
        vec_sid.push(*value);
    }
    return vec_sid
}

/// Function to decode objectGUID binary to string value. 
/// src: <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/001eec5a-7f8b-4293-9e21-ca349392db40>
/// Thanks to: <https://github.com/picketlink/picketlink/blob/master/modules/common/src/main/java/org/picketlink/common/util/LDAPUtil.java>
pub fn decode_guid(raw_guid: &Vec<u8>) -> String
{
    // A byte-based String representation in the form of \[0]\[1]\[2]\[3]\[4]\[5]\[6]\[7]\[8]\[9]\[10]\[11]\[12]\[13]\[14]\[15]
    // A string representing the decoded value in the form of [3][2][1][0]-[5][4]-[7][6]-[8][9]-[10][11][12][13][14][15].
    let mut str_guid: String = "".to_owned();

    let mut part1 = vec![];
    part1.push(raw_guid[3] & 0xFF);
    part1.push(raw_guid[2] & 0xFF);
    part1.push(raw_guid[1] & 0xFF);
    part1.push(raw_guid[0] & 0xFF);
    str_guid.push_str(&hex_push(&part1));

    str_guid.push_str("-");

    let mut part2 = vec![];
    part2.push(raw_guid[5] & 0xFF);
    part2.push(raw_guid[4] & 0xFF);
    str_guid.push_str(&hex_push(&part2));

    str_guid.push_str("-");

    let mut part3 = vec![];
    part3.push(raw_guid[7] & 0xFF);
    part3.push(raw_guid[6] & 0xFF);
    str_guid.push_str(&hex_push(&part3));

    str_guid.push_str("-");

    let mut part4 = vec![];
    part4.push(raw_guid[8] & 0xFF);
    part4.push(raw_guid[9] & 0xFF);
    str_guid.push_str(&hex_push(&part4));

    str_guid.push_str("-");

    let mut part5 = vec![];
    part5.push(raw_guid[10] & 0xFF);
    part5.push(raw_guid[11] & 0xFF);
    part5.push(raw_guid[12] & 0xFF);
    part5.push(raw_guid[13] & 0xFF);
    part5.push(raw_guid[14] & 0xFF);
    part5.push(raw_guid[15] & 0xFF);
    str_guid.push_str(&hex_push(&part5));

    return str_guid  
}

/// Function to get a hexadecimal representation from bytes
/// Thanks to: <https://newbedev.com/how-do-i-convert-a-string-to-hex-in-rust>
pub fn hex_push(blob: &[u8]) -> String {
    let mut buf: String = "".to_owned();
    for ch in blob {
        fn hex_from_digit(num: u8) -> char {
            if num < 10 {
                (b'0' + num) as char
            } else {
                (b'A' + num - 10) as char
            }
        }
        buf.push(hex_from_digit(ch / 16));
        buf.push(hex_from_digit(ch % 16));
    }
    return buf;
}


/// Function to get uuid from bin to string format
pub fn bin_to_string(raw_guid: &Vec<u8>) -> String
{
    // before: e2 49 30 00 aa 00 85 a2 11 d0 0d e6 bf 96 7a ba
    //         0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15
    // after: bf 96 7a ba - 0d e6 - 11 d0 - a2 85 - 00 aa 00 30 49 e2
    //        12 13 14 15   10 11   8  9    7  6    5  4  3  2  1  0 

    let mut str_guid: String = "".to_owned();

    let mut part1 = vec![];
    part1.push(raw_guid[12] & 0xFF);
    part1.push(raw_guid[13] & 0xFF);
    part1.push(raw_guid[14] & 0xFF);
    part1.push(raw_guid[15] & 0xFF);
    str_guid.push_str(&hex_push(&part1));

    str_guid.push_str("-");

    let mut part2 = vec![];
    part2.push(raw_guid[10] & 0xFF);
    part2.push(raw_guid[11] & 0xFF);
    str_guid.push_str(&hex_push(&part2));

    str_guid.push_str("-");

    let mut part3 = vec![];
    part3.push(raw_guid[8] & 0xFF);
    part3.push(raw_guid[9] & 0xFF);
    str_guid.push_str(&hex_push(&part3));

    str_guid.push_str("-");

    let mut part4 = vec![];
    part4.push(raw_guid[7] & 0xFF);
    part4.push(raw_guid[6] & 0xFF);
    str_guid.push_str(&hex_push(&part4));

    str_guid.push_str("-");

    let mut part5 = vec![];
    part5.push(raw_guid[5] & 0xFF);
    part5.push(raw_guid[4] & 0xFF);
    part5.push(raw_guid[3] & 0xFF);
    part5.push(raw_guid[2] & 0xFF);
    part5.push(raw_guid[1] & 0xFF);
    part5.push(raw_guid[0] & 0xFF);
    str_guid.push_str(&hex_push(&part5));

    return str_guid  
}

/* Another way to decode objectSID binary to string value. 
// src: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f992ad60-0fe4-4b87-9fed-beb478836861
pub fn decode_sid(raw_sid: &Vec<u8>, domain: &String) -> String
{
    let mut str_sid: String = "".to_owned();
    if raw_sid.len() <= 16 {
        str_sid.push_str(&domain.to_uppercase());
        str_sid.push_str(&"-S-".to_owned());
    }
    else
    {
        str_sid.push_str(&"S-".to_owned());
    }
    
    // get byte(0) - revision level
    let revision = String::from(raw_sid[0].to_string());
    str_sid.push_str(&revision);

    //next byte byte(1) - count of sub-authorities
    let count_sub_auths = usize::from(raw_sid[1]) & 0xFF;
    
    //byte(2-7) - 48 bit authority ([Big-Endian])
    let mut authority = 0;
    //String rid = "";
    for i in 2..=7 
    {
        authority = (usize::from(raw_sid[i])) << (8 * (5 - (i - 2)));
    }
    str_sid.push_str(&"-".to_owned());
    str_sid.push_str(&authority.to_string());

    //iterate all the sub-auths and then countSubAuths x 32 bit sub authorities ([Little-Endian])
    let mut offset = 8;
    let size = 4; //4 bytes for each sub auth

    for _j in 0..count_sub_auths
    {
        let mut sub_authority = 0;
        for k in 0..size
        {
            sub_authority |= (usize::from(raw_sid[offset + k] & 0xFF)) << (8 * k);
        }
        // format it
        str_sid.push_str(&"-".to_owned());
        str_sid.push_str(&sub_authority.to_string());
        offset += size;
    }
    
    return str_sid   
}
*/
