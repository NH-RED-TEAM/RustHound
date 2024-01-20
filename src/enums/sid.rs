use crate::enums::secdesc::LdapSid;
use log::{trace,error};
use regex::Regex;


/// Function to check if string is SID
pub fn is_sid(input: &String) -> bool {
    let regex = Regex::new(".*S-1-5.*").unwrap();
    regex.is_match(input)
}

/// Function to make SID String from ldap_sid struct
pub fn sid_maker(sid: LdapSid, domain: &String) -> String {
    trace!("sid_maker before: {:?}",&sid);

    let sub = sid.sub_authority.iter().map(|x| x.to_string()).collect::<Vec<String>>().join("-");

    let result = format!("S-{}-{}-{}", sid.revision, sid.identifier_authority.value[5], sub);

    let final_sid = {
        if result.len() <= 16 {
            format!("{}-{}", domain.to_uppercase(), result.to_owned())
        } else {
            result
        }
    };

    trace!("sid_maker value: {}",final_sid);
    if final_sid.contains("S-0-0"){
        error!("SID contains null bytes!\n[INPUT: {:?}]\n[OUTPUT: {}]", &sid, final_sid);
    }

    return final_sid;
}

/// Change SID value to correct format.
pub fn objectsid_to_vec8(sid: &String) -> Vec<u8>
{
    sid.as_bytes().iter().map(|x| *x).collect::<Vec<u8>>()
}

/// Function to decode objectGUID binary to string value. 
/// src: <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/001eec5a-7f8b-4293-9e21-ca349392db40>
/// Thanks to: <https://github.com/picketlink/picketlink/blob/master/modules/common/src/main/java/org/picketlink/common/util/LDAPUtil.java>
pub fn decode_guid(raw_guid: &Vec<u8>) -> String
{
    // A byte-based String representation in the form of \[0]\[1]\[2]\[3]\[4]\[5]\[6]\[7]\[8]\[9]\[10]\[11]\[12]\[13]\[14]\[15]
    // A string representing the decoded value in the form of [3][2][1][0]-[5][4]-[7][6]-[8][9]-[10][11][12][13][14][15].
    let raw_guid = raw_guid.iter().map(|x| x & 0xFF).collect::<Vec<u8>>();
    let rev = | x: &[u8] | -> Vec<u8> { x.iter().map(|i| *i).rev().collect::<Vec<u8>>()};

    // Note slice syntax means up to the second number, but not including, so [0..4] is [0, 1, 2, 3] for example.
    let str_guid = format!(
        "{}-{}-{}-{}-{}",
        &hex_push(&rev(&raw_guid[0..4])),
        &hex_push(&rev(&raw_guid[4..6])),
        &hex_push(&rev(&raw_guid[6..8])),
        &hex_push(&raw_guid[8..10]),
        &hex_push(&raw_guid[10..16]),
    );

    str_guid
}

/// Function to get a hexadecimal representation from bytes
/// Thanks to: <https://newbedev.com/how-do-i-convert-a-string-to-hex-in-rust>
pub fn hex_push(blob: &[u8]) -> String {
    // For each char in blob, get the capitalised hexadecimal representation (:X) and collect that into a String
    blob.iter().map(|x| format!("{:X}", x)).collect::<String>()
}


/// Function to get uuid from bin to string format
pub fn bin_to_string(raw_guid: &Vec<u8>) -> String
{
    // before: e2 49 30 00 aa 00 85 a2 11 d0 0d e6 bf 96 7a ba
    //         0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15
    // after: bf 96 7a ba - 0d e6 - 11 d0 - a2 85 - 00 aa 00 30 49 e2
    //        12 13 14 15   10 11   8  9    7  6    5  4  3  2  1  0 

    let raw_guid = raw_guid.iter().map(|x| x & 0xFF).collect::<Vec<u8>>();
    let rev = | x: &[u8] | -> Vec<u8> { x.iter().map(|i| *i).collect::<Vec<u8>>()};

    let str_guid = format!(
        "{}-{}-{}-{}-{}",
        &hex_push(&raw_guid[12..16]),
        &hex_push(&raw_guid[10..12]),
        &hex_push(&raw_guid[8..10]),
        &hex_push(&rev(&raw_guid[6..8])),
        &hex_push(&rev(&raw_guid[0..6]))
    );

    return str_guid  
}