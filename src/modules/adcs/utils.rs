use std::convert::TryInto;

/// Function to convert pKIExpirationPeriod Vec<u8> format to u64.
pub fn filetime_to_span(filetime: Vec<u8>) -> u64 {
    if filetime.len() > 0 {
        let mut span = i64::from_ne_bytes(filetime[0..8].try_into().unwrap()) as f64;
        span *= -0.0000001;
        return span as u64
    }
    return 0
}

/// Function to change span format to String output date.
/// Thanks to ly4k works: <https://github.com/ly4k/Certipy/blob/main/certipy/commands/find.py#L48>
pub fn span_to_string(span: u64) -> String {
    if (span % 31536000 == 0) && ((span / 31536000) >= 1) {
        if (span / 31536000) == 1 {
            return "1 year".to_string()
        } else {
            return format!("{} years",(span / 31536000))
        }
    } else if (span % 2592000 == 0) && ((span / 2592000) >= 1) {
        if (span / 2592000) == 1 {
            return "1 month".to_string()
        } else {
            return format!("{} months",(span / 2592000))
        }
    } else if (span % 604800 == 0) && ((span / 604800) >= 1) {
        if (span / 604800) == 1 {
            return "1 week".to_string()
        } else {
            return format!("{} weeks",(span / 604800))
        }
    } else if (span % 86400 == 0) && ((span / 86400) >= 1) {
        if (span / 86400) == 1 {
            return "1 day".to_string()
        } else {
            return format!("{} days",(span / 86400))
        }
    } else if (span % 3600 == 0) && ((span / 3600) >= 1) {
        if (span / 3600) == 1 {
            return "1 hour".to_string()
        } else {
            return format!("{} hours",(span / 3600))
        }
    } else {
        return "".to_string()
    }
}