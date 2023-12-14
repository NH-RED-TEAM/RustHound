use sha1::{Sha1, Digest};

/// Easy function to get SHA1 hash
pub fn calculate_sha1(data: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(data);
    format!("{:X}", hasher.finalize())
}