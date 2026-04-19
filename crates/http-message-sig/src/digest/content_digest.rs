use sha2::{Digest, Sha256, Sha512};
use crate::encoding::base64_encode;

/// Calculate Content-Digest header value per RFC 9530
/// 
/// Format: {algorithm}=:{base64}:
/// Example: sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
pub fn calculate_content_digest(body: &[u8], algorithm: &str) -> String {
    let hash_bytes: Vec<u8> = match algorithm {
        "sha-256" => {
            let mut hasher = Sha256::new();
            hasher.update(body);
            hasher.finalize().to_vec()
        }
        "sha-512" => {
            let mut hasher = Sha512::new();
            hasher.update(body);
            hasher.finalize().to_vec()
        }
        _ => panic!("unsupported algorithm: {}", algorithm),
    };

    let base64_hash = base64_encode(&hash_bytes);
    format!("{}=:{}:", algorithm, base64_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_digest_sha256() {
        let body = b"{\"hello\": \"world\"}";
        let digest = calculate_content_digest(body, "sha-256");
        assert_eq!(
            digest,
            "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"
        );
    }

    #[test]
    fn test_content_digest_sha512() {
        let body = b"{\"hello\": \"world\"}";
        let digest = calculate_content_digest(body, "sha-512");
        assert_eq!(
            digest,
            "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"
        );
    }
}
