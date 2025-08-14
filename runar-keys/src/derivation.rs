use crate::error::KeyError;
use hkdf::Hkdf;
use p256::SecretKey as P256SecretKey;
use sha2::Sha256;

/// Derive a P-256 agreement private key from a master scalar using HKDF-SHA-256.
/// - ikm: raw 32-byte scalar of the master key
/// - label: info label base, counter will be appended if retries are needed
pub fn derive_agreement_from_master(ikm: &[u8], label: &[u8]) -> Result<P256SecretKey, KeyError> {
    let hk = Hkdf::<Sha256>::new(Some(b"RunarKeyDerivationSalt/v1"), ikm);
    let mut counter: u32 = 0;
    loop {
        let mut info = label.to_vec();
        if counter != 0 {
            info.extend_from_slice(b":");
            info.extend_from_slice(counter.to_string().as_bytes());
        }
        let mut candidate = [0u8; 32];
        hk.expand(&info, &mut candidate)
            .map_err(|e| KeyError::KeyDerivationError(format!("HKDF expansion failed: {e}")))?;
        match P256SecretKey::from_slice(&candidate) {
            Ok(sk) => return Ok(sk),
            Err(_) => {
                counter = counter.saturating_add(1);
                continue;
            }
        }
    }
}
