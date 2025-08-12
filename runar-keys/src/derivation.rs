use crate::error::KeyError;
use hkdf::Hkdf;
use p384::SecretKey as P384SecretKey;
use sha2::Sha384;

/// Derive a P-384 agreement private key from a master scalar using HKDF-SHA-384.
/// - ikm: raw 48-byte scalar of the master key
/// - label: info label base, counter will be appended if retries are needed
pub fn derive_agreement_from_master(ikm: &[u8], label: &[u8]) -> Result<P384SecretKey, KeyError> {
    let hk = Hkdf::<Sha384>::new(Some(b"RunarKeyDerivationSalt/v1"), ikm);
    let mut counter: u32 = 0;
    loop {
        let mut info = label.to_vec();
        if counter != 0 {
            info.extend_from_slice(b":");
            info.extend_from_slice(counter.to_string().as_bytes());
        }
        let mut candidate = [0u8; 48];
        hk.expand(&info, &mut candidate).map_err(|e| {
            KeyError::KeyDerivationError(format!("HKDF expansion failed: {e}"))
        })?;
        match P384SecretKey::from_slice(&candidate) {
            Ok(sk) => return Ok(sk),
            Err(_) => {
                counter = counter.saturating_add(1);
                continue;
            }
        }
    }
}


