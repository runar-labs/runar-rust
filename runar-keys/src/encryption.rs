use crate::{error::KeyError, types::NodeKey, Result};
use aes_gcm::aead::generic_array::typenum::U12;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm,
    Nonce, // Or Aes128Gcm, depending on desired key size
};
use ed25519_dalek::SECRET_KEY_LENGTH;
use hkdf::Hkdf;
use sha2::Sha256;

const SYMMETRIC_KEY_LENGTH: usize = 32; // For AES-256
                                        // const NONCE_LENGTH: usize = 12; // AES-GCM standard nonce size (96 bits) - Not directly used as generate_nonce provides it.

/// Derives a symmetric encryption key from a NodeKey's secret using HKDF-SHA256.
///
/// The `salt` is optional but recommended for HKDF. If not provided, a default or no salt is used.
/// The `info` context string helps in domain separation for derived keys.
pub fn derive_symmetric_key_from_node_key(
    node_key: &NodeKey,
    salt: Option<&[u8]>,
    info: &[u8],
) -> Result<[u8; SYMMETRIC_KEY_LENGTH]> {
    let ikm = &node_key.keypair.to_keypair_bytes()[..SECRET_KEY_LENGTH]; // Input Keying Material (IKM) from NodeKey's secret
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = [0u8; SYMMETRIC_KEY_LENGTH]; // Output Keying Material

    hk.expand(info, &mut okm)
        .map_err(|e| KeyError::CryptoError(format!("HKDF expansion failed: {}", e)))?;
    Ok(okm)
}

/// Encrypts data using AES-256-GCM with a derived symmetric key.
/// Returns a tuple of (ciphertext, nonce).
/// The nonce is generated randomly and must be stored alongside the ciphertext to enable decryption.
pub fn encrypt_data(
    symmetric_key: &[u8; SYMMETRIC_KEY_LENGTH],
    plaintext: &[u8],
    associated_data: Option<&[u8]>, // Optional Associated Data (AAD)
) -> Result<(Vec<u8>, Nonce<U12>)> {
    let cipher = Aes256Gcm::new_from_slice(symmetric_key).map_err(|e| {
        KeyError::CryptoError(format!("Failed to initialize AES-GCM cipher: {}", e))
    })?;

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // Generate a random nonce

    let final_ciphertext = if let Some(aad_data) = associated_data {
        cipher
            .encrypt(
                &nonce,
                aes_gcm::aead::Payload {
                    msg: plaintext,
                    aad: aad_data,
                },
            )
            .map_err(|e| KeyError::CryptoError(format!("Encryption with AAD failed: {}", e)))?
    } else {
        cipher
            .encrypt(&nonce, plaintext.as_ref())
            .map_err(|e| KeyError::CryptoError(format!("Encryption failed: {}", e)))?
    };

    Ok((final_ciphertext, nonce))
}

/// Decrypts data using AES-256-GCM with a derived symmetric key and the original nonce.
pub fn decrypt_data(
    symmetric_key: &[u8; SYMMETRIC_KEY_LENGTH],
    ciphertext: &[u8],
    nonce: &Nonce<U12>,
    associated_data: Option<&[u8]>, // Optional Associated Data (AAD), must match encryption AAD
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(symmetric_key).map_err(|e| {
        KeyError::CryptoError(format!("Failed to initialize AES-GCM cipher: {}", e))
    })?;

    let plaintext = if let Some(aad_data) = associated_data {
        cipher
            .decrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: ciphertext,
                    aad: aad_data,
                },
            )
            .map_err(|e| KeyError::CryptoError(format!("Decryption with AAD failed: {}", e)))?
    } else {
        cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| KeyError::CryptoError(format!("Decryption failed: {}", e)))?
    };

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hd::derive_node_key_from_master_key;
    use crate::types::UserMasterKey;

    fn get_test_node_key() -> NodeKey {
        let master_key = UserMasterKey::generate();
        derive_node_key_from_master_key(&master_key, 0).unwrap()
    }

    #[test]
    fn test_derive_symmetric_key() {
        let node_key = get_test_node_key();
        let salt_bytes = b"test_salt";
        let salt = Some(salt_bytes.as_slice());
        let info_bytes = b"test_encryption_context";
        let info = info_bytes.as_slice();

        let sym_key_result = derive_symmetric_key_from_node_key(&node_key, salt, info);
        assert!(sym_key_result.is_ok());
        let sym_key = sym_key_result.unwrap();
        assert_eq!(sym_key.len(), SYMMETRIC_KEY_LENGTH);

        let sym_key_again = derive_symmetric_key_from_node_key(&node_key, salt, info).unwrap();
        assert_eq!(sym_key, sym_key_again);

        let different_info_bytes = b"another_context";
        let different_info = different_info_bytes.as_slice();
        let sym_key_different =
            derive_symmetric_key_from_node_key(&node_key, salt, different_info).unwrap();
        assert_ne!(sym_key, sym_key_different);
    }

    #[test]
    fn test_encrypt_decrypt_data_no_aad() {
        let node_key = get_test_node_key();
        let info_bytes = b"encryption_key_for_data_no_aad";
        let info = info_bytes.as_slice();
        let symmetric_key = derive_symmetric_key_from_node_key(&node_key, None, info).unwrap();

        let plaintext = b"This is a secret message.";
        let (ciphertext, nonce) = encrypt_data(&symmetric_key, plaintext, None).unwrap();

        assert_ne!(plaintext.as_slice(), ciphertext.as_slice());

        let decrypted_plaintext = decrypt_data(&symmetric_key, &ciphertext, &nonce, None).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted_plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_data_with_aad() {
        let node_key = get_test_node_key();
        let info_bytes = b"encryption_key_for_data_with_aad";
        let info = info_bytes.as_slice();
        let symmetric_key = derive_symmetric_key_from_node_key(&node_key, None, info).unwrap();

        let plaintext = b"This is another secret message.";
        let aad_bytes = b"this_is_associated_data";
        let aad = Some(aad_bytes.as_slice());
        let (ciphertext, nonce) = encrypt_data(&symmetric_key, plaintext, aad).unwrap();

        assert_ne!(plaintext.as_slice(), ciphertext.as_slice());

        let decrypted_plaintext = decrypt_data(&symmetric_key, &ciphertext, &nonce, aad).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted_plaintext);

        let tampered_aad_bytes = b"tampered_associated_data";
        let tampered_aad = Some(tampered_aad_bytes.as_slice());
        let decrypt_result_tampered_aad =
            decrypt_data(&symmetric_key, &ciphertext, &nonce, tampered_aad);
        assert!(decrypt_result_tampered_aad.is_err());

        let decrypt_result_missing_aad = decrypt_data(&symmetric_key, &ciphertext, &nonce, None);
        assert!(decrypt_result_missing_aad.is_err());
    }

    #[test]
    fn test_decrypt_tampered_ciphertext() {
        let node_key = get_test_node_key();
        let info_bytes = b"encryption_key_for_tampering_test";
        let info = info_bytes.as_slice();
        let symmetric_key = derive_symmetric_key_from_node_key(&node_key, None, info).unwrap();

        let plaintext = b"Original message.";
        let (mut ciphertext, nonce) = encrypt_data(&symmetric_key, plaintext, None).unwrap();

        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0x01;
        }

        let decrypt_result = decrypt_data(&symmetric_key, &ciphertext, &nonce, None);
        assert!(
            decrypt_result.is_err(),
            "Decryption of tampered ciphertext should fail"
        );
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let node_key1 = get_test_node_key();
        let info_bytes = b"encryption_key_for_wrong_key_test";
        let info = info_bytes.as_slice();
        let symmetric_key1 = derive_symmetric_key_from_node_key(&node_key1, None, info).unwrap();

        // Generate a second, different key for testing
        let symmetric_key2 = loop {
            let nk2 = get_test_node_key();
            let sk2 = derive_symmetric_key_from_node_key(&nk2, None, info).unwrap();
            if sk2 != symmetric_key1 {
                break sk2;
            }
        };

        let plaintext = b"Secret data.";
        let (ciphertext, nonce) = encrypt_data(&symmetric_key1, plaintext, None).unwrap();

        let decrypt_result = decrypt_data(&symmetric_key2, &ciphertext, &nonce, None);
        assert!(
            decrypt_result.is_err(),
            "Decryption with wrong key should fail"
        );
    }
}
