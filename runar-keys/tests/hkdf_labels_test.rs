use hkdf::Hkdf;
use p256::SecretKey as P256SecretKey;
use runar_keys::derivation::derive_agreement_from_master;
use sha2::Sha256;

fn derive_manual_with_retry(ikm: &[u8], base_label: &str) -> P256SecretKey {
    let hk = Hkdf::<Sha256>::new(Some(b"RunarKeyDerivationSalt/v1"), ikm);
    let mut counter: u32 = 0;
    loop {
        let info = if counter == 0 {
            base_label.as_bytes().to_vec()
        } else {
            let mut v = base_label.as_bytes().to_vec();
            v.extend_from_slice(b":");
            v.extend_from_slice(counter.to_string().as_bytes());
            v
        };
        let mut candidate = [0u8; 32];
        hk.expand(&info, &mut candidate).expect("hkdf expand");
        if let Ok(sk) = P256SecretKey::from_slice(&candidate) {
            return sk;
        }
        counter = counter.saturating_add(1);
    }
}

#[test]
fn test_profile_agreement_label_alignment() {
    // Fixed IKM for deterministic result
    let ikm = [0x11u8; 32];
    let base_label = "runar-v1:profile:agreement:personal";

    let expected = derive_manual_with_retry(&ikm, base_label);
    let actual = derive_agreement_from_master(&ikm, base_label.as_bytes())
        .expect("derive_agreement_from_master failed");

    assert_eq!(expected.to_bytes().as_slice(), actual.to_bytes().as_slice());
}

#[test]
fn test_network_agreement_label_alignment() {
    let ikm = [0x22u8; 32];
    let base_label = "runar-v1:network:agreement:home";

    let expected = derive_manual_with_retry(&ikm, base_label);
    let actual = derive_agreement_from_master(&ikm, base_label.as_bytes())
        .expect("derive_agreement_from_master failed");

    assert_eq!(expected.to_bytes().as_slice(), actual.to_bytes().as_slice());
}

#[test]
fn test_node_identity_agreement_label_alignment() {
    let ikm = [0x33u8; 32];
    let base_label = "runar-v1:node-identity:agreement";

    let expected = derive_manual_with_retry(&ikm, base_label);
    let actual = derive_agreement_from_master(&ikm, base_label.as_bytes())
        .expect("derive_agreement_from_master failed");

    assert_eq!(expected.to_bytes().as_slice(), actual.to_bytes().as_slice());
}
