#[cfg(test)]
mod tests {
    use crate::ca_node_types::CaRevocationList;
    use runar_macros_common::VecVecBytes;
    use serde::{Deserialize, Serialize};
    use serde_cbor;

    #[derive(Serialize, Deserialize)]
    struct TestStruct {
        #[serde(with = "VecVecBytes")]
        pub revoked_serials: Vec<Vec<u8>>,
    }

    #[test]
    fn test_ca_revocation_list_with_vec_vec_bytes() {
        // Test that CaRevocationList now uses proper byte string encoding
        let crl = CaRevocationList {
            network_id: "test_network".to_string(),
            issuing_ca_serial_hex: "1234567890abcdef".to_string(),
            revoked_serials: vec![vec![0x01, 0x02, 0x03, 0x04], vec![0x05, 0x06, 0x07, 0x08]],
            generated_at: 1234567890,
            signature: vec![0x11, 0x22, 0x33, 0x44],
            signer_ski: vec![0x55, 0x66, 0x77, 0x88],
            sig_alg: "ecdsa-with-SHA256".to_string(),
        };

        let cbor = serde_cbor::to_vec(&crl).unwrap();
        println!("CaRevocationList CBOR: {:02x?}", cbor);

        // Verify that the revoked_serials field contains byte string markers
        // Look for 0x44 markers (byte string of length 4)
        let byte_string_markers: Vec<usize> = cbor
            .iter()
            .enumerate()
            .filter(|(_, &b)| b == 0x44) // 0x44 = byte string of length 4
            .map(|(i, _)| i)
            .collect();

        // Should have 5 byte string markers total:
        // - 2 for revoked_serials (Vec<Vec<u8>> with VecVecBytes)
        // - 1 for signature (Vec<u8> with serde_bytes)
        // - 1 for signer_ski (Vec<u8> with serde_bytes)
        // - 1 for some other field
        assert!(
            byte_string_markers.len() >= 2,
            "Should have at least 2 byte string markers for revoked serials"
        );

        // Verify that we have the expected byte string markers for revoked serials
        // The CBOR should contain: 44, 01, 02, 03, 04, 44, 05, 06, 07, 08
        let expected_data = [0x44, 0x01, 0x02, 0x03, 0x04, 0x44, 0x05, 0x06, 0x07, 0x08];
        let mut found_sequence = false;
        for i in 0..cbor.len().saturating_sub(expected_data.len()) {
            if cbor[i..i + expected_data.len()] == expected_data {
                found_sequence = true;
                break;
            }
        }
        assert!(
            found_sequence,
            "Should find the expected byte string sequence for revoked serials"
        );

        // Verify round-trip serialization
        let deserialized: CaRevocationList = serde_cbor::from_slice(&cbor).unwrap();
        assert_eq!(crl.revoked_serials, deserialized.revoked_serials);
    }

    #[test]
    fn test_comparison_old_vs_new_encoding() {
        let data = vec![vec![0x01, 0x02, 0x03], vec![0x04, 0x05, 0x06]];

        // OLD APPROACH: Direct Vec<Vec<u8>> serialization
        let old_cbor = serde_cbor::to_vec(&data).unwrap();
        println!("OLD approach (direct Vec<Vec<u8>>): {:02x?}", old_cbor);

        // NEW APPROACH: Using our VecVecBytes serializer
        let test_struct = TestStruct {
            revoked_serials: data.clone(),
        };
        let new_cbor = serde_cbor::to_vec(&test_struct).unwrap();
        println!("NEW approach (with VecVecBytes): {:02x?}", new_cbor);

        // Verify the new approach has byte string markers
        let new_byte_string_markers: Vec<usize> = new_cbor
            .iter()
            .enumerate()
            .filter(|(_, &b)| b == 0x43) // 0x43 = byte string of length 3
            .map(|(i, _)| i)
            .collect();

        // Verify the old approach does NOT have byte string markers
        let old_byte_string_markers: Vec<usize> = old_cbor
            .iter()
            .enumerate()
            .filter(|(_, &b)| b == 0x43)
            .map(|(i, _)| i)
            .collect();

        assert_eq!(
            new_byte_string_markers.len(),
            2,
            "New approach should have 2 byte string markers"
        );
        assert_eq!(
            old_byte_string_markers.len(),
            0,
            "Old approach should NOT have byte string markers"
        );

        // Verify round-trip works for both approaches
        let old_deserialized: Vec<Vec<u8>> = serde_cbor::from_slice(&old_cbor).unwrap();
        let new_deserialized: TestStruct = serde_cbor::from_slice(&new_cbor).unwrap();

        assert_eq!(data, old_deserialized);
        assert_eq!(data, new_deserialized.revoked_serials);
    }
}
