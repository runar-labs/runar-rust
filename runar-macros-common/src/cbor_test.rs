#[cfg(test)]
mod tests {
    use crate::VecVecBytes;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    struct TestStruct {
        #[serde(with = "VecVecBytes")]
        pub profile_public_keys: Vec<Vec<u8>>,
    }

    #[test]
    fn test_vec_vec_u8_byte_string_encoding() {
        // Test Vec<Vec<u8>> with our custom serializer
        let test_data = TestStruct {
            profile_public_keys: vec![
                vec![0x01, 0x02, 0x03], // First public key
                vec![0x04, 0x05, 0x06], // Second public key
            ],
        };

        let cbor = serde_cbor::to_vec(&test_data).unwrap();

        println!("Vec<Vec<u8>> with VecVecBytes CBOR data: {cbor:?}");
        println!("Vec<Vec<u8>> with VecVecBytes CBOR hex: {cbor:02x?}");

        // Expected: Each Vec<u8> should be encoded as a byte string
        // Structure: { "profile_public_keys": [byte_string1, byte_string2] }
        // Where each byte_string is: 0x43 0x01 0x02 0x03 (for 3-byte data)

        // Find the byte string markers (0x43 for length 3)
        let byte_string_markers: Vec<usize> = cbor
            .iter()
            .enumerate()
            .filter(|(_, &b)| b == 0x43)
            .map(|(i, _)| i)
            .collect();

        assert_eq!(
            byte_string_markers.len(),
            2,
            "Should have 2 byte string markers"
        );

        // Check first byte string: 0x43 0x01 0x02 0x03
        let first_marker = byte_string_markers[0];
        assert_eq!(cbor[first_marker + 1], 0x01, "First byte string first byte");
        assert_eq!(
            cbor[first_marker + 2],
            0x02,
            "First byte string second byte"
        );
        assert_eq!(cbor[first_marker + 3], 0x03, "First byte string third byte");

        // Check second byte string: 0x43 0x04 0x05 0x06
        let second_marker = byte_string_markers[1];
        assert_eq!(
            cbor[second_marker + 1],
            0x04,
            "Second byte string first byte"
        );
        assert_eq!(
            cbor[second_marker + 2],
            0x05,
            "Second byte string second byte"
        );
        assert_eq!(
            cbor[second_marker + 3],
            0x06,
            "Second byte string third byte"
        );
    }

    #[test]
    fn test_round_trip_serialization() {
        // Test that we can serialize and deserialize back to the same data
        let original = TestStruct {
            profile_public_keys: vec![vec![0x11, 0x22, 0x33, 0x44], vec![0x55, 0x66, 0x77, 0x88]],
        };

        let cbor = serde_cbor::to_vec(&original).unwrap();
        let deserialized: TestStruct = serde_cbor::from_slice(&cbor).unwrap();

        assert_eq!(
            original.profile_public_keys,
            deserialized.profile_public_keys
        );
    }

    #[test]
    fn test_comparison_with_old_approach() {
        // Compare our new approach with the old approach
        let data = vec![vec![0x01, 0x02, 0x03], vec![0x04, 0x05, 0x06]];

        // OLD APPROACH: Direct Vec<Vec<u8>> serialization
        let old_cbor = serde_cbor::to_vec(&data).unwrap();
        println!("OLD approach CBOR: {old_cbor:02x?}");
        // Expected: [0x82, 0x83, 0x01, 0x02, 0x03, 0x83, 0x04, 0x05, 0x06]
        // Size: 9 bytes

        // NEW APPROACH: Using our VecVecBytes serializer
        let test_struct = TestStruct {
            profile_public_keys: data.clone(),
        };
        let new_cbor = serde_cbor::to_vec(&test_struct).unwrap();
        println!("NEW approach CBOR: {new_cbor:02x?}");
        // Expected: Contains byte string markers (0x43 for length 3)
        // Size: Larger due to struct wrapper, but each Vec<u8> is a proper byte string

        // Verify the new approach has byte string markers
        let byte_string_markers: Vec<usize> = new_cbor
            .iter()
            .enumerate()
            .filter(|(_, &b)| b == 0x43) // 0x43 = byte string of length 3
            .map(|(i, _)| i)
            .collect();

        assert_eq!(
            byte_string_markers.len(),
            2,
            "Should have 2 byte string markers in new approach"
        );

        // Verify the old approach does NOT have byte string markers
        let old_byte_string_markers: Vec<usize> = old_cbor
            .iter()
            .enumerate()
            .filter(|(_, &b)| b == 0x43)
            .map(|(i, _)| i)
            .collect();

        assert_eq!(
            old_byte_string_markers.len(),
            0,
            "Old approach should NOT have byte string markers"
        );
    }
}
