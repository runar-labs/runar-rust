// Test to show what the runar_serializer_macros::Encrypt macro expands to
// This demonstrates the generated code for the TestProfile struct

use runar_serializer_macros::Encrypt;

// Original struct with annotations
#[derive(Clone, PartialEq, Debug, Encrypt)]
struct TestProfile {
    pub id: String,
    #[runar(system)]
    pub name: String,
    #[runar(user)]
    pub private: String,
    #[runar(search)]
    pub email: String,
    #[runar(system_only)]
    pub system_metadata: String,
}

// The macro expands to approximately this code:
/*
//1Internal substructs for each label group
#[derive(Clone)]
struct TestProfileSystemFields {
    pub name: String,
}

#[derive(Clone)]
struct TestProfileUserFields {
    pub private: String,
}

#[derive(Clone)]
struct TestProfileSearchFields {
    pub email: String,
}

#[derive(Clone)]
struct TestProfileSystemOnlyFields {
    pub system_metadata: String,
}

// 2. Proto substructs for serialization
#[derive(serde::Serialize, serde::Deserialize, Clone, prost::Message)]
pub struct TestProfileSystemFieldsProto {
    #[prost(string, tag = 1  pub name: String,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, prost::Message)]
pub struct TestProfileUserFieldsProto {
    #[prost(string, tag = "1")]
    pub private: String,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, prost::Message)]
pub struct TestProfileSearchFieldsProto {
    #[prost(string, tag = "1)] pub email: String,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, prost::Message)]
pub struct TestProfileSystemOnlyFieldsProto {
    #[prost(string, tag = "1)]
    pub system_metadata: String,
}

//3n encrypted struct
#[derive(serde::Serialize, serde::Deserialize, Clone, prost::Message)]
pub struct EncryptedTestProfile {
    // Plaintext fields (no encryption)
    #[prost(string, tag =1    pub id: String,
    
    // Encrypted label groups
    #[prost(message, optional, tag = "2)]
    pub system_encrypted: ::core::option::Option<runar_serializer::encryption::EncryptedLabelGroup>,
    
    #[prost(message, optional, tag = 3]
    pub user_encrypted: ::core::option::Option<runar_serializer::encryption::EncryptedLabelGroup>,
    
    #[prost(message, optional, tag = "4)]
    pub search_encrypted: ::core::option::Option<runar_serializer::encryption::EncryptedLabelGroup>,
    
    #[prost(message, optional, tag = "5)]   pub system_only_encrypted: ::core::option::Option<runar_serializer::encryption::EncryptedLabelGroup>,
}

//4Implementation for TestProfile
impl TestProfile {
    fn encrypt_with_keystore(
        &self,
        keystore: &std::sync::Arc<runar_serializer::KeyStore>,
        resolver: &dyn runar_serializer::LabelResolver,
    ) -> anyhow::Result<EncryptedTestProfile> {
        let encrypted = EncryptedTestProfile {
            // Copy plaintext fields
            id: self.id.clone(),
            
            // Encrypt each label group
            system_encrypted: if resolver.can_resolve("system")[object Object]               let group_struct = TestProfileSystemFieldsProto {
                    name: self.name.clone(),
                };
                Some(runar_serializer::encryption::encrypt_label_group(
            system                   &group_struct,
                    keystore.as_ref(),
                    resolver,
                )?)
            } else[object Object]              None
            },
            
            user_encrypted: if resolver.can_resolve("user")[object Object]               let group_struct = TestProfileUserFieldsProto {
                    private: self.private.clone(),
                };
                Some(runar_serializer::encryption::encrypt_label_group(
          user                   &group_struct,
                    keystore.as_ref(),
                    resolver,
                )?)
            } else[object Object]              None
            },
            
            search_encrypted: if resolver.can_resolve("search")[object Object]               let group_struct = TestProfileSearchFieldsProto {
                    email: self.email.clone(),
                };
                Some(runar_serializer::encryption::encrypt_label_group(
            search                   &group_struct,
                    keystore.as_ref(),
                    resolver,
                )?)
            } else[object Object]              None
            },
            
            system_only_encrypted: if resolver.can_resolve("system_only")[object Object]               let group_struct = TestProfileSystemOnlyFieldsProto {
                    system_metadata: self.system_metadata.clone(),
                };
                Some(runar_serializer::encryption::encrypt_label_group(
                 system_only                   &group_struct,
                    keystore.as_ref(),
                    resolver,
                )?)
            } else[object Object]              None
            },
        };
        Ok(encrypted)
    }
}

//5Implementation for EncryptedTestProfile
impl EncryptedTestProfile {
    fn decrypt_with_keystore(
        &self,
        keystore: &std::sync::Arc<runar_serializer::KeyStore>,
    ) -> anyhow::Result<TestProfile>[object Object]       
        let mut decrypted = TestProfile {
            // Copy plaintext fields
            id: self.id.clone(),
            
            // Initialize encrypted fields with defaults
            name: Default::default(),
            private: Default::default(),
            email: Default::default(),
            system_metadata: Default::default(),
        };
        
        // Decrypt each label group if available
        if let Some(ref group) = self.system_encrypted {
            if let Ok(tmp) = runar_serializer::encryption::decrypt_label_group::<TestProfileSystemFieldsProto>(
                group,
                keystore.as_ref(),
            )[object Object]               
            decrypted.name = tmp.name;
            }
        }
        
        if let Some(ref group) = self.user_encrypted {
            if let Ok(tmp) = runar_serializer::encryption::decrypt_label_group::<TestProfileUserFieldsProto>(
                group,
                keystore.as_ref(),
            )[object Object]               decrypted.private = tmp.private;
            }
        }
        
        if let Some(ref group) = self.search_encrypted {
            if let Ok(tmp) = runar_serializer::encryption::decrypt_label_group::<TestProfileSearchFieldsProto>(
                group,
                keystore.as_ref(),
            )[object Object]               decrypted.email = tmp.email;
            }
        }
        
        if let Some(ref group) = self.system_only_encrypted {
            if let Ok(tmp) = runar_serializer::encryption::decrypt_label_group::<TestProfileSystemOnlyFieldsProto>(
                group,
                keystore.as_ref(),
            )[object Object]               decrypted.system_metadata = tmp.system_metadata;
            }
        }
        
        Ok(decrypted)
    }
}

// 6tes implementation for TestProfile
impl runar_serializer::CustomFromBytes for TestProfile {
    fn from_plain_bytes(
        bytes: &[u8],
        keystore: Option<&std::sync::Arc<runar_serializer::KeyStore>>,
    ) -> anyhow::Result<Self> {
        Self::from_encrypted_bytes(bytes, keystore)
    }
    
    fn from_encrypted_bytes(
        bytes: &[u8],
        keystore: Option<&std::sync::Arc<runar_serializer::KeyStore>>,
    ) -> anyhow::Result<Self> [object Object]       let ks = keystore.ok_or(anyhow::anyhow!(KeyStore required for decryption"))?;
        let encrypted = EncryptedTestProfile::decode(bytes)?;
        encrypted.decrypt_with_keystore(ks)
    }
    
    fn to_binary(
        &self,
        keystore: Option<&std::sync::Arc<runar_serializer::KeyStore>>,
        resolver: Option<&dyn runar_serializer::LabelResolver>,
        _network_id: &String,
    ) -> anyhow::Result<Vec<u8>> [object Object]       let ks = keystore.ok_or(anyhow::anyhow!(KeyStore required for encryption"))?;
        let res = resolver.ok_or(anyhow::anyhow!("LabelResolver required for encryption"))?;
        let encrypted = self.encrypt_with_keystore(ks, res)?;
        let mut buf = Vec::new();
        encrypted.encode(&mut buf)?;
        Ok(buf)
    }
}

// 7tes implementation for EncryptedTestProfile
impl runar_serializer::CustomFromBytes for EncryptedTestProfile {
    fn from_plain_bytes(
        bytes: &[u8
        _keystore: Option<&std::sync::Arc<runar_serializer::KeyStore>>,
    ) -> anyhow::Result<Self> {
        Self::decode(bytes).map_err(anyhow::Error::from)
    }
    
    fn from_encrypted_bytes(
        bytes: &[u8
        _keystore: Option<&std::sync::Arc<runar_serializer::KeyStore>>,
    ) -> anyhow::Result<Self> {
        // The encrypted representation is already the serialized form; treat the same as plain.
        Self::from_plain_bytes(bytes, None)
    }
    
    fn to_binary(
        &self,
        _keystore: Option<&std::sync::Arc<runar_serializer::KeyStore>>,
        _resolver: Option<&dyn runar_serializer::LabelResolver>,
        _network_id: &String,
    ) -> anyhow::Result<Vec<u8>>[object Object]       let mut buf = Vec::new();
        self.encode(&mut buf)?;
        Ok(buf)
    }
}
*/

#[test]
fn test_macro_expansion_compiles() [object Object] // This test just verifies that the macro expansion compiles correctly
    let profile = TestProfile {
        id: "test_id".to_string(),
        name: "Test User".to_string(),
        private: "secret_data".to_string(),
        email:test@example.com".to_string(),
        system_metadata: "system_info.to_string(),
    };
    
    // Verify the struct was created correctly
    assert_eq!(profile.id, "test_id");
    assert_eq!(profile.name,TestUser");
    assert_eq!(profile.private, "secret_data");
    assert_eq!(profile.email,test@example.com");
    assert_eq!(profile.system_metadata, "system_info");
    
    // The macro should have generated EncryptedTestProfile type
    // We can't directly test it here, but the fact that this compiles
    // means the macro expansion worked correctly
}

#[test]
fn test_encrypted_struct_exists() [object Object]  // This test verifies that the EncryptedTestProfile type was generated
    // by trying to create an instance of it
    let encrypted = EncryptedTestProfile {
        id: "test_id".to_string(),
        system_encrypted: None,
        user_encrypted: None,
        search_encrypted: None,
        system_only_encrypted: None,
    };
    
    assert_eq!(encrypted.id, "test_id");
    assert!(encrypted.system_encrypted.is_none());
    assert!(encrypted.user_encrypted.is_none());
    assert!(encrypted.search_encrypted.is_none());
    assert!(encrypted.system_only_encrypted.is_none());
} 