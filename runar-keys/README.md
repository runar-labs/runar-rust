Runar Keys
==========

Standards-compliant key and certificate management for the Runar network.

Highlights
----------

- X.509 certificates with proper CA hierarchy (user/mobile CA → node certs)
- Single cryptographic suite: ECDSA P-256 for signing; AES-GCM for symmetric
- CSR-based issuance and full signature/validity verification
- Envelope encryption helpers for network and profile keys

Install
-------

```toml
[dependencies]
runar-keys = "0.1"
```

Quick start
-----------

```rust
use runar_common::logging::{Component, Logger};
use runar_keys::{MobileKeyManager, CertificateRequest};
use std::sync::Arc;

let logger = Arc::new(Logger::new_root(Component::Node, "node-123"));
let mut mobile = MobileKeyManager::new(logger)?;

// Initialize mobile user identity and derive agreement pubkey
let _user_agreement_pub = mobile.initialize_user_identity()?;

// Node side: generate key pair and CSR subject
let subject = "CN=node-123,O=Runar,C=US";
let node_key = runar_keys::certificate::EcdsaKeyPair::new()?;
let csr_der = CertificateRequest::create(&node_key, subject)?;

// Simulated setup token
let setup = runar_keys::mobile::SetupToken {
    node_public_key: node_key.public_key_bytes(),
    node_agreement_public_key: node_key.public_key_bytes(),
    csr_der,
    node_id: "node-123".into(),
};

// Mobile issues the certificate
let msg = mobile.process_setup_token(&setup)?;
mobile.validate_certificate(&msg.node_certificate)?;
```

Envelope encryption
-------------------

```rust
// Generate a network data key and encrypt data for the network and profile
let network_id = mobile.generate_network_data_key()?;
let profile_pub = mobile.derive_user_profile_key("default")?;

let env = mobile.encrypt_with_envelope(b"secret", Some(&network_id), vec![profile_pub])?;
let pt = mobile.decrypt_with_network(&env)?;
assert_eq!(pt, b"secret");
```

MSRV
----

Minimum supported Rust version: 1.70.0

License
-------

MIT license. See `LICENSE`.


