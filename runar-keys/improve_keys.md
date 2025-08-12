### Keys and Certificates Refactor Plan (final)

This document consolidates the final recommendations to align Rust and Swift key management with modern TLS/ECDSA best practices. It defines a single design to implement on both sides. No hacks, no shortcuts. If something is unclear, stop and ask.

### Principles

- Think from first principles. Understand specs and library semantics before coding.
- Strict key separation by purpose; no key reuse across signing and key-agreement.
- Standard, interoperable formats; deterministic derivation where appropriate.
- Tests drive changes; update existing tests and add new ones as needed.

### Final decisions (single design)

- Curve and algorithms
  - Use P-384 everywhere (ECDSA-SHA-384 for signatures; ECDH for key agreement).
  - Use HKDF-SHA-384 for all private-key derivations.

- Deterministic key hierarchy with HKDF
  - Each scope (user-root, node-identity, network, profile) has a master private key.
  - Derive child keys per purpose using HKDF with disjoint labels:
    - IKM: raw scalar bytes of the master private key (48 bytes for P-384).
    - Salt: "RunarKeyDerivationSalt/v1" (bytes).
    - Info: "runar-v1:{scope}:{purpose}:{label?}:{counter?}"
      - scope ∈ {user-root, node-identity, network, profile}
      - purpose ∈ {signing, agreement, storage}
      - label optional (e.g., profile name, network id)
      - counter optional for invalid scalar retries (rare)
    - Output: 48 bytes → create scalar; if invalid, increment counter and retry.
  - Child keys:
    - signing-key: ECDSA P-384 Signing/Verifying keypair
    - agreement-key: ECDH P-384 private/public keypair
    - storage-key: 32-byte symmetric key (HKDF output length = 32) when needed

- Strict key usage separation
  - TLS/CSRs/certificates/digital signatures → signing-key only.
  - ECIES (envelope key wrapping, E2E exchange) → agreement-key only.
  - Storage encryption → storage-key only.

- CSR issuance (strict)
  - Always require PKCS#10 CSR signed by the node's signing-key (PoP required).
  - Verify CSR signature; reject on failure.
  - Enforce subject policy:
    - CN = DNS-safe node-id (for continuity) but rely on SANs for identity.
    - SANs must include the operational identity (DNS names used via SNI and/or IPs). Prefer computing SANs server-side from node config; optionally validate CSR-requested SANs by policy.
  - Sign leaf cert with CA signing-key using ECDSA-SHA-384.

- TLS certificate profiles (ECDSA best-practice)
  - CA (root):
    - BasicConstraints CA, pathLen = 0
    - KeyUsage: keyCertSign, cRLSign
    - SubjectKeyIdentifier (SKI) and AuthorityKeyIdentifier (AKI)
  - Leaf (node):
    - BasicConstraints notCA
    - KeyUsage: digitalSignature only (no keyEncipherment for ECDSA)
    - ExtendedKeyUsage: serverAuth, clientAuth (adjust per role if needed)
    - Subject Alternative Name (SAN): required (DNS/IP)
    - SKI and AKI
  - Validity: CA ~10y; leaf 90–365d (shorter preferred operationally).

- ECIES wire format (standard)
  - Curve: P-384; ephemeral uncompressed SEC1 public key (97 bytes).
  - KDF: HKDF-SHA-384 over ECDH shared secret; info "runar-v1:ecies:envelope-key".
  - Symmetric: AES-256-GCM with 12-byte random nonce.
  - Payload layout: 97-byte ephemeral pubkey || AES-GCM combined (nonce||ciphertext||tag).

- IDs and serialization
  - Node/network/profile IDs: base64url(no padding) of the first 16 bytes of SHA-256(pubkey).
  - Private key transport encoding: PKCS#8 DER for signing keys when export is required. Agreement keys are not exported unless necessary; if exported, use the same PKCS#8 policy (or document raw-scalar if chosen consistently on both sides).

- Storage keys
  - Derive via HKDF-SHA-384 from the relevant master with purpose = storage and distinct labels. Do not reuse signing or agreement scalars for storage encryption.

### Rust implementation plan

- Dependencies and curve switch
  - Replace `p256` with `p384` (features: `ecdsa`, `ecdh`, `pkcs8`, `serde`).
  - Update hashing/signing to SHA-384 where applicable.

- HKDF derivation helpers
  - Add a derivation utility to produce signing, agreement, and storage keys from a master (with counter retry for invalid scalars).

- Key separation
  - In `runar-keys/src/node.rs` and `runar-keys/src/mobile.rs`:
    - Maintain master keys per scope.
    - Derive and cache child `signing-key` and `agreement-key` on demand.
    - Update ECIES to use the agreement-key only; update TLS/CSR/signature paths to use the signing-key only.

- Certificates and CSR
  - In `runar-keys/src/certificate.rs`:
    - Switch OpenSSL signing to `MessageDigest::sha384()` and ensure `secp384r1`.
    - CA template: BasicConstraints CA (pathLen=0), KeyUsage keyCertSign+cRLSign, SKI/AKI.
    - Leaf template: BasicConstraints notCA, KeyUsage digitalSignature only, EKU serverAuth+clientAuth, SANs (DNS/IP), SKI/AKI.
    - CSR: verify signature (PoP), enforce subject CN policy, read/validate CSR SANs or compute SANs deterministically.

- ECIES format
  - Move to P-384 ephemeral 97-byte pubkey and AES-GCM combined layout as specified.
  - Keep HKDF info label consistent: "runar-v1:ecies:envelope-key".

- Network key distribution
  - Standardize on PKCS#8 DER for exported private keys.
  - In `NodeKeyManager.install_network_key`: accept PKCS#8; optionally accept raw scalar during transition.

- IDs
  - Keep `runar-common` `compact_id` as-is (base64url first 16 bytes of SHA-256).

### Swift implementation plan

- Derivation and keys
  - Add HKDF-SHA-384 helper with counter retry.
  - Store master keys per scope; derive signing/agreement/storage per the scheme above.
  - Use signing-key for CSR/TLS; agreement-key for ECIES.

- Certificates and CSR
  - In `Sources/RunarKeys/Certificate.swift`: ensure CA pathLen=0; include SKI/AKI; compute SANs from node identity.
  - In `Sources/RunarKeys/MobileKeyManager.swift`: require PKCS#10 CSR, verify PoP, enforce CN and SANs, then sign with CA signing-key.

- ECIES and format
  - Confirm ephemeral 97-byte uncompressed SEC1, HKDF-SHA-384, AES-GCM combined layout, info label as above.

- IDs and serialization
  - Align `CryptoUtils.compactId` to the Rust scheme (base64url of first 16 bytes of SHA-256(pubkey)).
  - Use PKCS#8 for exported private keys consistently.

### Tests (both stacks)

- Derivation
  - Determinism: same master+labels → same child; different purposes/labels → different children.
  - Invalid-scalar retry path covered.

- CSR
  - Reject tampered CSR (signature invalid).
  - Reject CN mismatch; require SANs (or compute them and verify presence in leaf).

- Certificates
  - CA has required extensions; leaf has SANs and correct KeyUsage/EKU; signature alg is ECDSA-SHA-384.

- ECIES
  - Round-trip with 97-byte ephemeral key; verify payload layout; HKDF info label fixed.

- Interop
  - Swift-issued cert accepted by Rust; Rust-issued cert accepted by Swift (if implemented on both sides).
  - Envelope encryption/decryption works cross-language.

- IDs
  - Node/network/profile IDs identical across Rust and Swift for the same public key bytes.

### Migration notes

- This is a refactor to a new, stricter design. Remove legacy paths (public-key-only issuance; signing-key used for ECIES). Provide temporary fallbacks (e.g., accept raw scalar import) only if needed for data migration.

### Execution guidance

- Update code and tests in small, verifiable steps; keep builds green.
- Consult library docs (OpenSSL, p384, swift-certificates, CryptoKit) to avoid guesswork.
- When in doubt, implement the spec above rather than ad-hoc fixes.
