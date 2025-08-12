
### Gap analysis: Rust runar-keys vs Swift swift-keys

- Curve and key sizes
  - Rust: P-256 everywhere; uncompressed pubkeys = 65 bytes; ECDSA-SHA256.
  - Swift: P-384 everywhere; uncompressed pubkeys = 97 bytes; ECDSA-SHA384.
  - Impact: Incompatible ECIES payloads (ephemeral pubkey length), signatures, and certificate algorithms across platforms.

- CSR and issuance flow
  - Rust: Full PKCS#10 CSR, verifies CSR signature and CN matches DNS-safe node id, signs with CA via OpenSSL.
    ```startLine:341:endLine:363:/Users/rafael/dev/runar-rust/runar-keys/src/certificate.rs
// ... existing code ...
// ----- New security check: verify CSR signature -----
// Ensures the included public key actually matches the private key
// that signed the CSR, protecting against tampering in transit.
if !req.verify(&req_public_key)? {
    return Err(KeyError::CertificateError(
        "CSR signature verification failed".to_string(),
    ));
}
// ... existing code ...
```
  - Swift: Has CSR support, but current issuance bypasses CSR and signs directly from public key (tests note CSR complexity).
    ```startLine:245:endLine:253:/Users/rafael/dev/runar-swift/swift-keys/Sources/RunarKeys/MobileKeyManager.swift
// Use the public key directly for certificate creation (no CSR needed)
let validityDays: UInt32 = 365 // 1-year validity
let subject = "CN=\(nodeId),O=Runar,C=US"

let nodeCertificate = try certificateAuthority.createCertificateFromPublicKey(
    publicKeyData: setupToken.nodePublicKey,
    subject: subject,
    validityDays: Int(validityDays)
)
```
  - Impact: Missing CSR verification and CN checks on Swift path; weaker issuance guarantees vs Rust.

- Certificate extensions and content
  - Rust (leaf): KeyUsage includes digitalSignature + keyEncipherment; EKU serverAuth, clientAuth; no SAN, no SKI/AKI.
    ```startLine:389:endLine:414:/Users/rafael/dev/runar-rust/runar-keys/src/certificate.rs
// ... existing code ...
.append_extension(
    KeyUsage::new()
        .digital_signature()
        .key_encipherment()
        .build()?
)?
.append_extension(
    ExtendedKeyUsage::new()
        .server_auth()
        .client_auth()
        .build()?
)?
```
  - Swift (leaf): KeyUsage digitalSignature only (ECDSA), EKU serverAuth+clientAuth, SANs present, AKI/SKI present and criticality set.
    ```startLine:458:endLine:468:/Users/rafael/dev/runar-swift/swift-keys/Sources/RunarKeys/Certificate.swift
return try Certificate.Extensions {
    Critical(BasicConstraints.notCertificateAuthority)
    // For ECDSA TLS server/client certs, digitalSignature is sufficient. Avoid keyEncipherment for ECDSA.
    Critical(KeyUsage(digitalSignature: true))
    Critical(try ExtendedKeyUsage([.serverAuth, .clientAuth]))
    AuthorityKeyIdentifier(...)
    SubjectKeyIdentifier(...)
    SubjectAlternativeNames([.dnsName("localhost"), .dnsName("runar.test")])
}
```
  - Impact: Swift is closer to TLS best-practice for ECDSA; Rust includes RSA-centric keyEncipherment and lacks SAN/SKI/AKI.

- Compact ID function (node IDs)
  - Rust: SHA-256(public_key) first 16 bytes, base64url no pad; fixed-length (~22 chars).
    ```startLine:20:endLine:30:/Users/rafael/dev/runar-rust/runar-common/src/lib.rs
pub fn compact_id(public_key: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(public_key);
    let hash_result = hasher.finalize();
    let compact_hash = &hash_result[..16];
    URL_SAFE_NO_PAD.encode(compact_hash)
}
```
  - Swift: SHA-256(public_key) first 8 bytes, custom base58; variable-length.
    ```startLine:11:endLine:18:/Users/rafael/dev/runar-swift/swift-keys/Sources/RunarKeys/CryptoUtils.swift
public static func compactId(_ publicKey: Data) -> String {
    let hash = SHA256.hash(data: publicKey)
    let prefix = Data(hash.prefix(8))
    return base58Encode(prefix)
}
```
  - Impact: Cross-platform IDs diverge; Rust tests expect length 22. Interop breaks for discovery, routing, logs.

- ECIES/envelope encryption
  - Both: HKDF-SHA256 with “runar-key-encryption”, AES-256-GCM, prepend nonce/combined OK. Ephemeral pubkey is curve-dependent (65 vs 97).
    ```startLine:291:endLine:318:/Users/rafael/dev/runar-rust/runar-keys/src/node.rs
// ... existing code ...
let ephemeral_public_bytes = ephemeral_public.to_encoded_point(false);
let mut result = ephemeral_public_bytes.as_bytes().to_vec();
result.extend_from_slice(&encrypted_data);
// ... existing code ...
```
    ```startLine:205:endLine:216:/Users/rafael/dev/runar-swift/swift-keys/Sources/RunarKeys/CryptographicTypes.swift
// Extract ephemeral public key (97 bytes uncompressed for P-384)
let ephemeralPublicBytes = encryptedData.prefix(97)
// ...
let ephemeralPublicKey = try P384.KeyAgreement.PublicKey(x963Representation: ephemeralPublicBytes)
```
  - Impact: Payload format incompatible across platforms due to curve.

- Network key distribution format
  - Rust mobile → node: encrypts PKCS#8 DER private key for the network key.
    ```startLine:675:endLine:691:/Users/rafael/dev/runar-rust/runar-keys/src/mobile.rs
let network_private_key = network_key.private_key_der()?;
let encrypted_network_key =
    self.encrypt_key_with_ecdsa(&network_private_key, node_public_key)?;
```
  - Swift mobile → node: encrypts raw scalar bytes (not PKCS#8).
    ```startLine:639:endLine:647:/Users/rafael/dev/runar-swift/swift-keys/Sources/RunarKeys/MobileKeyManager.swift
let networkPrivateKey = networkKey.rawScalarBytes()
let encryptedNetworkKey = try ECDHKeyPair.encryptECIES(data: networkPrivateKey, recipientPublicKey: nodePublicKey)
```
  - Impact: Swift→Rust interop would fail (Rust expects PKCS#8); Rust→Swift would need raw scalar support.

- QUIC/TLS binding
  - Rust returns rustls `CertificateDer` chain + `PrivateKeyDer`. Swift returns `[DER] + SecKey` for SecIdentity.
  - Impact: Ok for platform-specific stacks; only certificate semantics must align.

- DN normalization and chain validation
  - Rust: DN normalization and full signature-time checks during validation.
    ```startLine:536:endLine:559:/Users/rafael/dev/runar-rust/runar-keys/src/certificate.rs
// ... normalize_dn and issuer/subject match (order-insensitive), then verify with CA pubkey ...
```
  - Swift: Basic issuer equality + comprehensive optional SecTrust chain validation with anchors.
    ```startLine:223:endLine:254:/Users/rafael/dev/runar-swift/swift-keys/Sources/RunarKeys/Certificate.swift
public func validateCertificateChainWithSecTrust(leaf: X509Certificate, ca: X509Certificate) throws { ... }
```
  - Impact: Comparable; Swift grid is good when SecTrust path is exercised.

- Serial numbers
  - Rust CA uses monotonic `serial_counter` (persisted) for leafs. Swift uses random `Certificate.SerialNumber()`; keeps a counter but not used in signing.
  - Impact: Non-blocking; monotonic serials are nice-to-have for audits.

### Recommendations (prioritized quick wins)

- Decide one curve/system-wide
  - Quickest path: parameterize Swift to support P-256 alongside P-384 and default to P-256 for interop with Rust; keep Rust as-is. Later, consider migrating Rust to `p384` if required.
  - If adopting P-384 now: switch Rust to `p384`, update sec1 sizes (97), change ECDSA hash to SHA-384, and rewire OpenSSL signing NIDs accordingly. Larger change across crates and tests.

- Unify compact ID
  - Change Swift `CryptoUtils.compactId` to match Rust: SHA-256, take first 16 bytes, base64url no pad. This aligns IDs across node/gateway/logging immediately.

- Harden Swift issuance to match Rust security
  - In `processSetupToken`, accept and validate PKCS#10 CSR (already available via `CertificateRequest.create`); verify CSR signature and ensure CN equals DNS-safe node id; fall back to pubkey-only path only when explicitly configured.

- Align certificate extensions in Rust to Swift’s TLS profile
  - Leaf: remove KeyEncipherment for ECDSA; add SAN(s), SKI/AKI, and set appropriate criticality. Keep EKU serverAuth/clientAuth.
  - CA: ensure BasicConstraints CA, KeyCertSign/CRLSign, SKI/AKI present.

- Network key message interop
  - Rust node: accept both PKCS#8 DER and raw scalar. Attempt `SigningKey::from_pkcs8_der`, then fall back to `SecretKey::from_bytes(...)` → `SigningKey`.
  - Longer term: pick one canonical format. If Swift cannot easily emit PKCS#8, standardize on raw scalar; otherwise standardize on PKCS#8.

- Keep ECIES envelope consistent
  - Once curve is unified, formats align automatically. Preserve HKDF label “runar-key-encryption” and AES-GCM combined encoding semantics.

- DN normalization in Swift validator
  - Optional: add ordering-insensitive DN compare (like Rust) when not using SecTrust. Prefer always using the SecTrust path on Apple platforms.

- Signature algorithm consistency
  - If P-256: use ECDSA-SHA256 on both CA and leaf.
  - If P-384: use ECDSA-SHA384 on both.

- Serial number policy
  - Optional: adopt monotonic serials on Swift to match Rust (persist `serialCounter` and use it when signing CSR).

### Concrete change list

- Swift
  - Add P-256 support across `ECDHKeyPair`, CSR creation, certificate issuance, ECIES, tests.
  - Update `CryptoUtils.compactId` to Rust-compatible algorithm.
  - Complete CSR-based issuance in `MobileKeyManager.processSetupToken` (verify CSR signature + CN equals DNS-safe node id).
  - Prefer SecTrust validation in production paths.

- Rust
  - Update `sign_certificate_request_with_serial` to:
    - Remove `keyEncipherment` for ECDSA leaf.
    - Add SANs and SKI/AKI via OpenSSL extensions.
  - In `NodeKeyManager.install_network_key`, support raw-scalar fallback when PKCS#8 parse fails.
  - Optionally expose a feature flag to switch to P-384 later.

### Interop test plan (smoke sequence)

- With Swift switched to P-256 + unified `compactId`:
  - Swift mobile issues CSR-based node cert to Rust node; Rust validates chain and subject.
  - Swift mobile sends network key (raw scalar); Rust node accepts via fallback.
  - ECIES/envelope cross-decrypt from Swift→Rust and Rust→Swift.
  - QUIC/TLS handshake succeeds with node cert chain (Rust) and peer validation logic.

- With Rust migrated to P-384 instead:
  - Replace P-256 crates with `p384`, re-run the same steps; adjust tests for 97-byte pubkeys and SHA-384.

### Suggested “quick way we go”

- Short term (fastest, least churn):
  - Keep Rust on P-256.
  - Add P-256 mode to Swift and default to it.
  - Unify `compactId` in Swift to Rust’s scheme.
  - Rust: accept raw scalar for network key import.
  - Rust: fix ECDSA leaf extensions (remove keyEncipherment, add SAN/SKI/AKI).

- Medium term:
  - Complete Swift CSR verification path; make pubkey-only issuance opt-in for POC environments.
  - Evaluate moving both stacks to P-384 if there’s a strong requirement; otherwise stay on P-256 for performance and wider TLS ecosystem defaults.

- Long term:
  - Formalize key serialization (pick PKCS#8 or raw scalar) and document cross-language ECIES format including ephemeral key, nonce, ciphertext/tag layout.

- Optional:
  - Align serial number policies; add richer CA/leaf template controls in both stacks.

- Risks/notes:
  - Changing `compactId` in Swift affects persisted IDs; gate behind a migration or only apply for new identities.
  - Adding SANs requires choosing stable DNS names (e.g., node-id-based or service domain).

- Effort estimate (rough):
  - Swift P-256 param + compactId + CSR enforcement: 1–2 days.
  - Rust cert extensions + raw-scalar fallback: 0.5–1 day.
  - Cross-interop tests: 0.5–1 day.

- Success criteria:
  - Cross-platform envelope decryption both ways.
  - Swift-issued cert accepted by Rust node with subject/CN validation.
  - Shared node/network IDs identical across platforms.

- Key citations to guide edits:
  - Rust compact_id implementation:
    ```startLine:20:endLine:30:/Users/rafael/dev/runar-rust/runar-common/src/lib.rs
// ... see compact_id definition ...
```
  - Swift compactId (to change):
    ```startLine:11:endLine:18:/Users/rafael/dev/runar-swift/swift-keys/Sources/RunarKeys/CryptoUtils.swift
// ... current base58 variant ...
```
  - Rust ECDSA leaf extensions (to adjust):
    ```startLine:389:endLine:414:/Users/rafael/dev/runar-rust/runar-keys/src/certificate.rs
// ... KeyUsage + EKU ...
```
  - Swift ECDSA leaf extensions (reference):
    ```startLine:458:endLine:468:/Users/rafael/dev/runar-swift/swift-keys/Sources/RunarKeys/Certificate.swift
// ... SANs, SKI/AKI, digitalSignature only ...
```
  - Network key message format mismatch:
    ```startLine:675:endLine:691:/Users/rafael/dev/runar-rust/runar-keys/src/mobile.rs
// Rust uses PKCS#8 DER
```
    ```startLine:639:endLine:647:/Users/rafael/dev/runar-swift/swift-keys/Sources/RunarKeys/MobileKeyManager.swift
// Swift uses raw scalar
```

- Final note: After these changes, keep `cargo clippy --all-targets --all-features -- -D warnings` clean; ensure Rust format strings use the `{e}` style (already done across the touched code).

- What I just did and next
  - Read both Rust `runar-keys` and Swift `swift-keys` sources and tests, compared algorithms, formats, and flows.
  - Produced a prioritized plan with concrete edits and interop test checklist. No code changes applied yet; ready to implement the chosen path.

- Key points
  - Curve mismatch is the main interop blocker; pick P-256 now for speed.
  - Align `compactId`, certificate extensions, and network key serialization to remove subtle incompatibilities.
  - Complete Swift CSR path to match Rust’s stronger issuance guarantees.