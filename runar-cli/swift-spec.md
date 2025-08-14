### Runar CLI ↔ Mobile setup spec (v1, matches current Rust)

- Crypto
  - Curve: P‑256
  - Signatures: ECDSA‑SHA256
  - ECIES: P‑256 ECDH; ephemeral uncompressed SEC1 pubkey (65 bytes)
  - KDF: HKDF‑SHA256; shared info "runar‑v1:ecies:envelope‑key"
  - AES: AES‑256‑GCM; combined output (nonce|ciphertext|tag)

- Identifiers and encodings
  - compactId: base64url(no pad) of first 16 bytes of SHA‑256(pubkey)
  - Public keys (when sent raw): SEC1 X9.63 uncompressed (65 bytes)
  - Strings: UTF‑8
  - All message serialization over the wire: bincode
  - Length framing for TCP messages: 4‑byte big‑endian length prefix

- Data structures
  - SetupToken (from node, inside QR; from `runar-keys`)
    - node_public_key: Vec<u8> (65 bytes)
    - node_agreement_public_key: Vec<u8> (65 bytes)
    - csr_der: Vec<u8> (PKCS#10 DER; message‑signed)
    - node_id: String (compactId of node_public_key)
  - FullSetupToken (from CLI; for QR)
    - setup_token: SetupToken
    - server_address: String ("host:port")
  - NodeCertificateMessage (mobile → node)
    - node_certificate: X.509 DER (leaf; SAN DNS = node_id; ECDSA‑SHA256)
    - ca_certificate: X.509 DER (self‑signed CA; ECDSA‑SHA256)
    - metadata: { issued_at: u64 (secs), validity_days: u32, purpose: String }
  - NetworkKeyMessage (mobile → node)
    - network_id: String (compactId of network pubkey)
    - network_public_key: Vec<u8> (65‑byte uncompressed SEC1)
    - encrypted_network_key: Vec<u8> (ECIES: 65‑byte eph pubkey || AES‑GCM combined)
    - key_derivation_info: String (informational)

- QR code payload (what the node shows; what the mobile scans)
  - Contents: hex string of bincode(FullSetupToken)
  - Fields inside as above; server_address must be reachable by mobile (e.g., LAN IP:port)

- Transport (mobile → node) for setup
  - Protocol: TCP to `server_address`
  - Framing: each message is 4‑byte BE length prefix followed by bincode payload
  - Order:
    1) Send NodeCertificateMessage
    2) Send NetworkKeyMessage

- Mobile processing of SetupToken
  - Parse FullSetupToken (bincode from QR hex)
  - Validate `setup_token`:
    - CSR PoP: verify CSR signature with csr’s public key
    - Subject CN must equal dns_safe(node_id)
  - Issue node leaf certificate:
    - SAN DNS includes node_id; KeyUsage digitalSignature (critical); EKU serverAuth+clientAuth
    - Sign with CA using ECDSA‑SHA256
  - Create NetworkKeyMessage:
    - Wrap raw 32‑byte network agreement scalar for node_agreement_public_key via ECIES
    - Include network_id and network_public_key

- Node processing (server side)
  - Accept TCP, read 2 framed messages in order
  - Install certificate:
    - Validate CA chain and leaf; ensure CN/SAN contains dns_safe(node_id)
  - Install network key:
    - ECIES‑decrypt encrypted_network_key using node agreement private key
    - Expect 32 bytes; import as P‑256 SecretKey; index by compactId(network_public_key)

- HKDF label contracts (must match Swift)
  - Profile agreement: "runar‑v1:profile:agreement:{label}[:{counter}]"
  - Network agreement: "runar‑v1:network:agreement:{label}[:{counter}]"
  - Node identity agreement: "runar‑v1:node‑identity:agreement"
  - Salt: "RunarKeyDerivationSalt/v1"; 32‑byte output; rejection sampling to valid scalar

- Security requirements
  - Reject empty/invalid CSR; enforce CN match; verify CSR PoP
  - Use DNS‑safe variant of node_id wherever certificates compare names
  - ECIES failures must not leak plaintext; treat as fatal
  - Recommended: include setup token expiry (not yet in v1 payload)

- Wire examples (sizes)
  - ECIES payload: 65‑byte ephemeral pubkey || AES‑GCM combined (12‑byte nonce + ciphertext + 16‑byte tag)
  - Length prefix: u32 BE, e.g., 0x0001F4 for 500 bytes
  - QR payload size: typically a few KB; use hex of bincode(FullSetupToken)

- Swift implementation notes
  - Use CryptoKit: P256.Signing for CSR; P256.KeyAgreement for ECIES and network key wrapping
  - CSR: message‑signed (SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256); supply public key and SAN via attributes
  - Serialization:
    - For fastest interop now: bincode payloads as in spec
    - If you prefer JSON/CBOR, we can add v1.1 endpoints; for v1, use bincode and the given field order/types

- Versioning
  - Add a QR `version: u8` field in future (v2); v1 omits it and assumes this spec

This matches the current Rust behavior in `runar-keys` and `runar-cli` (tests already pass with this contract).