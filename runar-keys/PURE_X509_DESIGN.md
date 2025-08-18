## Pure Rust X.509 Issuance Plan (OpenSSL Removal)

This document defines the plan to remove OpenSSL from `runar-keys` while preserving full functionality and test parity (including QUIC tests).

### Goals
- No loss of features: retain all current certificate behaviors and extensions
  - Self‑signed CA cert (CA=true, pathLen=0)
  - CSR verification before issuance
  - Leaf issuance with: BasicConstraints (CA=false), KeyUsage, ExtendedKeyUsage, SAN (from CSR), SKI, AKI (keyid + issuer/serial), controlled serial, validity bounds
- Pure Rust issuance and parsing path
- Maintain current public API surface and semantics

### Crate Stack (Pure Rust)
- `p256` + `pkcs8`: signing and key material (already used)
- `x509-cert`: build `TbsCertificate` and `Certificate`, add extensions
- `spki`, `der`, `const-oid`: SPKI/ASN.1/OID helpers
- `sha1`: compute SKI as SHA‑1 over SPKI (standard practice)
- `x509-parser`: used for parsing CSRs and certs in tests/validation

### Mapping current functionality → Pure Rust
1. Self‑signed CA [IMPLEMENTED]
   - Produce `TbsCertificate` with subject=issuer=Runar User CA
   - Extensions:
     - BasicConstraints: CA=true, pathLen=0, critical
     - KeyUsage: keyCertSign + cRLSign, critical
     - SKI: SHA‑1 of SubjectPublicKey
     - AKI: keyid from SKI (issuer/serial not included for self-signed)
   - Sign with ECDSA P‑256 + SHA‑256 → DER‐encoded certificate bytes

2. CSR verification and leaf issuance [IMPLEMENTED]
   - Parse CSR via `x509-cert` and verify signature manually using `p256`
   - Subject: copied from CSR
   - Issuer: CA subject
   - Serial: provided `u64` or deterministic fallback in tests; encoded as positive ASN.1 INTEGER
   - Validity: not_before=now, not_after=now+days (UTCTime)
   - Extensions:
     - BasicConstraints: CA=false, critical
     - KeyUsage: digitalSignature, critical
     - ExtendedKeyUsage: serverAuth + clientAuth
     - SAN: required, strictly parsed from CSR extensions (no CN fallback)
     - SKI: SHA‑1 of leaf SPKI
     - AKI: keyid from CA SKI; includes issuer DirectoryName and serial (parity with OpenSSL)
   - Sign with CA key (ECDSA P‑256 + SHA‑256)

3. Validation path [UNCHANGED]
   - Use existing `X509Certificate` wrapper and `x509-parser` for parsing/validation
   - DN normalization and signature verification logic retained

### Pitfalls to avoid
- ASN.1 INTEGER serial must be positive; prepend 0x00 if high bit set
- Time encoding (UTCTime vs GeneralizedTime) must match date ranges expected by consumers (e.g., < 2050 → UTCTime)
- DN ordering differences can persist; continue using normalization for comparisons
- AlgorithmIdentifier for ECDSA w/ SHA‑256 is OID `1.2.840.10045.4.3.2`; ensure parameters handling conforms

### Feature gating and migration
- Feature flags in place: `pure-x509` and `openssl-x509` (default still `openssl-x509` during transition)
- Parallel issuance module implemented: `pure_x509.rs`; `CertificateAuthority` dispatches based on feature
- Next: flip default to `pure-x509` after transporter tests pass; then remove OpenSSL code path

### Tests (status)
- Unit/integration:
  - Pure issuance end-to-end used by existing tests [PASS]
  - Parity test comparing OpenSSL vs pure for extensions, serial, SPKI, signature OIDs [PASS]
- Transport/QUIC:
  - To run with `pure-x509` and verify rustls handshakes in existing transporter tests [PENDING]

### Remaining Work
- Make `pure-x509` the default feature and gate OpenSSL behind opt-in [PENDING]
- Run full transporter/QUIC tests with `pure-x509` on CI and local [PENDING]
- Remove OpenSSL code path after sustained green runs [PENDING]
- FFI: proceed with `runar-keys-ffi` crate exposing stable C ABI (CBOR for complex types) [NEXT PHASE]

### Implementation Steps
1. Add dependencies: `x509-cert`, `pkcs10`, `spki`, `der`, `const-oid`, `sha1`
2. Implement helper utilities:
   - Compute SKI from SPKI (SHA‑1)
   - Build AKI from CA SKI + issuer/serial
   - Serial encoding helper (u64 → ASN.1 INTEGER bytes)
3. Implement CA self‑sign using `x509-cert`
4. Implement CSR parse/verify and leaf issuance with full extensions
5. Wire into `CertificateAuthority` behind `pure-x509` feature; keep OpenSSL path for fallback
6. Run all tests (including QUIC) on macOS/iOS/Android CI

### Notes on CSR generation
- Nodes currently use `rcgen` to create CSRs; we will continue to accept those and verify via `pkcs10`
- If needed later, we can refactor CSR creation to `pkcs10` too, but not required for removal of OpenSSL on issuance path


