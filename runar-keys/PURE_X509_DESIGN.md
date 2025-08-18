## Pure Rust X.509 Issuance Plan (OpenSSL Removal)

This document defines the plan to remove OpenSSL from `runar-keys` while preserving full functionality and test parity (including QUIC tests).

### Goals
- No loss of features: retain all current certificate behaviors and extensions
  - Self‑signed CA cert (CA=true, pathLen=0)
  - CSR verification before issuance
  - Leaf issuance with: BasicConstraints (CA=false), KeyUsage, ExtendedKeyUsage, SAN (from CSR or CN fallback), SKI, AKI (keyid + issuer/serial), controlled serial, validity bounds
- Pure Rust issuance and parsing path
- Maintain current public API surface and semantics

### Crate Stack (Pure Rust)
- `p256` + `pkcs8`: signing and key material (already used)
- `pkcs10`: CSR parsing + signature verification
- `x509-cert`: build `TbsCertificate` and `Certificate`, add extensions
- `spki`, `der`, `const-oid`: SPKI/ASN.1/OID helpers
- `sha1`: compute SKI as SHA‑1 over SPKI (standard practice)
- Optional: keep `x509-parser` for read/validate paths already in use

### Mapping current functionality → Pure Rust
1. Self‑signed CA
   - Produce `TbsCertificate` with subject=issuer=Runar User CA
   - Extensions:
     - BasicConstraints: CA=true, pathLen=0, critical
     - KeyUsage: keyCertSign + cRLSign, critical
     - SKI: SHA‑1 of SubjectPublicKey
     - AKI: keyid from SKI; include issuer/serial fields
   - Sign with ECDSA P‑256 + SHA‑256 → DER‐encoded certificate bytes

2. CSR verification and leaf issuance
   - Parse CSR via `pkcs10`, extract subject and SPKI
   - Verify CSR signature using the embedded algorithm and SPKI
   - Subject: copy from CSR
   - Issuer: CA subject
   - Serial: use provided `u64` or random 64‑bit; encode as positive ASN.1 INTEGER
   - Validity: not_before=now, not_after=now+days (UTCTime/GeneralizedTime as appropriate)
   - Extensions:
     - BasicConstraints: CA=false, critical
     - KeyUsage: digitalSignature, critical
     - ExtendedKeyUsage: serverAuth + clientAuth
     - SAN: prefer CSR SANs; if absent, add DNS=CN (matching current behavior)
     - SKI: SHA‑1 of leaf SPKI
     - AKI: keyid from CA SKI; include issuer/serial
   - Sign with CA key (ECDSA P‑256 + SHA‑256)

3. Validation path
   - Continue using existing `X509Certificate` wrapper and `x509-parser` for parsing/validation
   - Preserve DN normalization and signature verification logic already in place

### Pitfalls to avoid
- ASN.1 INTEGER serial must be positive; prepend 0x00 if high bit set
- Time encoding (UTCTime vs GeneralizedTime) must match date ranges expected by consumers (e.g., < 2050 → UTCTime)
- DN ordering differences can persist; continue using normalization for comparisons
- AlgorithmIdentifier for ECDSA w/ SHA‑256 is OID `1.2.840.10045.4.3.2`; ensure parameters handling conforms

### Feature gating and migration
- Add feature flags: `pure-x509` and `openssl-x509` (default remains `openssl-x509` during transition)
- Implement a parallel issuance module (e.g., `pure_x509.rs`) with identical public functions used by `CertificateAuthority`
- Switch default to `pure-x509` once tests pass across targets; remove OpenSSL dependency afterward

### Tests (must remain green)
- Unit tests:
  - CA self‑sign: check extensions, AKI/SKI correctness, and signature validity
  - CSR roundtrip: generate CSR (existing rcgen path), verify, and issue leaf
  - Leaf cert contains expected subject, SANs, KU/EKU, validity and serial
  - Signature verification using CA public key
- Integration/QUIC tests:
  - Ensure rustls accepts the chain (node + CA) and handshakes succeed

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


