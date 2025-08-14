### Compact ID (DNS-safe) – Spec for Rust alignment

- Purpose
  - Provide a single DNS-safe identifier for node/profile/network IDs usable in CN, SAN, and SNI.
  - Maintain 128-bit security while keeping IDs short and deterministic.

- Input
  - Public key bytes of the entity (P‑256):
    - Use uncompressed SEC1/X9.63 representation: 65 bytes (0x04 || X(32) || Y(32)).
    - Same rule for signing and agreement keys when computing their IDs.

- Derivation
  - Compute SHA‑256 over the public key bytes.
  - Truncate to the first 16 bytes (128 bits).
  - Encode using RFC 4648 Base32hex alphabet, lowercase, no padding.
    - Alphabet: 0–9, a–v
    - No separators, no padding, ASCII lowercase only.

- Output
  - Length: 26 characters (ceil(128/5)).
  - Character set: [0-9a-v], DNS label-safe. Suitable for CN, SAN (dNSName), and TLS SNI.
  - Example format: “1p9m…3v” (26 chars). Note: underscore “_” and hyphen “-” do not appear.

- Usage
  - Node ID: computed from node’s P-256 signing public key (X9.63).
  - Profile ID / Network ID: computed from their P-256 agreement public keys (X9.63).
  - Certificates:
    - CN = node-id
    - SAN includes node-id as dNSName
    - TLS SNI = node-id
  - Transport/tests: treat ID as DNS label; 26 chars; use in SNI hostnames directly.

- Rationale
  - Base32hex lowercase is DNS-safe (letters+digits only) and widely understood.
  - 128-bit truncated SHA-256 provides strong collision resistance for identifiers.
  - Replaces prior base64url (which could include “_” and is not DNS compliant).

- Backward compatibility
  - IDs change format. No fallback/aliasing maintained. All components must adopt the new format.

- Rust implementation hints
  - Hash: SHA‑256 over 65-byte SEC1/X9.63 pubkey.
  - Truncate: first 16 bytes.
  - Encode: RFC 4648 base32hex without padding, lowercase.
    - Suggested crate: `data-encoding` with `BASE32HEX_NOPAD` then `.to_lowercase()`, or implement a simple base32hex encoder mapping to 0–9,a–v.
  - Unit tests:
    - Verify output length = 26.
    - Verify charset ⊆ [0-9a-v].
    - Verify determinism for known public key fixtures.
    - Validate that result is accepted by a DNS label parser.

- Security notes
  - 128-bit truncated identifiers are sufficient as opaque IDs; underlying keys remain 256-bit.
  - SPKI pinning, CA issuance, and PoP flows are unchanged.