# Runar Keys

---

## Glossary

| Term / Key | Scope & Owner | Algorithm (recommended) | Stored Where | Rotation Cadence |
|------------|--------------|-------------------------|--------------|------------------|
| **User Root Key** | User-wide, master of trust | `Ed25519` (signing) + `X25519` (encryption) via SLIP-0010 path `m/0'` | Mobile wallet / Ledger | Rare; user-initiated |
| **User CA Key** | Per user, signs node membership certs | `Ed25519` | Mobile wallet | On CA compromise |
| **Node TLS Key** | Per node, generated *on node* | `Ed25519` CSR signed by User CA | Node | Annual or on compromise |
| **Node Storage Key** | Per node, generated *on node* | XChaCha20-Poly1305 file key wrapped by node X25519 | Node | Quarterly or on compromise |
| **User Profile Key** | Per profile ID | `X25519` pair derived via SLIP-0010 `m/44'/1'/profile_index'` | Mobile wallet | Rare |
| **Envelope Key** | Per object/file, ephemeral | Random 256-bit symmetric | Stored with ciphertext header | New for every object |

---

## Functional Requirements

### F1. Key Generation & Derivation
1. The *User Root Key* is generated once and never leaves the secure device.
2. Nodes self-generate their TLS & Storage keypairs, then send CSRs to the mobile app.
3. The mobile app signs CSRs using the appropriate **Network CA Key**.
4. *User Profile Keys* are derived from the Root via SLIP-0010 path `m/44'/1'/profile_index'`.

### F2. Node Setup Workflow
1. Node displays a **one-time, 120-second QR token** (no long-term secret).
2. Phone establishes a Noise_X + SPAKE2 channel, verifies the node public key, and signs node certificates.
3. Phone pushes network-membership certs and initial ACL policy to the node.

### F3. Encryption & Data Sharing
1. Every stored object is encrypted with a fresh *Envelope Key*.
2. The Envelope Key is encrypted for:
   • the Network **Data Key** (public X25519 key shared by all nodes that belong to the network);  
   • each recipient *User Profile Key* authorised to access the data within that network.
3. A node can unwrap an Envelope Key only if it both:  
   a) holds a valid network-membership certificate signed by the Network CA, **and**  
   b) successfully uses the Network Data Key to decrypt the Envelope header.
4. Node Storage Keys protect the physical filesystem (configs, databases); they are **not** used for Envelope decryption. This separation lets the same encrypted record replicate across multiple nodes in the same network.

---

## Security Requirements

S1. Private keys (User Root, Network CA, User Profiles) **never leave** the mobile wallet / Ledger.
S2. Node private keys stay on node; restoring a node requires re-signing new CSRs from a backup device.
S3. Revocation: user can revoke node certs, network membership certs, or rotate profile keys. Future data is re-encrypted; past data remains safe because each object has its own envelope key.
S4. Separate keys for transport (TLS) and storage to avoid cross-use and enable PFS.

---

## Operational Requirements

O1. Provide CLI & mobile UI to rotate Node TLS & Storage keys.
O2. Maintain an append-only audit log of certificate issuance & revocation on each node.
O3. Backup: allow exporting an encrypted BIP-39 seed phrase of the User Root to offline storage.

---

## Usability Requirements

U1. Mobile app offers single-tap flows: *Add Node*, *Create Network*, *Share Data with App*.
U2. Default UX hides key taxonomy; power users may manage multiple profiles.
U3. Glossary is accessible via Help > Security Overview.

---

## Out of Scope (separate specs)

• Detailed backup & social recovery flows  
• Malicious app data caching (handled by permission & reputation layers)  
• Hardware-based anti-tamper requirements

---

## Rationale & Open Questions

This refined design removes long-lived shared keys, separates transport-layer TLS from at-rest encryption, delegates CA duties to the user, and keeps all high-value private material inside a hardened wallet while still allowing node restore by re-signing CSRs.  

**Open for next round:**
1. Is SLIP-0010 the preferred derivation spec, or should we adopt KERI-style attestations instead?  
2. Rotation cadences – are the proposed intervals acceptable operationally?  
3. Do we need additional metadata encryption (filenames, sizes)?

---

### Appendix A – Derivation (SLIP-0010) vs. Attestation (KERI)

| Criterion | SLIP-0010 Hierarchical Derivation | KERI / Event-Log Attestations |
|-----------|-----------------------------------|------------------------------|
| *Maturity / Tooling* | Widely supported in crypto wallets & HSMs | Emerging; limited off-the-shelf libs |
| *Key Exposure* | Child private keys exported if derived on host | Nodes generate keys; only attestations leave wallet |
| *Revocation* | Rotate affected branch or derive new index | Issue rotation event; simple, log-based |
| *Determinism* | Deterministic paths enable seed-based recovery | Non-deterministic; backups per key pair |
| *Auditability* | Needs external cert logs | Built-in verifiable event log |
| *Implementation Effort* | Straightforward (mature libs) | Higher – requires controller, witnesses |
| *Fit for Offline Wallet* | Excellent – seed phrase friendly | Good, but heavier metadata |

**Recommendation:** Today, SLIP-0010 best matches our "single seed in secure wallet" goal and has robust tooling. KERI adds powerful rotation and tamper-evident audit trails but at the cost of extra infrastructure. We can begin with SLIP-0010 and revisit KERI once basic network functionality is proven.

