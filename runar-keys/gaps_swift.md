Gap
SAN (Subject Alternative Names) not emitted in Rust leafs; Swift emits SAN DNS.
Evidence:
}
Rust OpenSSL leaf build sets KU/EKU/SKI/AKI but does not add SAN.
Fix (Rust):
Add SubjectAlternativeName extension with DNS = node id when signing CSR on mobile.

Gaps
Label semantics differ for profile:
Swift derives profile agreement scalar directly: scope "profile", purpose "agreement".
Rust derives a profile signing key, then derives the agreement from that signing scalar; info used is "runar‑v1:profile:signing:{label}" before agreement derivation.
Fix (Rust, if matching Swift spec desired):
Derive profile agreement scalar directly from user‑root secret with info "runar‑v1:profile:agreement:{label}" and skip intermediate signing key, unless a signing key is also required.


Separation of signing vs agreement keys
Significant gap
Swift strictly separates signing and agreement:
Signing: P256.Signing.PrivateKey (often Secure Enclave for node identity).
Agreement: P256.KeyAgreement.PrivateKey (profile/network, and node’s ECIES recipient).
Rust currently conflates usage:
Uses ECDSA signing key material for ECDH in multiple places (constructs p256::SecretKey from signing scalar, uses it for diffie_hellman).
Wraps network private key to the node’s signing public key (not the node’s agreement public key).
Evidence:
;
tests
)
Impact:
Swift expects wrapping to node’s agreement public key; Rust encrypts to node’s signing public key.
Swift cannot derive agreement from signing key (Secure Enclave keys are non‑extractable). Rust derives node agreement deterministically from signing scalar; Swift uses independent agreement keys.
Fix (Rust):
Use and require node_agreement_public_key (already present in SetupToken) for wrapping network keys and message ECIES, not the signing public key.
Store/track a node agreement private key separately on node and use it for ECIES decryption; avoid reconstructing from signing scalar.
Keep signing and agreement paths separate throughout APIs and state.


Network key wrap format
Gap
Swift wraps the raw agreement private scalar bytes (priv.rawRepresentation) via ECIES.
Rust wraps the PKCS#8 DER of the network key, then reconstructs an ECDSA signing key from it on node install.
Evidence:
)
;
;
Fix (Rust):
Align to Swift by wrapping only the raw 32‑byte scalar for the network agreement key; on node side, import into a p256::SecretKey (agreement) rather than an ECDSA signing key.

Concrete recommendations to fully align
Network key wrapping and key roles
Use node agreement public key (not signing pub) as ECIES recipient for all wraps and messages.
Keep signing and agreement keys separate in Rust APIs and storage; stop repurposing the signing scalar for ECDH.
Wrap raw 32‑byte agreement private scalars (not PKCS#8) to match Swift; import as p256::SecretKey for decryption.
Profile and network derivation labels
Derive agreement keys directly from the user‑root secret with info strings that match Swift’s scheme:
Profile: "runar‑v1:profile:agreement:{label}"
Network: "runar‑v1:network:agreement:{label}"
Only derive signing keys when actually needed for signatures.
Certificate SANs
Add SAN DNS entries equal to the node‑id when issuing leaf certificates on Rust mobile.
Node identity and CSR
Optional: accept a CSR signed by SE in production builds (already aligned) and ensure SAN validation takes SAN DNS (not just subject CN) where applicable.