# Runar Keys – KERI-Aligned Design

---

## Rationale

The original `Runar Keys` specification relied on hierarchical key derivation (SLIP-0010) for
profile keys and traditional X.509 certificates for node onboarding.
KERI (Key Event Receipt Infrastructure) offers a cleaner security model:

*  Self-certifying Autonomous Identifiers (AIDs) instead of external PKI roots.
*  Immutable, tamper-evident Key Event Logs (KELs) that record inception, rotation and
   delegation events.
*  Cryptographically verifiable receipts from mutually-distrusting witnesses, removing
   long-lived CA secrets.

This document rewrites the previous requirements so that **nothing conflicts with KERI** while
preserving the original user experience goals.

---

## Glossary (KERI-centric)

| Term / Key | Scope & Controller | KERI Event Type | Stored Where | Rotation Cadence |
|------------|-------------------|-----------------|--------------|------------------|
| **User AID** | Global identifier for the human user | *Inception* at wallet install | Mobile wallet / Ledger | Rare; user initiated |
| **Network AID** | Identifies a private data-sharing network | *Inception* signed by User AID | Wallet; witnessed by nodes | On compromise |
| **Node AID** | Each physical node/device | *Delegated Inception* under Network AID | Node flash storage | Annual or on compromise |
| **Node Storage Key** | Symmetric at-rest encryption key | Not in KEL – recorded in node metadata | Node | Quarterly or on compromise |
| **Profile AID** | Identifies one user profile/persona | *Inception* under User AID | Wallet | Rare |
| **Envelope Key** | Ephemeral per object | N/A | Stored with ciphertext header | New for every object |

Notes:
1. *AID* = Autonomous Identifier — a self-addressing identifier bound to a public key set.
2. All verifiable actions (creation, rotation, revocation) are expressed as KERI events and
   anchored in the relevant KELs.

---

## Functional Requirements (KERI Flow)

### F1. Inception & Delegation
1. Wallet creates the **User AID** via an *inception* event and commits it to the wallet KEL.
2. For every new **Network**, the wallet issues an *inception* event creating a **Network AID**;
   witnesses include at least one node designated by the user.
3. When a node is provisioned, it:
   a. Generates its initial key set locally.
   b. Displays a one-time QR containing its public keys and witness info (valid ≤120 s).
   c. The wallet issues a *delegated inception* event → establishing the **Node AID** under the
      Network AID; receipts are returned to the node.

### F2. Secure Channel Establishment
Wallet and node use Noise_X + SPAKE2 to mutually authenticate their AIDs and exchange the
signed receipts. After verification, the node stores the receipts and the wallet records the
successful delegation in its log.

### F3. Data Encryption & Sharing
1. Every stored object is encrypted with a fresh **Envelope Key**.
2. The Envelope Key is encrypted for:
   • the **Network Data Public Key** (latest from Network AID event); and
   • each authorised **Profile AID**.
3. A node unwraps an Envelope Key only if:
   a) its **Node AID** delegation is still valid in the Network KEL, **and**
   b) it possesses the current Network Data key to decrypt the envelope header.
4. Node Storage Keys protect local configuration/databases; they are **not** used for Envelope
   decryption, enabling safe replication across nodes.

### F4. Rotation & Revocation
1. Any AID key set (User, Network, Node, Profile) can be rotated by emitting a *rotation* event.
2. Revocation is expressed via a *rotation* to an empty key-set or a *delegation-revocation* event.
3. Witnesses must acknowledge the rotation; un-acknowledged events are considered unverified.

---

## Security Requirements

S1. Private keys backing User, Network and Profile AIDs **never leave** the secure wallet/Ledger.
S2. Node private keys stay on node; restoring a node requires issuing a new delegated inception.
S3. Revocation: user can rotate or revoke Node, Network or Profile AIDs. Future data uses new
    keys; past ciphertext remains protected by per-object Envelope Keys.
S4. Separate key sets for transport (Noise/TLS) and storage to maintain PFS.

---

## Operational Requirements

O1. Provide CLI & mobile UI for key rotation events (Node, Network, Profile).
O2. Every node maintains an append-only KEL fragment plus an audit log of receipts.
O3. Wallet allows exporting an encrypted mnemonic of the User AID seed using BIP-39.

---

## Usability Requirements

U1. Mobile app offers single-tap flows: *Add Node*, *Create Network*, *Share Data*.
U2. Default UX hides KERI terminology; power users may view full KELs.
U3. Glossary & security overview are accessible from Help.

---

## Open Questions

1. Minimum witness threshold per Network for acceptable availability?
2. Are quarterly rotations of Node Storage Keys operationally feasible?
3. Should filenames & sizes be encrypted to resist traffic analysis?

---
