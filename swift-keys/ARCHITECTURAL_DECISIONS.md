# Architectural Decisions

## Key Type Design Decision: ECDH as Primary Type

### Problem
The original Rust implementation uses ECDSA keys (`EcdsaKeyPair`) for all operations, including ECIES encryption/decryption. This requires converting ECDSA signing keys to ECDH key agreement keys using:

```rust
let secret_key = SecretKey::from_bytes(&key_pair.signing_key().to_bytes())
```

This conversion works in Rust's p256 crate because both types share the same underlying scalar representation, but it fails in Swift's CryptoKit where `P256.Signing.PrivateKey` and `P256.KeyAgreement.PrivateKey` have incompatible `rawRepresentation` formats.

### Root Cause
The fundamental issue is **mixing key purposes**:
- **ECDSA keys** are designed for **signing/verification** operations
- **ECDH keys** are designed for **key agreement** operations (ECIES)
- Using signing keys for key agreement is conceptually incorrect and platform-dependent

### Solution: ECDH as Primary Type
**Decision**: Use `P256.KeyAgreement.PrivateKey` as the primary key type for all operations.

**Rationale**:
1. **ECDH keys can perform both operations**:
   - Key agreement (ECIES encryption/decryption)
   - Signing/verification (ECDSA operations)
2. **Eliminates key conversion** - No more fragile platform-dependent conversions
3. **Conceptually correct** - Using the right tool for the job
4. **Platform consistency** - Works the same way across Rust and Swift
5. **Maintains all functionality** - All existing operations remain possible

### Implementation Strategy
1. **Swift Implementation**: Use `P256.KeyAgreement.PrivateKey` as primary type
2. **Test thoroughly** to ensure all operations work correctly
3. **If successful**: Update Rust implementation to use the same approach
4. **Migration path**: Both implementations will converge on the cleaner design

### Key Usage Mapping
| Operation | ECDSA Key (Old) | ECDH Key (New) |
|-----------|----------------|----------------|
| Certificate Signing | ✅ Native | ✅ Via ECDSA conversion |
| Certificate Verification | ✅ Native | ✅ Via ECDSA conversion |
| ECIES Encryption | ❌ Requires conversion | ✅ Native |
| ECIES Decryption | ❌ Requires conversion | ✅ Native |
| Key Agreement | ❌ Requires conversion | ✅ Native |

### Benefits
- **Eliminates platform differences** - Same approach works in Rust and Swift
- **Simpler codebase** - No more key conversion logic
- **Better security model** - Using keys for their intended purpose
- **Future-proof** - Works consistently across all platforms

### Migration Notes
- This change is **backward compatible** for all cryptographic operations
- **No data format changes** - All encrypted data remains compatible
- **Performance impact** - Minimal, ECDH operations are equally efficient
- **Security level** - Maintains the same security guarantees

---

*Decision Date: 2025-01-20*
*Status: Implemented in Swift, pending Rust migration* 