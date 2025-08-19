Ran tool

### Root-cause analysis (no changes made)

- Yes, we are passing a proper `NodeKeyManager` from the Swift side, but the Rust FFI forgets to provide two additional items required by the transporter constructor:
  - a keystore (`Arc<dyn runar_serializer::traits::EnvelopeCrypto>`)
  - a label resolver (`Arc<dyn runar_serializer::traits::LabelResolver>`)

FIRST ISSUE HERE>. keytore and keymanger are the same thing.. if the tranposter is requiring botha  the moment we nmee dto fix that in thet ranposter.. we just just require with_key_manager() and taht has all the API we need.. inclufing the envelop api define in the keystore trait.. so lets remove the keystore option.. 



- In the FFI transport constructor, we set the key manager and other callbacks, but never set `keystore` or `label_resolver`. This makes `QuicTransport::new()` immediately fail with “keystore is required” before it even evaluates the certificate chain from the key manager.

```1378:1406:/Users/rafael/dev/runar-swift/runar-rust/runar-ffi/src/lib.rs
    options = options
        .with_key_manager(node_arc.clone())
        .with_local_node_public_key(node_arc.get_node_public_key())
        .with_logger_from_node_id(node_id)
        .with_peer_connected_callback(pc_cb)
        .with_peer_disconnected_callback(pd_cb)
        .with_request_callback(rq_cb)
        .with_event_callback(ev_cb);
```

- The transporter hard-requires both fields at construction time:

```702:708:/Users/rafael/dev/runar-swift/runar-rust/runar-transporter/src/transport/quic_transport.rs
        let keystore = options
            .keystore
            .take()
            .ok_or_else(|| NetworkError::ConfigurationError("keystore is required".into()))?;
        let label_resolver = options
            .label_resolver
            .take()
            .ok_or_else(|| NetworkError::ConfigurationError("label_resolver is required".into()))?;
```

- Separately, TLS identity (certs+key+roots) can come from either:
  - the key manager (preferred), which we did provide; or
  - the deprecated inline options (for tests only).
  That selection happens later in the QUIC config builder, which correctly uses the key manager if present:


```784:805:/Users/rafael/dev/runar-swift/runar-rust/runar-transporter/src/transport/quic_transport.rs
        let (certs, key): (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) =
            if let Some(km) = self.options.key_manager() {
                let cfg = km.get_quic_certificate_config().map_err(|e| {
                    NetworkError::ConfigurationError(format!(
                        "Failed to get QUIC certificate config from key manager: {e}"
                    ))
                })?;
                (cfg.certificate_chain, cfg.private_key)
            } else {
                // fallback to explicit cert/key
            };
```

- So even if Swift passed the deprecated inline `cert_chain_der`/`private_key_der`/`root_certs_der`, it would still fail here first due to the missing keystore/resolver.

- The good news: `NodeKeyManager` already implements the keystore trait the transporter wants:

```926:950:/Users/rafael/dev/runar-swift/runar-rust/runar-keys/src/node.rs
impl crate::EnvelopeCrypto for NodeKeyManager {
    fn encrypt_with_envelope(&self, data: &[u8], network_id: Option<&str>, _profile_public_keys: Vec<Vec<u8>>)
        -> crate::Result<crate::mobile::EnvelopeEncryptedData> { /* … */ }

    fn decrypt_envelope_data(&self, env: &crate::mobile::EnvelopeEncryptedData)
        -> crate::Result<Vec<u8>> { /* … */ }
}
```

- A default label resolver can be provided from `runar_serializer::traits` (e.g., `ConfigurableLabelResolver` with an empty `KeyMappingConfig`), which the transporter accepts.

### Conclusion

- The failure is on the Rust FFI side, not Swift usage. We pass a valid `NodeKeyManager`, but `rn_transport_new_with_keys` doesn’t set:
  - `options = options.with_keystore(node_arc.clone())`
  - `options = options.with_label_resolver(Arc::new(ConfigurableLabelResolver::new(KeyMappingConfig { label_mappings: Default::default() })))`

- After adding those two in the FFI, `QuicTransport::new()` will proceed to TLS setup via the key manager, and your Swift real-transport tests should get past the “keystore is required” error.

- This matches your intended behavior: deprecated inline certs are optional; passing a `NodeKeyManager` should be sufficient, with transporter deriving certs/keys/roots internally. The missing piece was wiring the keystore and a label resolver in the FFI constructor.