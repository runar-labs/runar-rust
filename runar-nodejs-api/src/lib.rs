// Full impl for Keys
use anyhow::anyhow;
use napi::bindgen_prelude::*;
use napi::threadsafe_function::{ThreadsafeFunction, ThreadsafeFunctionCallMode};
// no event registration exported for now
use napi_derive::napi;
use once_cell::sync::Lazy;
use runar_common::logging::{Component, Logger};
use runar_keys::{MobileKeyManager, NodeKeyManager};
use runar_schemas::NodeInfo;

use runar_transporter::discovery::{DiscoveryEvent, DiscoveryOptions};
use runar_transporter::transport::NetworkTransport;
use runar_transporter::{NodeDiscovery, QuicTransport, QuicTransportOptions};
use serde_cbor as cbor;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::runtime::Runtime;
use tokio::sync::{oneshot, Mutex as AsyncMutex};

static RT: Lazy<Runtime> = Lazy::new(|| Runtime::new().unwrap());

#[napi(object)]
pub struct DeviceKeystoreCaps {
    pub version: u32,
    pub flags: u32,
}

#[napi]
pub struct Keys {
    inner: Arc<Mutex<KeysInner>>,
}

struct KeysInner {
    node_owned: Option<NodeKeyManager>,
    node_shared: Option<Arc<NodeKeyManager>>,
    mobile: Option<MobileKeyManager>,
    persistence_dir: Option<String>,
    auto_persist: bool,
    logger: Arc<Logger>,

    local_node_info: Arc<Mutex<Option<NodeInfo>>>,
}

#[napi]
impl Keys {
    #[napi(constructor)]
    pub fn new() -> Self {
        let logger = Arc::new(Logger::new_root(Component::Keys));
        Keys {
            inner: Arc::new(Mutex::new(KeysInner {
                node_owned: None,
                node_shared: None,
                mobile: None,
                persistence_dir: None,
                auto_persist: true,
                logger,

                local_node_info: Arc::new(Mutex::new(None)),
            })),
        }
    }

    /// Initialize this instance as a mobile manager
    /// Returns error if already initialized with different type
    #[napi]
    pub fn init_as_mobile(&self) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();

        // Check if already initialized as node
        if inner.node_owned.is_some() || inner.node_shared.is_some() {
            return Err(Error::from_reason("Already initialized as node manager"));
        }

        // Initialize mobile manager if not already present
        if inner.mobile.is_none() {
            inner.mobile = Some(
                MobileKeyManager::new(inner.logger.clone())
                    .map_err(|e| Error::from_reason(e.to_string()))?,
            );
        }

        Ok(())
    }

    /// Initialize this instance as a node manager
    /// Returns error if already initialized with different type
    #[napi]
    pub fn init_as_node(&self) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();

        // Check if already initialized as mobile
        if inner.mobile.is_some() {
            return Err(Error::from_reason("Already initialized as mobile manager"));
        }

        // Initialize node manager if not already present
        if inner.node_owned.is_none() && inner.node_shared.is_none() {
            let node = NodeKeyManager::new(inner.logger.clone())
                .map_err(|e| Error::from_reason(e.to_string()))?;
            let node_id = node.get_node_id();
            inner.logger.set_node_id(node_id);
            inner.node_owned = Some(node);
        }

        Ok(())
    }

    #[napi]
    pub fn set_persistence_dir(&self, dir: String) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.persistence_dir = Some(dir.clone());
        if let Some(n) = inner.node_owned.as_mut() {
            n.set_persistence_dir(dir.clone().into());
        }
        if let Some(m) = inner.mobile.as_mut() {
            m.set_persistence_dir(dir.into());
        }
        Ok(())
    }

    #[napi]
    pub async fn mobile_initialize_user_root_key(&self) -> Result<()> {
        let mut guard = self.inner.lock().unwrap();
        if guard.mobile.is_none() {
            guard.mobile = Some(
                MobileKeyManager::new(guard.logger.clone())
                    .map_err(|e| Error::from_reason(e.to_string()))?,
            );
        }
        guard
            .mobile
            .as_mut()
            .unwrap()
            .initialize_user_root_key()
            .map_err(|e| Error::from_reason(e.to_string()))
            .map(|_| ())
    }

    /// Encrypt data using envelope encryption with mobile manager
    ///
    /// This function encrypts data for a specific network and profile public keys
    /// using the mobile key manager's envelope encryption.
    #[napi]
    pub fn mobile_encrypt_with_envelope(
        &self,
        data: Buffer,
        network_public_key: Option<Buffer>, // ← NETWORK PUBLIC KEY BYTES
        profile_public_keys: Vec<Buffer>,
    ) -> Result<Buffer> {
        let inner = self.inner.lock().unwrap();

        let mobile_manager = inner
            .mobile
            .as_ref()
            .ok_or_else(|| Error::from_reason("Mobile manager not initialized"))?;

        let network_public_key_ref = network_public_key.as_ref().map(|b| b.as_ref());
        let profile_keys_ref: Vec<Vec<u8>> =
            profile_public_keys.iter().map(|pk| pk.to_vec()).collect();

        let encrypted = mobile_manager
            .encrypt_with_envelope(&data, network_public_key_ref, profile_keys_ref)
            .map_err(|e| Error::from_reason(e.to_string()))?;

        // Convert EnvelopeEncryptedData to CBOR bytes like the FFI implementation
        let cbor_bytes = cbor::to_vec(&encrypted).map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(Buffer::from(cbor_bytes))
    }

    /// Encrypt data using envelope encryption with node manager
    ///
    /// This function encrypts data for a specific network and profile public keys
    /// using the node key manager's envelope encryption.
    #[napi]
    pub fn node_encrypt_with_envelope(
        &self,
        data: Buffer,
        network_public_key: Option<Buffer>, // ← NETWORK PUBLIC KEY BYTES
        profile_public_keys: Vec<Buffer>,
    ) -> Result<Buffer> {
        let inner = self.inner.lock().unwrap();

        let node_manager = inner
            .node_owned
            .as_ref()
            .ok_or_else(|| Error::from_reason("Node manager not initialized"))?;

        let network_public_key_ref = network_public_key.as_ref().map(|b| b.as_ref());
        let profile_keys_ref: Vec<Vec<u8>> =
            profile_public_keys.iter().map(|pk| pk.to_vec()).collect();

        let encrypted = node_manager
            .encrypt_with_envelope(&data, network_public_key_ref, profile_keys_ref)
            .map_err(|e| Error::from_reason(e.to_string()))?;

        // Convert EnvelopeEncryptedData to CBOR bytes like the FFI implementation
        let cbor_bytes = cbor::to_vec(&encrypted).map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(Buffer::from(cbor_bytes))
    }

    #[napi]
    pub fn node_get_node_id(&self) -> Result<String> {
        let inner = self.inner.lock().unwrap();
        let id = if let Some(n) = inner.node_owned.as_ref() {
            n.get_node_id()
        } else if let Some(n) = inner.node_shared.as_ref() {
            n.get_node_id()
        } else {
            return Err(Error::from_reason("Node not init"));
        };
        Ok(id)
    }

    #[napi]
    pub fn node_get_public_key(&self) -> Result<Buffer> {
        let inner = self.inner.lock().unwrap();
        let pk = if let Some(n) = inner.node_owned.as_ref() {
            n.get_node_public_key()
        } else if let Some(n) = inner.node_shared.as_ref() {
            n.get_node_public_key()
        } else {
            return Err(Error::from_reason("Node not init"));
        };
        Ok(Buffer::from(pk))
    }

    #[napi]
    pub fn enable_auto_persist(&self, enabled: bool) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(n) = inner.node_owned.as_mut() {
            n.enable_auto_persist(enabled);
        }
        if let Some(m) = inner.mobile.as_mut() {
            m.enable_auto_persist(enabled);
        }
        inner.auto_persist = enabled;
        Ok(())
    }

    #[napi]
    pub async fn wipe_persistence(&self) -> Result<()> {
        let inner = self.inner.lock().unwrap();
        if let Some(n) = inner.node_owned.as_ref() {
            n.wipe_persistence()
                .map_err(|e| Error::from_reason(e.to_string()))?;
        }
        if let Some(m) = inner.mobile.as_ref() {
            m.wipe_persistence()
                .map_err(|e| Error::from_reason(e.to_string()))?;
        }
        Ok(())
    }

    #[napi]
    pub async fn flush_state(&self) -> Result<()> {
        let inner = self.inner.lock().unwrap();
        if let Some(n) = inner.node_owned.as_ref() {
            n.flush_state()
                .map_err(|e| Error::from_reason(e.to_string()))?;
        }
        if let Some(m) = inner.mobile.as_ref() {
            m.flush_state()
                .map_err(|e| Error::from_reason(e.to_string()))?;
        }
        Ok(())
    }

    #[napi]
    pub fn node_get_keystore_state(&self) -> Result<i32> {
        let mut inner = self.inner.lock().unwrap();
        let mut ready = 0i32;
        if let Some(n) = inner.node_owned.as_mut() {
            match n.probe_and_load_state() {
                Ok(true) => ready = 1,
                _ => ready = 0,
            }
        }
        Ok(ready)
    }

    #[napi]
    pub fn mobile_get_keystore_state(&self) -> Result<i32> {
        let mut inner = self.inner.lock().unwrap();
        if inner.mobile.is_none() {
            inner.mobile = Some(
                MobileKeyManager::new(inner.logger.clone())
                    .map_err(|e| Error::from_reason(e.to_string()))?,
            );
        }
        let mut ready = 0i32;
        if let Some(m) = inner.mobile.as_mut() {
            match m.probe_and_load_state() {
                Ok(true) => ready = 1,
                _ => ready = 0,
            }
        }
        Ok(ready)
    }

    #[napi]
    pub fn get_keystore_caps(&self) -> Result<DeviceKeystoreCaps> {
        let inner = self.inner.lock().unwrap();
        let caps = if let Some(n) = inner.node_owned.as_ref() {
            n.get_keystore_caps().unwrap_or_default()
        } else if let Some(m) = inner.mobile.as_ref() {
            m.get_keystore_caps().unwrap_or_default()
        } else {
            runar_keys::keystore::DeviceKeystoreCaps::default()
        };
        let mut flags = 0u32;
        if caps.hardware_backed {
            flags |= 1;
        }
        if caps.biometric_gate {
            flags |= 2;
        }
        if caps.screenlock_required {
            flags |= 4;
        }
        if caps.strongbox {
            flags |= 8;
        }
        Ok(DeviceKeystoreCaps {
            version: caps.version,
            flags,
        })
    }

    #[napi]
    pub fn encrypt_local_data(&self, data: Buffer) -> Result<Buffer> {
        let inner = self.inner.lock().unwrap();
        let node_ref = inner
            .node_owned
            .as_ref()
            .or(inner.node_shared.as_deref())
            .ok_or_else(|| Error::from_reason("Node not init".to_string()))?;
        let out = node_ref
            .encrypt_local_data(&data)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(Buffer::from(out))
    }

    #[napi]
    pub fn decrypt_local_data(&self, data: Buffer) -> Result<Buffer> {
        let inner = self.inner.lock().unwrap();
        let node_ref = inner
            .node_owned
            .as_ref()
            .or(inner.node_shared.as_deref())
            .ok_or_else(|| Error::from_reason("Node not init".to_string()))?;
        let out = node_ref
            .decrypt_local_data(&data)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(Buffer::from(out))
    }

    #[napi]
    pub fn mobile_decrypt_envelope(&self, eed_cbor: Buffer) -> Result<Buffer> {
        let inner = self.inner.lock().unwrap();

        // Validate mobile manager exists
        if inner.mobile.is_none() {
            return Err(Error::from_reason("Mobile manager not initialized"));
        }

        let eed: runar_keys::mobile::EnvelopeEncryptedData =
            cbor::from_slice(&eed_cbor).map_err(|e| Error::from_reason(e.to_string()))?;

        let plain = inner
            .mobile
            .as_ref()
            .unwrap()
            .decrypt_with_network(&eed)
            .map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(Buffer::from(plain))
    }

    #[napi]
    pub fn node_decrypt_envelope(&self, eed_cbor: Buffer) -> Result<Buffer> {
        let inner = self.inner.lock().unwrap();

        // Validate node manager exists
        if inner.node_owned.is_none() && inner.node_shared.is_none() {
            return Err(Error::from_reason("Node manager not initialized"));
        }

        let eed: runar_keys::mobile::EnvelopeEncryptedData =
            cbor::from_slice(&eed_cbor).map_err(|e| Error::from_reason(e.to_string()))?;

        let plain = if let Some(n) = inner.node_owned.as_ref() {
            n.decrypt_envelope_data(&eed)
        } else if let Some(n) = inner.node_shared.as_ref() {
            n.decrypt_envelope_data(&eed)
        } else {
            return Err(Error::from_reason("Node manager not available"));
        }
        .map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(Buffer::from(plain))
    }

    #[napi]
    pub fn node_generate_csr(&self) -> Result<Buffer> {
        let mut inner = self.inner.lock().unwrap();
        let n = inner
            .node_owned
            .as_mut()
            .ok_or_else(|| Error::from_reason("node is shared; CSR not available".to_string()))?;
        let st = n
            .generate_csr()
            .map_err(|e| Error::from_reason(e.to_string()))?;
        cbor::to_vec(&st)
            .map(Buffer::from)
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub fn mobile_process_setup_token(&self, st_cbor: Buffer) -> Result<Buffer> {
        let mut inner = self.inner.lock().unwrap();
        if inner.mobile.is_none() {
            inner.mobile = Some(
                MobileKeyManager::new(inner.logger.clone())
                    .map_err(|e| Error::from_reason(e.to_string()))?,
            );
        }
        let st: runar_keys::mobile::SetupToken =
            cbor::from_slice(&st_cbor).map_err(|e| Error::from_reason(e.to_string()))?;
        let msg = inner
            .mobile
            .as_mut()
            .unwrap()
            .process_setup_token(&st)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        cbor::to_vec(&msg)
            .map(Buffer::from)
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub fn node_install_certificate(&self, ncm_cbor: Buffer) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        let n = inner.node_owned.as_mut().ok_or_else(|| {
            Error::from_reason("node is shared; install_certificate not available".to_string())
        })?;
        let msg: runar_keys::mobile::NodeCertificateMessage =
            cbor::from_slice(&ncm_cbor).map_err(|e| Error::from_reason(e.to_string()))?;
        n.install_certificate(msg)
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub fn mobile_generate_network_data_key(&self) -> Result<String> {
        let mut inner = self.inner.lock().unwrap();
        if inner.mobile.is_none() {
            inner.mobile = Some(
                MobileKeyManager::new(inner.logger.clone())
                    .map_err(|e| Error::from_reason(e.to_string()))?,
            );
        }
        inner
            .mobile
            .as_mut()
            .unwrap()
            .generate_network_data_key()
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub fn mobile_install_network_public_key(&self, network_pk: Buffer) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.mobile.is_none() {
            inner.mobile = Some(
                MobileKeyManager::new(inner.logger.clone())
                    .map_err(|e| Error::from_reason(e.to_string()))?,
            );
        }
        inner
            .mobile
            .as_mut()
            .unwrap()
            .install_network_public_key(&network_pk)
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub fn node_install_network_key(&self, nkm_cbor: Buffer) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        let n = inner.node_owned.as_mut().ok_or_else(|| {
            Error::from_reason("node is shared; install_network_key not available".to_string())
        })?;
        let msg: runar_keys::mobile::NetworkKeyMessage =
            cbor::from_slice(&nkm_cbor).map_err(|e| Error::from_reason(e.to_string()))?;
        n.install_network_key(msg)
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub fn set_local_node_info(&self, node_info_cbor: Buffer) -> Result<()> {
        let info: NodeInfo =
            cbor::from_slice(&node_info_cbor).map_err(|e| Error::from_reason(e.to_string()))?;
        let inner = self.inner.lock().unwrap();
        let mut holder = inner.local_node_info.lock().unwrap();
        *holder = Some(info);
        Ok(())
    }

    #[napi]
    pub fn encrypt_for_public_key(&self, data: Buffer, recipient_pk: Buffer) -> Result<Buffer> {
        let inner = self.inner.lock().unwrap();
        let node_ref = inner
            .node_owned
            .as_ref()
            .or(inner.node_shared.as_deref())
            .ok_or_else(|| Error::from_reason("Node not init".to_string()))?;
        let eed = node_ref
            .encrypt_for_public_key(&data, &recipient_pk)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        cbor::to_vec(&eed)
            .map(Buffer::from)
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub fn encrypt_for_network(&self, data: Buffer, network_id: String) -> Result<Buffer> {
        let inner = self.inner.lock().unwrap();
        let node_ref = inner
            .node_owned
            .as_ref()
            .or(inner.node_shared.as_deref())
            .ok_or_else(|| Error::from_reason("Node not init".to_string()))?;
        let eed = node_ref
            .encrypt_for_network(&data, &network_id)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        cbor::to_vec(&eed)
            .map(Buffer::from)
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub fn decrypt_network_data(&self, eed_cbor: Buffer) -> Result<Buffer> {
        let inner = self.inner.lock().unwrap();
        let node_ref = inner
            .node_owned
            .as_ref()
            .or(inner.node_shared.as_deref())
            .ok_or_else(|| Error::from_reason("Node not init".to_string()))?;
        let eed: runar_keys::mobile::EnvelopeEncryptedData =
            cbor::from_slice(&eed_cbor).map_err(|e| Error::from_reason(e.to_string()))?;
        let plain = node_ref
            .decrypt_network_data(&eed)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(Buffer::from(plain))
    }

    #[napi]
    pub fn encrypt_message_for_mobile(&self, message: Buffer, mobile_pk: Buffer) -> Result<Buffer> {
        let inner = self.inner.lock().unwrap();
        let node_ref = inner
            .node_owned
            .as_ref()
            .or(inner.node_shared.as_deref())
            .ok_or_else(|| Error::from_reason("Node not init".to_string()))?;
        let cipher = node_ref
            .encrypt_message_for_mobile(&message, &mobile_pk)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(Buffer::from(cipher))
    }

    #[napi]
    pub fn decrypt_message_from_mobile(&self, encrypted: Buffer) -> Result<Buffer> {
        let inner = self.inner.lock().unwrap();
        let node_ref = inner
            .node_owned
            .as_ref()
            .or(inner.node_shared.as_deref())
            .ok_or_else(|| Error::from_reason("Node not init".to_string()))?;
        let plain = node_ref
            .decrypt_message_from_mobile(&encrypted)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(Buffer::from(plain))
    }

    #[napi]
    pub fn mobile_derive_user_profile_key(&self, label: String) -> Result<Buffer> {
        let mut inner = self.inner.lock().unwrap();
        if inner.mobile.is_none() {
            inner.mobile = Some(
                MobileKeyManager::new(inner.logger.clone())
                    .map_err(|e| Error::from_reason(e.to_string()))?,
            );
        }
        let pk = inner
            .mobile
            .as_mut()
            .unwrap()
            .derive_user_profile_key(&label)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(Buffer::from(pk))
    }

    #[napi]
    pub fn mobile_get_network_public_key(&self, network_id: String) -> Result<Buffer> {
        let mut inner = self.inner.lock().unwrap();
        if inner.mobile.is_none() {
            inner.mobile = Some(
                MobileKeyManager::new(inner.logger.clone())
                    .map_err(|e| Error::from_reason(e.to_string()))?,
            );
        }
        let pk = inner
            .mobile
            .as_mut()
            .unwrap()
            .get_network_public_key(&network_id)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(Buffer::from(pk))
    }

    #[napi]
    pub fn mobile_create_network_key_message(
        &self,
        network_id: String,
        node_agreement_pk: Buffer,
    ) -> Result<Buffer> {
        let mut inner = self.inner.lock().unwrap();
        if inner.mobile.is_none() {
            inner.mobile = Some(
                MobileKeyManager::new(inner.logger.clone())
                    .map_err(|e| Error::from_reason(e.to_string()))?,
            );
        }
        let msg = inner
            .mobile
            .as_mut()
            .unwrap()
            .create_network_key_message(&network_id, &node_agreement_pk)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        cbor::to_vec(&msg)
            .map(Buffer::from)
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub fn ensure_symmetric_key(&self, key_name: String) -> Result<Buffer> {
        let mut inner = self.inner.lock().unwrap();
        let key = if let Some(n) = inner.node_owned.as_mut() {
            n.ensure_symmetric_key(&key_name)
        } else if let Some(_n) = inner.node_shared.as_ref() {
            // For shared NodeKeyManager, we can't modify it, so we can't ensure symmetric keys
            return Err(Error::from_reason(
                "node is shared; ensure_symmetric_key not available",
            ));
        } else {
            return Err(Error::from_reason("Node not init"));
        }
        .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(Buffer::from(key))
    }

    /// Get the user public key after mobile initialization
    /// This is essential for encrypting setup tokens to the mobile
    #[napi]
    pub fn mobile_get_user_public_key(&self) -> Result<Buffer> {
        let inner = self.inner.lock().unwrap();

        // Validate mobile manager exists
        if inner.mobile.is_none() {
            return Err(Error::from_reason("Mobile manager not initialized"));
        }

        let pk = inner
            .mobile
            .as_ref()
            .unwrap()
            .get_user_public_key()
            .map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(Buffer::from(pk))
    }

    /// Get the node agreement public key
    /// This is used for verifying agreement keys in CSR flow
    #[napi]
    pub fn node_get_agreement_public_key(&self) -> Result<Buffer> {
        let inner = self.inner.lock().unwrap();

        // Validate node manager exists
        if inner.node_owned.is_none() && inner.node_shared.is_none() {
            return Err(Error::from_reason("Node manager not initialized"));
        }

        let pk = if let Some(n) = inner.node_owned.as_ref() {
            n.get_node_agreement_public_key()
        } else if let Some(n) = inner.node_shared.as_ref() {
            n.get_node_agreement_public_key()
        } else {
            return Err(Error::from_reason("Node manager not available"));
        }
        .map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(Buffer::from(pk))
    }
}

#[cfg(all(feature = "linux-keystore", target_os = "linux"))]
#[napi]
impl Keys {
    #[napi]
    pub fn register_linux_device_keystore(&self, service: String, account: String) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        let ks: Arc<dyn runar_keys::keystore::DeviceKeystore> = Arc::new(
            runar_keys::keystore::linux::LinuxDeviceKeystore::new(&service, &account)
                .map_err(|e| Error::from_reason(e.to_string()))?,
        );
        if let Some(n) = inner.node_owned.as_mut() {
            n.register_device_keystore(ks.clone());
        }
        if let Some(m) = inner.mobile.as_mut() {
            m.register_device_keystore(ks.clone());
        }
        Ok(())
    }
}

impl Default for Keys {
    fn default() -> Self {
        Self::new()
    }
}

// Transport
#[napi]
pub struct Transport {
    inner: Arc<Mutex<TransportInner>>,
}

type EventTsfn = ThreadsafeFunction<(String, Buffer)>;

struct TransportInner {
    transport: Arc<QuicTransport>,
    pending:
        AsyncMutex<HashMap<String, oneshot::Sender<runar_transporter::transport::NetworkMessage>>>,
}

#[napi]
impl Transport {
    #[napi(constructor)]
    pub fn new(keys: &Keys, options_cbor: Buffer) -> Result<Self> {
        // Extract shared NodeKeyManager and logger/resolver
        let (km_arc, logger, local_info_arc, node_pk) = {
            let mut guard = keys.inner.lock().unwrap();
            let km_arc: Arc<NodeKeyManager> = if let Some(shared) = guard.node_shared.as_ref() {
                Arc::clone(shared)
            } else if let Some(owned) = guard.node_owned.take() {
                let arc = Arc::new(owned);
                guard.node_shared = Some(Arc::clone(&arc));
                arc
            } else {
                return Err(Error::from_reason("Node not init"));
            };
            let logger = guard.logger.clone();
            let node_pk = km_arc.get_node_public_key();
            (km_arc, logger, guard.local_node_info.clone(), node_pk)
        };

        // Parse bind address from options (CBOR: { bind_addr: "ip:port" })
        let mut bind_addr: std::net::SocketAddr = "0.0.0.0:0".parse().unwrap();
        if let Ok(serde_cbor::Value::Map(map)) =
            cbor::from_slice::<serde_cbor::Value>(&options_cbor)
        {
            if let Some(serde_cbor::Value::Text(addr)) =
                map.get(&serde_cbor::Value::Text("bind_addr".into()))
            {
                if let Ok(parsed) = addr.parse() {
                    bind_addr = parsed
                }
            }
        }

        // Threadsafe event emitter holder and pending map
        let event_tsfn: Arc<Mutex<Option<EventTsfn>>> = Arc::new(Mutex::new(None));
        let pending_map: Arc<
            AsyncMutex<
                HashMap<String, oneshot::Sender<runar_transporter::transport::NetworkMessage>>,
            >,
        > = Arc::new(AsyncMutex::new(HashMap::new()));

        // Build transport options with callbacks
        let get_local_node_info: runar_transporter::transport::GetLocalNodeInfoCallback = {
            let local_info_arc = Arc::clone(&local_info_arc);
            let km_arc = Arc::clone(&km_arc);
            Arc::new(move || {
                let local_info_arc = Arc::clone(&local_info_arc);
                let km_arc = Arc::clone(&km_arc);
                Box::pin(async move {
                    if let Some(info) = local_info_arc.lock().unwrap().clone() {
                        Ok(info)
                    } else {
                        Ok(runar_schemas::NodeInfo {
                            node_public_key: km_arc.get_node_public_key(),
                            network_ids: Vec::new(),
                            addresses: vec!["0.0.0.0:0".to_string()],
                            node_metadata: runar_schemas::NodeMetadata {
                                services: Vec::new(),
                                subscriptions: Vec::new(),
                            },
                            version: 0,
                        })
                    }
                })
            })
        };

        let request_cb: runar_transporter::transport::RequestCallback = {
            let event_tsfn = Arc::clone(&event_tsfn);
            let pending_map = Arc::clone(&pending_map);
            Arc::new(move |req: runar_transporter::transport::NetworkMessage| {
                let event_tsfn = Arc::clone(&event_tsfn);
                let pending_map = Arc::clone(&pending_map);
                Box::pin(async move {
                    // If no JS listener registered, auto-echo to avoid hangs in tests
                    let maybe_tsfn_present = event_tsfn.lock().unwrap().is_some();
                    if !maybe_tsfn_present {
                        return Ok(runar_transporter::transport::NetworkMessage {
                            source_node_id: String::new(),
                            destination_node_id: String::new(),
                            message_type: 5, // MESSAGE_TYPE_RESPONSE
                            payload: runar_transporter::transport::NetworkMessagePayloadItem {
                                path: req.payload.path.clone(),
                                payload_bytes: req.payload.payload_bytes.clone(),
                                correlation_id: req.payload.correlation_id.clone(),
                                network_public_key: None,
                                profile_public_keys: req.payload.profile_public_keys.clone(),
                            },
                        });
                    }
                    // Else, register oneshot and emit event for JS to complete
                    let (tx, rx) = oneshot::channel();
                    {
                        let mut map = pending_map.lock().await;
                        map.insert(req.payload.correlation_id.clone(), tx);
                    }
                    if let Some(tsfn) = event_tsfn.lock().unwrap().as_ref() {
                        let payload = cbor::to_vec(&req)
                            .map_err(|e| anyhow!(format!("Failed to CBOR encode request: {e}")))?;
                        let _ = tsfn.call(
                            Ok(("request".to_string(), Buffer::from(payload))),
                            ThreadsafeFunctionCallMode::NonBlocking,
                        );
                    }
                    let resp = rx.await.map_err(|_| anyhow!("request canceled"))?;
                    Ok(resp)
                })
            })
        };

        let event_cb: runar_transporter::transport::EventCallback = {
            let event_tsfn = Arc::clone(&event_tsfn);
            Arc::new(move |ev: runar_transporter::transport::NetworkMessage| {
                let event_tsfn = Arc::clone(&event_tsfn);
                Box::pin(async move {
                    if let Some(tsfn) = event_tsfn.lock().unwrap().as_ref() {
                        if let Ok(payload) = cbor::to_vec(&ev) {
                            let _ = tsfn.call(
                                Ok(("event".to_string(), Buffer::from(payload))),
                                ThreadsafeFunctionCallMode::NonBlocking,
                            );
                        }
                    }
                    Ok(())
                })
            })
        };

        let peer_connected_cb: runar_transporter::transport::PeerConnectedCallback = {
            let event_tsfn = Arc::clone(&event_tsfn);
            Arc::new(move |_peer_id: String, info: runar_schemas::NodeInfo| {
                let event_tsfn = Arc::clone(&event_tsfn);
                Box::pin(async move {
                    if let Some(tsfn) = event_tsfn.lock().unwrap().as_ref() {
                        if let Ok(payload) = cbor::to_vec(&info) {
                            let _ = tsfn.call(
                                Ok(("peerConnected".to_string(), Buffer::from(payload))),
                                ThreadsafeFunctionCallMode::NonBlocking,
                            );
                        }
                    }
                })
            })
        };

        let opts = QuicTransportOptions::new()
            .with_bind_addr(bind_addr)
            .with_local_node_public_key(node_pk)
            .with_logger(logger)
            .with_key_manager(km_arc)
            .with_get_local_node_info(get_local_node_info)
            .with_request_callback(request_cb)
            .with_event_callback(event_cb)
            .with_peer_connected_callback(peer_connected_cb);

        let transport = QuicTransport::new(opts)
            .map_err(|e| Error::from_reason(format!("Transport init error: {e}")))?;

        Ok(Transport {
            inner: Arc::new(Mutex::new(TransportInner {
                transport: Arc::new(transport),
                pending: AsyncMutex::new(HashMap::new()),
            })),
        })
    }

    // Intentionally not exposing event registration to JS yet; tests use request/publish directly

    #[napi]
    pub async fn complete_request(
        &self,
        request_id: String,
        response_payload: Buffer,
        profile_public_keys: Vec<Buffer>,
    ) -> Result<()> {
        let guard = self.inner.lock().unwrap();
        let mut map = guard.pending.blocking_lock();
        if let Some(sender) = map.remove(&request_id) {
            let profile_pks: Vec<Vec<u8>> =
                profile_public_keys.iter().map(|pk| pk.to_vec()).collect();
            let _ = sender.send(runar_transporter::transport::NetworkMessage {
                source_node_id: String::new(),
                destination_node_id: String::new(),
                message_type: 5, // MESSAGE_TYPE_RESPONSE
                payload: runar_transporter::transport::NetworkMessagePayloadItem {
                    path: String::new(),
                    payload_bytes: response_payload.to_vec(),
                    correlation_id: String::new(),
                    network_public_key: None,
                    profile_public_keys: profile_pks,
                },
            });
            Ok(())
        } else {
            Err(Error::from_reason("unknown request_id"))
        }
    }

    // --- Transport control & messaging API ---

    #[napi]
    pub async fn start(&self) -> Result<()> {
        let t = { self.inner.lock().unwrap().transport.clone() };
        t.start()
            .await
            .map_err(|e| Error::from_reason(format!("start failed: {e}")))
    }

    #[napi]
    pub async fn stop(&self) -> Result<()> {
        let t = { self.inner.lock().unwrap().transport.clone() };
        t.stop()
            .await
            .map_err(|e| Error::from_reason(format!("stop failed: {e}")))
    }

    #[napi]
    pub async fn connect_peer(&self, peer_info_cbor: Buffer) -> Result<()> {
        let peer: runar_transporter::discovery::multicast_discovery::PeerInfo =
            cbor::from_slice(&peer_info_cbor)
                .map_err(|e| Error::from_reason(format!("peer decode failed: {e}")))?;
        let t = { self.inner.lock().unwrap().transport.clone() };
        runar_transporter::transport::NetworkTransport::connect_peer(t, peer)
            .await
            .map_err(|e| Error::from_reason(format!("connect_peer failed: {e}")))
    }

    #[napi]
    pub async fn is_connected(&self, peer_id: String) -> Result<bool> {
        let t = { self.inner.lock().unwrap().transport.clone() };
        Ok(t.is_connected(&peer_id).await)
    }

    #[napi]
    pub async fn is_connected_to_public_key(&self, peer_public_key: Buffer) -> Result<bool> {
        let id = runar_common::compact_ids::compact_id(&peer_public_key);
        self.is_connected(id)
            .await
            .map_err(|e| Error::from_reason(format!("is_connected failed: {e}")))
    }

    #[napi]
    pub async fn request(
        &self,
        path: String,
        correlation_id: String,
        payload: Buffer,
        dest_peer_id: String,
        network_public_key: Option<Buffer>,
        profile_public_keys: Option<Vec<Buffer>>,
    ) -> Result<Buffer> {
        let t = { self.inner.lock().unwrap().transport.clone() };
        let network_pk = network_public_key.map(|b| b.to_vec());
        let profile_pks = profile_public_keys
            .map(|pks| pks.iter().map(|pk| pk.to_vec()).collect())
            .unwrap_or_default();

        let res = t
            .request(
                &path,
                &correlation_id,
                payload.to_vec(),
                &dest_peer_id,
                network_pk,
                profile_pks,
            )
            .await
            .map_err(|e| Error::from_reason(format!("request failed: {e}")))?;
        Ok(Buffer::from(res))
    }

    #[napi]
    pub async fn request_to_public_key(
        &self,
        path: String,
        correlation_id: String,
        payload: Buffer,
        dest_public_key: Buffer,
        network_public_key: Option<Buffer>,
        profile_public_keys: Option<Vec<Buffer>>,
    ) -> Result<Buffer> {
        let id = runar_common::compact_ids::compact_id(&dest_public_key);
        self.request(
            path,
            correlation_id,
            payload,
            id,
            network_public_key,
            profile_public_keys,
        )
        .await
    }

    #[napi]
    pub async fn publish(
        &self,
        path: String,
        correlation_id: String,
        payload: Buffer,
        dest_peer_id: String,
        network_public_key: Option<Buffer>,
    ) -> Result<()> {
        let t = { self.inner.lock().unwrap().transport.clone() };
        let network_pk = network_public_key.map(|b| b.to_vec());
        t.publish(
            &path,
            &correlation_id,
            payload.to_vec(),
            &dest_peer_id,
            network_pk,
        )
        .await
        .map_err(|e| Error::from_reason(format!("publish failed: {e}")))
    }

    #[napi]
    pub async fn publish_to_public_key(
        &self,
        path: String,
        correlation_id: String,
        payload: Buffer,
        dest_public_key: Buffer,
        network_public_key: Option<Buffer>,
    ) -> Result<()> {
        let id = runar_common::compact_ids::compact_id(&dest_public_key);
        self.publish(path, correlation_id, payload, id, network_public_key)
            .await
    }

    #[napi]
    pub async fn update_peers(&self, node_info_cbor: Buffer) -> Result<()> {
        let info: runar_schemas::NodeInfo = cbor::from_slice(&node_info_cbor)
            .map_err(|e| Error::from_reason(format!("NodeInfo decode failed: {e}")))?;
        let t = { self.inner.lock().unwrap().transport.clone() };
        t.update_peers(info)
            .await
            .map_err(|e| Error::from_reason(format!("update_peers failed: {e}")))
    }
}

// Discovery implementation
#[napi]
pub struct Discovery {
    inner: Arc<Mutex<DiscoveryInner>>,
}

struct DiscoveryInner {
    discovery: Arc<runar_transporter::discovery::MulticastDiscovery>,
}

fn parse_discovery_options(cbor_bytes: &[u8]) -> DiscoveryOptions {
    let mut opts = DiscoveryOptions::default();
    if let Ok(serde_cbor::Value::Map(m)) = cbor::from_slice::<serde_cbor::Value>(cbor_bytes) {
        for (k, v) in m {
            if let serde_cbor::Value::Text(s) = k {
                match s.as_str() {
                    "announce_interval_ms" => {
                        if let serde_cbor::Value::Integer(ms) = v {
                            if ms > 0 {
                                opts.announce_interval = std::time::Duration::from_millis(ms as u64)
                            }
                        }
                    }
                    "discovery_timeout_ms" => {
                        if let serde_cbor::Value::Integer(ms) = v {
                            if ms > 0 {
                                opts.discovery_timeout = std::time::Duration::from_millis(ms as u64)
                            }
                        }
                    }
                    "debounce_window_ms" => {
                        if let serde_cbor::Value::Integer(ms) = v {
                            if ms > 0 {
                                opts.debounce_window = std::time::Duration::from_millis(ms as u64)
                            }
                        }
                    }
                    "use_multicast" => {
                        if let serde_cbor::Value::Bool(b) = v {
                            opts.use_multicast = b
                        }
                    }
                    "local_network_only" => {
                        if let serde_cbor::Value::Bool(b) = v {
                            opts.local_network_only = b
                        }
                    }
                    "multicast_group" => {
                        if let serde_cbor::Value::Text(addr) = v {
                            opts.multicast_group = addr
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    opts
}

#[napi]
impl Discovery {
    #[napi(constructor)]
    pub fn new(keys: &Keys, options_cbor: Buffer) -> Result<Self> {
        let inner = keys.inner.lock().unwrap();
        let node_pk = if let Some(n) = inner.node_owned.as_ref() {
            n.get_node_public_key()
        } else if let Some(n) = inner.node_shared.as_ref() {
            n.get_node_public_key()
        } else {
            return Err(Error::from_reason("Node not init"));
        };
        let mut addrs: Vec<String> = Vec::new();
        if let Ok(serde_cbor::Value::Map(map)) =
            cbor::from_slice::<serde_cbor::Value>(&options_cbor)
        {
            if let Some(serde_cbor::Value::Array(arr)) =
                map.get(&serde_cbor::Value::Text("local_addresses".into()))
            {
                for it in arr {
                    if let serde_cbor::Value::Text(a) = it {
                        addrs.push(a.to_string())
                    }
                }
            }
        }
        let local_peer =
            runar_transporter::discovery::multicast_discovery::PeerInfo::new(node_pk, addrs);
        let logger = inner.logger.clone();
        let opts = parse_discovery_options(&options_cbor);
        let disc = RT
            .block_on(runar_transporter::discovery::MulticastDiscovery::new(
                local_peer,
                opts,
                (*logger).clone(),
            ))
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(Discovery {
            inner: Arc::new(Mutex::new(DiscoveryInner {
                discovery: Arc::new(disc),
            })),
        })
    }

    #[napi]
    pub async fn init(&self, options_cbor: Buffer) -> Result<()> {
        let opts = parse_discovery_options(&options_cbor);
        let d = { self.inner.lock().unwrap().discovery.clone() };
        d.init(opts)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub async fn bind_events_to_transport(&self, transport: &Transport) -> Result<()> {
        let d = { self.inner.lock().unwrap().discovery.clone() };
        let t = { transport.inner.lock().unwrap().transport.clone() };
        let listener: runar_transporter::discovery::DiscoveryListener =
            Arc::new(move |ev: DiscoveryEvent| {
                let t = t.clone();
                Box::pin(async move {
                    match ev {
                        DiscoveryEvent::Discovered(peer) | DiscoveryEvent::Updated(peer) => {
                            let _ = NetworkTransport::connect_peer(t.clone(), peer).await;
                        }
                        DiscoveryEvent::Lost(_id) => {
                            // Optional: disconnect
                        }
                    }
                })
            });
        d.subscribe(listener)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub async fn start_announcing(&self) -> Result<()> {
        let d = { self.inner.lock().unwrap().discovery.clone() };
        d.start_announcing()
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub async fn stop_announcing(&self) -> Result<()> {
        let d = { self.inner.lock().unwrap().discovery.clone() };
        d.stop_announcing()
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub async fn shutdown(&self) -> Result<()> {
        let d = { self.inner.lock().unwrap().discovery.clone() };
        d.shutdown()
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub async fn update_local_peer_info(&self, peer_info_cbor: Buffer) -> Result<()> {
        let d = { self.inner.lock().unwrap().discovery.clone() };
        let peer: runar_transporter::discovery::multicast_discovery::PeerInfo =
            cbor::from_slice(&peer_info_cbor).map_err(|e| Error::from_reason(e.to_string()))?;
        d.update_local_peer_info(peer)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }
}
