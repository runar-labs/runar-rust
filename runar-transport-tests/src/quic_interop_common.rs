use anyhow::{anyhow, Context, Result};
use clap::Parser;
use runar_common::logging::{Component, Logger};
use runar_common::routing::TopicPath;
use runar_schemas::NodeInfo;
use runar_transporter::transport::{NetworkMessage, NetworkMessagePayloadItem};
// Intentionally not importing QuicTransportOptions here
use runar_keys::{mobile::EnvelopeEncryptedData, Result as KeyResult};
use runar_schemas::{ActionMetadata, NodeMetadata, ServiceMetadata};
use runar_serializer::traits::{EnvelopeCrypto, LabelResolverConfig, LabelValue};
use runar_transporter::transport::MESSAGE_TYPE_REQUEST;
use rustls_pemfile::{read_all, Item};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Parser, Debug, Clone)]
pub struct CommonArgs {
    /// Server: host:port to bind. Client: ignored.
    #[arg(long)]
    pub bind: Option<String>,

    /// Client: peer host:port to connect to.
    #[arg(long)]
    pub peer: Option<String>,

    /// CA certificate file (PEM)
    #[arg(long)]
    pub ca: String,

    /// Node certificate file (PEM)
    #[arg(long)]
    pub cert: String,

    /// Private key file (PEM, PKCS#8)
    #[arg(long)]
    pub key: String,

    /// Node id (SNI and compact id alignment). If omitted we derive from cert public key where possible.
    #[arg(long)]
    pub node_id: Option<String>,

    /// Timeout in seconds
    #[arg(long, default_value_t = 5u64)]
    pub timeout: u64,
}

pub fn read_pem_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut f = File::open(path).with_context(|| format!("open ca: {path}"))?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    let mut certs = Vec::new();
    for item in read_all(&mut &buf[..])? {
        if let Item::X509Certificate(der) = item {
            certs.push(CertificateDer::from(der));
        }
    }
    if certs.is_empty() {
        return Err(anyhow!("no certificates in {path}"));
    }
    Ok(certs)
}

pub fn read_pem_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let mut f = File::open(path).with_context(|| format!("open key: {path}"))?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    for item in read_all(&mut &buf[..])? {
        match item {
            Item::PKCS8Key(der) => {
                return Ok(PrivateKeyDer::from(PrivatePkcs8KeyDer::from(der)));
            }
            Item::ECKey(der) => {
                return Ok(PrivateKeyDer::from(PrivateSec1KeyDer::from(der)));
            }
            _ => {}
        }
    }
    Err(anyhow!("no private key found in {path}"))
}

pub fn default_logger() -> Arc<Logger> {
    Arc::new(Logger::new_root(Component::Transporter))
}

/// Minimal NoCrypto that satisfies EnvelopeCrypto for interop (no-op envelope)
pub struct NoCrypto {
    network_public_key: Vec<u8>,
}

impl Default for NoCrypto {
    fn default() -> Self {
        Self::new()
    }
}

impl NoCrypto {
    pub fn new() -> Self {
        // Generate a proper network public key for interop tests
        use p256::ecdsa::SigningKey;
        use rand::thread_rng;
        let signing_key = SigningKey::random(&mut thread_rng());
        let public_key = signing_key.verifying_key().to_encoded_point(false);
        Self {
            network_public_key: public_key.as_bytes().to_vec(),
        }
    }
}

impl EnvelopeCrypto for NoCrypto {
    fn encrypt_with_envelope(
        &self,
        data: &[u8],
        _network_public_key: Option<&[u8]>,
        _profile_public_keys: Vec<Vec<u8>>,
    ) -> KeyResult<EnvelopeEncryptedData> {
        use std::collections::HashMap;
        Ok(EnvelopeEncryptedData {
            encrypted_data: data.to_vec(),
            network_public_key: Some(self.network_public_key.clone()),
            network_encrypted_key: vec![],
            profile_encrypted_keys: HashMap::new(),
        })
    }

    fn decrypt_envelope_data(&self, env: &EnvelopeEncryptedData) -> KeyResult<Vec<u8>> {
        Ok(env.encrypted_data.clone())
    }

    fn has_network_private_key(&self, _network_public_key: &[u8]) -> KeyResult<Vec<u8>> {
        Ok(self.network_public_key.clone())
    }

    fn get_network_public_key_by_id(&self, _network_id: &str) -> KeyResult<Vec<u8>> {
        Ok(self.network_public_key.clone())
    }
}

pub fn default_label_resolver() -> Arc<LabelResolverConfig> {
    // Generate a proper network public key for interop tests
    use p256::ecdsa::SigningKey;
    use rand::thread_rng;
    let signing_key = SigningKey::random(&mut thread_rng());
    let public_key = signing_key.verifying_key().to_encoded_point(false);
    let network_public_key = public_key.as_bytes().to_vec();

    let mut mappings = HashMap::new();
    mappings.insert(
        "interop".to_string(),
        LabelValue {
            network_public_key: Some(network_public_key),
            user_key_spec: None,
        },
    );
    Arc::new(LabelResolverConfig {
        label_mappings: mappings,
    })
}

pub fn build_node_info(node_id: &str, bind_addr: &SocketAddr) -> NodeInfo {
    // minimal metadata
    let services = vec![ServiceMetadata {
        network_id: "interop".to_string(),
        service_path: "interop".to_string(),
        name: "interop".to_string(),
        version: "0.1.0".to_string(),
        description: "interop echo".to_string(),
        actions: vec![ActionMetadata {
            name: "echo".to_string(),
            description: "echo".to_string(),
            input_schema: None,
            output_schema: None,
        }],
        registration_time: now_secs(),
        last_start_time: None,
    }];
    let node_metadata = NodeMetadata {
        services,
        subscriptions: vec![],
    };
    NodeInfo {
        node_public_key: node_id.as_bytes().to_vec(),
        network_ids: vec!["interop".to_string()],
        addresses: vec![bind_addr.to_string()],
        node_metadata,
        version: 1,
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

pub fn topic_echo() -> TopicPath {
    TopicPath::new("interop/echo", "interop").expect("valid topic")
}

pub fn make_echo_request(source_id: &str, dest_id: &str, payload: &[u8]) -> NetworkMessage {
    NetworkMessage {
        source_node_id: source_id.to_string(),
        destination_node_id: dest_id.to_string(),
        message_type: MESSAGE_TYPE_REQUEST,
        payload: NetworkMessagePayloadItem {
            path: topic_echo().as_str().to_string(),
            payload_bytes: payload.to_vec(),
            correlation_id: Uuid::new_v4().to_string(),
            network_public_key: None,
            profile_public_keys: vec![],
        },
    }
}
