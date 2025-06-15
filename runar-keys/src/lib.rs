//! Runar Keys – public API facade

pub mod access_token;
pub mod encryption;
pub mod error;
pub mod hd;
pub mod manager;
pub mod types;

pub use error::{KeyError, Result};

pub use types::{
    current_unix_timestamp, NetworkId, NetworkKey, NodeKey, PeerId, SharedKey, UserMasterKey,
    UserProfileKey,
};

pub use hd::{derive_network_key, derive_node_key, derive_profile_key};

pub use encryption::{
    decrypt, derive_network_shared_key, derive_node_shared_key, derive_symmetric_key_from_node,
    encrypt, SYMMETRIC_KEY_LEN,
};

pub use access_token::{AccessToken, Capability};

pub use manager::KeyManager;
