pub mod encryption;
pub mod error;
pub mod hd;
pub mod manager;
pub mod token;
pub mod types;

pub use crate::encryption::{decrypt_data, derive_symmetric_key_from_node_key, encrypt_data};
pub use error::KeyError;
pub use hd::{
    derive_network_key, derive_node_key_from_master_key, derive_quic_key_from_network_key,
};
pub use manager::KeyManager;
pub use token::{AccessToken, Capability};
pub use types::{
    current_unix_timestamp, NetworkId, NetworkKey, NodeKey, PeerId, QuicKey, UserMasterKey,
};

pub type Result<T> = std::result::Result<T, KeyError>;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
