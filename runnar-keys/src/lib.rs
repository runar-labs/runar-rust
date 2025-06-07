pub mod error;
pub mod types;
pub mod hd;
pub mod token;
pub mod encryption;
pub mod manager;

pub use error::KeyError;
pub use types::{
    UserMasterKey,
    NetworkId,
    NetworkKey,
    QuicKey,
    PeerId,
    NodeKey,
    current_unix_timestamp,
};
pub use hd::{
    derive_network_key,
    derive_quic_key_from_network_key,
    derive_node_key_from_master_key,
};
pub use token::{AccessToken, Capability};
pub use crate::encryption::{decrypt_data, derive_symmetric_key_from_node_key, encrypt_data};
pub use manager::KeyManager;

pub type Result<T> = std::result::Result<T, KeyError>;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}

