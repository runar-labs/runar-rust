//! In-memory KeyManager.

use crate::error::Result;
use crate::hd::{derive_network_key, derive_node_key};
use crate::types::{NetworkKey, NodeKey, UserMasterKey};
use std::collections::HashMap;

pub struct KeyManager {
    master: UserMasterKey,
    networks: HashMap<u32, NetworkKey>,
    nodes: HashMap<u32, NodeKey>,
}

impl KeyManager {
    pub fn new(master: UserMasterKey) -> Self {
        Self {
            master,
            networks: HashMap::new(),
            nodes: HashMap::new(),
        }
    }

    pub fn get_or_create_network(&mut self, index: u32) -> Result<&NetworkKey> {
        if !self.networks.contains_key(&index) {
            let nk = derive_network_key(&self.master, index)?;
            self.networks.insert(index, nk);
        }
        Ok(self.networks.get(&index).unwrap())
    }

    pub fn get_or_create_node(&mut self, index: u32) -> Result<&NodeKey> {
        if !self.nodes.contains_key(&index) {
            let nk = derive_node_key(&self.master, index)?;
            self.nodes.insert(index, nk);
        }
        Ok(self.nodes.get(&index).unwrap())
    }
}
