// Peer directory: single source of truth for known peers

use std::sync::Arc;

use dashmap::DashMap;

use crate::network::discovery::NodeInfo;

#[derive(Default)]
pub struct PeerDirectory {
    inner: Arc<DashMap<String, PeerRecord>>, // peer_id -> record
}

#[derive(Clone)]
struct PeerRecord {
    connected: bool,
    last_capabilities_version: i64,
    node_info: Option<NodeInfo>,
}

impl PeerRecord {
    fn new() -> Self {
        Self {
            connected: false,
            last_capabilities_version: -1,
            node_info: None,
        }
    }
}

impl PeerDirectory {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
        }
    }

    pub fn is_connected(&self, peer_id: &str) -> bool {
        self.inner
            .get(peer_id)
            .map(|r| r.connected)
            .unwrap_or(false)
    }

    pub fn mark_connected(&self, peer_id: &str) {
        let mut entry = self
            .inner
            .entry(peer_id.to_string())
            .or_insert_with(PeerRecord::new);
        entry.connected = true;
    }

    pub fn mark_disconnected(&self, peer_id: &str) {
        if let Some(mut rec) = self.inner.get_mut(peer_id) {
            rec.connected = false;
        }
    }

    pub fn set_node_info(&self, peer_id: &str, info: NodeInfo) {
        let mut entry = self
            .inner
            .entry(peer_id.to_string())
            .or_insert_with(PeerRecord::new);
        entry.last_capabilities_version = info.version;
        entry.node_info = Some(info);
    }

    pub fn get_node_info(&self, peer_id: &str) -> Option<NodeInfo> {
        self.inner.get(peer_id).and_then(|r| r.node_info.clone())
    }

    pub fn take_node_info(&self, peer_id: &str) -> Option<NodeInfo> {
        if let Some(mut rec) = self.inner.get_mut(peer_id) {
            let info = rec.node_info.clone();
            rec.node_info = None;
            return info;
        }
        None
    }
}


