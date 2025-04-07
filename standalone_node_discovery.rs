// Standalone Node Discovery Example
//
// This file can be run directly with `rustc standalone_node_discovery.rs && ./standalone_node_discovery`
// or with cargo by creating a simple project.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};
use std::env;

// A simple node identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct NodeIdentifier {
    network_id: String,
    node_id: String,
}

impl NodeIdentifier {
    fn new(network_id: impl Into<String>, node_id: impl Into<String>) -> Self {
        Self {
            network_id: network_id.into(),
            node_id: node_id.into(),
        }
    }
}

// Information about a node in the network
#[derive(Clone, Debug)]
struct NodeInfo {
    identifier: NodeIdentifier,
    address: String,
    capabilities: Vec<String>,
    last_seen: SystemTime,
}

// A simple in-memory node discovery implementation
struct SimpleDiscovery {
    nodes: Arc<RwLock<HashMap<String, NodeInfo>>>,
    local_node: RwLock<Option<NodeInfo>>,
}

impl SimpleDiscovery {
    fn new() -> Self {
        Self {
            nodes: Arc::new(RwLock::new(HashMap::new())),
            local_node: RwLock::new(None),
        }
    }
    
    // Register this node's information
    fn register_node(&self, info: NodeInfo) {
        // Store local node info
        *self.local_node.write().unwrap() = Some(info.clone());
        
        // Add to nodes map
        self.nodes.write().unwrap().insert(info.identifier.node_id.clone(), info);
    }
    
    // Add a test node for simulation
    fn add_test_node(&self, info: NodeInfo) {
        self.nodes.write().unwrap().insert(info.identifier.node_id.clone(), info);
    }
    
    // Find all nodes
    fn discover_nodes(&self) -> Vec<NodeInfo> {
        let nodes = self.nodes.read().unwrap();
        nodes.values().cloned().collect()
    }
    
    // Find nodes in a specific network
    fn find_nodes_by_network(&self, network_id: &str) -> Vec<NodeInfo> {
        let nodes = self.nodes.read().unwrap();
        nodes.values()
             .filter(|info| info.identifier.network_id == network_id)
             .cloned()
             .collect()
    }
}

// Generate a random ID for demo purposes
fn generate_random_id() -> String {
    let random_bytes: [u8; 4] = [
        rand::random::<u8>(),
        rand::random::<u8>(),
        rand::random::<u8>(),
        rand::random::<u8>(),
    ];
    
    format!("{:02x}{:02x}{:02x}{:02x}", 
        random_bytes[0], 
        random_bytes[1],
        random_bytes[2],
        random_bytes[3]
    )
}

fn main() {
    // Setup command-line arguments
    let args: Vec<String> = env::args().collect();
    let network_id = if args.len() > 1 {
        args[1].clone()
    } else {
        "test-network".to_string()
    };
    
    println!("Starting node in network '{}'", network_id);
    
    // Create node identifier
    let node_id = generate_random_id();
    let identifier = NodeIdentifier::new(&network_id, node_id.clone());
    
    println!("Node identifier: {}:{}", identifier.network_id, identifier.node_id);
    
    // Create node info
    let node_info = NodeInfo {
        identifier: identifier.clone(),
        address: format!("127.0.0.1:8080"),
        capabilities: vec!["data".to_string(), "control".to_string()],
        last_seen: SystemTime::now(),
    };
    
    // Create discovery service
    let discovery = SimpleDiscovery::new();
    
    // Register this node
    discovery.register_node(node_info);
    
    // Add a few simulated nodes for testing
    for i in 1..5 {
        let other_id = NodeIdentifier::new(&network_id, format!("node-{}", i));
        let other_info = NodeInfo {
            identifier: other_id,
            address: format!("127.0.0.1:{}", 8080 + i),
            capabilities: vec!["data".to_string()],
            last_seen: SystemTime::now(),
        };
        discovery.add_test_node(other_info);
    }
    
    // Add a node from a different network
    let other_net_id = NodeIdentifier::new("other-network", "external-node");
    let other_net_info = NodeInfo {
        identifier: other_net_id,
        address: "192.168.1.100:9000".to_string(),
        capabilities: vec!["data".to_string()],
        last_seen: SystemTime::now(),
    };
    discovery.add_test_node(other_net_info);
    
    // Discover all nodes
    let all_nodes = discovery.discover_nodes();
    println!("\nDiscovered {} nodes in total:", all_nodes.len());
    
    for node in all_nodes {
        println!("  * {}:{} at {}", 
            node.identifier.network_id, 
            node.identifier.node_id,
            node.address
        );
    }
    
    // Discover nodes in our network
    let network_nodes = discovery.find_nodes_by_network(&network_id);
    println!("\nDiscovered {} nodes in network '{}':", network_nodes.len(), network_id);
    
    for node in network_nodes {
        println!("  * {}:{} at {}", 
            node.identifier.network_id, 
            node.identifier.node_id,
            node.address
        );
    }
    
    println!("\nSimple discovery example completed.");
} 