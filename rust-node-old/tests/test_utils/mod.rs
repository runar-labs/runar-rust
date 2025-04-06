use anyhow::Result;
use runar_node::node::{Node, NodeConfig};
use tempfile::TempDir;

/// Create a test node with a temporary directory
pub async fn create_test_node() -> Result<(Node, TempDir, NodeConfig)> {
    // Create a temporary directory for node storage
    let temp_dir = tempfile::tempdir()?;
    let node_path = temp_dir.path().to_str().unwrap();
    let network_id = "test-network";

    // Create a NodeConfig for the node
    let node_config = NodeConfig::new(network_id, node_path, &format!("{}/db", node_path));

    // Create and initialize the node
    let node_config_clone = node_config.clone();
    let mut node = Node::new(node_config_clone).await?;
    node.init().await?;

    Ok((node, temp_dir, node_config))
} 