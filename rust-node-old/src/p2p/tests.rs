#[cfg(test)]
mod tests {
    
    
    use crate::p2p::transport::{P2PTransport, TransportConfig};
    use runar_common::utils::logging::{configure_test_logging, info_log, Component};
    use anyhow::Result;
    use tokio::time::{sleep, timeout, Duration};

    const TEST_TIMEOUT: Duration = Duration::from_secs(30);

    #[tokio::test]
    async fn test_initialization() -> Result<()> {
        timeout(TEST_TIMEOUT, async {
            let config = TransportConfig {
                network_id: "test-network".to_string(),
                state_path: "/tmp/test-p2p".to_string(),
                bootstrap_nodes: None,
                listen_addr: None,
            };
            let transport = P2PTransport::new(config, None)
                .await
                .expect("Failed to create transport");
            assert!(
                !transport.get_peer_id().is_empty(),
                "Peer ID should not be empty"
            );
            Ok(())
        })
        .await?
    }

    #[tokio::test]
    async fn test_p2p_basic_connectivity() -> Result<()> {
        timeout(TEST_TIMEOUT, async {
            // Set up logging for tests
            configure_test_logging();

            // Create temporary directories for each transport
            let temp_dir1 = tempfile::tempdir()?;
            let temp_dir2 = tempfile::tempdir()?;

            // Use the same network ID for both transports
            let network_id = "test_network_123";

            // Create first transport with explicit port
            let transport1_config = TransportConfig {
                network_id: network_id.to_string(),
                state_path: temp_dir1.path().to_str().unwrap().to_string(),
                bootstrap_nodes: None,
                listen_addr: Some("127.0.0.1:60001".to_string()),
            };

            // Create second transport with explicit port
            let transport2_config = TransportConfig {
                network_id: network_id.to_string(),
                state_path: temp_dir2.path().to_str().unwrap().to_string(),
                bootstrap_nodes: None,
                listen_addr: Some("127.0.0.1:60002".to_string()),
            };

            info_log(Component::Test, "Creating P2P transports").await;

            // Create both transports with the same fixed network ID
            let transport1 = P2PTransport::new(transport1_config, Some(network_id)).await?;
            let transport2 = P2PTransport::new(transport2_config, Some(network_id)).await?;

            // Get peer IDs
            let peer_id1 = transport1.get_peer_id();
            let peer_id2 = transport2.get_peer_id();

            info_log(
                Component::Test,
                &format!("Transport 1 Peer ID: {:?}", peer_id1),
            );
            info_log(
                Component::Test,
                &format!("Transport 2 Peer ID: {:?}", peer_id2),
            );

            // Start both transports
            info_log(Component::Test, "Starting P2P transports").await;
            transport1.start().await?;
            transport2.start().await?;

            // Wait for transports to fully start
            sleep(Duration::from_secs(1)).await;

            // Verify both transports are ready
            assert!(transport1.is_ready(), "Transport 1 should be ready");
            assert!(transport2.is_ready(), "Transport 2 should be ready");

            // Connect transport1 to transport2
            info_log(Component::Test, "Connecting transport1 to transport2").await;
            let peer_id2_value = (*peer_id2).clone();
            transport1
                .connect_to_peer(
                    peer_id2_value,
                    transport1.get_network_id().clone(),
                    "127.0.0.1:60002".to_string(),
                )
                .await?;

            // Wait for connection to establish
            sleep(Duration::from_secs(2)).await;

            // Send a test message from transport1 to transport2
            let test_message = "Hello from Transport 1!";
            info_log(
                Component::Test,
                &format!("Sending test message: {}", test_message),
            );
            let peer_id2_value = (*peer_id2).clone();
            transport1
                .send_to_peer(peer_id2_value, test_message)
                .await?;

            // Wait for message to be received
            sleep(Duration::from_secs(1)).await;

            // Clean up
            info_log(Component::Test, "Stopping P2P transports").await;
            transport1.stop().await?;
            transport2.stop().await?;

            info_log(Component::Test, "Test completed successfully").await;
            Ok(())
        })
        .await?
    }
}
