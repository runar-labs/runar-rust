//! Setup server for mobile device communication
//!
//! This module implements a simple TCP server that waits for mobile devices
//! to send certificate messages and network key messages during the node initialization process.

use anyhow::{Context, Result};
use futures_util::StreamExt;
use runar_common::logging::Logger;
use runar_keys::mobile::{NetworkKeyMessage, NodeCertificateMessage};
use runar_macros_common::{log_debug, log_error, log_info};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_stream::wrappers::TcpListenerStream;

/// Complete setup data received from mobile device
#[derive(Debug)]
pub struct SetupData {
    pub certificate_message: NodeCertificateMessage,
    pub network_key_message: NetworkKeyMessage,
}

pub struct SetupServer {
    ip: String,
    port: u16,
    logger: Arc<Logger>,
}

impl SetupServer {
    pub fn new(ip: String, port: u16, logger: Arc<Logger>) -> Self {
        Self { ip, port, logger }
    }

    /// Start the setup server and wait for certificate and network key messages from mobile
    pub async fn wait_for_setup_data(&self) -> Result<SetupData> {
        let address = format!("{}:{}", self.ip, self.port);

        log_info!(self.logger, "Starting setup server on {address}");

        // Create TCP listener
        let listener = TcpListener::bind(&address)
            .await
            .with_context(|| format!("Failed to bind to {address}"))?;

        log_info!(
            self.logger,
            "Setup server started - waiting for mobile device connection..."
        );

        // Convert to stream for easier handling
        let mut stream = TcpListenerStream::new(listener);

        while let Some(stream_result) = stream.next().await {
            match stream_result {
                Ok(socket) => {
                    log_info!(self.logger, "Mobile device connected");

                    // Handle the connection
                    match self.handle_connection(socket).await {
                        Ok(setup_data) => {
                            log_info!(self.logger, "Setup data received successfully");
                            return Ok(setup_data);
                        }
                        Err(e) => {
                            log_error!(self.logger, "Failed to handle connection: {e}");
                            // Continue waiting for another connection
                            continue;
                        }
                    }
                }
                Err(e) => {
                    log_error!(self.logger, "Failed to accept connection: {e}");
                    return Err(anyhow::anyhow!("Failed to accept connection: {}", e));
                }
            }
        }

        Err(anyhow::anyhow!("Setup server stream ended unexpectedly"))
    }

    async fn handle_connection(&self, socket: TcpStream) -> Result<SetupData> {
        log_debug!(self.logger, "Handling mobile device connection");

        // Read both certificate and network key messages from the socket
        let certificate_message = self.read_certificate_message(&socket).await?;
        let network_key_message = self.read_network_key_message(&socket).await?;

        log_info!(
            self.logger,
            "Certificate and network key messages received and parsed successfully"
        );

        Ok(SetupData {
            certificate_message,
            network_key_message,
        })
    }

    async fn read_certificate_message(&self, socket: &TcpStream) -> Result<NodeCertificateMessage> {
        self.read_message(socket).await
    }

    async fn read_network_key_message(&self, socket: &TcpStream) -> Result<NetworkKeyMessage> {
        self.read_message(socket).await
    }

    async fn read_message<T>(&self, socket: &TcpStream) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
    {
        const MAX_MESSAGE_SIZE: usize = 1024 * 1024; // 1MB limit to prevent DoS

        // Read the message length (4 bytes, big endian) - ensure complete read
        let mut length_bytes = [0u8; 4];
        let mut length_bytes_read = 0;

        while length_bytes_read < 4 {
            socket
                .readable()
                .await
                .context("Failed to wait for socket to be readable")?;

            match socket.try_read(&mut length_bytes[length_bytes_read..]) {
                Ok(0) => {
                    return Err(anyhow::anyhow!(
                        "Connection closed while reading message length"
                    ));
                }
                Ok(n) => {
                    length_bytes_read += n;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Continue the loop to call readable().await again
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }

        let message_length = u32::from_be_bytes(length_bytes) as usize;

        // Bounds checking to prevent DoS via excessive memory allocation
        if message_length > MAX_MESSAGE_SIZE {
            return Err(anyhow::anyhow!(
                "Message size {} exceeds maximum allowed size {}",
                message_length,
                MAX_MESSAGE_SIZE
            ));
        }

        if message_length == 0 {
            return Err(anyhow::anyhow!("Invalid message length: 0"));
        }

        log_debug!(self.logger, "Reading message of {message_length} bytes");

        // Read the actual message - ensure complete read
        let mut message_bytes = vec![0u8; message_length];
        let mut bytes_read = 0;

        while bytes_read < message_length {
            socket
                .readable()
                .await
                .context("Failed to wait for socket to be readable")?;

            match socket.try_read(&mut message_bytes[bytes_read..]) {
                Ok(0) => {
                    return Err(anyhow::anyhow!(
                        "Connection closed prematurely. Expected {} bytes, got {} bytes",
                        message_length,
                        bytes_read
                    ));
                }
                Ok(n) => {
                    bytes_read += n;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Continue the loop to call readable().await again
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }

        // Verify we read the complete message before deserialization
        if bytes_read != message_length {
            return Err(anyhow::anyhow!(
                "Incomplete message received. Expected {} bytes, got {} bytes",
                message_length,
                bytes_read
            ));
        }

        // Deserialize the message (CBOR)
        let message: T =
            serde_cbor::from_slice(&message_bytes).context("Failed to deserialize CBOR message")?;

        log_debug!(self.logger, "Message deserialized successfully");

        Ok(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_setup_server() {
        // This is a basic test to ensure the server can start
        // In a real test, you would need to mock the mobile device
        let logger = Arc::new(Logger::new_root(runar_common::logging::Component::CLI));
        let server = SetupServer::new("127.0.0.1".to_string(), 0, logger);

        // The server should be created successfully
        assert_eq!(server.ip, "127.0.0.1");
        assert_eq!(server.port, 0);
    }
}
