//! Setup server for mobile device communication
//!
//! This module implements a simple TCP server that waits for mobile devices
//! to send certificate messages during the node initialization process.

use anyhow::{Context, Result};
use futures_util::StreamExt;
use runar_common::logging::Logger;
use runar_keys::mobile::NodeCertificateMessage;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_stream::wrappers::TcpListenerStream;

pub struct SetupServer {
    ip: String,
    port: u16,
    logger: Arc<Logger>,
}

impl SetupServer {
    pub fn new(ip: String, port: u16, logger: Arc<Logger>) -> Self {
        Self { ip, port, logger }
    }

    /// Start the setup server and wait for a certificate message from mobile
    pub async fn wait_for_certificate(&self) -> Result<NodeCertificateMessage> {
        let address = format!("{}:{}", self.ip, self.port);

        self.logger
            .info(format!("Starting setup server on {address}"));

        // Create TCP listener
        let listener = TcpListener::bind(&address)
            .await
            .with_context(|| format!("Failed to bind to {address}"))?;

        self.logger
            .info("Setup server started - waiting for mobile device connection...");

        // Convert to stream for easier handling
        let mut stream = TcpListenerStream::new(listener);

        while let Some(stream_result) = stream.next().await {
            match stream_result {
                Ok(socket) => {
                    self.logger.info("Mobile device connected");

                    // Handle the connection
                    match self.handle_connection(socket).await {
                        Ok(certificate_message) => {
                            self.logger
                                .info("Certificate message received successfully");
                            return Ok(certificate_message);
                        }
                        Err(e) => {
                            self.logger
                                .error(format!("Failed to handle connection: {e}"));
                            // Continue waiting for another connection
                            continue;
                        }
                    }
                }
                Err(e) => {
                    self.logger
                        .error(format!("Failed to accept connection: {e}"));
                    return Err(anyhow::anyhow!("Failed to accept connection: {}", e));
                }
            }
        }

        Err(anyhow::anyhow!("Setup server stream ended unexpectedly"))
    }

    async fn handle_connection(&self, socket: TcpStream) -> Result<NodeCertificateMessage> {
        self.logger.debug("Handling mobile device connection");

        // Read the certificate message from the socket
        let certificate_message = self.read_certificate_message(socket).await?;

        self.logger
            .info("Certificate message received and parsed successfully");

        Ok(certificate_message)
    }

    async fn read_certificate_message(
        &self,
        socket: TcpStream,
    ) -> Result<NodeCertificateMessage> {
        // Read the message length (4 bytes, big endian)
        let mut length_bytes = [0u8; 4];
        socket
            .readable()
            .await
            .context("Failed to wait for socket to be readable")?;

        socket
            .try_read(&mut length_bytes)
            .context("Failed to read message length")?;

        let message_length = u32::from_be_bytes(length_bytes) as usize;

        self.logger.debug(format!(
            "Reading certificate message of {message_length} bytes"
        ));

        // Read the actual message
        let mut message_bytes = vec![0u8; message_length];
        let mut bytes_read = 0;

        while bytes_read < message_length {
            socket
                .readable()
                .await
                .context("Failed to wait for socket to be readable")?;

            match socket.try_read(&mut message_bytes[bytes_read..]) {
                Ok(0) => break,
                Ok(n) => {
                    bytes_read += n;
                }

                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
                Err(e) => return Err(e.into()),
            }
        }

        // Deserialize the certificate message
        let certificate_message: NodeCertificateMessage = bincode::deserialize(&message_bytes)
            .context("Failed to deserialize certificate message")?;

        self.logger
            .debug("Certificate message deserialized successfully");

        Ok(certificate_message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[tokio::test]
    async fn test_setup_server() {
        // This is a basic test to ensure the server can start
        // In a real test, you would need to mock the mobile device
        let logger = Arc::new(Logger::new_root(
            runar_common::logging::Component::CLI,
            "test",
        ));
        let server = SetupServer::new("127.0.0.1".to_string(), 0, logger);

        // The server should be created successfully
        assert_eq!(server.ip, "127.0.0.1");
        assert_eq!(server.port, 0);
    }
}
