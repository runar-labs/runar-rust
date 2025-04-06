// IPC (Inter-Process Communication) Module
//
// This module provides a cross-platform IPC mechanism for communication between
// processes and the Runar node. On Unix-like systems (macOS/Linux), it uses Unix domain
// sockets. On Windows, it's designed to support Named Pipes (though currently not
// fully implemented).

use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::UnixListener;
use anyhow::Result;
use log::{info, error};

use serde::{Serialize, Deserialize};
use serde_json::Value;

// IPC message types

/// IPC Request Type
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum IpcRequestType {
    /// Publish a message to a topic
    Publish,
    /// Subscribe to a topic
    Subscribe,
    /// Request data from a topic
    Request,
    /// Unsubscribe from a topic
    Unsubscribe,
    /// Ping request
    Ping,
    /// Echo request
    Echo,
}

/// IPC Request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcRequest {
    /// Request ID
    #[serde(rename = "id")]
    pub request_id: Option<String>,
    /// Request type
    pub request_type: IpcRequestType,
    /// Topic to act on
    pub topic: Option<String>,
    /// Operation to perform (for service requests)
    pub operation: Option<String>,
    /// Data payload
    pub data: Option<Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum IpcResponseStatus {
    Success,
    Error,
}

/// IPC Response
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IpcResponse {
    pub request_id: String,
    pub status: IpcResponseStatus,
    pub message: Option<String>,
    pub topic: Option<String>,
    pub data: Option<Value>,
    pub operation: Option<String>,
}

impl IpcResponse {
    // Helper methods for creating responses
    pub fn ping_success(request_id: String, message: String) -> Self {
        IpcResponse {
            request_id,
            status: IpcResponseStatus::Success,
            message: Some(message),
            topic: None,
            data: None,
            operation: None,
        }
    }

    pub fn echo_success(request_id: String, data: Value) -> Self {
        IpcResponse {
            request_id,
            status: IpcResponseStatus::Success,
            message: Some("Echo".to_string()),
            topic: None,
            data: Some(data),
            operation: None,
        }
    }

    pub fn publish_success(request_id: String, topic: String, data: Option<Value>) -> Self {
        IpcResponse {
            request_id,
            status: IpcResponseStatus::Success,
            message: Some("Published".to_string()),
            topic: Some(topic),
            data,
            operation: None,
        }
    }

    pub fn subscribe_success(request_id: String, topic: String) -> Self {
        IpcResponse {
            request_id,
            status: IpcResponseStatus::Success,
            message: Some("Subscribed".to_string()),
            topic: Some(topic),
            data: None,
            operation: None,
        }
    }

    pub fn unsubscribe_success(request_id: String, topic: String) -> Self {
        IpcResponse {
            request_id,
            status: IpcResponseStatus::Success,
            message: Some("Unsubscribed".to_string()),
            topic: Some(topic),
            data: None,
            operation: None,
        }
    }

    pub fn error(request_id: String, message: String) -> Self {
        IpcResponse {
            request_id,
            status: IpcResponseStatus::Error,
            message: Some(message),
            topic: None,
            data: None,
            operation: None,
        }
    }
}

/// Initialize the IPC server
pub async fn init_ipc_server(
    node: Arc<crate::node::Node>,
    socket_path: PathBuf,
) -> Result<()> {
    // This is a simplified stub implementation
    info!("IPC server initialized at {:?}", socket_path);
    
    // Remove the socket file if it exists
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
    }

    // Start a background task to handle IPC connections
    let service_registry = node.service_registry();
    let db = node.db().clone();
    let network_id = node.network_id().to_string();
    
    tokio::spawn(async move {
        match UnixListener::bind(&socket_path) {
            Ok(listener) => {
                info!("IPC server started on {:?}", socket_path);
                
                // Accept connections
                while let Ok((_stream, _)) = listener.accept().await {
                    let _service_registry_clone = service_registry.clone();
                    let _db_clone = db.clone();
                    let _network_id_clone = network_id.clone();
                    
                    tokio::spawn(async move {
                        // For now, we'll just log that we received a connection
                        // A real implementation would parse and handle IPC requests
                        info!("IPC connection received");
                    });
                }
            }
            Err(e) => {
                error!("Failed to bind IPC socket: {}", e);
            }
        }
    });

    Ok(())
} 