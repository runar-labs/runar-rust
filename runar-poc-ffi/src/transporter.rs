use async_trait::async_trait;
use libc::c_char;
use std::ffi::CStr;

use crate::types::{ErrorCode, SampleObject};

/// Callback function types for FFI communication
pub type ResponseCallback = extern "C" fn(payload_bytes: *const u8, payload_len: usize);
pub type ErrorCallback = extern "C" fn(error_code: u32, error_message: *const c_char);

/// Transporter trait for handling requests
#[async_trait]
pub trait Transporter {
    async fn request(
        &self,
        topic: &str,
        payload_bytes: &[u8],
        peer_node_id: &str,
        profile_public_key: &[u8],
        response_callback: ResponseCallback,
        error_callback: ErrorCallback,
    ) -> Result<(), Box<dyn std::error::Error>>;
}

/// Mock transporter implementation for testing
pub struct MockTransporter;

impl MockTransporter {
    pub fn new() -> Self {
        Self
    }

    /// Process the request and call appropriate callback
    async fn process_request(
        &self,
        payload_bytes: &[u8],
        response_callback: ResponseCallback,
        error_callback: ErrorCallback,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Deserialize the incoming CBOR data
        let sample_object: SampleObject = match serde_cbor::from_slice(payload_bytes) {
            Ok(obj) => obj,
            Err(e) => {
                log::error!("Failed to deserialize CBOR: {e}");
                let error_msg = format!("Deserialization failed: {e}");
                let c_error_msg = std::ffi::CString::new(error_msg).unwrap();
                unsafe {
                    error_callback(ErrorCode::DeserializationError as u32, c_error_msg.as_ptr());
                }
                return Err(e.into());
            }
        };

        // Check if this is an error test
        if sample_object.is_error_test() {
            log::info!("Received error test object, calling error callback");
            let error_msg = "This is a test error from Rust";
            let c_error_msg = std::ffi::CString::new(error_msg).unwrap();
            unsafe {
                error_callback(ErrorCode::UnknownError as u32, c_error_msg.as_ptr());
            }
            return Ok(());
        }

        // Process the object
        let mut modified_object = sample_object.clone();
        modified_object.modify_for_test();

        // Serialize the modified object back to CBOR
        let modified_bytes = match serde_cbor::to_vec(&modified_object) {
            Ok(bytes) => bytes,
            Err(e) => {
                log::error!("Failed to serialize modified object: {e}");
                let error_msg = format!("Serialization failed: {e}");
                let c_error_msg = std::ffi::CString::new(error_msg).unwrap();
                unsafe {
                    error_callback(ErrorCode::SerializationError as u32, c_error_msg.as_ptr());
                }
                return Err(e.into());
            }
        };

        // Call the response callback with the modified data
        log::info!("Calling response callback with {} bytes", modified_bytes.len());
        unsafe {
            response_callback(modified_bytes.as_ptr(), modified_bytes.len());
        }

        Ok(())
    }
}

#[async_trait]
impl Transporter for MockTransporter {
    async fn request(
        &self,
        topic: &str,
        payload_bytes: &[u8],
        peer_node_id: &str,
        _profile_public_key: &[u8],
        response_callback: ResponseCallback,
        error_callback: ErrorCallback,
    ) -> Result<(), Box<dyn std::error::Error>> {
        log::info!(
            "MockTransporter received request - Topic: {}, Peer: {}, Payload size: {}",
            topic,
            peer_node_id,
            payload_bytes.len()
        );

        // Validate pointers - function pointers can't be null in Rust
        // We'll assume they're valid if provided

        // Process the request
        self.process_request(payload_bytes, response_callback, error_callback)
            .await
    }
}

impl Default for MockTransporter {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper function to convert C string to Rust string safely
pub fn c_str_to_string(c_str: *const c_char) -> Result<String, ErrorCode> {
    if c_str.is_null() {
        return Err(ErrorCode::InvalidPointer);
    }

    unsafe {
        CStr::from_ptr(c_str)
            .to_str()
            .map(|s| s.to_string())
            .map_err(|_| ErrorCode::InvalidData)
    }
}
