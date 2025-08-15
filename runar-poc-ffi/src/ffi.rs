use libc::c_char;
use std::ffi::CString;

use crate::transporter::{MockTransporter, Transporter};
use crate::types::ErrorCode;

/// Global transporter instance
static mut TRANSPORTER: Option<MockTransporter> = None;

/// Initialize the transporter
#[no_mangle]
pub extern "C" fn transporter_init() -> i32 {
    unsafe {
        TRANSPORTER = Some(MockTransporter::new());
        log::info!("Transporter initialized successfully");
        ErrorCode::Success as i32
    }
}

/// Cleanup the transporter
#[no_mangle]
pub extern "C" fn transporter_cleanup() -> i32 {
    unsafe {
        TRANSPORTER = None;
        log::info!("Transporter cleaned up successfully");
        ErrorCode::Success as i32
    }
}

/// Main request function that can be called from Swift/Kotlin
#[no_mangle]
pub extern "C" fn transporter_request(
    topic: *const c_char,
    payload_bytes: *const u8,
    payload_len: usize,
    peer_node_id: *const c_char,
    profile_public_key: *const u8,
    profile_key_len: usize,
    response_callback: extern "C" fn(payload_bytes: *const u8, payload_len: usize),
    error_callback: extern "C" fn(error_code: u32, error_message: *const c_char),
) -> i32 {
    // Validate input parameters
    if topic.is_null() || payload_bytes.is_null() || peer_node_id.is_null() {
        log::error!("Invalid input parameters");
        let error_msg = CString::new("Invalid input parameters").unwrap();
        unsafe {
            error_callback(ErrorCode::InvalidPointer as u32, error_msg.as_ptr());
        }
        return ErrorCode::InvalidPointer as i32;
    }

    // Function pointers can't be null in Rust, so we assume they're valid

    // Convert C strings to Rust strings
    let topic_str = match crate::transporter::c_str_to_string(topic) {
        Ok(s) => s,
        Err(e) => {
            let error_msg = CString::new("Invalid topic string").unwrap();
            unsafe {
                error_callback(e as u32, error_msg.as_ptr());
            }
            return e as i32;
        }
    };

    let peer_node_id_str = match crate::transporter::c_str_to_string(peer_node_id) {
        Ok(s) => s,
        Err(e) => {
            let error_msg = CString::new("Invalid peer node ID string").unwrap();
            unsafe {
                error_callback(e as u32, error_msg.as_ptr());
            }
            return e as i32;
        }
    };

    // Get the payload data
    let payload_data = unsafe {
        std::slice::from_raw_parts(payload_bytes, payload_len)
    };

    // Get the profile public key data
    let profile_key_data = unsafe {
        std::slice::from_raw_parts(profile_public_key, profile_key_len)
    };

    // Get the transporter instance
    let transporter = unsafe {
        match &TRANSPORTER {
            Some(t) => t,
            None => {
                let error_msg = CString::new("Transporter not initialized").unwrap();
                error_callback(ErrorCode::UnknownError as u32, error_msg.as_ptr());
                return ErrorCode::UnknownError as i32;
            }
        }
    };

    // Create a runtime and run the async request
    let rt = tokio::runtime::Runtime::new().unwrap();
    let result = rt.block_on(async {
        transporter
            .request(
                &topic_str,
                payload_data,
                &peer_node_id_str,
                profile_key_data,
                response_callback,
                error_callback,
            )
            .await
    });

    match result {
        Ok(_) => {
            log::info!("Request processed successfully");
            ErrorCode::Success as i32
        }
        Err(e) => {
            log::error!("Request failed: {e}");
            let error_msg = CString::new(format!("Request failed: {e}")).unwrap();
            unsafe {
                error_callback(ErrorCode::UnknownError as u32, error_msg.as_ptr());
            }
            ErrorCode::UnknownError as i32
        }
    }
}

/// Test function to create a sample object and serialize it to CBOR
#[no_mangle]
pub extern "C" fn create_test_object(
    id: u64,
    name: *const c_char,
    out_bytes: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if name.is_null() || out_bytes.is_null() || out_len.is_null() {
        return ErrorCode::InvalidPointer as i32;
    }

    // Convert name to Rust string
    let name_str = match crate::transporter::c_str_to_string(name) {
        Ok(s) => s,
        Err(e) => return e as i32,
    };

    // Create test object
    let mut metadata = std::collections::HashMap::new();
    metadata.insert("test".to_string(), "true".to_string());
    
    let values = vec![1.0, 2.0, 3.0, 4.0, 5.0];
    let sample_object = crate::types::SampleObject::new(id, name_str, metadata, values);

    // Serialize to CBOR
    match serde_cbor::to_vec(&sample_object) {
        Ok(bytes) => {
            // Allocate memory for the bytes
            let boxed_bytes = bytes.into_boxed_slice();
            let raw_ptr = Box::into_raw(boxed_bytes);
            
            unsafe {
                *out_bytes = raw_ptr as *mut u8;
                *out_len = std::slice::from_raw_parts(raw_ptr as *const u8, 0).len();
            }
            
            ErrorCode::Success as i32
        }
        Err(_) => ErrorCode::SerializationError as i32,
    }
}

/// Free memory allocated by create_test_object
#[no_mangle]
pub extern "C" fn free_test_object_bytes(bytes: *mut u8, len: usize) -> i32 {
    if bytes.is_null() {
        return ErrorCode::InvalidPointer as i32;
    }

    unsafe {
        let _ = Box::from_raw(std::slice::from_raw_parts_mut(bytes, len));
    }

    ErrorCode::Success as i32
}
