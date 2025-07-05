use anyhow;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use thiserror::Error;

/// Error codes for FFI operations
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RunarErrorCode {
    Success = 0,
    InvalidParameters = 1000,
    NodeNotInitialized = 1001,
    NodeAlreadyStarted = 1002,
    NodeNotStarted = 1003,
    ServiceNotFound = 2000,
    ServiceRegistrationFailed = 2001,
    KeychainError = 3000,
    KeychainItemNotFound = 3001,
    KeychainAccessDenied = 3002,
    NetworkError = 4000,
    NetworkTimeout = 4001,
    SerializationError = 5000,
    DeserializationError = 5001,
    MemoryError = 6000,
    RuntimeError = 7000,
    UnknownError = 9999,
}

/// C-compatible error structure
#[repr(C)]
pub struct CError {
    pub code: i32,
    pub message: *const c_char,
    pub context: *const c_char,
}

impl CError {
    pub fn new(code: RunarErrorCode, message: String, context: Option<String>) -> Self {
        let message_cstr = CString::new(message).unwrap_or_default();
        let context_cstr = context
            .map(|c| CString::new(c).unwrap_or_default())
            .unwrap_or_else(|| CString::new("").unwrap());

        Self {
            code: code as i32,
            message: message_cstr.into_raw(),
            context: context_cstr.into_raw(),
        }
    }

    pub fn from_anyhow(error: anyhow::Error) -> Self {
        let message = error.to_string();
        let context = error.source().map(|e| e.to_string());
        let code = Self::map_error_code(&error);

        Self::new(code, message, context)
    }

    fn map_error_code(error: &anyhow::Error) -> RunarErrorCode {
        let error_str = error.to_string().to_lowercase();

        if error_str.contains("keychain") {
            RunarErrorCode::KeychainError
        } else if error_str.contains("network") {
            RunarErrorCode::NetworkError
        } else if error_str.contains("serialization") || error_str.contains("json") {
            RunarErrorCode::SerializationError
        } else if error_str.contains("memory") {
            RunarErrorCode::MemoryError
        } else if error_str.contains("runtime") {
            RunarErrorCode::RuntimeError
        } else {
            RunarErrorCode::UnknownError
        }
    }

    pub fn free(self) {
        unsafe {
            if !self.message.is_null() {
                let _ = CString::from_raw(self.message as *mut c_char);
            }
            if !self.context.is_null() {
                let _ = CString::from_raw(self.context as *mut c_char);
            }
        }
    }
}

impl Default for CError {
    fn default() -> Self {
        Self::new(
            RunarErrorCode::UnknownError,
            "Unknown error occurred".to_string(),
            None,
        )
    }
}

/// Rust-side error types
#[derive(Error, Debug)]
pub enum RunarError {
    #[error("Invalid parameters: {message}")]
    InvalidParameters { message: String },

    #[error("Node not initialized")]
    NodeNotInitialized,

    #[error("Node already started")]
    NodeAlreadyStarted,

    #[error("Node not started")]
    NodeNotStarted,

    #[error("Service not found: {service_path}")]
    ServiceNotFound { service_path: String },

    #[error("Service registration failed: {reason}")]
    ServiceRegistrationFailed { reason: String },

    #[error("Keychain error: {message}")]
    KeychainError { message: String },

    #[error("Network error: {message}")]
    NetworkError { message: String },

    #[error("Serialization error: {message}")]
    SerializationError { message: String },

    #[error("Memory error: {message}")]
    MemoryError { message: String },

    #[error("Runtime error: {message}")]
    RuntimeError { message: String },

    #[error("Unknown error: {message}")]
    UnknownError { message: String },
}

impl From<anyhow::Error> for RunarError {
    fn from(err: anyhow::Error) -> Self {
        RunarError::UnknownError {
            message: err.to_string(),
        }
    }
}

impl From<anyhow::Error> for CError {
    fn from(err: anyhow::Error) -> Self {
        CError::from_anyhow(err)
    }
}

impl From<RunarError> for CError {
    fn from(err: RunarError) -> Self {
        match err {
            RunarError::InvalidParameters { message } => {
                CError::new(RunarErrorCode::InvalidParameters, message, None)
            }
            RunarError::NodeNotInitialized => CError::new(
                RunarErrorCode::NodeNotInitialized,
                "Node not initialized".to_string(),
                None,
            ),
            RunarError::NodeAlreadyStarted => CError::new(
                RunarErrorCode::NodeAlreadyStarted,
                "Node already started".to_string(),
                None,
            ),
            RunarError::NodeNotStarted => CError::new(
                RunarErrorCode::NodeNotStarted,
                "Node not started".to_string(),
                None,
            ),
            RunarError::ServiceNotFound { service_path } => CError::new(
                RunarErrorCode::ServiceNotFound,
                format!("Service not found: {}", service_path),
                None,
            ),
            RunarError::ServiceRegistrationFailed { reason } => CError::new(
                RunarErrorCode::ServiceRegistrationFailed,
                format!("Service registration failed: {}", reason),
                None,
            ),
            RunarError::KeychainError { message } => {
                CError::new(RunarErrorCode::KeychainError, message, None)
            }
            RunarError::NetworkError { message } => {
                CError::new(RunarErrorCode::NetworkError, message, None)
            }
            RunarError::SerializationError { message } => {
                CError::new(RunarErrorCode::SerializationError, message, None)
            }
            RunarError::MemoryError { message } => {
                CError::new(RunarErrorCode::MemoryError, message, None)
            }
            RunarError::RuntimeError { message } => {
                CError::new(RunarErrorCode::RuntimeError, message, None)
            }
            RunarError::UnknownError { message } => {
                CError::new(RunarErrorCode::UnknownError, message, None)
            }
        }
    }
}

/// FFI error handling functions
pub mod ffi {
    use super::*;

    /// Free a CError structure
    #[no_mangle]
    pub extern "C" fn runar_error_free(error: CError) {
        error.free();
    }

    /// Create a success error (no error)
    #[no_mangle]
    pub extern "C" fn runar_error_success() -> CError {
        CError::new(RunarErrorCode::Success, "Success".to_string(), None)
    }

    /// Create an invalid parameters error
    #[no_mangle]
    pub extern "C" fn runar_error_invalid_parameters(message: *const c_char) -> CError {
        let message_str = if message.is_null() {
            "Invalid parameters".to_string()
        } else {
            unsafe { CStr::from_ptr(message).to_string_lossy().into_owned() }
        };
        CError::new(RunarErrorCode::InvalidParameters, message_str, None)
    }
}
