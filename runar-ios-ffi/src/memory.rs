use std::collections::VecDeque;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::{Arc, Mutex};

/// FFI memory manager for tracking allocated resources
pub struct FFIMemoryManager {
    allocated_strings: Arc<Mutex<Vec<usize>>>, // Store as usize for Send/Sync
    allocated_data: Arc<Mutex<Vec<usize>>>,    // Store as usize for Send/Sync
    string_pool: Arc<Mutex<VecDeque<CString>>>,
}

impl FFIMemoryManager {
    pub fn new() -> Self {
        Self {
            allocated_strings: Arc::new(Mutex::new(Vec::new())),
            allocated_data: Arc::new(Mutex::new(Vec::new())),
            string_pool: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    /// Allocate a C string from a Rust string
    pub fn allocate_string(&self, s: String) -> *mut c_char {
        let cstring = match CString::new(s) {
            Ok(cs) => cs,
            Err(_) => return std::ptr::null_mut(),
        };

        let ptr = cstring.into_raw();
        self.allocated_strings.lock().unwrap().push(ptr as usize);
        ptr
    }

    /// Allocate data from a byte vector
    pub fn allocate_data(&self, data: Vec<u8>) -> *mut u8 {
        let boxed = data.into_boxed_slice();
        let ptr = Box::into_raw(boxed) as *mut u8;
        self.allocated_data.lock().unwrap().push(ptr as usize);
        ptr
    }

    /// Get data length from allocated pointer
    pub fn get_data_length(&self, ptr: *mut u8) -> Option<usize> {
        if ptr.is_null() {
            return None;
        }

        // This is a simplified approach - in practice you'd need to track lengths
        // For now, we'll return None to indicate unknown length
        None
    }

    /// Free a specific string
    pub fn free_string(&self, ptr: *mut c_char) -> bool {
        if ptr.is_null() {
            return false;
        }

        let mut strings = self.allocated_strings.lock().unwrap();
        if let Some(index) = strings.iter().position(|&p| p == ptr as usize) {
            strings.remove(index);
            unsafe {
                let _ = CString::from_raw(ptr);
            }
            true
        } else {
            false
        }
    }

    /// Free a specific data pointer
    pub fn free_data(&self, ptr: *mut u8) -> bool {
        if ptr.is_null() {
            return false;
        }

        let mut data = self.allocated_data.lock().unwrap();
        if let Some(index) = data.iter().position(|&p| p == ptr as usize) {
            data.remove(index);
            unsafe {
                let _ = Box::from_raw(ptr);
            }
            true
        } else {
            false
        }
    }

    /// Clean up all allocated resources
    pub fn cleanup(&self) {
        // Free all allocated strings
        let mut strings = self.allocated_strings.lock().unwrap();
        for ptr in strings.drain(..) {
            unsafe {
                let _ = CString::from_raw(ptr as *mut c_char);
            }
        }

        // Free all allocated data
        let mut data = self.allocated_data.lock().unwrap();
        for ptr in data.drain(..) {
            unsafe {
                let _ = Box::from_raw(ptr as *mut u8);
            }
        }
    }

    /// Get memory usage statistics
    pub fn get_stats(&self) -> MemoryStats {
        let strings = self.allocated_strings.lock().unwrap();
        let data = self.allocated_data.lock().unwrap();

        MemoryStats {
            allocated_strings: strings.len(),
            allocated_data_blocks: data.len(),
        }
    }
}

impl Drop for FFIMemoryManager {
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// Memory usage statistics
#[derive(Debug, Clone)]
pub struct MemoryStats {
    pub allocated_strings: usize,
    pub allocated_data_blocks: usize,
}

/// Global memory manager instance
lazy_static::lazy_static! {
    static ref GLOBAL_MEMORY_MANAGER: FFIMemoryManager = FFIMemoryManager::new();
}

/// Get the global memory manager
pub fn get_memory_manager() -> &'static FFIMemoryManager {
    &GLOBAL_MEMORY_MANAGER
}

/// FFI memory management functions
pub mod ffi {
    use super::*;

    /// Free a C string allocated by the FFI
    #[no_mangle]
    pub extern "C" fn runar_string_free(s: *mut c_char) {
        if !s.is_null() {
            get_memory_manager().free_string(s);
        }
    }

    /// Free data allocated by the FFI
    #[no_mangle]
    pub extern "C" fn runar_data_free(data: *mut u8) {
        if !data.is_null() {
            get_memory_manager().free_data(data);
        }
    }

    /// Get memory usage statistics
    #[no_mangle]
    pub extern "C" fn runar_memory_stats() -> MemoryStats {
        get_memory_manager().get_stats()
    }

    /// Clean up all allocated memory (use with caution)
    #[no_mangle]
    pub extern "C" fn runar_memory_cleanup() {
        get_memory_manager().cleanup();
    }
}

/// Utility functions for safe string conversion
pub fn c_string_to_rust(c_str: *const c_char) -> Option<String> {
    if c_str.is_null() {
        return None;
    }

    unsafe { CStr::from_ptr(c_str).to_str().ok().map(|s| s.to_string()) }
}

pub fn rust_string_to_c(s: &str) -> *mut c_char {
    get_memory_manager().allocate_string(s.to_string())
}

/// Utility functions for safe data conversion
pub fn bytes_to_c_ptr(data: &[u8]) -> *mut u8 {
    get_memory_manager().allocate_data(data.to_vec())
}

pub fn c_ptr_to_bytes(ptr: *const u8, length: usize) -> Option<Vec<u8>> {
    if ptr.is_null() || length == 0 {
        return None;
    }

    unsafe {
        let slice = std::slice::from_raw_parts(ptr, length);
        Some(slice.to_vec())
    }
}
