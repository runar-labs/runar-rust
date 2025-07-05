use std::ffi::c_char;

#[repr(C)]
pub struct CNodeConfig {
    pub node_id: *const c_char,
    pub default_network_id: *const c_char,
}

#[repr(C)]
pub struct CNode {
    _private: [u8; 0],
}

#[no_mangle]
pub extern "C" fn test_function() -> i32 {
    42
}

#[no_mangle]
pub extern "C" fn runar_node_create(_config: *const CNodeConfig) -> *mut CNode {
    static mut DUMMY_NODE: CNode = CNode { _private: [] };
    let ptr = unsafe { &mut DUMMY_NODE as *mut CNode };
    eprintln!("runar_node_create returning ptr: {:p}", ptr);
    ptr
}

#[no_mangle]
pub extern "C" fn runar_node_start(
    _node: *mut CNode,
    _callback: extern "C" fn(*const std::ffi::c_char, *const std::ffi::c_char),
) {
    _callback(std::ptr::null(), std::ptr::null());
}

#[no_mangle]
pub extern "C" fn runar_node_request(
    _node: *mut CNode,
    _path: *const c_char,
    _data: *const c_char,
    _data_len: usize,
    _callback: extern "C" fn(*const c_char, usize, *const std::ffi::c_char),
) {
    eprintln!("=== runar_node_request ENTERED ===");
    eprintln!("runar_node_request called with data_len: {}", _data_len);
    eprintln!("_data pointer: {:?}", _data);

    // Echo back the actual request data
    if !_data.is_null() && _data_len > 0 {
        let data_slice = unsafe { std::slice::from_raw_parts(_data as *const u8, _data_len) };
        eprintln!("data_slice length: {}", data_slice.len());
        if let Ok(data_str) = std::str::from_utf8(data_slice) {
            eprintln!("Rust received request: '{}'", data_str);
            let response_cstr = std::ffi::CString::new(data_str).unwrap();
            eprintln!("Sending echo response: '{}'", data_str);
            _callback(
                response_cstr.as_ptr(),
                response_cstr.as_bytes().len(),
                std::ptr::null(),
            );
            return;
        } else {
            eprintln!("Failed to convert data to UTF-8 string");
        }
    } else {
        eprintln!("Data is null or empty");
    }

    // Fallback response if data is invalid
    let response = "Hello, Test!";
    let response_cstr = std::ffi::CString::new(response).unwrap();
    eprintln!("Sending fallback response: '{}'", response);
    _callback(response_cstr.as_ptr(), response.len(), std::ptr::null());
}
