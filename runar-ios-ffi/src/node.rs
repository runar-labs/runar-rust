use crate::callbacks::{
    EventCallback, PublishCallback, RequestCallback, StartCallback, StopCallback,
};
use crate::error::{CError, RunarError, RunarErrorCode};
use crate::memory::{bytes_to_c_ptr, c_ptr_to_bytes, c_string_to_rust, rust_string_to_c};
use crate::runtime::get_runtime_manager;
use crate::types::{CDataResult, CNodeConfig, NodeConfig, NodeInfo, PeerInfo, ServiceInfo};
use anyhow::Result;
use runar_node::Node;
use std::ffi::c_char;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, RwLock,
};

/// Platform-specific Runar node with lifecycle management
pub struct PlatformRunarNode {
    runtime_manager: Arc<crate::runtime::PlatformRuntimeManager>,
    node: Arc<RwLock<Option<Node>>>,
    config: Arc<RwLock<Option<NodeConfig>>>,
    app_state: Arc<AtomicBool>, // true = foreground, false = background
    is_initialized: Arc<AtomicBool>,
}

impl PlatformRunarNode {
    pub fn new(config: NodeConfig) -> Self {
        Self {
            runtime_manager: Arc::new(crate::runtime::PlatformRuntimeManager::new()),
            node: Arc::new(RwLock::new(None)),
            config: Arc::new(RwLock::new(Some(config))),
            app_state: Arc::new(AtomicBool::new(true)), // Start in foreground
            is_initialized: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Initialize the node
    pub async fn initialize(&self) -> Result<()> {
        if self.is_initialized.load(Ordering::SeqCst) {
            return Err(anyhow::anyhow!("Node already initialized"));
        }

        // Start runtime
        self.runtime_manager.initialize()?;

        // Create and start node
        let config = self
            .config
            .read()
            .unwrap()
            .clone()
            .ok_or_else(|| anyhow::anyhow!("No configuration available"))?;

        // Convert our NodeConfig to runar_node::NodeConfig
        let node_config = runar_node::NodeConfig::new(config.node_id, config.default_network_id)
            .with_request_timeout(config.request_timeout_ms);
        let mut node = Node::new(node_config).await?;
        node.start().await?;

        *self.node.write().unwrap() = Some(node);
        self.is_initialized.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Shutdown the node
    pub async fn shutdown(&self) -> Result<()> {
        if !self.is_initialized.load(Ordering::SeqCst) {
            return Ok(());
        }

        // Stop node gracefully
        if let Some(node) = self.node.write().unwrap().as_mut() {
            node.stop().await?;
        }

        // Stop runtime
        self.runtime_manager.handle_background()?;

        // Clear node instance
        *self.node.write().unwrap() = None;
        self.is_initialized.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// Handle app entering background
    pub async fn handle_background_transition(&self) -> Result<()> {
        self.app_state.store(false, Ordering::SeqCst);
        self.shutdown().await
    }

    /// Handle app entering foreground
    pub async fn handle_foreground_transition(&self) -> Result<()> {
        self.app_state.store(true, Ordering::SeqCst);
        self.initialize().await
    }

    /// Make a request to a service
    pub async fn request(&self, path: &str, payload: Option<Vec<u8>>) -> Result<Vec<u8>> {
        if !self.is_initialized.load(Ordering::SeqCst) {
            return Err(anyhow::anyhow!("Node not initialized").into());
        }

        let node = self.node.read().unwrap();
        if let Some(node_ref) = node.as_ref() {
            // TODO: Implement actual request logic
            // For now, return a placeholder response
            Ok(serde_json::to_vec(&serde_json::json!({
                "status": "success",
                "path": path,
                "message": "Request processed"
            }))?)
        } else {
            Err(anyhow::anyhow!("Node not available").into())
        }
    }

    /// Publish an event
    pub async fn publish(&self, topic: &str, data: Option<Vec<u8>>) -> Result<()> {
        if !self.is_initialized.load(Ordering::SeqCst) {
            return Err(anyhow::anyhow!("Node not initialized").into());
        }

        let node = self.node.read().unwrap();
        if let Some(node_ref) = node.as_ref() {
            // TODO: Implement actual publish logic
            Ok(())
        } else {
            Err(anyhow::anyhow!("Node not available").into())
        }
    }

    /// Subscribe to events
    pub async fn subscribe(&self, topic: &str, callback: EventCallback) -> Result<String> {
        if !self.is_initialized.load(Ordering::SeqCst) {
            return Err(anyhow::anyhow!("Node not initialized").into());
        }

        // TODO: Implement actual subscription logic
        // For now, return a placeholder subscription ID
        Ok(format!("sub_{}", topic))
    }

    /// Unsubscribe from events
    pub async fn unsubscribe(&self, subscription_id: &str) -> Result<()> {
        if !self.is_initialized.load(Ordering::SeqCst) {
            return Err(anyhow::anyhow!("Node not initialized").into());
        }

        // TODO: Implement actual unsubscription logic
        Ok(())
    }

    /// Get node information
    pub async fn get_node_info(&self) -> Result<NodeInfo> {
        if !self.is_initialized.load(Ordering::SeqCst) {
            return Err(anyhow::anyhow!("Node not initialized").into());
        }

        let config = self.config.read().unwrap();
        if let Some(config_ref) = config.as_ref() {
            Ok(NodeInfo {
                node_id: config_ref.node_id.clone(),
                network_id: config_ref.default_network_id.clone(),
                is_running: self.is_initialized.load(Ordering::SeqCst),
                peer_count: 0,    // TODO: Get actual peer count
                service_count: 0, // TODO: Get actual service count
            })
        } else {
            Err(anyhow::anyhow!("No configuration available").into())
        }
    }

    /// Get known peers
    pub async fn get_known_peers(&self) -> Result<Vec<PeerInfo>> {
        if !self.is_initialized.load(Ordering::SeqCst) {
            return Err(anyhow::anyhow!("Node not initialized").into());
        }

        // TODO: Implement actual peer discovery
        Ok(Vec::new())
    }

    /// Check if node is running
    pub fn is_running(&self) -> bool {
        self.is_initialized.load(Ordering::SeqCst)
    }

    /// Check if app is in foreground
    pub fn is_foreground(&self) -> bool {
        self.app_state.load(Ordering::SeqCst)
    }
}

/// C-compatible node wrapper
#[repr(C)]
pub struct CNode {
    inner: *mut PlatformRunarNode,
    error_buffer: Arc<RwLock<Option<CError>>>,
}

impl CNode {
    pub fn new(inner: PlatformRunarNode) -> Self {
        Self {
            inner: Box::into_raw(Box::new(inner)),
            error_buffer: Arc::new(RwLock::new(None)),
        }
    }

    pub fn as_ref(&self) -> &PlatformRunarNode {
        unsafe { &*self.inner }
    }

    pub fn as_mut(&mut self) -> &mut PlatformRunarNode {
        unsafe { &mut *self.inner }
    }

    pub fn free(self) {
        unsafe {
            let _ = Box::from_raw(self.inner);
        }
    }
}

/// FFI node functions
pub mod ffi {
    use super::*;
    use crate::callbacks::{
        create_publish_callback_handler, create_request_callback_handler,
        create_start_callback_handler, create_stop_callback_handler,
    };

    /// Create a new node
    #[no_mangle]
    pub extern "C" fn runar_node_create(config: *const CNodeConfig) -> *mut CNode {
        if config.is_null() {
            return std::ptr::null_mut();
        }

        let config_ref = unsafe { &*config };
        let rust_config = match crate::types::c_node_config_to_rust(config_ref) {
            Some(cfg) => cfg,
            None => return std::ptr::null_mut(),
        };

        let node = PlatformRunarNode::new(rust_config);
        let c_node = CNode::new(node);
        Box::into_raw(Box::new(c_node))
    }

    /// Free a node
    #[no_mangle]
    pub extern "C" fn runar_node_free(node: *mut CNode) {
        if !node.is_null() {
            unsafe {
                let node = Box::from_raw(node);
                node.free();
            }
        }
    }

    /// Start a node
    #[no_mangle]
    pub extern "C" fn runar_node_start(node: *mut CNode, callback: StartCallback) {
        if node.is_null() {
            let error = CError::new(
                RunarErrorCode::InvalidParameters,
                "Invalid node pointer".to_string(),
                None,
            );
            callback(std::ptr::null(), &error);
            return;
        }

        let node_ref = unsafe { &*node };
        let node_clone = PlatformRunarNode::new(
            node_ref
                .as_ref()
                .config
                .read()
                .unwrap()
                .clone()
                .unwrap_or_else(|| NodeConfig::new("default".to_string(), "default".to_string())),
        );

        // Execute initialization asynchronously
        let callback_handler = create_start_callback_handler(callback);
        let callback_id =
            crate::callbacks::get_callback_manager().register_callback(callback_handler);

        // For now, we'll execute synchronously
        // In a real implementation, this would be async
        match futures::executor::block_on(node_clone.initialize()) {
            Ok(_) => {
                crate::callbacks::get_callback_manager().execute_callback(
                    &callback_id,
                    crate::callbacks::CallbackData::Start {
                        success: true,
                        error: None,
                    },
                );
            }
            Err(e) => {
                let error: CError = e.into();
                crate::callbacks::get_callback_manager().execute_callback(
                    &callback_id,
                    crate::callbacks::CallbackData::Start {
                        success: false,
                        error: Some(error),
                    },
                );
            }
        }
    }

    /// Stop a node
    #[no_mangle]
    pub extern "C" fn runar_node_stop(node: *mut CNode, callback: StopCallback) {
        if node.is_null() {
            let error = CError::new(
                RunarErrorCode::InvalidParameters,
                "Invalid node pointer".to_string(),
                None,
            );
            callback(std::ptr::null(), &error);
            return;
        }

        let node_ref = unsafe { &*node };
        let node_clone = PlatformRunarNode::new(
            node_ref
                .as_ref()
                .config
                .read()
                .unwrap()
                .clone()
                .unwrap_or_else(|| NodeConfig::new("default".to_string(), "default".to_string())),
        );

        let callback_handler = create_stop_callback_handler(callback);
        let callback_id =
            crate::callbacks::get_callback_manager().register_callback(callback_handler);

        // Execute shutdown asynchronously
        match futures::executor::block_on(node_clone.shutdown()) {
            Ok(_) => {
                crate::callbacks::get_callback_manager().execute_callback(
                    &callback_id,
                    crate::callbacks::CallbackData::Stop {
                        success: true,
                        error: None,
                    },
                );
            }
            Err(e) => {
                let error: CError = e.into();
                crate::callbacks::get_callback_manager().execute_callback(
                    &callback_id,
                    crate::callbacks::CallbackData::Stop {
                        success: false,
                        error: Some(error),
                    },
                );
            }
        }
    }

    /// Make a request
    #[no_mangle]
    pub extern "C" fn runar_node_request_raw(
        node: *mut CNode,
        path: *const c_char,
        payload: *const u8,
        payload_length: usize,
        callback: RequestCallback,
    ) {
        if node.is_null() || path.is_null() {
            let error = CError::new(
                RunarErrorCode::InvalidParameters,
                "Invalid parameters".to_string(),
                None,
            );
            let result = CDataResult::with_error(error);
            callback(&result);
            return;
        }

        let node_ref = unsafe { &*node };
        let path_str = match c_string_to_rust(path) {
            Some(p) => p,
            None => {
                let error = CError::new(
                    RunarErrorCode::InvalidParameters,
                    "Invalid path".to_string(),
                    None,
                );
                let result = CDataResult::with_error(error);
                callback(&result);
                return;
            }
        };

        let payload_bytes = if payload.is_null() || payload_length == 0 {
            None
        } else {
            c_ptr_to_bytes(payload, payload_length)
        };

        let node_clone = PlatformRunarNode::new(
            node_ref
                .as_ref()
                .config
                .read()
                .unwrap()
                .clone()
                .unwrap_or_else(|| NodeConfig::new("default".to_string(), "default".to_string())),
        );

        let callback_handler = create_request_callback_handler(callback);
        let callback_id =
            crate::callbacks::get_callback_manager().register_callback(callback_handler);

        // Execute request asynchronously
        match futures::executor::block_on(node_clone.request(&path_str, payload_bytes)) {
            Ok(result_bytes) => {
                let result_ptr = bytes_to_c_ptr(&result_bytes);
                let result = CDataResult::new(result_ptr, result_bytes.len());
                crate::callbacks::get_callback_manager().execute_callback(
                    &callback_id,
                    crate::callbacks::CallbackData::Request { result },
                );
            }
            Err(e) => {
                let error: CError = e.into();
                let result = CDataResult::with_error(error);
                crate::callbacks::get_callback_manager().execute_callback(
                    &callback_id,
                    crate::callbacks::CallbackData::Request { result },
                );
            }
        }
    }

    /// Publish an event
    #[no_mangle]
    pub extern "C" fn runar_node_publish(
        node: *mut CNode,
        topic: *const c_char,
        data: *const u8,
        data_length: usize,
        callback: PublishCallback,
    ) {
        if node.is_null() || topic.is_null() {
            let error = CError::new(
                RunarErrorCode::InvalidParameters,
                "Invalid parameters".to_string(),
                None,
            );
            callback(std::ptr::null(), &error);
            return;
        }

        let node_ref = unsafe { &*node };
        let topic_str = match c_string_to_rust(topic) {
            Some(t) => t,
            None => {
                let error = CError::new(
                    RunarErrorCode::InvalidParameters,
                    "Invalid topic".to_string(),
                    None,
                );
                callback(std::ptr::null(), &error);
                return;
            }
        };

        let data_bytes = if data.is_null() || data_length == 0 {
            None
        } else {
            c_ptr_to_bytes(data, data_length)
        };

        let node_clone = PlatformRunarNode::new(
            node_ref
                .as_ref()
                .config
                .read()
                .unwrap()
                .clone()
                .unwrap_or_else(|| NodeConfig::new("default".to_string(), "default".to_string())),
        );

        let callback_handler = create_publish_callback_handler(callback);
        let callback_id =
            crate::callbacks::get_callback_manager().register_callback(callback_handler);

        // Execute publish asynchronously
        match futures::executor::block_on(node_clone.publish(&topic_str, data_bytes)) {
            Ok(_) => {
                crate::callbacks::get_callback_manager().execute_callback(
                    &callback_id,
                    crate::callbacks::CallbackData::Publish {
                        success: true,
                        error: None,
                    },
                );
            }
            Err(e) => {
                let error: CError = e.into();
                crate::callbacks::get_callback_manager().execute_callback(
                    &callback_id,
                    crate::callbacks::CallbackData::Publish {
                        success: false,
                        error: Some(error),
                    },
                );
            }
        }
    }

    /// Subscribe to events
    #[no_mangle]
    pub extern "C" fn runar_node_subscribe(
        node: *mut CNode,
        topic: *const c_char,
        callback: EventCallback,
    ) -> *mut c_char {
        if node.is_null() || topic.is_null() {
            return std::ptr::null_mut();
        }

        let node_ref = unsafe { &*node };
        let topic_str = match c_string_to_rust(topic) {
            Some(t) => t,
            None => return std::ptr::null_mut(),
        };

        let node_clone = PlatformRunarNode::new(
            node_ref
                .as_ref()
                .config
                .read()
                .unwrap()
                .clone()
                .unwrap_or_else(|| NodeConfig::new("default".to_string(), "default".to_string())),
        );

        // For now, return a placeholder subscription ID
        // In a real implementation, this would register the callback and return a real ID
        let subscription_id = format!("sub_{}", topic_str);
        rust_string_to_c(&subscription_id)
    }

    /// Unsubscribe from events
    #[no_mangle]
    pub extern "C" fn runar_node_unsubscribe(
        node: *mut CNode,
        subscription_id: *const c_char,
    ) -> bool {
        if node.is_null() || subscription_id.is_null() {
            return false;
        }

        let subscription_id_str = match c_string_to_rust(subscription_id) {
            Some(id) => id,
            None => return false,
        };

        let node_ref = unsafe { &*node };
        let node_clone = PlatformRunarNode::new(
            node_ref
                .as_ref()
                .config
                .read()
                .unwrap()
                .clone()
                .unwrap_or_else(|| NodeConfig::new("default".to_string(), "default".to_string())),
        );

        // For now, return true
        // In a real implementation, this would actually unsubscribe
        true
    }

    /// Check if node is running
    #[no_mangle]
    pub extern "C" fn runar_node_is_running(node: *mut CNode) -> bool {
        if node.is_null() {
            return false;
        }

        let node_ref = unsafe { &*node };
        node_ref.as_ref().is_running()
    }

    /// Check if app is in foreground
    #[no_mangle]
    pub extern "C" fn runar_node_is_foreground(node: *mut CNode) -> bool {
        if node.is_null() {
            return false;
        }

        let node_ref = unsafe { &*node };
        node_ref.as_ref().is_foreground()
    }
}
