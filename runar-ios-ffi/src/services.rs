use crate::error::{CError, RunarError};
use crate::memory::{bytes_to_c_ptr, c_ptr_to_bytes, c_string_to_rust, rust_string_to_c};
use async_trait::async_trait;
use runar_node::{AbstractService, LifecycleContext};
use serde_json::Value;
use std::collections::HashMap;
use std::ffi::c_char;
use std::sync::{Arc, RwLock};

/// Service adapter for bridging Swift closures to Rust services
pub struct SwiftServiceAdapter {
    name: String,
    path: String,
    version: String,
    description: String,
    network_id: Option<String>,
    action_handlers: Arc<RwLock<HashMap<String, Box<dyn ActionHandler + Send + Sync>>>>,
    event_handlers: Arc<RwLock<HashMap<String, Box<dyn EventHandler + Send + Sync>>>>,
}

impl SwiftServiceAdapter {
    pub fn new(name: String, path: String, version: String, description: String) -> Self {
        Self {
            name,
            path,
            version,
            description,
            network_id: None,
            action_handlers: Arc::new(RwLock::new(HashMap::new())),
            event_handlers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register an action handler
    pub fn register_action<F>(&self, action_name: String, handler: F)
    where
        F: Fn(Vec<u8>) -> Result<Vec<u8>, RunarError> + Send + Sync + 'static,
    {
        let wrapper = ActionHandlerWrapper(handler);
        self.action_handlers
            .write()
            .unwrap()
            .insert(action_name, Box::new(wrapper));
    }

    /// Register an event handler
    pub fn register_event<F>(&self, event_name: String, handler: F)
    where
        F: Fn(Vec<u8>) -> Result<(), RunarError> + Send + Sync + 'static,
    {
        let wrapper = EventHandlerWrapper(handler);
        self.event_handlers
            .write()
            .unwrap()
            .insert(event_name, Box::new(wrapper));
    }

    /// Handle an action with JSON payload
    pub async fn handle_action_json(
        &self,
        action_name: &str,
        payload: Value,
    ) -> Result<Value, RunarError> {
        let payload_bytes =
            serde_json::to_vec(&payload).map_err(|e| RunarError::SerializationError {
                message: e.to_string(),
            })?;

        let handlers = self.action_handlers.read().unwrap();
        if let Some(handler) = handlers.get(action_name) {
            let result_bytes = handler.handle(payload_bytes)?;
            let result: Value = serde_json::from_slice(&result_bytes).map_err(|e| {
                RunarError::SerializationError {
                    message: e.to_string(),
                }
            })?;
            Ok(result)
        } else {
            Err(RunarError::ServiceNotFound {
                service_path: action_name.to_string(),
            })
        }
    }

    /// Handle an event with JSON payload
    pub async fn handle_event_json(
        &self,
        event_name: &str,
        payload: Value,
    ) -> Result<(), RunarError> {
        let payload_bytes =
            serde_json::to_vec(&payload).map_err(|e| RunarError::SerializationError {
                message: e.to_string(),
            })?;

        let handlers = self.event_handlers.read().unwrap();
        if let Some(handler) = handlers.get(event_name) {
            handler.handle(payload_bytes)
        } else {
            Err(RunarError::ServiceNotFound {
                service_path: event_name.to_string(),
            })
        }
    }
}

#[async_trait]
impl AbstractService for SwiftServiceAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn path(&self) -> &str {
        &self.path
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn network_id(&self) -> Option<String> {
        self.network_id.clone()
    }

    fn set_network_id(&mut self, network_id: String) {
        self.network_id = Some(network_id);
    }

    async fn init(&self, context: LifecycleContext) -> Result<(), anyhow::Error> {
        // Register all action handlers with the context
        let handlers = self.action_handlers.read().unwrap();
        for (action_name, _) in handlers.iter() {
            // TODO: Register handler with context
            // This would require extending the LifecycleContext to support dynamic handlers
        }
        Ok(())
    }

    async fn start(&self, _context: LifecycleContext) -> Result<(), anyhow::Error> {
        // Service starts successfully
        Ok(())
    }

    async fn stop(&self, _context: LifecycleContext) -> Result<(), anyhow::Error> {
        // Service stops gracefully
        Ok(())
    }
}

/// Trait for action handlers
pub trait ActionHandler {
    fn handle(&self, payload: Vec<u8>) -> Result<Vec<u8>, RunarError>;
}

/// Trait for event handlers
pub trait EventHandler {
    fn handle(&self, payload: Vec<u8>) -> Result<(), RunarError>;
}

/// Wrapper for action handler functions
pub struct ActionHandlerWrapper<F>(F);

impl<F> ActionHandler for ActionHandlerWrapper<F>
where
    F: Fn(Vec<u8>) -> Result<Vec<u8>, RunarError> + Send + Sync,
{
    fn handle(&self, payload: Vec<u8>) -> Result<Vec<u8>, RunarError> {
        (self.0)(payload)
    }
}

/// Wrapper for event handler functions
pub struct EventHandlerWrapper<F>(F);

impl<F> EventHandler for EventHandlerWrapper<F>
where
    F: Fn(Vec<u8>) -> Result<(), RunarError> + Send + Sync,
{
    fn handle(&self, payload: Vec<u8>) -> Result<(), RunarError> {
        (self.0)(payload)
    }
}

/// Service manager for tracking registered services
pub struct ServiceManager {
    services: Arc<RwLock<HashMap<String, Arc<SwiftServiceAdapter>>>>,
}

impl ServiceManager {
    pub fn new() -> Self {
        Self {
            services: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a service
    pub fn register_service(&self, service: SwiftServiceAdapter) -> Result<(), RunarError> {
        let path = service.path().to_string();
        let service_arc = Arc::new(service);

        self.services.write().unwrap().insert(path, service_arc);

        Ok(())
    }

    /// Unregister a service
    pub fn unregister_service(&self, path: &str) -> Result<(), RunarError> {
        if self.services.write().unwrap().remove(path).is_some() {
            Ok(())
        } else {
            Err(RunarError::ServiceNotFound {
                service_path: path.to_string(),
            })
        }
    }

    /// Get a service by path
    pub fn get_service(&self, path: &str) -> Option<Arc<SwiftServiceAdapter>> {
        self.services.read().unwrap().get(path).cloned()
    }

    /// List all registered services
    pub fn list_services(&self) -> Vec<String> {
        self.services.read().unwrap().keys().cloned().collect()
    }

    /// Get service count
    pub fn service_count(&self) -> usize {
        self.services.read().unwrap().len()
    }
}

/// Global service manager instance
lazy_static::lazy_static! {
    static ref GLOBAL_SERVICE_MANAGER: Arc<ServiceManager> = Arc::new(ServiceManager::new());
}

/// Get the global service manager
pub fn get_service_manager() -> &'static ServiceManager {
    &GLOBAL_SERVICE_MANAGER
}

/// FFI service management functions
pub mod ffi {
    use super::*;
    use crate::callbacks::{create_service_callback_handler, ServiceCallback};

    /// Create a new service adapter
    #[no_mangle]
    pub extern "C" fn runar_service_create(
        name: *const c_char,
        path: *const c_char,
        version: *const c_char,
        description: *const c_char,
    ) -> *mut SwiftServiceAdapter {
        let name = match c_string_to_rust(name) {
            Some(n) => n,
            None => return std::ptr::null_mut(),
        };

        let path = match c_string_to_rust(path) {
            Some(p) => p,
            None => return std::ptr::null_mut(),
        };

        let version = match c_string_to_rust(version) {
            Some(v) => v,
            None => return std::ptr::null_mut(),
        };

        let description = match c_string_to_rust(description) {
            Some(d) => d,
            None => return std::ptr::null_mut(),
        };

        let service = SwiftServiceAdapter::new(name, path, version, description);
        Box::into_raw(Box::new(service))
    }

    /// Free a service adapter
    #[no_mangle]
    pub extern "C" fn runar_service_free(service: *mut SwiftServiceAdapter) {
        if !service.is_null() {
            unsafe {
                let _ = Box::from_raw(service);
            }
        }
    }

    /// Register a service with the global service manager
    #[no_mangle]
    pub extern "C" fn runar_service_register(
        service: *mut SwiftServiceAdapter,
        callback: ServiceCallback,
    ) {
        if service.is_null() {
            let error = CError::new(
                crate::error::RunarErrorCode::InvalidParameters,
                "Invalid service pointer".to_string(),
                None,
            );
            let message = std::ptr::null();
            callback(message, &error);
            return;
        }

        let service_ref = unsafe { &*service };
        let service_clone = SwiftServiceAdapter::new(
            service_ref.name.clone(),
            service_ref.path.clone(),
            service_ref.version.clone(),
            service_ref.description.clone(),
        );

        match get_service_manager().register_service(service_clone) {
            Ok(_) => {
                let message = rust_string_to_c("Service registered successfully");
                callback(message, std::ptr::null());
            }
            Err(e) => {
                let error: CError = e.into();
                callback(std::ptr::null(), &error);
            }
        }
    }

    /// Unregister a service
    #[no_mangle]
    pub extern "C" fn runar_service_unregister(path: *const c_char, callback: ServiceCallback) {
        let path_str = match c_string_to_rust(path) {
            Some(p) => p,
            None => {
                let error = CError::new(
                    crate::error::RunarErrorCode::InvalidParameters,
                    "Invalid path pointer".to_string(),
                    None,
                );
                callback(std::ptr::null(), &error);
                return;
            }
        };

        match get_service_manager().unregister_service(&path_str) {
            Ok(_) => {
                let message = rust_string_to_c("Service unregistered successfully");
                callback(message, std::ptr::null());
            }
            Err(e) => {
                let error: CError = e.into();
                callback(std::ptr::null(), &error);
            }
        }
    }

    /// Handle an action with raw bytes
    #[no_mangle]
    pub extern "C" fn runar_service_handle_action(
        service: *mut SwiftServiceAdapter,
        action_name: *const c_char,
        payload: *const u8,
        payload_length: usize,
        callback: extern "C" fn(*const u8, usize, *const CError),
    ) {
        if service.is_null() || action_name.is_null() {
            let error = CError::new(
                crate::error::RunarErrorCode::InvalidParameters,
                "Invalid service or action name pointer".to_string(),
                None,
            );
            callback(std::ptr::null(), 0, &error);
            return;
        }

        let service_ref = unsafe { &*service };
        let action_name_str = match c_string_to_rust(action_name) {
            Some(name) => name,
            None => {
                let error = CError::new(
                    crate::error::RunarErrorCode::InvalidParameters,
                    "Invalid action name".to_string(),
                    None,
                );
                callback(std::ptr::null(), 0, &error);
                return;
            }
        };

        let payload_bytes = if payload.is_null() || payload_length == 0 {
            Vec::new()
        } else {
            match c_ptr_to_bytes(payload, payload_length) {
                Some(bytes) => bytes,
                None => {
                    let error = CError::new(
                        crate::error::RunarErrorCode::InvalidParameters,
                        "Invalid payload data".to_string(),
                        None,
                    );
                    callback(std::ptr::null(), 0, &error);
                    return;
                }
            }
        };

        // Parse payload as JSON
        let payload_json: Value = if payload_bytes.is_empty() {
            Value::Null
        } else {
            match serde_json::from_slice(&payload_bytes) {
                Ok(json) => json,
                Err(e) => {
                    let error = CError::new(
                        crate::error::RunarErrorCode::DeserializationError,
                        format!("Failed to parse payload as JSON: {e}"),
                        None,
                    );
                    callback(std::ptr::null(), 0, &error);
                    return;
                }
            }
        };

        // Handle the action asynchronously
        let service_clone = SwiftServiceAdapter::new(
            service_ref.name.clone(),
            service_ref.path.clone(),
            service_ref.version.clone(),
            service_ref.description.clone(),
        );

        // For now, we'll handle this synchronously
        // In a real implementation, this would be async
        match futures::executor::block_on(
            service_clone.handle_action_json(&action_name_str, payload_json),
        ) {
            Ok(result) => match serde_json::to_vec(&result) {
                Ok(result_bytes) => {
                    let result_ptr = bytes_to_c_ptr(&result_bytes);
                    callback(result_ptr, result_bytes.len(), std::ptr::null());
                }
                Err(e) => {
                    let error = CError::new(
                        crate::error::RunarErrorCode::SerializationError,
                        format!("Failed to serialize result: {e}"),
                        None,
                    );
                    callback(std::ptr::null(), 0, &error);
                }
            },
            Err(e) => {
                let error: CError = e.into();
                callback(std::ptr::null(), 0, &error);
            }
        }
    }
}
