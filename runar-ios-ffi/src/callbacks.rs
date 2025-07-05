use crate::error::CError;
use crate::types::CDataResult;
use std::collections::HashMap;
use std::ffi::c_char;
use std::sync::{Arc, Mutex};
use tokio::sync::oneshot;

/// Callback types for different operations
pub type StartCallback = extern "C" fn(*const c_char, *const CError);
pub type StopCallback = extern "C" fn(*const c_char, *const CError);
pub type RequestCallback = extern "C" fn(*const CDataResult);
pub type PublishCallback = extern "C" fn(*const c_char, *const CError);
pub type EventCallback = extern "C" fn(*const c_char, *const u8, usize);
pub type ServiceCallback = extern "C" fn(*const c_char, *const CError);

/// Callback manager for tracking and executing callbacks
pub struct CallbackManager {
    callbacks: Arc<Mutex<HashMap<String, Box<dyn CallbackHandler + Send + Sync>>>>,
    next_id: Arc<Mutex<u64>>,
}

impl CallbackManager {
    pub fn new() -> Self {
        Self {
            callbacks: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(Mutex::new(1)),
        }
    }

    /// Register a callback and return its ID
    pub fn register_callback<H>(&self, handler: H) -> String
    where
        H: CallbackHandler + Send + Sync + 'static,
    {
        let mut id_counter = self.next_id.lock().unwrap();
        let id = format!("callback_{}", *id_counter);
        *id_counter += 1;

        self.callbacks
            .lock()
            .unwrap()
            .insert(id.clone(), Box::new(handler));
        id
    }

    /// Execute a callback by ID
    pub fn execute_callback(&self, id: &str, data: CallbackData) -> bool {
        if let Some(handler) = self.callbacks.lock().unwrap().get(id) {
            handler.execute(data);
            true
        } else {
            false
        }
    }

    /// Remove a callback by ID
    pub fn remove_callback(&self, id: &str) -> bool {
        self.callbacks.lock().unwrap().remove(id).is_some()
    }

    /// Clean up all callbacks
    pub fn cleanup(&self) {
        self.callbacks.lock().unwrap().clear();
    }
}

/// Trait for callback handlers
pub trait CallbackHandler {
    fn execute(&self, data: CallbackData);
}

/// Data that can be passed to callbacks
pub enum CallbackData {
    Start {
        success: bool,
        error: Option<CError>,
    },
    Stop {
        success: bool,
        error: Option<CError>,
    },
    Request {
        result: CDataResult,
    },
    Publish {
        success: bool,
        error: Option<CError>,
    },
    Event {
        topic: String,
        data: Vec<u8>,
    },
    Service {
        success: bool,
        error: Option<CError>,
    },
}

/// Start callback handler
pub struct StartCallbackHandler {
    callback: StartCallback,
}

impl StartCallbackHandler {
    pub fn new(callback: StartCallback) -> Self {
        Self { callback }
    }
}

impl CallbackHandler for StartCallbackHandler {
    fn execute(&self, data: CallbackData) {
        match data {
            CallbackData::Start { success, error } => {
                let message = if success {
                    crate::memory::rust_string_to_c("Node started successfully")
                } else {
                    std::ptr::null()
                };

                let error_ptr = error
                    .as_ref()
                    .map(|e| e as *const CError)
                    .unwrap_or(std::ptr::null());
                (self.callback)(message, error_ptr);
            }
            _ => {}
        }
    }
}

/// Stop callback handler
pub struct StopCallbackHandler {
    callback: StopCallback,
}

impl StopCallbackHandler {
    pub fn new(callback: StopCallback) -> Self {
        Self { callback }
    }
}

impl CallbackHandler for StopCallbackHandler {
    fn execute(&self, data: CallbackData) {
        match data {
            CallbackData::Stop { success, error } => {
                let message = if success {
                    crate::memory::rust_string_to_c("Node stopped successfully")
                } else {
                    std::ptr::null()
                };

                let error_ptr = error
                    .as_ref()
                    .map(|e| e as *const CError)
                    .unwrap_or(std::ptr::null());
                (self.callback)(message, error_ptr);
            }
            _ => {}
        }
    }
}

/// Request callback handler
pub struct RequestCallbackHandler {
    callback: RequestCallback,
}

impl RequestCallbackHandler {
    pub fn new(callback: RequestCallback) -> Self {
        Self { callback }
    }
}

impl CallbackHandler for RequestCallbackHandler {
    fn execute(&self, data: CallbackData) {
        match data {
            CallbackData::Request { result } => {
                (self.callback)(&result);
            }
            _ => {}
        }
    }
}

/// Publish callback handler
pub struct PublishCallbackHandler {
    callback: PublishCallback,
}

impl PublishCallbackHandler {
    pub fn new(callback: PublishCallback) -> Self {
        Self { callback }
    }
}

impl CallbackHandler for PublishCallbackHandler {
    fn execute(&self, data: CallbackData) {
        match data {
            CallbackData::Publish { success, error } => {
                let message = if success {
                    crate::memory::rust_string_to_c("Event published successfully")
                } else {
                    std::ptr::null()
                };

                let error_ptr = error
                    .as_ref()
                    .map(|e| e as *const CError)
                    .unwrap_or(std::ptr::null());
                (self.callback)(message, error_ptr);
            }
            _ => {}
        }
    }
}

/// Event callback handler
pub struct EventCallbackHandler {
    callback: EventCallback,
}

impl EventCallbackHandler {
    pub fn new(callback: EventCallback) -> Self {
        Self { callback }
    }
}

impl CallbackHandler for EventCallbackHandler {
    fn execute(&self, data: CallbackData) {
        match data {
            CallbackData::Event { topic, data } => {
                let topic_ptr = crate::memory::rust_string_to_c(&topic);
                let data_ptr = if data.is_empty() {
                    std::ptr::null()
                } else {
                    crate::memory::bytes_to_c_ptr(&data)
                };
                (self.callback)(topic_ptr, data_ptr, data.len());
            }
            _ => {}
        }
    }
}

/// Service callback handler
pub struct ServiceCallbackHandler {
    callback: ServiceCallback,
}

impl ServiceCallbackHandler {
    pub fn new(callback: ServiceCallback) -> Self {
        Self { callback }
    }
}

impl CallbackHandler for ServiceCallbackHandler {
    fn execute(&self, data: CallbackData) {
        match data {
            CallbackData::Service { success, error } => {
                let message = if success {
                    crate::memory::rust_string_to_c("Service operation completed successfully")
                } else {
                    std::ptr::null()
                };

                let error_ptr = error
                    .as_ref()
                    .map(|e| e as *const CError)
                    .unwrap_or(std::ptr::null());
                (self.callback)(message, error_ptr);
            }
            _ => {}
        }
    }
}

/// Global callback manager instance
lazy_static::lazy_static! {
    static ref GLOBAL_CALLBACK_MANAGER: Arc<CallbackManager> = Arc::new(CallbackManager::new());
}

/// Get the global callback manager
pub fn get_callback_manager() -> &'static CallbackManager {
    &GLOBAL_CALLBACK_MANAGER
}

/// Async callback executor that runs callbacks on the main thread
pub struct AsyncCallbackExecutor {
    callback_manager: Arc<CallbackManager>,
}

impl AsyncCallbackExecutor {
    pub fn new() -> Self {
        Self {
            callback_manager: Arc::new(CallbackManager::new()),
        }
    }

    /// Execute a callback asynchronously
    pub async fn execute_callback(&self, id: &str, data: CallbackData) {
        // In a real implementation, this would dispatch to the main thread
        // For now, we'll execute directly
        self.callback_manager.execute_callback(id, data);
    }

    /// Execute a callback with a oneshot channel for completion
    pub async fn execute_callback_with_completion<F>(
        &self,
        id: &str,
        data: CallbackData,
        completion: F,
    ) where
        F: FnOnce() + Send + 'static,
    {
        self.execute_callback(id, data).await;
        completion();
    }
}

/// Utility functions for creating callback handlers
pub fn create_start_callback_handler(callback: StartCallback) -> StartCallbackHandler {
    StartCallbackHandler::new(callback)
}

pub fn create_stop_callback_handler(callback: StopCallback) -> StopCallbackHandler {
    StopCallbackHandler::new(callback)
}

pub fn create_request_callback_handler(callback: RequestCallback) -> RequestCallbackHandler {
    RequestCallbackHandler::new(callback)
}

pub fn create_publish_callback_handler(callback: PublishCallback) -> PublishCallbackHandler {
    PublishCallbackHandler::new(callback)
}

pub fn create_event_callback_handler(callback: EventCallback) -> EventCallbackHandler {
    EventCallbackHandler::new(callback)
}

pub fn create_service_callback_handler(callback: ServiceCallback) -> ServiceCallbackHandler {
    ServiceCallbackHandler::new(callback)
}
