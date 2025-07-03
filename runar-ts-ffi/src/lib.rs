#![deny(clippy::all)]

use std::sync::Arc;

#[allow(unused_imports)]
use napi::bindgen_prelude::*;

use async_trait::async_trait;
use napi_derive::napi;
use runar_common::types::ArcValue;
use runar_node::NodeDelegate;
use runar_node::{AbstractService, ActionHandler, LifecycleContext};
use runar_node::{Node, NodeConfig};
use serde_json::Value as JsonValue;
use tokio::sync::Mutex;

/// Convert anyhow::Error into napi::Error for throwing into JS.
fn to_napi_error(err: anyhow::Error) -> napi::Error {
    napi::Error::new(napi::Status::GenericFailure, format!("{err:?}"))
}

#[napi]
pub struct JsNode {
    inner: Arc<Mutex<Node>>, // Protect mutable Node operations
}

#[napi]
impl JsNode {
    /// Synchronous constructor. Internally blocks on the async `Node::new`.
    #[napi(constructor)]
    pub fn new() -> napi::Result<Self> {
        // For now use default config; later expose richer config parsing from JS.
        let config = NodeConfig::new_with_generated_id("default");

        // Use the current Tokio runtime provided by `napi` to block on async initialization.
        let handle = tokio::runtime::Handle::current();
        let node = handle.block_on(Node::new(config)).map_err(to_napi_error)?;

        Ok(Self {
            inner: Arc::new(Mutex::new(node)),
        })
    }

    /// Start the node. Resolves when networking and services are ready.
    #[napi]
    pub async fn start(&self) -> napi::Result<()> {
        let mut node = self.inner.lock().await;
        node.start().await.map_err(to_napi_error)
    }

    /// Stop the node gracefully.
    #[napi]
    pub async fn stop(&self) -> napi::Result<()> {
        let mut node = self.inner.lock().await;
        node.stop().await.map_err(to_napi_error)
    }

    /// Make a service request and return the response as JSON.
    #[napi]
    pub async fn request(
        &self,
        path: String,
        payload: Option<JsonValue>,
    ) -> napi::Result<JsonValue> {
        let node = self.inner.lock().await;

        // Convert payload into ArcValue expected by Rust core.
        let payload_av: Option<ArcValue> = payload.map(ArcValue::from_json);

        let resp: JsonValue = node
            .request::<ArcValue, JsonValue>(path, payload_av)
            .await
            .map_err(to_napi_error)?;

        Ok(resp)
    }

    /// Publish an event. Errors if topic invalid.
    #[napi]
    pub async fn publish(&self, topic: String, data: Option<JsonValue>) -> napi::Result<()> {
        let node = self.inner.lock().await;
        let data_av = data.map(ArcValue::from_json);
        node.publish(topic, data_av).await.map_err(to_napi_error)
    }

    /// Add a JavaScript service to the node.
    #[napi]
    pub async fn add_service(&self, js_service: JsService) -> napi::Result<()> {
        let mut node = self.inner.lock().await;
        let wrapper = JsServiceWrapper::from(js_service);
        node.add_service(wrapper).await.map_err(to_napi_error)
    }

    // Additional API methods will be added in future milestones.
}

/// JavaScript service definition with proper error handling for ThreadsafeFunction
#[napi(object)]
pub struct JsService {
    pub name: String,
    pub path: String,
    pub version: Option<String>,
    pub description: Option<String>,
    // For now, we'll handle action registration manually rather than passing functions directly
    // This avoids the complex ThreadsafeFunction serialization issues
}

/// Action call data passed to JavaScript - simplified for initial implementation
#[napi(object)]
pub struct JsActionCall {
    pub payload: Option<JsonValue>,
    pub path: String,
    pub network_id: String,
}

/// Response from JavaScript action handler
#[napi(object)]
pub struct JsActionResponse {
    pub success: bool,
    pub data: Option<JsonValue>,
    pub error: Option<String>,
}

/// Wrapper service that delegates to JavaScript handlers via a different mechanism
/// This avoids the ThreadsafeFunction complexity for now while maintaining the architecture
pub struct JsServiceWrapper {
    name: String,
    path: String,
    version: String,
    description: String,
    network_id: Option<String>,
}

impl JsServiceWrapper {
    pub fn new(js_service: JsService) -> Self {
        Self {
            name: js_service.name,
            path: js_service.path,
            version: js_service.version.unwrap_or_else(|| "1.0.0".to_string()),
            description: js_service
                .description
                .unwrap_or_else(|| "JS Service".to_string()),
            network_id: None,
        }
    }
}

#[async_trait]
impl AbstractService for JsServiceWrapper {
    fn name(&self) -> &str {
        &self.name
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn path(&self) -> &str {
        &self.path
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

    async fn init(&self, context: LifecycleContext) -> anyhow::Result<()> {
        // For now, register a simple echo action to demonstrate the pattern
        // In the full implementation, this would register JS callbacks
        let echo_handler: ActionHandler = Arc::new(move |payload, _ctx| {
            Box::pin(async move {
                // Echo back the payload or return a simple message
                match payload {
                    Some(data) => Ok(data),
                    None => Ok(ArcValue::new_primitive("JS service responding".to_string())),
                }
            })
        });

        context.register_action("echo", echo_handler).await?;

        context
            .logger
            .info(format!("Initialized JS service: {}", self.name));
        Ok(())
    }

    async fn start(&self, context: LifecycleContext) -> anyhow::Result<()> {
        context
            .logger
            .info(format!("Started JS service: {}", self.name));
        Ok(())
    }

    async fn stop(&self, context: LifecycleContext) -> anyhow::Result<()> {
        context
            .logger
            .info(format!("Stopped JS service: {}", self.name));
        Ok(())
    }
}

// Implement the conversion from JsService to the wrapper
impl From<JsService> for JsServiceWrapper {
    fn from(js_service: JsService) -> Self {
        JsServiceWrapper::new(js_service)
    }
}
