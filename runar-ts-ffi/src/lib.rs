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

/// Context object passed to JavaScript action handlers
#[napi(object)]
pub struct Context {
    pub network_id: String,
    pub service_name: String,
    pub service_path: String,
}

/// Logger interface for JavaScript services
#[napi]
pub struct JsLogger {
    inner: Arc<runar_common::logging::Logger>,
}

#[napi]
impl JsLogger {
    #[napi]
    pub fn debug(&self, message: String) {
        self.inner.debug(message);
    }

    #[napi]
    pub fn info(&self, message: String) {
        self.inner.info(message);
    }

    #[napi]
    pub fn warn(&self, message: String) {
        self.inner.warn(message);
    }

    #[napi]
    pub fn error(&self, message: String) {
        self.inner.error(message);
    }
}

impl From<Arc<runar_common::logging::Logger>> for JsLogger {
    fn from(logger: Arc<runar_common::logging::Logger>) -> Self {
        Self { inner: logger }
    }
}

/// JavaScript service definition with action handlers
#[napi(object)]
pub struct JsService {
    pub name: String,
    pub path: String,
    pub version: Option<String>,
    pub description: Option<String>,
    pub actions: Option<JsActions>,
}

/// JavaScript action handlers
#[napi(object)]
pub struct JsActions {
    // Support both boolean flags for built-in actions and function callbacks
    pub echo: Option<bool>, // Placeholder for echo action
    pub add: Option<bool>,  // Placeholder for math add action
                            // Custom action handlers will be stored separately in the wrapper
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

/// Wrapper service that delegates to JavaScript handlers
pub struct JsServiceWrapper {
    name: String,
    path: String,
    version: String,
    description: String,
    network_id: Option<String>,
    actions: Option<JsActions>,
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
            actions: js_service.actions,
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
        // Register actions based on the JS service definition
        if let Some(actions) = &self.actions {
            // Register echo action if specified
            if actions.echo.unwrap_or(false) {
                let echo_handler: ActionHandler = Arc::new(move |payload, ctx| {
                    let logger = ctx.logger.clone();
                    Box::pin(async move {
                        logger.debug("Echo action called from JS service".to_string());
                        match payload {
                            Some(data) => Ok(data),
                            None => Ok(ArcValue::new_primitive(
                                "JS echo service responding".to_string(),
                            )),
                        }
                    })
                });
                context.register_action("echo", echo_handler).await?;
            }

            // Register add action if specified
            if actions.add.unwrap_or(false) {
                let add_handler: ActionHandler = Arc::new(move |payload, ctx| {
                    let logger = ctx.logger.clone();
                    Box::pin(async move {
                        logger.debug("Add action called from JS service".to_string());

                        // Parse the payload as JSON to extract numbers
                        if let Some(data) = payload {
                            if let Ok(json) = serde_json::to_value(&data) {
                                if let (Some(a), Some(b)) = (json.get("a"), json.get("b")) {
                                    if let (Some(a_num), Some(b_num)) = (a.as_f64(), b.as_f64()) {
                                        let result = a_num + b_num;
                                        logger.info(format!(
                                            "JS math service: {} + {} = {}",
                                            a_num, b_num, result
                                        ));
                                        return Ok(ArcValue::new_primitive(result));
                                    }
                                }
                            }
                        }

                        Err(anyhow::anyhow!(
                            "Invalid payload for add action. Expected: {{a: number, b: number}}"
                        ))
                    })
                });
                context.register_action("add", add_handler).await?;
            }
        } else {
            // Default echo action for backward compatibility
            let echo_handler: ActionHandler = Arc::new(move |payload, _ctx| {
                Box::pin(async move {
                    match payload {
                        Some(data) => Ok(data),
                        None => Ok(ArcValue::new_primitive("JS service responding".to_string())),
                    }
                })
            });
            context.register_action("echo", echo_handler).await?;
        }

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
