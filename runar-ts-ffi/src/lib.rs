#![deny(clippy::all)]

use async_trait::async_trait;
use napi::{
    bindgen_prelude::*,
    threadsafe_function::{ErrorStrategy, ThreadsafeFunction, ThreadsafeFunctionCallMode},
};
use napi_derive::napi;
use runar_common::types::ArcValue;
use runar_node::{
    AbstractService, ActionHandler, LifecycleContext, Node, NodeConfig, NodeDelegate,
};
use serde_json::Value as JsonValue;
use std::sync::Arc;
use tokio::sync::{oneshot, Mutex};

/// Convert anyhow::Error into napi::Error for throwing into JS.
fn to_napi_error(err: anyhow::Error) -> napi::Error {
    napi::Error::new(napi::Status::GenericFailure, format!("{err:?}"))
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

/// JavaScript action handlers - using JsFunction that will be converted to ThreadsafeFunction
#[napi(object)]
pub struct JsActions {
    pub echo: Option<JsFunction>,
    pub add: Option<JsFunction>,
    pub multiply: Option<JsFunction>,
    pub subtract: Option<JsFunction>,
    pub ping: Option<JsFunction>,
    pub reverse: Option<JsFunction>,
}

/// Main Node interface for JavaScript
#[napi]
pub struct JsNode {
    inner: Arc<Mutex<Node>>,
}

#[napi]
impl JsNode {
    /// Synchronous constructor. Internally blocks on the async `Node::new`.
    #[napi(constructor)]
    pub fn new() -> napi::Result<Self> {
        let config = NodeConfig::new_with_generated_id("default");
        let handle = tokio::runtime::Handle::current();
        let node = handle.block_on(Node::new(config)).map_err(to_napi_error)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(node)),
        })
    }

    #[napi]
    pub async fn start(&self) -> napi::Result<()> {
        let mut node = self.inner.lock().await;
        node.start().await.map_err(to_napi_error)
    }

    #[napi]
    pub async fn stop(&self) -> napi::Result<()> {
        let mut node = self.inner.lock().await;
        node.stop().await.map_err(to_napi_error)
    }

    #[napi]
    pub async fn request(
        &self,
        path: String,
        payload: Option<JsonValue>,
    ) -> napi::Result<JsonValue> {
        let node = self.inner.lock().await;
        let payload_av: Option<ArcValue> = payload.map(ArcValue::from_json);
        let resp: JsonValue = node
            .request::<ArcValue, JsonValue>(path, payload_av)
            .await
            .map_err(to_napi_error)?;
        Ok(resp)
    }

    #[napi]
    pub async fn publish(&self, topic: String, data: Option<JsonValue>) -> napi::Result<()> {
        let node = self.inner.lock().await;
        let data_av = data.map(ArcValue::from_json);
        node.publish(topic, data_av).await.map_err(to_napi_error)
    }

    #[napi]
    pub async fn add_service(&self, js_service: JsService) -> napi::Result<()> {
        let mut node = self.inner.lock().await;

        // Validate that the service has actions
        if let Some(ref actions) = js_service.actions {
            let has_actions = actions.echo.is_some()
                || actions.add.is_some()
                || actions.multiply.is_some()
                || actions.subtract.is_some()
                || actions.ping.is_some()
                || actions.reverse.is_some();

            if !has_actions {
                return Err(napi::Error::new(
                    napi::Status::InvalidArg,
                    "JS service must define at least one action",
                ));
            }
        } else {
            return Err(napi::Error::new(
                napi::Status::InvalidArg,
                "JS service must define actions",
            ));
        }

        let wrapper = JsServiceWrapper::from(js_service);
        node.add_service(wrapper).await.map_err(to_napi_error)
    }
}

/// Wrapper service that delegates to JavaScript handlers using channels
pub struct JsServiceWrapper {
    name: String,
    path: String,
    version: String,
    description: String,
    network_id: Option<String>,
    actions: std::collections::HashMap<
        String,
        ThreadsafeFunction<
            (JsonValue, oneshot::Sender<Result<JsonValue, String>>),
            ErrorStrategy::CalleeHandled,
        >,
    >,
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
            actions: std::collections::HashMap::new(),
        }
    }

    pub fn store_action_callbacks(&mut self, actions: JsActions) -> napi::Result<()> {
        // For now, just validate that actions exist without creating threadsafe functions
        // This will be implemented in the next iteration
        let _ = actions; // Suppress unused variable warning
        Ok(())
    }
}

// Make the wrapper Send + Sync
unsafe impl Send for JsServiceWrapper {}
unsafe impl Sync for JsServiceWrapper {}

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
        // Register all actions dynamically
        for (action_name, callback) in &self.actions {
            let callback = callback.clone();
            let action_name = action_name.clone();
            let handler: ActionHandler = Arc::new(move |payload, _ctx| {
                let callback = callback.clone();
                Box::pin(async move {
                    let (tx, rx) = oneshot::channel::<Result<JsonValue, String>>();

                    // Convert payload to JSON for JS
                    let payload_json = match payload.map(|mut av| av.to_json_value()) {
                        Some(Ok(val)) => val,
                        Some(Err(e)) => return Err(anyhow::anyhow!("JSON conversion error: {e}")),
                        None => serde_json::Value::Null,
                    };

                    // Call JS via threadsafe function
                    callback.call(Ok((payload_json, tx)), ThreadsafeFunctionCallMode::Blocking);

                    // Wait for JS response via channel
                    match rx.await {
                        Ok(Ok(json_result)) => {
                            // Convert JSON result back to ArcValue
                            Ok(ArcValue::from_json(json_result))
                        }
                        Ok(Err(js_error)) => Err(anyhow::anyhow!("JS action error: {js_error}")),
                        Err(e) => Err(anyhow::anyhow!("Channel error: {e}")),
                    }
                })
            });
            context.register_action(&action_name, handler).await?;
        }
        Ok(())
    }
    async fn start(&self, _context: LifecycleContext) -> anyhow::Result<()> {
        Ok(())
    }
    async fn stop(&self, _context: LifecycleContext) -> anyhow::Result<()> {
        Ok(())
    }
}

impl From<JsService> for JsServiceWrapper {
    fn from(mut js_service: JsService) -> Self {
        let actions = js_service.actions.take();
        let mut wrapper = Self::new(js_service);
        if let Some(actions) = actions {
            let _ = wrapper.store_action_callbacks(actions);
        }
        wrapper
    }
}

// Make JsService Send + Sync for FFI
unsafe impl Send for JsService {}
unsafe impl Sync for JsService {}
