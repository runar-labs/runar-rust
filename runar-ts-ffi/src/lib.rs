#![deny(clippy::all)]

use async_trait::async_trait;
use dashmap::DashMap;
use napi::bindgen_prelude::*;
use napi::threadsafe_function::{ErrorStrategy, ThreadsafeFunction, ThreadsafeFunctionCallMode};
use napi_derive::napi;
use once_cell::sync::OnceCell;
use runar_common::types::ArcValue;
use runar_node::{AbstractService, ActionHandler, LifecycleContext, Node, NodeDelegate};
use serde_json::Value as JsonValue;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

/// Convert anyhow::Error into napi::Error for throwing into JS.
fn anyhow_to_napi_error(err: anyhow::Error) -> napi::Error {
    napi::Error::new(napi::Status::GenericFailure, err.to_string())
}

/// JavaScript service interface - completely dynamic
#[napi(object)]
pub struct JsService {
    pub name: String,
    #[napi(js_name = "servicePath")]
    pub path: String,
    pub version: String,
    pub description: String,
    #[napi(js_name = "networkId")]
    pub network_id: Option<String>,
    pub actions: Vec<String>, // Just the action names
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
        let config = runar_test_utils::create_node_test_config().map_err(anyhow_to_napi_error)?;
        let handle = tokio::runtime::Handle::current();
        let node = handle
            .block_on(Node::new(config))
            .map_err(anyhow_to_napi_error)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(node)),
        })
    }

    #[napi]
    pub async fn start(&self) -> napi::Result<()> {
        let mut node = self.inner.lock().await;
        node.start().await.map_err(anyhow_to_napi_error)
    }

    #[napi]
    pub async fn stop(&self) -> napi::Result<()> {
        let mut node = self.inner.lock().await;
        node.stop().await.map_err(anyhow_to_napi_error)
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
            .map_err(anyhow_to_napi_error)?;
        Ok(resp)
    }

    #[napi]
    pub async fn publish(&self, topic: String, data: Option<JsonValue>) -> napi::Result<()> {
        let node = self.inner.lock().await;
        let data_av = data.map(ArcValue::from_json);
        node.publish(topic, data_av)
            .await
            .map_err(anyhow_to_napi_error)
    }

    #[napi]
    pub async fn add_service(&self, js_service: JsService) -> napi::Result<()> {
        let mut node = self.inner.lock().await;

        // Validate that the service has actions
        if js_service.actions.is_empty() {
            return Err(napi::Error::new(
                napi::Status::InvalidArg,
                "JS service must define at least one action",
            ));
        }

        // Validate path
        if js_service.path.trim().is_empty() {
            return Err(napi::Error::new(
                napi::Status::InvalidArg,
                "JS service 'path' must be provided and non-empty",
            ));
        }
        if js_service.path.chars().any(char::is_whitespace) {
            return Err(napi::Error::new(
                napi::Status::InvalidArg,
                "JS service 'path' must not contain whitespace",
            ));
        }

        // Validate version
        if js_service.version.trim().is_empty() {
            return Err(napi::Error::new(
                napi::Status::InvalidArg,
                "JS service 'version' must be provided and non-empty",
            ));
        }

        let wrapper = JsWrapperService::new(js_service)?;
        node.add_service(wrapper)
            .await
            .map_err(anyhow_to_napi_error)
    }
}

/// Wrapper service that delegates to JavaScript via work queue
struct JsWrapperService {
    name: String,
    path: String,
    version: String,
    description: String,
    network_id: Option<String>,
    actions: Vec<String>,
}

impl JsWrapperService {
    pub fn new(js_service: JsService) -> napi::Result<Self> {
        // Validate that the service has actions
        if js_service.actions.is_empty() {
            return Err(napi::Error::new(
                napi::Status::InvalidArg,
                "JS service must define at least one action",
            ));
        }

        // Validate path
        if js_service.path.trim().is_empty() {
            return Err(napi::Error::new(
                napi::Status::InvalidArg,
                "JS service 'path' must be provided and non-empty",
            ));
        }
        if js_service.path.chars().any(char::is_whitespace) {
            return Err(napi::Error::new(
                napi::Status::InvalidArg,
                "JS service 'path' must not contain whitespace",
            ));
        }

        // Validate version
        if js_service.version.trim().is_empty() {
            return Err(napi::Error::new(
                napi::Status::InvalidArg,
                "JS service 'version' must be provided and non-empty",
            ));
        }

        Ok(Self {
            name: js_service.name,
            path: js_service.path,
            version: js_service.version,
            description: js_service.description,
            network_id: js_service.network_id,
            actions: js_service.actions,
        })
    }
}

#[async_trait]
impl AbstractService for JsWrapperService {
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
        for action_name in &self.actions {
            let action_name_clone = action_name.clone();
            let service_name = self.path.clone();
            let handler: ActionHandler = Arc::new(move |payload, _ctx| {
                let action_name = action_name_clone.clone();
                let service_name = service_name.clone();
                Box::pin(async move {
                    // Convert payload to JSON that can be sent across the FFI boundary
                    let payload_json = match &payload {
                        Some(av) => {
                            let mut av_mut = av.clone();
                            av_mut.to_json_value().map_err(|e| {
                                anyhow::anyhow!("Failed to convert payload to JSON: {e}")
                            })?
                        }
                        None => serde_json::Value::Null,
                    };

                    // Create correlation id and oneshot channel entry in the pending map
                    let id = Uuid::new_v4().to_string();
                    let (tx, rx) = tokio::sync::oneshot::channel::<serde_json::Value>();

                    // Check if JS dispatcher is registered before inserting into pending map
                    let tsfn = match JS_DISPATCHER.get() {
                        Some(tsfn) => tsfn,
                        None => {
                            return Err(anyhow::anyhow!("JS dispatcher not registered"));
                        }
                    };

                    // Now safe to insert into pending map since we know dispatcher exists
                    PENDING.insert(id.clone(), tx);

                    // Construct the message to JS
                    let msg = serde_json::json!({
                        "id": id,
                        "type": "action",
                        "service": service_name,
                        "action": action_name,
                        "payload": payload_json,
                    });

                    // Dispatch via threadsafe function
                    let status = tsfn.call(Ok(msg.clone()), ThreadsafeFunctionCallMode::Blocking);
                    if status != napi::Status::Ok {
                        // Remove from pending map on dispatch failure
                        PENDING.remove(&id);
                        return Err(anyhow::anyhow!("TSFN call failed with status: {status:?}"));
                    }

                    // Wait up to 10 seconds for the response
                    match tokio::time::timeout(std::time::Duration::from_secs(10), rx).await {
                        Ok(Ok(resp)) => {
                            // Remove from pending map on successful response
                            PENDING.remove(&id);
                            Ok(ArcValue::from_json(resp))
                        }
                        Ok(Err(_)) => {
                            // Remove from pending map on channel error
                            PENDING.remove(&id);
                            Err(anyhow::anyhow!("JS channel closed before sending response"))
                        }
                        Err(_) => {
                            // Remove from pending map on timeout
                            PENDING.remove(&id);
                            Err(anyhow::anyhow!("Timed out awaiting JS response"))
                        }
                    }
                })
            });
            context.register_action(action_name, handler).await?;
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

/// Global TSFN to call back into JS
static JS_DISPATCHER: OnceCell<
    ThreadsafeFunction<serde_json::Value, ErrorStrategy::CalleeHandled>,
> = OnceCell::new();

/// Pending map: id -> oneshot sender
type PendingMap = DashMap<String, tokio::sync::oneshot::Sender<serde_json::Value>>;
static PENDING: once_cell::sync::Lazy<PendingMap> = once_cell::sync::Lazy::new(DashMap::new);

/// Register dispatcher from JS
#[napi]
pub fn register_js_dispatch(cb: JsFunction) -> napi::Result<()> {
    let tsfn: ThreadsafeFunction<serde_json::Value, ErrorStrategy::CalleeHandled> = cb
        .create_threadsafe_function(0, |ctx| {
            let js_obj = ctx.env.to_js_value(&ctx.value)?;
            Ok(vec![js_obj])
        })?;
    JS_DISPATCHER
        .set(tsfn)
        .map_err(|_| napi::Error::from_reason("Dispatcher already registered"))?;
    Ok(())
}

/// JS calls into Rust with a message; returns a promise
#[napi]
pub async fn dispatch_to_rust(js_msg: serde_json::Value) -> napi::Result<serde_json::Value> {
    let msg_type = js_msg.get("type").and_then(|v| v.as_str()).unwrap_or("");
    let id = js_msg
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    match msg_type {
        "response" => {
            // Response from JS for a pending action
            if let Some((_, tx)) = PENDING.remove(&id) {
                let payload = js_msg
                    .get("payload")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                let _ = tx.send(payload);
            }
            Ok(serde_json::json!({"status":"ok"}))
        }
        _ => Err(napi::Error::from_reason(
            "Unknown or unsupported message type from JS",
        )),
    }
}
