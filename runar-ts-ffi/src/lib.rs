#![deny(clippy::all)]

use std::sync::Arc;

#[allow(unused_imports)]
use napi::bindgen_prelude::*;

use napi_derive::napi;
use runar_common::types::ArcValue;
use runar_node::NodeDelegate;
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

    // Additional API methods will be added in future milestones.
}
