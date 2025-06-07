use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use runar_common::types::{erased_arc::ErasedArc, ArcValueType, ValueCategory};
use runar_node::services::{LifecycleContext, RequestContext, ServiceFuture};
use runar_node::AbstractService;
use serde::{Deserialize, Serialize};

use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;




pub struct GatwayService {
    name: String,
    version: String,
    path: String,
    description: String,
    network_id: Option<String>,
}


// Manual implementation of Clone for MathService
impl Clone for GatwayService {
    fn clone(&self) -> Self {
        GatwayService {
            name: self.name.clone(),
            version: self.version.clone(),
            path: self.path.clone(),
            description: self.description.clone(),
            network_id: self.network_id.clone(),
            counter: self.counter.clone(),
        }
    }
}

impl GatwayService {
    /// Create a new MathService with the specified name and path
    pub fn new(name: &str, path: &str) -> Self {
        Self {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            path: path.to_string(),
            description: "Gateway service".to_string(),
            network_id: None,
        }
    }
}


#[async_trait]
impl AbstractService for GatwayService {
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

    async fn init(&self, context: LifecycleContext) -> Result<()> {
        // Log the service information being initialized
        context.info(format!(
            "Initializing GatwayService with name: {}, path: {}",
            self.name, self.path
        ));

        // Create an owned copy to move into the closures
        let owned_self = self.clone();


        context.subscribe("$registry/service/added", Box::new(move |ctx, value| {
            // Create a boxed future that returns Result<(), anyhow::Error>
            Box::pin(async move {
                ctx.info(format!(
                    "MathService received math/added event: {}",
                    value.unwrap()
                ));
                Ok(()) // Return Result::Ok
            })
        })).await?;

       // let result = context.request()

        // Register add action
        context.info(format!("Registering 'add' action for path: {}", self.path));
        context
            .register_action(
                "add",
                Arc::new(move |params, request_ctx| {
                    let self_clone = owned_self.clone();
                    Box::pin(async move { self_clone.handle_add(params, request_ctx).await })
                }),
            )
            .await?;

        Ok(())
    }

    async fn start(&self, context: LifecycleContext) -> Result<()> {
        // Update state in a thread-safe way
        let mut counter = self.counter.lock().unwrap();
        *counter = 0; // Reset counter on start
        drop(counter); // Release the lock

        context.info("MathService started".to_string());
        Ok(())
    }

    async fn stop(&self, context: LifecycleContext) -> Result<()> {
        context.info("MathService stopped".to_string());
        Ok(())
    }
}
