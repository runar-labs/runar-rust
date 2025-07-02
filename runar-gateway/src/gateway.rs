use anyhow::{anyhow, Result};
use async_trait::async_trait;
use axum::{
    extract::{Json as AxumJson, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use runar_common::types::schemas::{ActionMetadata, ServiceMetadata};
use runar_common::types::ArcValue;
use runar_node::services::{EventContext, LifecycleContext};
use runar_node::AbstractService;
use serde_json::Value as JsonValue;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex}; // Renamed to avoid conflict if any
use tokio::sync::oneshot;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

// Import Uuid if still needed, otherwise remove if not used after refactor
// use uuid::Uuid;
// Import HashMap if still needed
// use std::collections::HashMap;

/// Gateway service that exposes other services via HTTP REST API
pub struct GatwayService {
    name: String,
    version: String,
    path: String,
    description: String,
    network_id: Option<String>,
    shutdown_tx: Arc<StdMutex<Option<oneshot::Sender<()>>>>,
    listen_addr: SocketAddr,
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
            // counter field removed as it's not in the struct definition
            // The new fields shutdown_tx and listen_addr should also be cloned if GatwayService instances are meant to be fully independent
            // However, AbstractService instances are typically singletons managed by the Node.
            // For shutdown_tx, we want to share the sender, so Arc<Mutex<...>> is cloned (Arc clone).
            // listen_addr is usually fixed per instance.
            shutdown_tx: self.shutdown_tx.clone(),
            listen_addr: self.listen_addr, // SocketAddr is Copy
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
            description: "Gateway service that exposes other services via HTTP REST API"
                .to_string(),
            network_id: None,
            shutdown_tx: Arc::new(StdMutex::new(None)),
            listen_addr: "0.0.0.0:3000"
                .parse()
                .expect("Failed to parse default listen address"), // Default, can be made configurable
        }
    }

    // Optional: Allow configuring listen address
    pub fn with_listen_addr(mut self, addr: SocketAddr) -> Self {
        self.listen_addr = addr;
        self
    }

    fn add_route_to_router(
        &self,
        router: Router<LifecycleContext>,
        service_meta: &ServiceMetadata,
        action_meta: &ActionMetadata,
    ) -> Router<LifecycleContext> {
        let full_path = format!("/{}/{}", service_meta.service_path, action_meta.name);
        let service_path_clone = service_meta.service_path.clone();
        let action_name_clone = action_meta.name.clone();

        // Decide HTTP method based on input_schema
        if action_meta.input_schema.is_none() {
            // GET request
            router.route(
                &full_path,
                get(move |State(ctx): State<LifecycleContext>| async move {
                    let req_path = format!("{service_path_clone}/{action_name_clone}");
                    let req_path_for_json_err = req_path.clone(); // Clone for use in error handling closure
                    match ctx.request::<(), ArcValue>(req_path, None).await {
                        Ok(mut arc_value) => {
                            let json_value = arc_value
                                .to_json_value()
                                .expect("Failed to convert ArcValue to JSON");
                            ctx.debug(format!("Response: {json_value}"));
                            (StatusCode::OK, AxumJson(json_value)).into_response()
                        }
                        Err(e) => {
                            ctx.error(format!(
                                "Error calling action: '{req_path_for_json_err}': {e}"
                            ));
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                format!("Service request error: {e}"),
                            )
                                .into_response()
                        }
                    }
                }),
            )
        } else {
            // POST request
            router.route(
                &full_path,
                post(
                    move |State(ctx): State<LifecycleContext>,
                          AxumJson(payload): AxumJson<JsonValue>| async move {
                        ctx.debug(format!(
                            "handling post request for action: {action_name_clone} with payload: {payload}"
                        ));

                        let req_path = format!("{service_path_clone}/{action_name_clone}");
                        let request_arc_value = ArcValue::from_json(payload);

                        let req_path_for_json_err = req_path.clone(); // Clone for use in error handling closure
                        match ctx
                            .request::<ArcValue, serde_json::Value>(
                                req_path,
                                Some(request_arc_value),
                            )
                            .await
                        {
                            Ok(json_value) => {
                                ctx.debug(format!("Response: {json_value}"));
                                (StatusCode::OK, AxumJson(json_value)).into_response()
                            }
                            Err(e) => {
                                ctx.error(format!(
                                    "Error calling action: '{req_path_for_json_err}': {e}"
                                ));
                                (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    format!("Service request error: {e}"),
                                )
                                    .into_response()
                            }
                        }
                    },
                ),
            )
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

    fn set_network_id(&mut self, network_id: String) {
        self.network_id = Some(network_id);
    }

    async fn init(&self, context: LifecycleContext) -> Result<()> {
        context.info(format!(
            "Initializing GatwayService '{name}' (path: '{path}', version: '{version}') listening on {listen_addr}",
            name=self.name, path=self.path, version=self.version, listen_addr=self.listen_addr
        ));

        // Subscribe to service additions. Dynamic route updates are not yet implemented
        // but the subscription is kept for future enhancements.
        // The handler needs to be Send + Sync + 'static.
        let service_name = self.name.clone();
        context
            .subscribe(
                "$registry/service/added",
                Box::new(
                    move |event_ctx: Arc<EventContext>, value: Option<ArcValue>| {
                        let service_name_clone = service_name.clone();
                        Box::pin(async move {
                            if let Some(val) = value {
                                event_ctx.info(format!(
                                    "GatwayService '{service_name_clone}' received $registry/service/added event: {val}",
                                ));
                                // TODO: Implement dynamic route updates if required
                            } else {
                                event_ctx.warn(format!(
                        "GatwayService '{service_name_clone}' received $registry/service/added event with no value"
                    ));
                            }
                            Ok(())
                        })
                    },
                ),
            )
            .await
            .map_err(|e| anyhow!("Failed to subscribe to $registry/service/added: {}", e))?;

        // Removed placeholder 'add' action registration.
        // The Gateway's role is to expose other services, not provide its own actions.

        context.info(format!(
            "GatwayService '{name}' initialized.",
            name = self.name
        ));
        Ok(())
    }

    async fn start(&self, context: LifecycleContext) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        *self.shutdown_tx.lock().unwrap() = Some(tx);

        let mut router = Router::new().layer(TraceLayer::new_for_http()).layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        );

        context.info(format!(
            "GatwayService '{name}': Loading services and building routes...",
            name = self.name
        ));

        match context
            .request::<(), Vec<ServiceMetadata>>("$registry/services/list".to_string(), None)
            .await
        {
            Ok(services) => {
                for service_meta in services {
                    if service_meta.service_path == self.path
                        || service_meta.service_path == "$registry"
                    {
                        continue;
                    }
                    context.info(format!(
                        "GatwayService '{name}': Processing service '{service_name}' (path: '{service_path}') with {actions_len} actions",
                        name=self.name, service_name=service_meta.name, service_path=service_meta.service_path, actions_len=service_meta.actions.len()
                    ));
                    for action_meta in service_meta.actions.iter() {
                        context.info(format!(
                            "GatwayService '{name}': Adding route for action '{service_path}/{action_name}'",
                            name=self.name, service_path=service_meta.service_path, action_name=action_meta.name
                        ));
                        router =
                            self.add_route_to_router(router.clone(), &service_meta, action_meta);
                    }
                }
            }
            Err(e) => {
                let err_msg = format!(
                    "GatwayService '{name}': Failed to list services from registry: {e}",
                    name = self.name,
                    e = e
                );
                context.error(err_msg.clone());
                return Err(anyhow!(err_msg));
            }
        }

        // Pass LifecycleContext as state to Axum handlers
        let app = router.with_state(context.clone());

        let addr = self.listen_addr;
        context.info(format!(
            "GatwayService '{name}' starting HTTP server on {addr}",
            name = self.name,
            addr = addr
        ));

        let server_name_for_shutdown = self.name.clone();
        let server_name_for_error = self.name.clone();
        tokio::spawn(async move {
            axum::serve(
                tokio::net::TcpListener::bind(addr).await.unwrap(),
                app.into_make_service(),
            )
            .with_graceful_shutdown(async move {
                rx.await.ok();
                println!(
                    "GatwayService '{server_name_for_shutdown}' HTTP server shutting down gracefully.",
                );
            })
            .await
            .unwrap_or_else(|e| {
                eprintln!(
                    "GatwayService '{server_name_for_error}' HTTP server error: {e}",
                );
            });
        });

        context.info(format!(
            "GatwayService '{name}' HTTP server started and listening on {addr}",
            name = self.name,
            addr = addr
        ));
        Ok(())
    }

    async fn stop(&self, context: LifecycleContext) -> Result<()> {
        if let Some(tx) = self.shutdown_tx.lock().unwrap().take() {
            context.info(format!(
                "GatwayService '{name}': Sending shutdown signal to HTTP server...",
                name = self.name
            ));
            if tx.send(()).is_err() {
                context.warn(format!(
                    "GatwayService '{name}': Failed to send shutdown signal, receiver already dropped.",
                    name=self.name
                ));
            }
        } else {
            context.warn(format!(
                "GatwayService '{name}': Shutdown signal sender not found or already taken.",
                name = self.name
            ));
        }
        context.info(format!("GatwayService '{name}' stopped.", name = self.name));
        Ok(())
    }
}
