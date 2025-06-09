// runar-gateway/tests/gateway_test.rs

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use axum::http::StatusCode as HttpStatus; // Renamed to avoid conflict if any from other crates
use runar_common::types::schemas::{FieldSchema, SchemaDataType};
use runar_common::types::ArcValueType;
use runar_gateway::GatwayService; // Ensure GatwayService is pub in runar-gateway/src/lib.rs
use runar_node::services::ActionRegistrationOptions;
use runar_node::services::{LifecycleContext, RequestContext};
use runar_node::NodeConfig;
use runar_node::{AbstractService, Node};
use serde_json::{json, Value as JsonValue};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

// --- Test Data Struct ---
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct MyTestData {
    id: i32,
    name: String,
    active: bool,
}

// --- Mock EchoService ---
#[derive(Clone)]
struct EchoService {
    name: String,
    path: String,
    network_id: Option<String>,
}

impl EchoService {
    fn new(name: &str, path: &str) -> Self {
        Self {
            name: name.to_string(),
            path: path.to_string(),
            network_id: None,
        }
    }

    async fn handle_ping(
        &self,
        _ctx: Arc<RequestContext>,
    ) -> Result<ArcValueType> {
        Ok(ArcValueType::new_primitive("pong".to_string()))
    }

    async fn handle_echo(
        &self,
        _ctx: RequestContext,
        mut message_avt: ArcValueType, // Expects an ArcValueType that IS a string
    ) -> Result<ArcValueType> {
        let message_str = message_avt.as_type::<String>().map_err(|e| {
            _ctx.logger.error(format!(
                "Error extracting string from ArcValueType in handle_echo: {}",
                e
            ));
            anyhow!("Parameter is not a valid string ArcValueType: {}", e)
        })?;

        // The test expects the exact message back
        Ok(ArcValueType::new_primitive(message_str))
    }

    async fn handle_echo_map(
        &self,
        _ctx: RequestContext,
        mut params: ArcValueType, // Expects an ArcValueType that IS a map
    ) -> Result<ArcValueType> {
        // The schema should enforce this. If it's not a map, this will error.
        // We are just echoing. as_map_ref is used here to confirm it's a map.
        params.as_map_ref::<String, ArcValueType>().map_err(|e| {
            _ctx.logger.error(format!("handle_echo_map: param not a map: {}", e));
            anyhow!("Parameter is not a valid map ArcValueType: {}", e)
        })?;
        Ok(params)
    }

    async fn handle_echo_list(
        &self,
        _ctx: RequestContext,
        mut params: ArcValueType, // Expects an ArcValueType that IS a list
    ) -> Result<ArcValueType> {
        params.as_list_ref::<ArcValueType>().map_err(|e| {
             _ctx.logger.error(format!("handle_echo_list: param not a list: {}", e));
            anyhow!("Parameter is not a valid list ArcValueType: {}", e)
        })?;
        Ok(params)
    }

    async fn handle_echo_struct(
        &self,
        _ctx: RequestContext,
        mut params: ArcValueType, // Expects an ArcValueType that IS a struct (represented as a map)
    ) -> Result<ArcValueType> {
        // The schema should enforce the structure. Here, we confirm it's a map.
        // A more robust handler might deserialize to MyTestData and then re-serialize.
        params.as_map_ref::<String, ArcValueType>().map_err(|e| {
            _ctx.logger.error(format!("handle_echo_struct: param not a map for struct: {}", e));
            anyhow!("Parameter is not a valid map ArcValueType for struct: {}", e)
        })?;
        Ok(params)
    }
}

#[async_trait]
impl AbstractService for EchoService {
    fn name(&self) -> &str {
        &self.name
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn path(&self) -> &str {
        &self.path
    }
    fn description(&self) -> &str {
        "A simple service that echoes messages and pings."
    }
    fn network_id(&self) -> Option<String> {
        self.network_id.clone()
    }

    async fn init(&self, context: LifecycleContext) -> Result<()> {
        context.info(format!("Initializing EchoService '{}'", self.name()));

        // --- Register "ping" action ---
        let self_clone_ping = self.clone();
        let ping_output_schema = FieldSchema {
            name: "ping_response".to_string(),
            data_type: SchemaDataType::String,
            description: Some("A 'pong' response indicating the service is reachable.".to_string()),
            nullable: Some(false),
            required: Some(vec![]), // For a simple type, required is about its presence in a parent object, not applicable here directly.
            ..FieldSchema::new("ping_response", SchemaDataType::String)  // Use default for others
        };
        let ping_options = ActionRegistrationOptions {
            description: Some("Responds with 'pong'. Takes no input parameters.".to_string()),
            input_schema: None,
            output_schema: Some(ping_output_schema),
        };
        context
            .register_action_with_options(
                "ping".to_string(),
                Arc::new(move |params, req_ctx| {
                    let s = self_clone_ping.clone();
                    Box::pin(async move {
                        if params.is_some() {
                            req_ctx.logger.warn("Ping action received unexpected parameters.");
                        }
                        s.handle_ping(req_ctx.into()).await
                    })
                }),
                ping_options,
            )
            .await?;

        // --- Register "echo" action ---
        let self_clone_echo = self.clone();
        let message_field_schema = Box::new(FieldSchema {
            name: "message".to_string(),
            data_type: SchemaDataType::String,
            description: Some("The string message to be echoed by the service.".to_string()),
            nullable: Some(false),
            ..FieldSchema::new("message", SchemaDataType::String) // Use default for others
        });

        let mut echo_input_props = HashMap::new();
        echo_input_props.insert("message".to_string(), message_field_schema);

        let echo_input_schema = FieldSchema {
            name: "echo_payload".to_string(),
            data_type: SchemaDataType::Object,
            description: Some(
                "Payload for the echo action, expecting an object with a 'message' field."
                    .to_string(),
            ),
            properties: Some(echo_input_props),
            required: Some(vec!["message".to_string()]),
            nullable: Some(false),
            ..FieldSchema::new("echo_payload", SchemaDataType::Object) // Use default for others
        };

        let echo_output_schema = FieldSchema {
            name: "echo_response".to_string(),
            data_type: SchemaDataType::String,
            description: Some("The original message, echoed back.".to_string()),
            nullable: Some(false),
            ..FieldSchema::new("echo_response", SchemaDataType::String) // Use default for others
        };

        let echo_options = ActionRegistrationOptions {
            description: Some("Echoes back the provided 'message' string.".to_string()),
            input_schema: Some(echo_input_schema),
            output_schema: Some(echo_output_schema),
        };

        context
            .register_action_with_options(
                "echo".to_string(),
                Arc::new(move |params, req_ctx| {
                    let s = self_clone_echo.clone();
                    Box::pin(async move {
                        let mut params_map_avt =
                            params.ok_or_else(|| anyhow!("Missing parameters for echo action"))?;
                        let message_avt = params_map_avt
                            .as_map_ref::<String, ArcValueType>()
                            .map_err(|e| anyhow!("Echo params not a map: {}", e))?
                            .get("message")
                            .cloned()
                            .ok_or_else(|| {
                                anyhow!("'message' field not found in echo params map")
                            })?;
                        s.handle_echo(req_ctx, message_avt).await
                    })
                }),
                echo_options,
            )
            .await?;

        // --- Register "echo_map" action ---
        let self_clone_echo_map = self.clone();
        let map_io_schema = FieldSchema {
            name: "map_payload".to_string(),
            data_type: SchemaDataType::Object, // Allows any object structure if properties is None
            description: Some("Payload for the echo_map action, expecting any JSON object.".to_string()),
            nullable: Some(false),
            properties: None, // Explicitly allow any properties
            required: None,
            items: None,
            pattern: None,
            enum_values: None,
            minimum: None,
            maximum: None,
            exclusive_minimum: None,
            exclusive_maximum: None,
            min_length: None,
            max_length: None,
            min_items: None,
            max_items: None,
            example: None,
            default_value: None,
        };
        let echo_map_options = ActionRegistrationOptions {
            description: Some("Echoes back a JSON map.".to_string()),
            input_schema: Some(map_io_schema.clone()),
            output_schema: Some(map_io_schema.clone()),
        };
        context
            .register_action_with_options(
                "echo_map".to_string(),
                Arc::new(move |params, req_ctx| {
                    let s = self_clone_echo_map.clone();
                    Box::pin(async move {
                        let map_params = params.ok_or_else(|| anyhow!("Missing parameters for echo_map action"))?;
                        s.handle_echo_map(req_ctx, map_params).await
                    })
                }),
                echo_map_options,
            )
            .await?;

        // --- Register "echo_list" action ---
        let self_clone_echo_list = self.clone();
        let list_item_schema = Box::new(FieldSchema {
            name: "list_item".to_string(), 
            data_type: SchemaDataType::Any, 
            description: Some("An item in the list.".to_string()),
            nullable: None,
            default_value: None,
            properties: None,
            required: None,
            items: None,
            pattern: None,
            enum_values: None,
            minimum: None,
            maximum: None,
            exclusive_minimum: None,
            exclusive_maximum: None,
            min_length: None,
            max_length: None,
            min_items: None,
            max_items: None,
            example: None,
        });
        let list_io_schema = FieldSchema {
            name: "list_payload".to_string(),
            data_type: SchemaDataType::Array,
            description: Some("Payload for the echo_list action, expecting any JSON array.".to_string()),
            items: Some(list_item_schema),
            nullable: Some(false),
            default_value: None,
            properties: None,
            required: None,
            pattern: None,
            enum_values: None,
            minimum: None,
            maximum: None,
            exclusive_minimum: None,
            exclusive_maximum: None,
            min_length: None,
            max_length: None,
            min_items: None,
            max_items: None,
            example: None,
        };
        let echo_list_options = ActionRegistrationOptions {
            description: Some("Echoes back a JSON list.".to_string()),
            input_schema: Some(list_io_schema.clone()),
            output_schema: Some(list_io_schema.clone()),
        };
        context
            .register_action_with_options(
                "echo_list".to_string(),
                Arc::new(move |params, req_ctx| {
                    let s = self_clone_echo_list.clone();
                    Box::pin(async move {
                        let list_params = params.ok_or_else(|| anyhow!("Missing parameters for echo_list action"))?;
                        s.handle_echo_list(req_ctx, list_params).await
                    })
                }),
                echo_list_options,
            )
            .await?;

        // --- Register "echo_struct" action ---
        let self_clone_echo_struct = self.clone();
        let mut struct_props = HashMap::new();
        struct_props.insert("id".to_string(), Box::new(FieldSchema {
            name: "id".to_string(),
            data_type: SchemaDataType::Int32,
            description: Some("Identifier for the test data".to_string()),
            nullable: Some(false), // Assuming 'id' is required, thus not nullable
            ..FieldSchema::new("id", SchemaDataType::Int32) // Fill with defaults
        }));
        struct_props.insert("name".to_string(), Box::new(FieldSchema {
            name: "name".to_string(),
            data_type: SchemaDataType::String,
            description: Some("Name for the test data".to_string()),
            nullable: Some(false), // Assuming 'name' is required
            ..FieldSchema::new("name", SchemaDataType::String)
        }));
        struct_props.insert("active".to_string(), Box::new(FieldSchema {
            name: "active".to_string(),
            data_type: SchemaDataType::Boolean,
            description: Some("Activity status for the test data".to_string()),
            nullable: Some(false), // Assuming 'active' is required
            ..FieldSchema::new("active", SchemaDataType::Boolean)
        }));

        let struct_io_schema = FieldSchema {
            name: "struct_payload".to_string(),
            data_type: SchemaDataType::Object,
            description: Some("Payload for the echo_struct action, expecting MyTestData structure.".to_string()),
            properties: Some(struct_props),
            required: Some(vec!["id".to_string(), "name".to_string(), "active".to_string()]),
            nullable: Some(false),
            items: None,
            pattern: None,
            enum_values: None,
            minimum: None,
            maximum: None,
            exclusive_minimum: None,
            exclusive_maximum: None,
            min_length: None,
            max_length: None,
            min_items: None,
            max_items: None,
            example: None,
            default_value: None,
        };
        let echo_struct_options = ActionRegistrationOptions {
            description: Some("Echoes back a MyTestData JSON struct.".to_string()),
            input_schema: Some(struct_io_schema.clone()),
            output_schema: Some(struct_io_schema.clone()),
        };
        context
            .register_action_with_options(
                "echo_struct".to_string(),
                Arc::new(move |params, req_ctx| {
                    let s = self_clone_echo_struct.clone();
                    Box::pin(async move {
                        let struct_params = params.ok_or_else(|| anyhow!("Missing parameters for echo_struct action"))?;
                        s.handle_echo_struct(req_ctx, struct_params).await
                    })
                }),
                echo_struct_options,
            )
            .await?;

        context.info(format!(
            "EchoService '{}' initialized with actions and schemas.",
            self.name()
        ));
        Ok(())
    }

    async fn start(&self, context: LifecycleContext) -> Result<()> {
        context.info(format!("EchoService '{}' started.", self.name()));
        Ok(())
    }

    async fn stop(&self, context: LifecycleContext) -> Result<()> {
        context.info(format!("EchoService '{}' stopped.", self.name()));
        Ok(())
    }
}

#[tokio::test]
async fn test_gateway_routes() -> Result<()> {
    // 1. Setup Node
    let node_network_id = "test-network-gw";
    let logging_config = runar_node::config::LoggingConfig::new()
        .with_default_level(runar_node::config::LogLevel::Off);
    let node_config =
        NodeConfig::new("gateway-test-node", node_network_id).with_logging_config(logging_config);
    let mut node = Node::new(node_config).await?;

    // 2. Setup and Add EchoService
    let echo_service_name = "EchoServiceTest";
    let echo_service_path = "echo-service";
    let echo_service = EchoService::new(echo_service_name, echo_service_path);
    node.add_service(echo_service).await?;

    // 4. Setup and Add GatwayService
    let gateway_listen_addr: SocketAddr = "127.0.0.1:3001".parse()?;
    let gateway_service =
        GatwayService::new("TestGateway", "gateway").with_listen_addr(gateway_listen_addr.clone());
    node.add_service(gateway_service).await?;

    // 5. Start Node
    node.start().await?;
    println!(
        "Node started, allowing time for GatwayService to initialize and Axum server to start..."
    );
    sleep(Duration::from_millis(1000)).await; // Increased delay to ensure server is up

    let client = reqwest::Client::new();
    let base_url = format!("http://{}", gateway_listen_addr);

    // 6. Test GET endpoint (/echo-service/ping)
    let ping_url = format!("{}/{}/ping", base_url, echo_service_path);
    println!("Testing GET: {}", ping_url);
    let resp_get = client.get(&ping_url).send().await?;
    assert_eq!(
        resp_get.status(),
        HttpStatus::OK,
        "Ping request failed. Status: {:?}, Body: {:?}",
        resp_get.status(),
        resp_get.text().await?
    );
    let body_get: JsonValue = resp_get.json().await?;
    assert_eq!(body_get, json!("pong"));
    println!("GET /{}/ping successful.", echo_service_path);

    // 7. Test POST endpoint (/echo-service/echo)
    let echo_url = format!("{}/{}/echo", base_url, echo_service_path);
    let payload = json!({ "message": "hello from gateway test" });
    println!("Testing POST: {} with payload: {}", echo_url, payload);

    let resp_post = client.post(&echo_url).json(&payload).send().await?;
    assert_eq!(
        resp_post.status(),
        HttpStatus::OK,
        "Echo request failed. Status: {:?}, Body: {:?}",
        resp_post.status(),
        resp_post.text().await?
    );
    let body_post: JsonValue = resp_post.json().await?;
    assert_eq!(body_post, json!("hello from gateway test"));
    println!("POST /{}/echo successful.", echo_service_path);

    // --- Test POST echo_map ---
    let map_payload = json!({
        "key1": "value1",
        "key2": 123,
        "nested": {
            "n_key": true
        }
    });
    let echo_map_url = format!("{}/{}/echo_map", base_url, echo_service_path);
    println!(
        "Testing POST: {} with payload: {}",
        echo_map_url,
        map_payload
    );
    let response_map = client
        .post(&echo_map_url)
        .json(&map_payload)
        .send()
        .await?;
    assert_eq!(response_map.status(), HttpStatus::OK, "echo_map request failed. Status: {:?}, Body: {:?}", response_map.status(), response_map.text().await?);
    let response_body_map: JsonValue = response_map.json().await?;
    assert_eq!(response_body_map, map_payload);
    println!("POST /{}/echo_map successful.", echo_service_path);

    // --- Test POST echo_list ---
    let list_payload = json!(["apple", "banana", json!({"fruit_type": "cherry"}), 100]);
    let echo_list_url = format!("{}/{}/echo_list", base_url, echo_service_path);
    println!(
        "Testing POST: {} with payload: {}",
        echo_list_url,
        list_payload
    );
    let response_list = client
        .post(&echo_list_url)
        .json(&list_payload)
        .send()
        .await?;
    assert_eq!(response_list.status(), HttpStatus::OK, "echo_list request failed. Status: {:?}, Body: {:?}", response_list.status(), response_list.text().await?);
    let response_body_list: JsonValue = response_list.json().await?;
    assert_eq!(response_body_list, list_payload);
    println!("POST /{}/echo_list successful.", echo_service_path);

    // --- Test POST echo_struct ---
    let struct_payload_data = MyTestData {
        id: 1,
        name: "Test Struct".to_string(),
        active: true,
    };
    let struct_payload_json = serde_json::to_value(&struct_payload_data)?;
    let echo_struct_url = format!("{}/{}/echo_struct", base_url, echo_service_path);
    println!(
        "Testing POST: {} with payload: {}",
        echo_struct_url,
        struct_payload_json
    );
    let response_struct = client
        .post(&echo_struct_url)
        .json(&struct_payload_json)
        .send()
        .await?;
    assert_eq!(response_struct.status(), HttpStatus::OK, "echo_struct request failed. Status: {:?}, Body: {:?}", response_struct.status(), response_struct.text().await?);
    let response_body_struct: MyTestData = response_struct.json().await?;
    assert_eq!(response_body_struct, struct_payload_data);
    println!("POST /{}/echo_struct successful.", echo_service_path);

    // 8. Stop Node
    node.stop().await?;
    println!("Node stopped.");

    Ok(())
}
