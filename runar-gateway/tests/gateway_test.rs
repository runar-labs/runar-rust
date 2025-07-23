use anyhow::{anyhow, Result};
use axum::http::StatusCode as HttpStatus;
use runar_gateway::GatwayService;
use runar_macros::{action, service, service_impl};
use runar_node::Node;
use runar_serializer::ArcValue;
use runar_test_utils::create_node_test_config;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::time::{sleep, Duration};

// --- Test Data Struct ---
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct MyTestData {
    id: i32,
    name: String,
    active: bool,
}

// --- Mock EchoService ---
#[service(
    name = "EchoService",
    path = "echo-service",
    description = "A simple service that echoes messages and pings.",
    version = "1.0.0"
)]
struct EchoService {/* No fields needed if stateless */}

#[service_impl]
impl EchoService {
    #[action]
    async fn ping(&self) -> Result<String> {
        Ok("pong".to_string())
    }

    #[action]
    async fn echo(&self, message: String) -> Result<String> {
        Ok(message)
    }

    #[action]
    async fn echo_map(
        &self,
        params: HashMap<String, ArcValue>,
    ) -> Result<HashMap<String, ArcValue>> {
        Ok(params)
    }

    #[action]
    async fn echo_list(&self, params: Vec<ArcValue>) -> Result<Vec<ArcValue>> {
        Ok(params)
    }

    #[action]
    async fn echo_struct(&self, params: MyTestData) -> Result<MyTestData> {
        Ok(params)
    }
}

#[tokio::test]
async fn test_gateway_routes() -> Result<()> {
    // 1. Setup Node
    let logging_config = runar_node::config::LoggingConfig::new()
        .with_default_level(runar_node::config::LogLevel::Debug);
    let node_config = create_node_test_config()
        .expect("Error creating test config")
        .with_logging_config(logging_config);
    let mut node = Node::new(node_config).await?;

    // 2. Setup and Add EchoService
    let echo_service = EchoService::default();
    node.add_service(echo_service).await?;

    let echo_service_path = "echo-service";

    // 4. Setup and Add GatwayService
    let gateway_listen_addr: SocketAddr = "127.0.0.1:3001".parse()?;
    let gateway_service =
        GatwayService::new("TestGateway", "gateway").with_listen_addr(gateway_listen_addr);
    node.add_service(gateway_service).await?;

    // 5. Start Node
    node.start().await?;
    println!(
        "Node started, allowing time for GatwayService to initialize and Axum server to start..."
    );
    sleep(Duration::from_millis(1000)).await; // Increased delay to ensure server is up

    let client = reqwest::Client::new();
    let base_url = format!("http://{gateway_listen_addr}");

    // 6. Test GET endpoint (/echo-service/ping)
    let ping_url = format!("{base_url}/{echo_service_path}/ping");
    println!("Testing GET: {ping_url}");
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
    println!("GET /{echo_service_path}/ping successful.");

    // 7. Test POST endpoint (/echo-service/echo)
    let echo_url = format!("{base_url}/{echo_service_path}/echo");
    let payload = json!({ "message": "hello from gateway test" });
    println!("Testing POST: {echo_url} with payload: {payload}");

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
    println!("POST /{echo_service_path}/echo successful.");

    // --- Test POST echo_list ---
    let list_payload = json!(["apple", "banana", json!({"fruit_type": "cherry"}), 100]);
    let echo_list_url = format!("{base_url}/{echo_service_path}/echo_list");
    println!("Testing POST: {echo_list_url} with payload: {list_payload}");
    let response_list = client
        .post(&echo_list_url)
        .json(&list_payload)
        .send()
        .await?;
    assert_eq!(
        response_list.status(),
        HttpStatus::OK,
        "echo_list request failed. Status: {:?}, Body: {:?}",
        response_list.status(),
        response_list.text().await?
    );
    let response_body_list: JsonValue = response_list.json().await?;
    assert_eq!(response_body_list, list_payload);
    println!("POST /{echo_service_path}/echo_list successful.");

    // --- Test POST echo_map ---
    let map_payload = json!({
        "key1": "value1",
        "key2": 123,
        "nested": {
            "n_key": true
        }
    });
    let echo_map_url = format!("{base_url}/{echo_service_path}/echo_map");
    println!("Testing POST: {echo_map_url} with payload: {map_payload}");
    let response_map = client.post(&echo_map_url).json(&map_payload).send().await?;
    assert_eq!(
        response_map.status(),
        HttpStatus::OK,
        "echo_map request failed. Status: {:?}, Body: {:?}",
        response_map.status(),
        response_map.text().await?
    );
    let response_body_map: JsonValue = response_map.json().await?;
    assert_eq!(response_body_map, map_payload);
    println!("POST /{echo_service_path}/echo_map successful.");

    // --- Test POST echo_struct ---
    let struct_payload_data = MyTestData {
        id: 1,
        name: "Test Struct".to_string(),
        active: true,
    };
    let struct_payload_json = serde_json::to_value(&struct_payload_data)?;
    let echo_struct_url = format!("{base_url}/{echo_service_path}/echo_struct");
    println!("Testing POST: {echo_struct_url} with payload: {struct_payload_json}");
    let response_struct = client
        .post(&echo_struct_url)
        .json(&struct_payload_json)
        .send()
        .await?;
    assert_eq!(
        response_struct.status(),
        HttpStatus::OK,
        "echo_struct request failed. Status: {:?}, Body: {:?}",
        response_struct.status(),
        response_struct.text().await?
    );
    let response_body_struct: MyTestData = response_struct.json().await?;
    assert_eq!(response_body_struct, struct_payload_data);
    println!("POST /{echo_service_path}/echo_struct successful.");

    // 8. Stop Node
    node.stop().await?;
    println!("Node stopped.");

    Ok(())
}
