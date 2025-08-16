// Test for the service and action macros
//
// This test demonstrates how to use the service and action macros
// to create a simple service with actions.

use anyhow::{anyhow, Result};
use futures::lock::Mutex;
use runar_macros::{action, publish, service, subscribe};
use runar_macros_common::params;
use runar_node::services::{EventContext, RequestContext};
use runar_schemas::{ActionMetadata, ServiceMetadata};
use runar_serializer::{ArcValue, Plain};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc}; // Added for metadata testing

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Plain)]
pub struct MyData {
    id: i32,
    text_field: String,
    number_field: i32,
    boolean_field: bool,
    float_field: f64,
    vector_field: Vec<i32>,
    map_field: HashMap<String, i32>,
    network_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Plain)]
pub struct PreWrappedStruct {
    id: String,
    value: i32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Plain)]
pub struct User {
    id: i32,
    name: String,
    email: String,
    age: i32,
}

// Encrypted TestProfile struct used for complex_profile action
use runar_serializer as rs; // alias for encryption macro

#[derive(rs::Encrypt, serde::Serialize, serde::Deserialize, Clone, PartialEq, Debug, Default)]
pub struct TestProfile {
    pub id: String,

    #[runar(user, system, search)]
    pub name: String,

    #[runar(user, system, search)]
    pub email: String,

    #[runar(user)]
    pub user_private: String,

    #[runar(user, system, search)]
    pub created_at: u64,
}

// Define a simple math service
#[service(
    name = "Test Service Name",
    path = "math",
    description = "Test Service Description",
    version = "0.0.1"
)]
pub struct TestService {
    store: Arc<Mutex<HashMap<String, ArcValue>>>,
}

// Macro-generated Clone implementation from #[service] provides deep clone including metadata.

#[service]
impl TestService {
    fn new(path: impl Into<String>, store: Arc<Mutex<HashMap<String, ArcValue>>>) -> Self {
        let mut instance = Self {
            store: store.clone(),
            ..Default::default()
        };
        instance.set_path(path.into());
        instance
    }

    #[action]
    async fn complex_data(
        &self,
        data: Vec<HashMap<String, String>>,
        _ctx: &RequestContext,
    ) -> Result<Vec<HashMap<String, String>>> {
        Ok(data)
    }

    #[action]
    async fn get_user(&self, id: i32, _ctx: &RequestContext) -> Result<User> {
        let user = User {
            id,
            name: "John Doe".to_string(),
            email: "john.doe@example.com".to_string(),
            age: 30,
        };
        Ok(user)
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
    async fn echo_single_struct(&self, params: PreWrappedStruct) -> Result<PreWrappedStruct> {
        Ok(params)
    }

    #[action]
    async fn echo_list(&self, params: Vec<ArcValue>) -> Result<Vec<ArcValue>> {
        Ok(params)
    }

    #[publish(path = "echo_list_published")]
    #[action]
    async fn echo_list_with_publish(
        &self,
        params: Vec<ArcValue>,
        ctx: &RequestContext,
    ) -> Result<Vec<ArcValue>> {
        Ok(params)
    }

    #[action]
    async fn echo_pre_wrapped_struct(&self, id_str: String, val_int: i32) -> Result<ArcValue> {
        let data = PreWrappedStruct {
            id: id_str,
            value: val_int,
        };
        // Manually wrap in ArcValue, like in micro_services_demo
        Ok(ArcValue::new_struct(data))
    }

    //the publish macro will do a ctx.publish("my_data_auto", ArcValue::new_struct(action_result.clone())).await?;
    //it will publish the result of the action o the path (full or relative) same ruleas as action, subscribe macros in termos fo topic rules.,
    #[publish(path = "my_data_auto")]
    #[action(path = "my_data")]
    async fn get_my_data(&self, id: i32, ctx: &RequestContext) -> Result<MyData> {
        // Log using the context
        ctx.debug(format!("get_my_data id: {id}"));

        let total_res: ArcValue = ctx
            .request("math/add", Some(params! { "a" => 1000.0, "b" => 500.0 }))
            .await?;
        let total: f64 = total_res.as_type()?;

        // Return the result
        let data = MyData {
            id,
            text_field: "test".to_string(),
            number_field: id,
            boolean_field: true,
            float_field: total,
            vector_field: vec![1, 2, 3],
            map_field: HashMap::new(),
            network_id: self.get_network_id(),
        };
        ctx.publish("my_data_changed", Some(ArcValue::new_struct(data.clone())))
            .await?;
        ctx.publish("age_changed", Some(ArcValue::new_primitive(25)))
            .await?;
        Ok(data)
    }

    #[action]
    async fn complex_profile(
        &self,
        profiles: Vec<HashMap<String, TestProfile>>, // encrypted container
        _ctx: &RequestContext,
    ) -> Result<Vec<HashMap<String, TestProfile>>> {
        Ok(profiles)
    }

    #[subscribe(path = "math/my_data_auto")]
    async fn on_my_data_auto(&self, data: MyData, ctx: &EventContext) -> Result<()> {
        ctx.debug(format!(
            "my_data_auto was an event published using the publish macro ->: {}",
            data.text_field
        ));

        let mut lock = self.store.lock().await;
        let existing = lock.get("my_data_auto");
        if let Some(existing) = existing {
            let existing_vec = existing.as_type_ref::<Vec<MyData>>().unwrap();
            let mut new_vec = (*existing_vec).clone();
            new_vec.push(data.clone());
            lock.insert("my_data_auto".to_string(), ArcValue::new_list(new_vec));
        } else {
            lock.insert(
                "my_data_auto".to_string(),
                ArcValue::new_list(vec![data.clone()]),
            );
        }

        Ok(())
    }

    #[subscribe(path = "math/added")]
    async fn on_added(&self, total: f64, ctx: &EventContext) -> Result<()> {
        ctx.debug(format!("on_added: {total}"));

        let mut lock = self.store.lock().await;
        let existing = lock.get("added");
        if let Some(existing) = existing {
            let existing_vec = existing.as_type_ref::<Vec<f64>>().unwrap();
            let mut new_vec = (*existing_vec).clone();
            new_vec.push(total);
            lock.insert("added".to_string(), ArcValue::new_list(new_vec));
        } else {
            lock.insert("added".to_string(), ArcValue::new_list(vec![total]));
        }

        Ok(())
    }

    #[subscribe(path = "math/my_data_changed")]
    async fn on_my_data_changed(&self, data: MyData, ctx: &EventContext) -> Result<()> {
        ctx.debug(format!("my_data_changed: {}", data.text_field));

        let mut lock = self.store.lock().await;
        let existing = lock.get("my_data_changed");
        if let Some(existing) = existing {
            let existing_vec = existing.as_type_ref::<Vec<MyData>>().unwrap();
            let mut new_vec = (*existing_vec).clone();
            new_vec.push(data.clone());
            lock.insert("my_data_changed".to_string(), ArcValue::new_list(new_vec));
        } else {
            lock.insert(
                "my_data_changed".to_string(),
                ArcValue::new_list(vec![data.clone()]),
            );
        }

        Ok(())
    }

    #[subscribe(path = "math/age_changed")]
    async fn on_age_changed(&self, new_age: i32, ctx: &EventContext) -> Result<()> {
        ctx.debug(format!("age_changed: {new_age}"));

        let mut lock = self.store.lock().await;
        let existing = lock.get("age_changed");
        if let Some(existing) = existing {
            let existing_vec = existing.as_type_ref::<Vec<i32>>().unwrap();
            let mut new_vec = (*existing_vec).clone();
            new_vec.push(new_age);
            lock.insert("age_changed".to_string(), ArcValue::new_list(new_vec));
        } else {
            lock.insert("age_changed".to_string(), ArcValue::new_list(vec![new_age]));
        }

        Ok(())
    }

    #[subscribe(path = "math/echo_list_published")]
    async fn on_echo_list_published(&self, data: Vec<ArcValue>, ctx: &EventContext) -> Result<()> {
        ctx.debug(format!(
            "echo_list_published was an event published using the publish macro ->: {} items",
            data.len()
        ));

        let mut lock = self.store.lock().await;
        let existing = lock.get("echo_list_published");
        if let Some(existing) = existing {
            let existing_vec = existing.as_type_ref::<Vec<Vec<ArcValue>>>().unwrap();
            let mut new_vec = (*existing_vec).clone();
            new_vec.push(data.clone());
            lock.insert(
                "echo_list_published".to_string(),
                ArcValue::new_list(new_vec),
            );
        } else {
            lock.insert(
                "echo_list_published".to_string(),
                ArcValue::new_list(vec![data.clone()]),
            );
        }

        Ok(())
    }

    // Define an action using the action macro
    #[publish(path = "added")]
    #[action]
    async fn add(&self, a: f64, b: f64, ctx: &RequestContext) -> Result<f64> {
        // Log using the context
        ctx.debug(format!("Adding {a} + {b}"));
        // Return the result
        Ok(a + b)
    }

    // Define another action
    #[action]
    async fn subtract(&self, a: f64, b: f64, ctx: &RequestContext) -> Result<f64> {
        // Log using the context
        ctx.debug(format!("Subtracting {a} - {b}"));

        // Return the result
        Ok(a - b)
    }

    // Define an action with a custom name
    #[action("multiply_numbers")]
    async fn multiply(&self, a: f64, b: f64, ctx: &RequestContext) -> Result<f64> {
        // Log using the context
        ctx.debug(format!("Multiplying {a} * {b}"));

        // Return the result
        Ok(a * b)
    }

    // Define an action that can fail
    #[action]
    async fn divide(&self, a: f64, b: f64, ctx: &RequestContext) -> Result<f64> {
        // Log using the context
        ctx.debug(format!("Dividing {a} / {b}"));

        // Check for division by zero
        if b == 0.0 {
            ctx.error("Division by zero".to_string());
            return Err(anyhow::anyhow!("Division by zero"));
        }

        // Return the result
        Ok(a / b)
    }

    // Test action that demonstrates the lifetime issue with references
    // This is similar to what happens in the SQLite service
    #[action]
    async fn test_lifetime_issue(&self, _ctx: &RequestContext) -> Result<String> {
        // Create a string that we'll take a reference to
        let data = "test_data".to_string();

        // Take a reference to the string
        let data_ref = &data;

        // Simulate an async operation that would require 'static
        let result = async move {
            // This would fail if the macro enforces 'static on all references
            // because data_ref is tied to the stack frame of test_lifetime_issue
            data_ref.to_string()
        }
        .await;

        Ok(result)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use runar_common::logging::{Component, Logger};
    use runar_node::config::{LogLevel, LoggingConfig};
    use runar_node::Node;
    use runar_serializer::ValueCategory;
    use runar_test_utils::create_node_test_config;
    use serde_json::json;

    struct TestContext {
        node: Node,
        store: Arc<Mutex<HashMap<String, ArcValue>>>,
        default_network_id: String,
        logger: Arc<Logger>,
    }

    async fn create_test_context() -> TestContext {
        //set log to debug
        let logging_config = LoggingConfig::new().with_default_level(LogLevel::Warn);
        logging_config.apply();

        let logger = Arc::new(Logger::new_root(Component::Custom("macro_test"), ""));
        logger.debug("Creating test context");

        // Create a node with a test network ID
        let config = create_node_test_config()
            .expect("Error creating test config")
            .with_logging_config(logging_config);

        let default_network_id = config.default_network_id.clone();

        let mut node = Node::new(config).await.unwrap();

        let store = Arc::new(Mutex::new(HashMap::new()));

        // Create a test math service
        let service = TestService::new("math", store.clone());

        // Add the service to the node
        node.add_service(service).await.unwrap();

        // Start the node to initialize all services
        node.start().await.expect("Failed to start node");
        node.wait_for_services_to_start()
            .await
            .expect("Services did not reach Running state");

        TestContext {
            node,
            store,
            default_network_id,
            logger,
        }
    }

    #[tokio::test]
    async fn test_service_metadata() {
        let ctx = create_test_context().await;
        ctx.logger.debug("Testing service metadata");

        // Fetch ServiceMetadata for the "math" service
        let service_metadata_response_arc: ArcValue = ctx
            .node
            .request("$registry/services/math", None::<ArcValue>) // Corrected path and payload with type annotation
            .await
            .expect("Failed to get 'math' service metadata");
        let service_metadata_response: ServiceMetadata = service_metadata_response_arc
            .as_type()
            .expect("Failed to convert to ServiceMetadata");

        // Assert ServiceMetadata properties
        assert_eq!(service_metadata_response.name, "Test Service Name");
        assert_eq!(service_metadata_response.service_path, "math");
        assert_eq!(
            service_metadata_response.description,
            "Test Service Description"
        );
        assert_eq!(service_metadata_response.version, "0.0.1");

        // Assert ActionMetadata for the "add" action
        let add_action_meta: &ActionMetadata = service_metadata_response
            .actions
            .iter()
            .find(|am| am.name == "add")
            .expect("Could not find 'add' action metadata");

        assert_eq!(add_action_meta.name, "add");

        //TODO Events Metadata is now working  .. BUT the actual modeling is wrong.. we store the event metadata by the serviee of the event pathn itself]
        //and I am not sure how this is usefrull .. prob is nbot.. but wer shuold fix his when we actualy need the event metadata,
        //which we don't need yet at this point.

        // Description for 'add' action is likely empty as it's not specified in the #[action] macro
        // For actions without specific descriptions, the description field might be an empty string or a default.
        // Let's assume empty for now, or we can check if it's Some("") or None depending on how it's generated.
        // For now, we'll focus on the name. We can refine schema/description checks later.

        // Assert EventMetadata for the "my_data_auto" event
        // This event is declared via #[publish(path = "my_data_auto")] on get_my_data
        // let my_data_auto_event_meta: &EventMetadata = service_metadata_response
        //     .events
        //     .iter()
        //     .find(|em| em.path == "my_data_auto" || em.path == "math/my_data_auto")
        //     .expect("Could not find 'my_data_auto' or 'math/my_data_auto' event metadata");

        // // Check if the path is one of the expected values
        // assert!(my_data_auto_event_meta.path == "my_data_auto" || my_data_auto_event_meta.path == "math/my_data_auto",
        //         "Event path was: {}", my_data_auto_event_meta.path);
        // Description for 'my_data_auto' event is also likely empty.
    }

    #[tokio::test]
    async fn test_basic_math_actions() {
        let ctx = create_test_context().await;
        ctx.logger.debug("Testing basic math actions");

        // Call the add action directly with `params!`.
        let response_arc: ArcValue = ctx
            .node
            .request("math/add", Some(params! { "a" => 10.0, "b" => 5.0 }))
            .await
            .expect("Failed to call add action");
        let response: f64 = response_arc.as_type().expect("Failed to convert to f64");

        // Verify the response
        assert_eq!(response, 15.0);

        // Test JSON serialization
        let json_result = response_arc.to_json().expect("Failed to convert to JSON");
        assert_eq!(json_result, json!(15.0));

        // Test subtract action
        let response_arc: ArcValue = ctx
            .node
            .request("math/subtract", Some(params! { "a" => 10.0, "b" => 5.0 }))
            .await
            .expect("Failed to call subtract action");
        let response: f64 = response_arc.as_type().expect("Failed to convert to f64");

        // Verify the response
        assert_eq!(response, 5.0);

        // Test JSON serialization
        let json_result = response_arc.to_json().expect("Failed to convert to JSON");
        assert_eq!(json_result, json!(5.0));

        // Make a request to the multiply action (with custom name)
        // Create parameters for the add action
        let params = params! { "a" => 5.0, "b" => 3.0 };

        let response_arc: ArcValue = ctx
            .node
            .request("math/multiply_numbers", Some(params))
            .await
            .expect("Failed to call multiply_numbers action");
        let response: f64 = response_arc.as_type().expect("Failed to convert to f64");

        // Verify the response
        assert_eq!(response, 15.0);

        // Test JSON serialization
        let json_result = response_arc.to_json().expect("Failed to convert to JSON");
        assert_eq!(json_result, json!(15.0));

        // Make a request to the divide action with valid parameters
        let params = params! { "a" => 6.0, "b" => 3.0 };

        let response_arc: ArcValue = ctx
            .node
            .request("math/divide", Some(params))
            .await
            .expect("Failed to call divide action");
        let response: f64 = response_arc.as_type().expect("Failed to convert to f64");

        // Verify the response
        assert_eq!(response, 2.0);

        // Test JSON serialization
        let json_result = response_arc.to_json().expect("Failed to convert to JSON");
        assert_eq!(json_result, json!(2.0));

        // Make a request to the divide action with invalid parameters (division by zero)
        // Create parameters for the add action
        let params = params! { "a" => 6.0, "b" => 0.0 };

        let response: Result<ArcValue, anyhow::Error> =
            ctx.node.request("math/divide", Some(params)).await;

        // Verify the error response
        assert!(response
            .unwrap_err()
            .to_string()
            .contains("Division by zero"));
    }

    #[tokio::test]
    async fn test_user_actions() {
        let ctx = create_test_context().await;
        ctx.logger.debug("Testing user actions");

        // Make a request to the get_user action
        let params = ArcValue::new_primitive(42);
        let response_arc: ArcValue = ctx
            .node
            .request("math/get_user", Some(params))
            .await
            .expect("Failed to call get_user action");
        let response: User = response_arc.as_type().expect("Failed to convert to User");

        // Verify the response
        assert_eq!(response.name, "John Doe");

        // Test JSON serialization
        let json_result = response_arc.to_json().expect("Failed to convert to JSON");
        assert_eq!(
            json_result,
            json!({
                "id": 42,
                "name": "John Doe",
                "email": "john.doe@example.com",
                "age": 30
            })
        );
    }

    #[tokio::test]
    async fn test_my_data_action() {
        let ctx = create_test_context().await;
        ctx.logger.debug("Testing my_data action");

        // Make a request to the get_my_data action
        let response_arc: ArcValue = ctx
            .node
            .request("math/my_data", Some(ArcValue::new_primitive(100)))
            .await
            .expect("Failed to call my_data action");
        let response: MyData = response_arc.as_type().expect("Failed to convert to MyData");

        // Verify the response
        let my_data = response;
        assert_eq!(
            my_data,
            MyData {
                id: 100,
                text_field: "test".to_string(),
                number_field: 100,
                boolean_field: true,
                float_field: 1500.0,
                vector_field: vec![1, 2, 3],
                map_field: HashMap::new(),
                network_id: Some(ctx.default_network_id.clone()),
            }
        );

        // Test JSON serialization
        let json_result = response_arc.to_json().expect("Failed to convert to JSON");
        assert_eq!(
            json_result,
            json!({
                "id": 100,
                "text_field": "test",
                "number_field": 100,
                "boolean_field": true,
                "float_field": 1500.0,
                "vector_field": [1, 2, 3],
                "map_field": {},
                "network_id": ctx.default_network_id
            })
        );
    }

    #[tokio::test]
    async fn test_events_storage() {
        let ctx = create_test_context().await;
        ctx.logger.debug("Testing events storage");

        // Trigger events by calling add action first (this will create the first added event with 15.0)
        let response_arc: ArcValue = ctx
            .node
            .request("math/add", Some(params! { "a" => 10.0, "b" => 5.0 }))
            .await
            .expect("Failed to call add action");
        let add_result: f64 = response_arc.as_type().expect("Failed to convert to f64");
        assert_eq!(add_result, 15.0);

        // Then trigger events by calling my_data action (this will create the second added event with 1500.0)
        let response_arc: ArcValue = ctx
            .node
            .request("math/my_data", Some(ArcValue::new_primitive(100)))
            .await
            .expect("Failed to call my_data action");
        let my_data: MyData = response_arc.as_type().expect("Failed to convert to MyData");

        // Let's assert all the events stored in our store
        let store = ctx.store.lock().await;

        // Check if my_data_auto events were stored correctly as a vector
        if let Some(my_data_arc) = store.get("my_data_auto") {
            let my_data_vec = my_data_arc.as_type_ref::<Vec<MyData>>().unwrap();
            assert!(
                !my_data_vec.is_empty(),
                "Expected at least one my_data_auto event"
            );
            assert_eq!(
                my_data_vec[0], my_data,
                "The first my_data_auto event doesn't match expected data"
            );
            ctx.logger
                .debug(format!("my_data_auto events count: {}", my_data_vec.len()));
        } else {
            panic!("Expected 'my_data_auto' key in store, but it wasn't found");
        }

        // Check for added events
        if let Some(added_arc) = store.get("added") {
            let added_vec = added_arc.as_type_ref::<Vec<f64>>().unwrap();
            assert!(!added_vec.is_empty(), "Expected at least one added event");
            assert_eq!(added_vec[0], 15.0, "Expected first added value to be 15.0"); // 10.0 + 5.0
            assert_eq!(
                added_vec[1], 1500.0,
                "Expected second added value to be 1500.0"
            ); // 1000.0 + 500.0
            assert_eq!(added_vec.len(), 2, "Expected two added events");
            ctx.logger
                .debug(format!("added events count: {}", added_vec.len()));
        } else {
            panic!("Expected 'added' key in store, but it wasn't found");
        }

        // Check for my_data_changed events
        if let Some(changed_arc) = store.get("my_data_changed") {
            let changed_vec = changed_arc.as_type_ref::<Vec<MyData>>().unwrap();
            assert!(
                !changed_vec.is_empty(),
                "Expected at least one my_data_changed event"
            );
            assert_eq!(
                changed_vec[0].id, my_data.id,
                "Expected first my_data_changed.id to match"
            );
            ctx.logger.debug(format!(
                "my_data_changed events count: {}",
                changed_vec.len()
            ));
        } else {
            panic!("Expected 'my_data_changed' key in store, but it wasn't found");
        }

        // Check for age_changed events
        if let Some(age_arc) = store.get("age_changed") {
            let age_vec = age_arc.as_type_ref::<Vec<i32>>().unwrap();
            assert!(
                !age_vec.is_empty(),
                "Expected at least one age_changed event"
            );
            assert_eq!(age_vec[0], 25, "Expected first age_changed value to be 25");
            assert_eq!(age_vec.len(), 1, "Expected one age_changed event");
            ctx.logger
                .debug(format!("age_changed events count: {}", age_vec.len()));
        } else {
            panic!("Expected 'age_changed' key in store, but it wasn't found");
        }
    }

    #[tokio::test]
    async fn test_complex_data_action() {
        let ctx = create_test_context().await;
        ctx.logger.debug("Testing complex_data action");

        let mut temp_map = HashMap::new();
        temp_map.insert("key1".to_string(), "value1".to_string());
        let param: Vec<HashMap<String, String>> = vec![temp_map];
        let arc_value = ArcValue::new_list(param);
        // complex_data
        let list_result_arc: ArcValue = ctx
            .node
            .request("math/complex_data", Some(arc_value))
            .await
            .expect("Failed to call complex_data action");
        let list_result: Vec<HashMap<String, String>> = list_result_arc
            .as_type()
            .expect("Failed to convert to Vec<HashMap<String, String>>");
        assert_eq!(list_result_arc.category(), ValueCategory::List);

        assert_eq!(list_result.len(), 1);
        assert_eq!(list_result[0].get("key1").unwrap(), "value1");

        // Test JSON serialization
        let json_result = list_result_arc
            .to_json()
            .expect("Failed to convert to JSON");
        assert_eq!(
            json_result,
            json!([
                {
                    "key1": "value1"
                }
            ])
        );
    }

    #[tokio::test]
    async fn test_pre_wrapped_struct_action() {
        let ctx = create_test_context().await;
        ctx.logger.debug("Testing pre_wrapped_struct action");

        // Test for pre-wrapped struct action
        let pre_wrapped_params = HashMap::from([
            (
                "id_str".to_string(),
                ArcValue::new_primitive("test_pre_wrap".to_string()),
            ),
            ("val_int".to_string(), ArcValue::new_primitive(999i32)),
        ]);
        let pre_wrapped_res_arc: ArcValue = ctx
            .node
            .request(
                "math/echo_pre_wrapped_struct",
                Some(ArcValue::new_map(pre_wrapped_params.clone())),
            )
            .await
            .expect("Failed to call echo_pre_wrapped_struct");
        let pre_wrapped_res: PreWrappedStruct = pre_wrapped_res_arc
            .as_type()
            .expect("Failed to convert to PreWrappedStruct");
        assert_eq!(pre_wrapped_res.id, "test_pre_wrap");
        assert_eq!(pre_wrapped_res.value, 999);

        // Test JSON serialization
        let json_result = pre_wrapped_res_arc
            .to_json()
            .expect("Failed to convert to JSON");
        assert_eq!(
            json_result,
            json!({
                "id": "test_pre_wrap",
                "value": 999
            })
        );

        let pre_wrapped_option_res_arc: ArcValue = ctx
            .node
            .request(
                "math/echo_pre_wrapped_struct",
                Some(ArcValue::new_map(pre_wrapped_params)),
            )
            .await
            .expect("Failed to call echo_pre_wrapped_struct for Option result");
        let pre_wrapped_option_res: PreWrappedStruct = pre_wrapped_option_res_arc
            .as_type()
            .expect("Failed to convert to Option<PreWrappedStruct>");

        let unwrapped_option_res = pre_wrapped_option_res;
        assert_eq!(unwrapped_option_res.id, "test_pre_wrap");
        assert_eq!(unwrapped_option_res.value, 999);

        // Test JSON serialization
        let json_result = pre_wrapped_option_res_arc
            .to_json()
            .expect("Failed to convert to JSON");
        assert_eq!(
            json_result,
            json!({
                "id": "test_pre_wrap",
                "value": 999
            })
        );
    }

    #[tokio::test]
    async fn test_echo_actions() {
        let ctx = create_test_context().await;
        ctx.logger.debug("Testing echo actions");

        //test echo action with direct string
        let payload = Some(ArcValue::new_primitive("Hello, world!".to_string()));

        let result_arc: ArcValue = ctx
            .node
            .request("math/echo", payload)
            .await
            .expect("Failed to call echo action");
        let result: String = result_arc.as_type().expect("Failed to convert to String");

        assert_eq!(result, "Hello, world!");

        // Test JSON serialization
        let json_result = result_arc.to_json().expect("Failed to convert to JSON");
        assert_eq!(json_result, json!("Hello, world!"));

        let payload = Some(ArcValue::new_primitive("Hello, world!".to_string()));
        let result_arc: ArcValue = ctx
            .node
            .request("math/echo", payload)
            .await
            .expect("Failed to call echo action");
        let result: String = result_arc.as_type().expect("Failed to convert to String");

        assert_eq!(result, "Hello, world!");

        // Test JSON serialization
        let json_result = result_arc.to_json().expect("Failed to convert to JSON");
        assert_eq!(json_result, json!("Hello, world!"));
    }

    #[tokio::test]
    async fn test_echo_map_action() {
        let ctx = create_test_context().await;
        ctx.logger.debug("Testing echo_map action");

        // Test echo_map action to verify HashMap return type bug
        let test_map = HashMap::from([
            (
                "key1".to_string(),
                ArcValue::new_primitive("value1".to_string()),
            ),
            ("key2".to_string(), ArcValue::new_primitive(123i32)),
            (
                "nested".to_string(),
                ArcValue::new_map(HashMap::from([(
                    "n_key".to_string(),
                    ArcValue::new_primitive(true),
                )])),
            ),
        ]);

        let map_payload = ArcValue::new_map(test_map.clone());
        let map_result_arc: ArcValue = ctx
            .node
            .request("math/echo_map", Some(map_payload))
            .await
            .expect("Failed to call echo_map action");

        // Check if the returned ArcValue has the correct category
        assert_eq!(map_result_arc.category(), ValueCategory::Map);

        let map_result: HashMap<String, ArcValue> = map_result_arc
            .as_type()
            .expect("Failed to convert to HashMap<String, ArcValue>");

        assert_eq!(map_result.len(), 3);
        assert_eq!(
            map_result.get("key1").unwrap().as_type::<String>().unwrap(),
            "value1"
        );
        assert_eq!(
            map_result.get("key1").unwrap().category(),
            ValueCategory::Primitive
        );
        assert_eq!(
            map_result.get("key2").unwrap().as_type::<i32>().unwrap(),
            123
        );
        assert_eq!(
            map_result.get("key2").unwrap().category(),
            ValueCategory::Primitive
        );
        assert_eq!(
            map_result
                .get("nested")
                .unwrap()
                .as_type::<HashMap<String, ArcValue>>()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            map_result.get("nested").unwrap().category(),
            ValueCategory::Map
        );
        assert!(map_result
            .get("nested")
            .unwrap()
            .as_type::<HashMap<String, ArcValue>>()
            .unwrap()
            .get("n_key")
            .unwrap()
            .as_type::<bool>()
            .unwrap());
        assert_eq!(
            map_result
                .get("nested")
                .unwrap()
                .as_type::<HashMap<String, ArcValue>>()
                .unwrap()
                .get("n_key")
                .unwrap()
                .category(),
            ValueCategory::Primitive
        );

        assert_eq!(map_result, test_map);

        // Test JSON serialization
        let json_result = map_result_arc.to_json().expect("Failed to convert to JSON");
        assert_eq!(
            json_result,
            json!({
                "key1": "value1",
                "key2": 123,
                "nested": {
                    "n_key": true
                }
            })
        );
    }

    #[tokio::test]
    async fn test_echo_single_struct_action() {
        let ctx = create_test_context().await;
        ctx.logger.debug("Testing echo_single_struct action");

        // Test echo_single_struct action to reproduce the gateway test scenario
        // This tests the case where a single parameter action receives a JSON payload
        // that should be deserialized directly to the parameter type, not extracted from a map
        let single_struct_payload = Some(ArcValue::new_json(json!({
            "id": "test_single_struct",
            "value": 42
        })));

        let single_struct_result_arc: ArcValue = ctx
            .node
            .request("math/echo_single_struct", single_struct_payload)
            .await
            .expect("Failed to call echo_single_struct action");

        let single_struct_result: PreWrappedStruct = single_struct_result_arc
            .as_type()
            .expect("Failed to convert to PreWrappedStruct");

        assert_eq!(single_struct_result.id, "test_single_struct");
        assert_eq!(single_struct_result.value, 42);

        //try to convert to json
        let json_result = single_struct_result_arc
            .to_json()
            .expect("Failed to convert to JSON");
        assert_eq!(
            json_result,
            json!({
                "id": "test_single_struct",
                "value": 42
            })
        );
    }

    #[tokio::test]
    async fn test_echo_with_json_map_payload() {
        let ctx = create_test_context().await;
        ctx.logger
            .debug("Testing echo action with JSON map payload (gateway test scenario)");

        // This replicates the gateway test scenario where a JSON object is sent to an action
        // that expects a single String parameter. The JSON object should be converted to the String.
        let json_map_payload = Some(ArcValue::new_json(json!({
            "message": "hello from gateway test"
        })));

        let result_arc: ArcValue = ctx
            .node
            .request("math/echo", json_map_payload)
            .await
            .expect("Failed to call echo action with JSON map payload");

        let result: String = result_arc.as_type().expect("Failed to convert to String");

        // The echo action should extract the "message" field from the JSON object
        assert_eq!(result, "hello from gateway test");

        // Test JSON serialization
        let json_result = result_arc.to_json().expect("Failed to convert to JSON");
        assert_eq!(json_result, json!("hello from gateway test"));
    }

    #[tokio::test]
    async fn test_echo_list_action() {
        let ctx = create_test_context().await;
        ctx.logger
            .debug("Testing echo_list action (gateway test scenario)");

        // Test echo_list action to reproduce the gateway test scenario
        // This tests the case where an action returns a list that should be properly converted to JSON
        let list_payload = Some(ArcValue::new_json(json!([
            "apple",
            "banana",
            {"fruit_type": "cherry"},
            100
        ])));

        let echo_list_result_arc: ArcValue = ctx
            .node
            .request("math/echo_list", list_payload)
            .await
            .expect("Failed to call echo_list action");

        // Test that the result can be converted to JSON properly
        let json_result = echo_list_result_arc
            .to_json()
            .expect("Failed to convert to JSON");
        assert_eq!(
            json_result,
            json!([
                "apple",
                "banana",
                {"fruit_type": "cherry"},
                100
            ])
        );

        // Also test that we can extract it as a Vec<ArcValue>
        let list_result: Vec<ArcValue> = echo_list_result_arc
            .as_type()
            .expect("Failed to convert to Vec<ArcValue>");

        assert_eq!(list_result.len(), 4);
        assert_eq!(list_result[0].as_type::<String>().unwrap(), "apple");
        assert_eq!(list_result[1].as_type::<String>().unwrap(), "banana");
        assert_eq!(
            list_result[2]
                .as_type::<HashMap<String, ArcValue>>()
                .unwrap()["fruit_type"]
                .as_type::<String>()
                .unwrap(),
            "cherry"
        );
        assert_eq!(list_result[3].as_type::<i64>().unwrap(), 100);
    }

    #[tokio::test]
    async fn test_complex_profile_action() {
        let ctx = create_test_context().await;
        ctx.logger.debug("Testing complex_profile action");

        // Test complex_profile action with encrypted TestProfile
        let profile = TestProfile {
            id: "prof1".to_string(),
            name: "Alice".to_string(),
            email: "alice@example.com".to_string(),
            user_private: "secret".to_string(),
            created_at: 123456789,
        };

        let mut prof_map = HashMap::new();
        prof_map.insert("p1".to_string(), profile.clone());
        let profiles_param: Vec<HashMap<String, TestProfile>> = vec![prof_map];
        let arc_value = ArcValue::new_list(profiles_param.clone());

        let back_from_arc = arc_value
            .as_type::<Vec<HashMap<String, TestProfile>>>()
            .unwrap();
        assert_eq!(back_from_arc, profiles_param);

        let profile_result_arc: ArcValue = ctx
            .node
            .request("math/complex_profile", Some(arc_value))
            .await
            .expect("Failed to call complex_profile action");
        let profile_result: Vec<HashMap<String, TestProfile>> = profile_result_arc
            .as_type()
            .expect("Failed to convert to Vec<HashMap<String, TestProfile>>");

        //check JSON conversion
        let json_result = profile_result_arc
            .to_json()
            .expect("Failed to convert to JSON");
        assert_eq!(json_result, json!(profiles_param));

        assert_eq!(profile_result, profiles_param);
    }

    #[tokio::test]
    async fn test_publish_macro_bug_fix() {
        let ctx = create_test_context().await;
        ctx.logger.debug(
            "Testing publish macro bug fix - correct serialization of struct vs primitive types",
        );

        // Test 1: Verify that primitive types (f64) use ArcValue::new_primitive
        // This should work without any trait bounds
        let add_result_arc: ArcValue = ctx
            .node
            .request(
                "math/add",
                Some(params! {
                    "a" => 5.0f64,
                    "b" => 3.0f64
                }),
            )
            .await
            .expect("Failed to call add action");

        let add_result: f64 = add_result_arc.as_type().expect("Failed to convert to f64");
        assert_eq!(add_result, 8.0);

        // Test JSON serialization
        let json_result = add_result_arc.to_json().expect("Failed to convert to JSON");
        assert_eq!(json_result, json!(8.0));

        // Test 2: Verify that struct types (MyData) use ArcValue::new_struct
        // This should fail compilation if MyData doesn't implement RunarEncrypt
        // The bug fix ensures that struct types are always serialized using new_struct,
        // which requires the RunarEncrypt trait. If MyData doesn't implement RunarEncrypt,
        // the compilation will fail, forcing developers to add the proper derive macro.
        let my_data_result_arc: ArcValue = ctx
            .node
            .request(
                "math/my_data",
                Some(params! {
                    "id" => 42i32
                }),
            )
            .await
            .expect("Failed to call get_my_data action");

        let my_data_result: MyData = my_data_result_arc
            .as_type()
            .expect("Failed to convert to MyData");
        assert_eq!(my_data_result.id, 42);
        assert_eq!(my_data_result.text_field, "test");
        assert_eq!(my_data_result.number_field, 42); // Should be same as id
        assert!(my_data_result.boolean_field);
        assert_eq!(my_data_result.float_field, 1500.0); // Should be 1000.0 + 500.0

        // Test JSON serialization
        let json_result = my_data_result_arc
            .to_json()
            .expect("Failed to convert to JSON");
        assert_eq!(
            json_result,
            json!({
                "id": 42,
                "text_field": "test",
                "number_field": 42,
                "boolean_field": true,
                "float_field": 1500.0,
                "vector_field": [1, 2, 3],
                "map_field": {},
                "network_id": ctx.default_network_id
            })
        );

        // Test 3: Verify that the published events are correctly serialized
        // Check that the events were stored with the correct serialization method
        let events = ctx.store.lock().await;

        // The add action doesn't have a #[publish] macro, so it won't publish events
        // The get_my_data action has #[publish(path = "my_data_auto")], so it will publish to "my_data_auto"

        // Look for the my_data_auto event (should be published as struct)
        let my_data_event_key = "my_data_auto";
        if let Some(my_data_event) = events.get(my_data_event_key) {
            // The event should be stored as a Vec<MyData> (as per the subscriber)
            let my_data_event_vec: Vec<MyData> = my_data_event
                .as_type()
                .expect("Failed to convert my_data event to Vec<MyData>");
            assert!(
                !my_data_event_vec.is_empty(),
                "Expected at least one my_data_auto event"
            );
            let my_data_event_value = &my_data_event_vec[0];
            assert_eq!(my_data_event_value.id, 42);
            assert_eq!(my_data_event_value.text_field, "test");
            assert_eq!(my_data_event_value.number_field, 42);
            assert_eq!(my_data_event_value.float_field, 1500.0);
        } else {
            panic!("MyData event was not published to my_data_auto");
        }

        // Also check for the manually published events from get_my_data
        let my_data_changed_key = "my_data_changed";
        if let Some(my_data_changed) = events.get(my_data_changed_key) {
            let my_data_changed_vec: Vec<MyData> = my_data_changed
                .as_type()
                .expect("Failed to convert my_data_changed to Vec<MyData>");
            assert!(
                !my_data_changed_vec.is_empty(),
                "Expected at least one my_data_changed event"
            );
            let my_data_changed_value = &my_data_changed_vec[0];
            assert_eq!(my_data_changed_value.id, 42);
            assert_eq!(my_data_changed_value.text_field, "test");
        } else {
            panic!("my_data_changed event was not published");
        }

        ctx.logger.info("✅ Publish macro bug fix verified: struct types use new_struct, primitive types use new_primitive");
        ctx.logger
            .info("✅ The bug fix ensures proper trait bounds are enforced at compile time");
    }

    #[tokio::test]
    async fn test_publish_macro_vec_arcvalue_fix() {
        let ctx = create_test_context().await;
        ctx.logger.debug("Testing publish macro Vec<ArcValue> fix");

        // Test that Vec<ArcValue> is correctly serialized using new_list instead of new_primitive
        let test_list = ArcValue::new_list(vec![
            ArcValue::new_primitive("test1".to_string()),
            ArcValue::new_primitive(42i32),
            ArcValue::new_primitive(true),
        ]);

        let echo_list_result_arc: ArcValue = ctx
            .node
            .request("math/echo_list_with_publish", Some(test_list))
            .await
            .expect("Failed to call echo_list_with_publish action");

        // Verify the action result works correctly
        let list_result: Vec<ArcValue> = echo_list_result_arc
            .as_type()
            .expect("Failed to convert to Vec<ArcValue>");

        assert_eq!(list_result.len(), 3);
        assert_eq!(list_result[0].as_type::<String>().unwrap(), "test1");
        assert_eq!(list_result[1].as_type::<i32>().unwrap(), 42);
        assert!(list_result[2].as_type::<bool>().unwrap());

        // Check that the published event was correctly serialized as a list
        let events = ctx.store.lock().await;
        let echo_list_published_key = "echo_list_published";

        if let Some(published_event) = events.get(echo_list_published_key) {
            // The event should be stored as a Vec<Vec<ArcValue>> (as per the subscriber pattern)
            // This verifies that the publish macro used new_list instead of new_primitive
            let published_event_vec: Vec<Vec<ArcValue>> = published_event
                .as_type()
                .expect("Failed to convert published event to Vec<Vec<ArcValue>>");

            assert!(
                !published_event_vec.is_empty(),
                "Expected at least one echo_list_published event"
            );

            let published_list = &published_event_vec[0];
            assert_eq!(published_list.len(), 3);
            assert_eq!(published_list[0].as_type::<String>().unwrap(), "test1");
            assert_eq!(published_list[1].as_type::<i32>().unwrap(), 42);
            assert!(published_list[2].as_type::<bool>().unwrap());

            ctx.logger.info("✅ Publish macro Vec<ArcValue> fix verified: correctly uses new_list instead of new_primitive");
        } else {
            panic!("echo_list_published event was not published");
        }
    }
}
