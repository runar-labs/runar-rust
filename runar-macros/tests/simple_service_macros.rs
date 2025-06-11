// Test for the service and action macros
//
// This test demonstrates how to use the service and action macros
// to create a simple service with actions.

use anyhow::{anyhow, Result};
use futures::lock::Mutex;
use runar_common::types::schemas::{ActionMetadata, ServiceMetadata};
use runar_common::types::ArcValue;
use runar_macros::{action, publish, service, subscribe};
use runar_node::services::{EventContext, RequestContext};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc}; // Added for metadata testing

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct MyData {
    id: i32,
    text_field: String,
    number_field: i32,
    boolean_field: bool,
    float_field: f64,
    vector_field: Vec<i32>,
    map_field: HashMap<String, i32>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct PreWrappedStruct {
    id: String,
    value: i32,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct User {
    id: i32,
    name: String,
    email: String,
    age: i32,
}

// Define a simple math service
pub struct TestService {
    store: Arc<Mutex<HashMap<String, ArcValue>>>,
}

// Implement Clone manually for TestMathService
impl Clone for TestService {
    fn clone(&self) -> Self {
        Self {
            store: self.store.clone(),
        }
    }
}

#[service(
    name = "Test Service Name",
    path = "math",
    description = "Test Service Description",
    version = "0.0.1"
)]
impl TestService {
    fn new(path: impl Into<String>, store: Arc<Mutex<HashMap<String, ArcValue>>>) -> Self {
        let instance = Self {
            store: store.clone(),
        };
        instance.set_path(&path.into());
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
    async fn echo_pre_wrapped_struct(&self, id_str: String, val_int: i32) -> Result<ArcValue> {
        let data = PreWrappedStruct {
            id: id_str,
            value: val_int,
        };
        // Manually wrap in ArcValue, like in micro_services_demo
        Ok(ArcValue::from_struct(data))
    }

    //the publish macro will do a ctx.publish("my_data_auto", ArcValue::from_struct(action_result.clone())).await?;
    //it will publish the result of the action o the path (full or relative) same ruleas as action, subscribe macros in termos fo topic rules.,
    #[publish(path = "my_data_auto")]
    #[action(path = "my_data")]
    async fn get_my_data(&self, id: i32, ctx: &RequestContext) -> Result<MyData> {
        // Log using the context
        ctx.debug(format!("get_my_data id: {}", id));

        let total_res: f64 = ctx
            .request(
                "math/add",
                Some(ArcValue::new_map(HashMap::from([
                    ("a".to_string(), 1000.0),
                    ("b".to_string(), 500.0),
                ]))),
            )
            .await?;
        let total = total_res;

        // Return the result
        let data = MyData {
            id,
            text_field: "test".to_string(),
            number_field: id,
            boolean_field: true,
            float_field: total,
            vector_field: vec![1, 2, 3],
            map_field: HashMap::new(),
        };
        ctx.publish("my_data_changed", Some(ArcValue::from_struct(data.clone())))
            .await?;
        ctx.publish("age_changed", Some(ArcValue::new_primitive(25)))
            .await?;
        Ok(data)
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
            let mut existing = existing.clone();
            let mut existing = existing.as_type::<Vec<MyData>>().unwrap();
            existing.push(data.clone());
            lock.insert("my_data_auto".to_string(), ArcValue::new_list(existing));
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
        ctx.debug(format!("on_added: {}", total));

        let mut lock = self.store.lock().await;
        let existing = lock.get("added");
        if let Some(existing) = existing {
            let mut existing = existing.clone();
            let mut existing = existing.as_type::<Vec<f64>>().unwrap();
            existing.push(total);
            lock.insert("added".to_string(), ArcValue::new_list(existing));
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
            let mut existing = existing.clone();
            let mut existing = existing.as_type::<Vec<MyData>>().unwrap();
            existing.push(data.clone());
            lock.insert("my_data_changed".to_string(), ArcValue::new_list(existing));
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
        ctx.debug(format!("age_changed: {}", new_age));

        let mut lock = self.store.lock().await;
        let existing = lock.get("age_changed");
        if let Some(existing) = existing {
            let mut existing = existing.clone();
            let mut existing = existing.as_type::<Vec<i32>>().unwrap();
            existing.push(new_age);
            lock.insert("age_changed".to_string(), ArcValue::new_list(existing));
        } else {
            lock.insert("age_changed".to_string(), ArcValue::new_list(vec![new_age]));
        }

        Ok(())
    }

    // Define an action using the action macro
    #[publish(path = "added")]
    #[action]
    async fn add(&self, a: f64, b: f64, ctx: &RequestContext) -> Result<f64> {
        // Log using the context
        ctx.debug(format!("Adding {} + {}", a, b));
        // Return the result
        Ok(a + b)
    }

    // Define another action
    #[action]
    async fn subtract(&self, a: f64, b: f64, ctx: &RequestContext) -> Result<f64> {
        // Log using the context
        ctx.debug(format!("Subtracting {} - {}", a, b));

        // Return the result
        Ok(a - b)
    }

    // Define an action with a custom name
    #[action("multiply_numbers")]
    async fn multiply(&self, a: f64, b: f64, ctx: &RequestContext) -> Result<f64> {
        // Log using the context
        ctx.debug(format!("Multiplying {} * {}", a, b));

        // Return the result
        Ok(a * b)
    }

    // Define an action that can fail
    #[action]
    async fn divide(&self, a: f64, b: f64, ctx: &RequestContext) -> Result<f64> {
        // Log using the context
        ctx.debug(format!("Dividing {} / {}", a, b));

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
    use runar_common::hmap;
    use runar_node::config::LogLevel;
    use runar_node::config::LoggingConfig;
    use runar_node::Node;
    use runar_node::NodeConfig;
    use serde_json::json;

    #[tokio::test]
    async fn test_math_service() {
        //set log to debug
        let logging_config = LoggingConfig::new().with_default_level(LogLevel::Debug);

        // Create a node with a test network ID
        let mut config =
            NodeConfig::new("test-node", "test_network").with_logging_config(logging_config);
        // Disable networking
        config.network_config = None;
        let mut node = Node::new(config).await.unwrap();

        let store = Arc::new(Mutex::new(HashMap::new()));

        // Create a test math service
        let service = TestService::new("math", store.clone());

        // Add the service to the node
        node.add_service(service).await.unwrap();

        // Start the node to initialize all services
        node.start().await.expect("Failed to start node");

        // Fetch ServiceMetadata for the "math" service
        let service_metadata_response: ServiceMetadata = node
            .request("$registry/services/math", None::<ArcValue>) // Corrected path and payload with type annotation
            .await
            .expect("Failed to get 'math' service metadata");

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
        //which we dont need yet at this point.

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

        // Create parameters for the add action
        let params = ArcValue::new_map(hmap! {
            "a" => 10.0,
            "b" => 5.0
        });

        // Call the add action
        let response: f64 = node
            .request("math/add", Some(params))
            .await
            .expect("Failed to call add action");

        // Verify the response
        assert_eq!(response, 15.0);

        // Make a request to the subtract action
        // Create parameters for the add action
        let params = ArcValue::new_map(hmap! {
            "a" => 10.0,
            "b" => 5.0
        });

        let response: f64 = node
            .request("math/subtract", Some(params))
            .await
            .expect("Failed to call subtract action");

        // Verify the response
        assert_eq!(response, 5.0);

        // Make a request to the multiply action (with custom name)
        // Create parameters for the add action
        let params = ArcValue::new_map(hmap! {
            "a" => 5.0,
            "b" => 3.0
        });

        let response: f64 = node
            .request("math/multiply_numbers", Some(params))
            .await
            .expect("Failed to call multiply_numbers action");

        // Verify the response
        assert_eq!(response, 15.0);

        // Make a request to the divide action with valid parameters
        let params = ArcValue::new_map(hmap! {
            "a" => 6.0,
            "b" => 3.0
        });

        let response: f64 = node
            .request("math/divide", Some(params))
            .await
            .expect("Failed to call divide action");

        // Verify the response
        assert_eq!(response, 2.0);

        // Make a request to the divide action with invalid parameters (division by zero)
        // Create parameters for the add action
        let params = ArcValue::new_map(hmap! {
            "a" => 6.0,
            "b" => 0.0
        });

        let response: Result<f64, anyhow::Error> = node.request("math/divide", Some(params)).await;

        // Verify the error response
        assert!(response
            .unwrap_err()
            .to_string()
            .contains("Division by zero"));

        // Make a request to the get_user action
        let params = ArcValue::new_primitive(42);
        let response: User = node
            .request("math/get_user", Some(params))
            .await
            .expect("Failed to call get_user action");

        // Verify the response
        assert_eq!(response.name, "John Doe");

        // Make a request to the get_my_data action
        let response: MyData = node
            .request("math/my_data", Some(ArcValue::new_primitive(100)))
            .await
            .expect("Failed to call my_data action");

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
            }
        );

        // Let's assert all the events stored in our store
        let store = store.lock().await;

        // Check if my_data_auto events were stored correctly as a vector
        if let Some(my_data_arc) = store.get("my_data_auto") {
            let mut my_data_arc = my_data_arc.clone(); // Clone to get ownership
            let my_data_vec = my_data_arc.as_list_ref::<MyData>().unwrap();
            assert!(
                !my_data_vec.is_empty(),
                "Expected at least one my_data_auto event"
            );
            assert_eq!(
                my_data_vec[0], my_data,
                "The first my_data_auto event doesn't match expected data"
            );
            println!("my_data_auto events count: {}", my_data_vec.len());
        } else {
            panic!("Expected 'my_data_auto' key in store, but it wasn't found");
        }

        // Check for added events
        if let Some(added_arc) = store.get("added") {
            let mut added_arc = added_arc.clone();
            let added_vec = added_arc.as_list_ref::<f64>().unwrap();
            assert!(!added_vec.is_empty(), "Expected at least one added event");
            assert_eq!(added_vec[0], 15.0, "Expected first added value to be 15.0"); // 10.0 + 5.0
            assert_eq!(
                added_vec[1], 1500.0,
                "Expected second added value to be 1500.0"
            ); // 1000.0 + 500.0
            assert_eq!(added_vec.len(), 2, "Expected two added events");
            println!("added events count: {}", added_vec.len());
        } else {
            panic!("Expected 'added' key in store, but it wasn't found");
        }

        // Check for my_data_changed events
        if let Some(changed_arc) = store.get("my_data_changed") {
            let mut changed_arc = changed_arc.clone();
            let changed_vec = changed_arc.as_list_ref::<MyData>().unwrap();
            assert!(
                !changed_vec.is_empty(),
                "Expected at least one my_data_changed event"
            );
            assert_eq!(
                changed_vec[0].id, my_data.id,
                "Expected first my_data_changed.id to match"
            );
            println!("my_data_changed events count: {}", changed_vec.len());
        } else {
            panic!("Expected 'my_data_changed' key in store, but it wasn't found");
        }

        // Check for age_changed events
        if let Some(age_arc) = store.get("age_changed") {
            let mut age_arc = age_arc.clone();
            let age_vec = age_arc.as_list_ref::<i32>().unwrap();
            assert!(
                !age_vec.is_empty(),
                "Expected at least one age_changed event"
            );
            assert_eq!(age_vec[0], 25, "Expected first age_changed value to be 25");
            assert_eq!(age_vec.len(), 1, "Expected one age_changed event");
            println!("age_changed events count: {}", age_vec.len());
        } else {
            panic!("Expected 'age_changed' key in store, but it wasn't found");
        }
        //make sure type were added properly to the serializer
        let serializer = node.serializer.read().await;
        let arc_value = ArcValue::from_struct(my_data.clone());
        let bytes = serializer.serialize_value(&arc_value).unwrap();

        // Create an Arc<[u8]> directly from the Vec<u8>
        #[allow(clippy::useless_conversion)]
        let arc_bytes = Arc::from(bytes);

        let mut deserialized = serializer.deserialize_value(arc_bytes).unwrap();
        let deserialized_my_data = deserialized.as_type::<MyData>().unwrap();

        assert_eq!(deserialized_my_data, my_data);

        //make sure type were added properly to the serializer
        let user = User {
            id: 42,
            name: "John Doe".to_string(),
            email: "john.doe@example.com".to_string(),
            age: 30,
        };
        let arc_value = ArcValue::from_struct(user.clone());
        let bytes = serializer.serialize_value(&arc_value).unwrap();

        // Create an Arc<[u8]> directly from the Vec<u8>
        #[allow(clippy::useless_conversion)]
        let arc_bytes = Arc::from(bytes);

        let mut deserialized = serializer.deserialize_value(arc_bytes).unwrap();
        let deserialized_user = deserialized.as_type::<User>().unwrap();

        assert_eq!(deserialized_user, user);

        let mut temp_map = HashMap::new();
        temp_map.insert("key1".to_string(), "value1".to_string());
        let param: Vec<HashMap<String, String>> = vec![temp_map];
        let arc_value = ArcValue::new_list(param);
        // complex_data
        let list_result: Vec<HashMap<String, String>> = node
            .request("math/complex_data", Some(arc_value))
            .await
            .expect("Failed to call complex_data action");

        assert_eq!(list_result.len(), 1);
        assert_eq!(list_result[0].get("key1").unwrap(), "value1");

        // Test for pre-wrapped struct action
        let pre_wrapped_params = HashMap::from([
            (
                "id_str".to_string(),
                ArcValue::new_primitive("test_pre_wrap".to_string()),
            ),
            ("val_int".to_string(), ArcValue::new_primitive(999i32)),
        ]);
        let pre_wrapped_res: PreWrappedStruct = node
            .request(
                "math/echo_pre_wrapped_struct",
                Some(ArcValue::new_map(pre_wrapped_params.clone())),
            )
            .await
            .expect("Failed to call echo_pre_wrapped_struct");
        assert_eq!(pre_wrapped_res.id, "test_pre_wrap");
        assert_eq!(pre_wrapped_res.value, 999);

        let pre_wrapped_option_res: Option<PreWrappedStruct> = node
            .request(
                "math/echo_pre_wrapped_struct",
                Some(ArcValue::new_map(pre_wrapped_params)),
            )
            .await
            .expect("Failed to call echo_pre_wrapped_struct for Option result");
        assert!(
            pre_wrapped_option_res.is_some(),
            "Expected Some(PreWrappedStruct) but got None"
        );
        let unwrapped_option_res = pre_wrapped_option_res.unwrap();
        assert_eq!(unwrapped_option_res.id, "test_pre_wrap");
        assert_eq!(unwrapped_option_res.value, 999);

        // Check for added events
        if let Some(added_arc) = store.get("added") {
            let mut added_arc = added_arc.clone();
            let added_vec = added_arc.as_list_ref::<f64>().unwrap();
            assert!(!added_vec.is_empty(), "Expected at least one added event");
            assert_eq!(added_vec[0], 15.0, "Expected first added value to be 15.0"); // 10.0 + 5.0
            assert_eq!(
                added_vec[1], 1500.0,
                "Expected second added value to be 1500.0"
            ); // 1000.0 + 500.0
            assert_eq!(added_vec.len(), 2, "Expected two added events");
            println!("added events count: {}", added_vec.len());
        } else {
            panic!("Expected 'added' key in store, but it wasn't found");
        }

        // Check for my_data_changed events
        if let Some(changed_arc) = store.get("my_data_changed") {
            let mut changed_arc = changed_arc.clone();
            let changed_vec = changed_arc.as_list_ref::<MyData>().unwrap();
            assert!(
                !changed_vec.is_empty(),
                "Expected at least one my_data_changed event"
            );
            assert_eq!(
                changed_vec[0].id, my_data.id,
                "Expected first my_data_changed.id to match"
            );
            println!("my_data_changed events count: {}", changed_vec.len());
        } else {
            panic!("Expected 'my_data_changed' key in store, but it wasn't found");
        }

        // Check for age_changed events
        if let Some(age_arc) = store.get("age_changed") {
            let mut age_arc = age_arc.clone();
            let age_vec = age_arc.as_list_ref::<i32>().unwrap();
            assert!(
                !age_vec.is_empty(),
                "Expected at least one age_changed event"
            );
            assert_eq!(age_vec[0], 25, "Expected first age_changed value to be 25");
            assert_eq!(age_vec.len(), 1, "Expected one age_changed event");
            println!("age_changed events count: {}", age_vec.len());
        } else {
            panic!("Expected 'age_changed' key in store, but it wasn't found");
        }
        //make sure type were added properly to the serializer
        let serializer = node.serializer.read().await;
        let arc_value = ArcValue::from_struct(my_data.clone());
        let bytes = serializer.serialize_value(&arc_value).unwrap();

        // Create an Arc<[u8]> directly from the Vec<u8>
        #[allow(clippy::useless_conversion)]
        let arc_bytes = Arc::from(bytes);

        let mut deserialized = serializer.deserialize_value(arc_bytes).unwrap();
        let deserialized_my_data = deserialized.as_type::<MyData>().unwrap();

        assert_eq!(deserialized_my_data, my_data);

        //make sure type were added properly to the serializer
        let user = User {
            id: 42,
            name: "John Doe".to_string(),
            email: "john.doe@example.com".to_string(),
            age: 30,
        };
        let arc_value = ArcValue::from_struct(user.clone());
        let bytes = serializer.serialize_value(&arc_value).unwrap();

        // Create an Arc<[u8]> directly from the Vec<u8>
        #[allow(clippy::useless_conversion)]
        let arc_bytes = Arc::from(bytes);

        let mut deserialized = serializer.deserialize_value(arc_bytes).unwrap();
        let deserialized_user = deserialized.as_type::<User>().unwrap();

        assert_eq!(deserialized_user, user);

        let mut temp_map = HashMap::new();
        temp_map.insert("key1".to_string(), "value1".to_string());
        let param: Vec<HashMap<String, String>> = vec![temp_map];
        let arc_value = ArcValue::new_list(param);
        // complex_data
        let list_result: Vec<HashMap<String, String>> = node
            .request("math/complex_data", Some(arc_value))
            .await
            .expect("Failed to call complex_data action");

        assert_eq!(list_result.len(), 1);
        assert_eq!(list_result[0].get("key1").unwrap(), "value1");

        //test echo action
        let payload = Some(ArcValue::from_json(json!({
            "message": "Hello, world!"
        })));

        let result: String = node
            .request("math/echo", payload)
            .await
            .expect("Failed to call echo action");

        assert_eq!(result, "Hello, world!");

        let payload = Some(ArcValue::new_primitive("Hello, world!".to_string()));
        let result: String = node
            .request("math/echo", payload)
            .await
            .expect("Failed to call echo action");

        assert_eq!(result, "Hello, world!");
    }
}
