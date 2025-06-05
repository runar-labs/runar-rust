# Runar Macros

This crate provides procedural macros for the Runar Node system, making it easier to define services, actions, and handle events.

## Service Macro
The `service` macro automatically implements the `AbstractService` trait for a struct, generating the required lifecycle methods and handling action registration. It follows the architectural principle of clear service boundaries with well-defined interfaces.

### INTENTION
Simplify service implementation by automating boilerplate code while maintaining architectural boundaries and ensuring proper documentation.

### Usage

```rust
#[service]
pub struct MathService {
    // Required fields for AbstractService
    name: String,
    path: String,
    version: String,
    description: String,
    network_id: Option<String>,
    
    // Service-specific fields
    counter: Arc<Mutex<i32>>,
}
```

The macro will:
1. Implement the `AbstractService` trait
2. Generate `Clone` implementation if not present
3. Create the `init()`, `start()`, and `stop()` methods
4. Set up the action registration infrastructure

## Action Macro

The `action` macro marks methods as actions to be registered during service initialization. It follows the architectural principle of request-based communication with clear API interfaces.

### INTENTION
Simplify action implementation by automating parameter extraction, error handling, and action registration while maintaining proper context usage.

### Usage

```rust
// Basic action with default name (same as method name)
#[action]
async fn add(&self, a: f64, b: f64, ctx: &RequestContext) -> Result<f64> {
    // Implementation with proper context usage for logging
    ctx.debug(format!("Adding {} + {}", a, b));
    Ok(a + b)
}

// Action with custom name
#[action("multiply_numbers")]
async fn multiply(&self, a: f64, b: f64, ctx: &RequestContext) -> Result<f64> {
    ctx.debug(format!("Multiplying {} * {}", a, b));
    Ok(a * b)
}
```

The macro will:
1. Generate a handler function that extracts parameters from the request
2. Properly handle errors and convert them to appropriate responses
3. Register the action during service initialization
4. Ensure proper context usage for logging and error reporting

### Event Macros
The `publish` and `subscribe` macros simplify event-based communication.

```rust
// Subscribe to events
#[subscribe("example_topic")]
async fn on_example_topic(&mut self, context: &RequestContext, payload: ArcValueType) -> Result<()> {
    // Handle event
    Ok(())
}

// Publish events - onmy make sense when combined with action macro - it will fire an event with the result of the action
#[action]
#[publish("example_topic")]
async fn example_topic_action(&self, context: &RequestContext, a: f64, b: f64) -> f64 {
    // Event will be published to the topic
    a * b
}
```

## Implementation Example

Here's a complete example showing how to use the service and action macros together to create a fully functional math service:

```rust
use anyhow::Result;
use runar_common::types::ArcValueType;
use runar_macros::{action, service};
use runar_node::services::{LifecycleContext, RequestContext, ServiceResponse};
use std::sync::{Arc, Mutex};

// Define a math service using the service macro
#[service]
pub struct MathService {
    // Required fields for AbstractService
    name: String,
    path: String,
    version: String,
    description: String,
    network_id: Option<String>,
    
    // Service-specific fields
    counter: Arc<Mutex<i32>>,
}

impl MathService {
    // Constructor following the single primary constructor principle
    pub fn new(name: &str, path: &str) -> Self {
        Self {
            name: name.to_string(),
            path: path.to_string(),
            version: "1.0.0".to_string(),
            description: "Math service".to_string(),
            network_id: None,
            counter: Arc::new(Mutex::new(0)),
        }
    }

    // Define an action using the action macro
    #[action]
    async fn add(&self, a: f64, b: f64, ctx: &RequestContext) -> Result<f64> {
        // Increment the counter
        let mut counter = self.counter.lock().unwrap();
        *counter += 1;

        // Log using the context
        ctx.debug(format!("Adding {} + {}", a, b));

        // Return the result
        Ok(a + b)
    }

    // Define another action with a custom name
    #[action("multiply_numbers")]
    async fn multiply(&self, a: f64, b: f64, ctx: &RequestContext) -> Result<f64> {
        // Increment the counter
        let mut counter = self.counter.lock().unwrap();
        *counter += 1;

        // Log using the context
        ctx.debug(format!("Multiplying {} * {}", a, b));

        // Return the result
        Ok(a * b)
    }

    // Method to get the current counter value
    pub fn get_counter(&self) -> i32 {
        *self.counter.lock().unwrap()
    }
}
```

## Testing the Implementation

Here's how to test the service and action macros in a real-world scenario:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use runar_node::Node;
    use runar_node::NodeConfig;
    use tokio::time::timeout;
    use std::time::Duration;

    #[tokio::test]
    async fn test_math_service() {
        // Create a node with a test network ID
        let mut config = NodeConfig::new("test-node", "test_network");
        // Disable networking for testing
        config.network_config = None;
        let mut node = Node::new(config).await.unwrap();

        // Create a test math service
        let service = MathService::new("Math", "math");

        // Add the service to the node
        node.add_service(service).await.unwrap();

        // Start the node to initialize all services
        node.start().await.unwrap();

        // Make a request to the add action
        let params = ArcValueType::new_array(vec![
            ArcValueType::new_primitive(5.0f64),
            ArcValueType::new_primitive(3.0f64),
        ]);

        let response = timeout(
            Duration::from_secs(5),
            node.request_action("math", "add", Some(params)),
        )
        .await
        .unwrap()
        .unwrap();

        // Verify the response
        assert_eq!(response.status, 200);
        assert_eq!(
            response.data.unwrap().as_type::<f64>().unwrap(),
            8.0
        );

        // Make a request to the multiply action (with custom name)
        let params = ArcValueType::new_array(vec![
            ArcValueType::new_primitive(5.0f64),
            ArcValueType::new_primitive(3.0f64),
        ]);

        let response = timeout(
            Duration::from_secs(5),
            node.request_action("math", "multiply_numbers", Some(params)),
        )
        .await
        .unwrap()
        .unwrap();

        // Verify the response
        assert_eq!(response.status, 200);
        assert_eq!(
            response.data.unwrap().as_type::<f64>().unwrap(),
            15.0
        );
    }
}
```
 