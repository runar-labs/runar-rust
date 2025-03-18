# Service Macros Implementation Plan

## Main Goal

**Implement all necessary features in the KAGI macros and node core to enable the full functionality demonstrated in `docs/services/macros_example.rs`.**

The primary focus is to support service operations through the Node API (not direct method calls), including:
1. Service registration with the Node
2. Action execution via `node.request()`
3. Event subscription and publishing through the Node
4. Support for both direct value and mapped parameters
5. Create an example file based on `docs/services/macros_example.rs` and make sure it compiles and runs correctly

At project completion, the example code must compile and run exactly as expected, with all features fully implemented (no mocks or shortcuts).

## Target API

As shown in `docs/services/macros_example.rs`, the desired API has these key features:

### 1. Service Creation and Registration with Node
```rust
// Define the service
#[service(
    name = "data",
    description = "Processes and transforms data",
    version = "1.0.0"
)]
struct DataProcessorService {
    counter: u32,
}

// Create and register with Node
let data_processor = DataProcessorService::new();
node.add_service(data_processor).await?;
```

### 2. Action Methods Invoked via Node API
```rust
// Define action in service
#[action(name = "transform")]
async fn transform(&self, context: &RequestContext, data: &str) -> Result<String> {
    // Implementation...
    Ok(transformed)
}

// Invoke through Node API
// With mapped parameters:
let transform_result = node.request(
    "data/transform",
    vmap! {
        "data" => "hello world"
    }
).await?;

// With direct parameter:
let transform_result2 = node.request(
    "data/transform",
     "hello world" 
).await?;
```

### 3. Event Subscriptions and Publishing Through Node
```rust
// Define subscription in service
#[subscribe(topic = "text_events")]
async fn handle_text_events(&mut self, payload: ValueType) -> Result<()> {
    // Implementation...
    Ok(())
}

// Publish event through context in action method
context.publish("events/data_events", event_data).await?;

// Publish event directly through Node API
node.publish(
    "events/custom",
    vmap! {
        "message" => "direct publish",
        "timestamp" => chrono::Utc::now().to_rfc3339(),
        "data" => "custom event data"
    }
).await?;
```

## Components to Implement

To achieve the target API, we need to implement or modify the following components:

1. **Service Macro (`service`)**
   - Generate AbstractService implementation for Node integration
   - Support registration with Node via `node.add_service()`
   - Implement metadata methods (name, path, description, version)
   - Handle request dispatch to action methods

2. **Action Macro (`action`)**
   - Allow action invocation via `node.request()`
   - Support both direct and mapped parameter extraction
   - Preserve method signatures returning `Result<T>` (not ServiceResponse)
   - Convert results to ServiceResponse when returning to Node

3. **Subscribe Macro (`subscribe`)**
   - Register handlers with Node's subscription system
   - Support both full path and service-relative topic paths
   - Support handler cloning for subscription callbacks

4. **Node API Extensions**
   - Implement `node.request()` to support both direct values and vmap parameters
   - Implement `node.publish()` for direct event publishing
   - Support service registration via `node.add_service()`
   - Handle parameter type conversion in request handling

5. **RequestContext Implementation**
   - Support event publishing via `context.publish()`
   - Provide access to request metadata
   - Bridge between handler and Node

## Implementation Plan

### Phase 1: Core Macro Development

#### Service Macro Implementation
- Parse struct and extract attributes (name, path, description, version)
- Generate AbstractService implementation that integrates with Node
- Implement dispatch logic in `handle_request` method
- Support subscription setup during service initialization

#### Action Macro Implementation
- Parse method and attributes
- Keep original method signature returning `Result<T>`
- Generate operation handlers that map to service methods
- Implement parameter extraction from both direct and mapped parameters
- Convert return values to ServiceResponse format

#### Subscribe Macro Implementation
- Parse method and topic attribute
- Support relative and absolute topic paths
- Register subscriptions with the Node during initialization
- Handle event payload extraction using vmap pattern

### Phase 2: Node API Integration

#### Node Request Method Enhancement
- Support both direct values and vmap! for parameters
- Implement path parsing to identify service and operation
- Route requests to the appropriate service handler
- Convert responses back to client-friendly format

#### Service Registry and Event System
- Implement service registration and lookup
- Support event subscription registration
- Implement event publishing and routing
- Handle service lifecycle events (init, start, stop)

### Phase 3: RequestContext Implementation
- Provide access to request metadata
- Implement event publishing
- Support parameter extraction

### Phase 4: Testing and Integration
- Create comprehensive tests for each macro
- Test Node API with various parameter patterns
- Validate event subscription and publishing
- Ensure example file works end-to-end

## Specific Implementation Details

### Service Macro Code Generation
```rust
// The service macro will generate code like this
impl AbstractService for DataProcessorService {
    async fn handle_request(&self, request: ServiceRequest) -> Result<ServiceResponse> {
        match request.operation.as_str() {
            "transform" => {
                // Extract parameters and call the actual method
                let data = extract_parameter::<String>(&request.params, "data")?;
                let result = self.transform(&request.context, &data).await?;
                Ok(ServiceResponse::success(result))
            },
            // Other operations...
            _ => Err(anyhow!("Unknown operation"))
        }
    }
    
    // Other method implementations...
}
```

### Action Registration Approach
```rust
// The action macro will add operations to the handle_request match
#[action(name = "transform")]
async fn transform(&self, context: &RequestContext, data: &str) -> Result<String> {
    // Original method implementation
}

// Will generate something like:
const _: () = {
    extern crate std;
    
    #[doc(hidden)]
    #[allow(non_snake_case)]
    fn __register_transform() {
        ACTION_HANDLERS.with(|handlers| {
            handlers.borrow_mut().insert("transform", |this, ctx, params| {
                Box::pin(async move {
                    // Parameter extraction
                    let data = extract_param::<String>(&params, "data")?;
                    
                    // Call actual method and convert result
                    let result = this.transform(ctx, &data).await?;
                    Ok(ServiceResponse::success(result))
                })
            });
        });
    }
}
```

### Subscription Registration
```rust
// The subscribe macro will register with the Node's event system
#[subscribe(topic = "text_events")]
async fn handle_text_events(&mut self, payload: ValueType) -> Result<()> {
    // Original handler implementation
}

// Will generate something like:
const _: () = {
    extern crate std;
    
    #[doc(hidden)]
    #[allow(non_snake_case)]
    fn __register_handle_text_events(service: &impl AbstractService, context: &RequestContext) {
        let service_clone = service.clone();
        
        tokio::spawn(async move {
            let topic = format!("{}/{}", service.path(), "text_events");
            
            context.subscribe_to_topic(&topic, move |payload| {
                let mut service_instance = service_clone.clone();
                
                Box::pin(async move {
                    service_instance.handle_text_events(payload).await?;
                    Ok(())
                })
            });
        });
    }
}
```

## Testing Strategy

1. Unit Tests for Each Macro
   - Test service macro with different attribute combinations
   - Test action macro with various parameter patterns
   - Test subscribe macro with different topic formats

2. Integration Tests for Node API
   - Test service registration and operation execution
   - Test direct value and mapped parameter passing
   - Test event subscription and publishing

3. Example File Validation
   - Ensure the entire example file compiles and runs correctly
   - Validate all operations work as expected

## Success Criteria

1. All macros generate correct code for Node integration
2. The `node.request()` method handles both direct values and vmap parameters
3. Event subscription and publishing work through the Node
4. All tests pass and example file runs as expected
5. Code follows guidelines in `guidelines.md`
6. No warnings or unused code

## Timeline

1. Phase 1: Core Macro Development (3 days)
2. Phase 2: Node API Integration (3 days)
3. Phase 3: RequestContext Implementation (2 days)
4. Phase 4: Testing and Integration (2 days)

Total estimated timeline: 10 working days. 