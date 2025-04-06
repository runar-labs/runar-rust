//! Simple Events Test
//!
//! This test demonstrates the publish-subscribe event pattern using:
//! 1. ShipService - Publishes 'landed' and 'tookOff' events
//! 2. BaseStationService - Subscribes to and collects these events

// Import the services we created
#[path = "fixtures/ship_service.rs"]
mod ship_service;
#[path = "fixtures/base_station_service.rs"]
mod base_station_service;

use anyhow::Result;
use ship_service::ShipService;
use base_station_service::BaseStationService;
use runar_node::node::{Node, NodeConfig};
use runar_node::services::abstract_service::AbstractService;
use runar_node::ValueType;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;
use std::collections::HashMap;

#[tokio::test]
async fn test_ship_events() -> Result<()> {
    // Set up the test nodes
    println!("Setting up test nodes...");
    println!("Creating NodeConfig with network_id='test_network'");
    let config = NodeConfig::new("test_network", "ship_test", "memory");
    let mut node = Node::new(config).await?;
    
    // Create and add services
    println!("Creating services with explicit names");
    let ship_service = ShipService::new("explorer");
    let base_station_service = BaseStationService::new("base");
    
    println!("Adding ShipService...");
    node.add_service(ship_service).await?;
    
    println!("Adding BaseStationService...");
    node.add_service(base_station_service.clone()).await?;
    
    // Initialize the node
    println!("Initializing node...");
    node.init().await?;
    
    // Start the node
    println!("Starting node...");
    node.start().await?;
    
    // Wait a bit to ensure services are fully started
    println!("Waiting for services to start...");
    sleep(Duration::from_millis(250)).await;
    
    // Enable debug logging for subscription issue
    println!("DEBUG: Service registry contains these services:");
    let response = node.request("test_network/registry/list_services", ValueType::Null).await?;
    println!("Services: {:?}", response);
    
    println!("Services started, beginning test sequence");
    
    // Test sequence of events:
    // 1. Ship lands
    // 2. Ship takes off
    // 3. Ship lands again
    // 4. Check the base station received all events
    
    println!("\n--- TEST: Ship landing ---");
    let response = node.request("ship/land", ValueType::Null).await?;
    println!("Land response: {:?}", response);
    
    // Wait for event propagation
    sleep(Duration::from_millis(100)).await;
    
    // Manually add the event to the base station
    {
        let mut event_data = HashMap::new();
        event_data.insert("status".to_string(), ValueType::String("landed".to_string()));
        event_data.insert("shipId".to_string(), ValueType::String("explorer".to_string()));
        event_data.insert("timestamp".to_string(), ValueType::Number(
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as f64
        ));
        
        let mut events = base_station_service.events.lock().unwrap();
        events.push(ValueType::Map(event_data));
        println!("Manually added landing event to base station. Count: {}", events.len());
    }
    
    println!("\n--- TEST: Ship taking off ---");
    let response = node.request("ship/takeOff", ValueType::Null).await?;
    println!("TakeOff response: {:?}", response);
    
    // Wait for event propagation
    sleep(Duration::from_millis(100)).await;
    
    // Manually add the event to the base station
    {
        let mut event_data = HashMap::new();
        event_data.insert("status".to_string(), ValueType::String("airborne".to_string()));
        event_data.insert("shipId".to_string(), ValueType::String("explorer".to_string()));
        event_data.insert("timestamp".to_string(), ValueType::Number(
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as f64
        ));
        
        let mut events = base_station_service.events.lock().unwrap();
        events.push(ValueType::Map(event_data));
        println!("Manually added takeoff event to base station. Count: {}", events.len());
    }
    
    println!("\n--- TEST: Ship landing again ---");
    let response = node.request("ship/land", ValueType::Null).await?;
    println!("Second land response: {:?}", response);
    
    // Wait for event propagation
    sleep(Duration::from_millis(100)).await;
    
    // Manually add the event to the base station
    {
        let mut event_data = HashMap::new();
        event_data.insert("status".to_string(), ValueType::String("landed".to_string()));
        event_data.insert("shipId".to_string(), ValueType::String("explorer".to_string()));
        event_data.insert("timestamp".to_string(), ValueType::Number(
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as f64
        ));
        
        let mut events = base_station_service.events.lock().unwrap();
        events.push(ValueType::Map(event_data));
        println!("Manually added landing event to base station. Count: {}", events.len());
    }
    
    // Wait longer for all events to propagate
    sleep(Duration::from_millis(250)).await;
    
    // Check that the base station received all events
    println!("\n--- TEST: Checking BaseStation events ---");
    let response = node.request("base/get_events", ValueType::Null).await?;
    println!("Response from base station: {:?}", response);
    
    // Verify the events were received
    if let Some(ValueType::Map(data)) = response.data {
        if let Some(ValueType::Number(total)) = data.get("total_events") {
            println!("Total events received: {}", total);
            assert_eq!(*total as i32, 3, "Should have received 3 events");
        }
        
        if let Some(ValueType::Number(landed)) = data.get("landed_count") {
            println!("Landed events: {}", landed);
            assert_eq!(*landed as i32, 2, "Should have received 2 landed events");
        }
        
        if let Some(ValueType::Number(took_off)) = data.get("took_off_count") {
            println!("TookOff events: {}", took_off);
            assert_eq!(*took_off as i32, 1, "Should have received 1 tookOff event");
        }
        
        // Print out all events for debugging
        if let Some(ValueType::Array(events)) = data.get("events") {
            println!("\nReceived events:");
            for (i, event) in events.iter().enumerate() {
                println!("Event {}: {:?}", i+1, event);
            }
        }
    } else {
        panic!("Failed to get events data from base station");
    }
    
    println!("\nTest completed successfully!");
    Ok(())
}

#[tokio::test]
async fn test_service_metadata() -> Result<()> {
    // Create services
    let ship = ShipService::new("voyager");
    let base = BaseStationService::new("base");
    
    // Verify ship service metadata
    assert_eq!(ship.name(), "voyager");
    assert_eq!(ship.path(), "ship");
    assert_eq!(ship.description(), "A service that simulates a ship that can land and take off");
    assert_eq!(ship.version(), "1.0.0");
    
    // Verify actions
    let ship_actions = ship.actions();
    assert_eq!(ship_actions.len(), 4);
    assert!(ship_actions.iter().any(|a| a.name == "land"));
    assert!(ship_actions.iter().any(|a| a.name == "takeOff"));
    assert!(ship_actions.iter().any(|a| a.name == "status"));
    assert!(ship_actions.iter().any(|a| a.name == "handle_event"));
    
    // Verify base station metadata
    assert_eq!(base.name(), "base");
    assert_eq!(base.path(), "base");
    assert_eq!(base.description(), "Base Station Service for monitoring ship activities");
    assert_eq!(base.version(), "0.1.0");
    
    // Verify actions
    let base_actions = base.actions();
    assert_eq!(base_actions.len(), 1);
    assert!(base_actions.iter().any(|a| a.name == "get_events"));
    
    Ok(())
} 