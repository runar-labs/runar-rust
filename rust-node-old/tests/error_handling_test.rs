//! Test for the standardized error handling approach

use anyhow::{Result, Context};
use runar_common::errors::{ServiceError, DatabaseError};
use runar_node::services::{
    ServiceResponse, ServiceResponseExt, ErrorHandlingDemoService, 
    AbstractService, ServiceRequest, ServiceState, RequestContext
};
use runar_common::types::ValueType;
use std::collections::HashMap;
use std::sync::Arc;

/// Helper function to create a test service
async fn create_test_service() -> Result<ErrorHandlingDemoService> {
    let mut service = ErrorHandlingDemoService::new("test");
    
    // Initialize the service
    let context = Arc::new(RequestContext::default());
    service.init(&context).await?;
    service.start().await?;
    
    // Verify the service is running
    assert_eq!(service.state(), ServiceState::Running);
    
    Ok(service)
}

/// Helper function to create a service request
fn create_request(action: &str, data_map: Option<HashMap<String, ValueType>>) -> ServiceRequest {
    let data = data_map.map(|map| ValueType::Map(map));
    
    ServiceRequest {
        path: "test/error_demo".to_string(),
        action: action.to_string(),
        data,
        request_id: Some("test-request-id".to_string()),
        context: Arc::new(RequestContext::default()),
        metadata: None,
        topic_path: None,
    }
}

#[tokio::test]
async fn test_service_error_handling() -> Result<()> {
    let service = create_test_service().await?;
    
    // Create a request for the service_error action with service_not_found error type
    let mut data_map = HashMap::new();
    data_map.insert("error_type".to_string(), ValueType::String("service_not_found".to_string()));
    let request = create_request("service_error", Some(data_map));
    
    // Call the service
    let response = service.handle_request(request).await?;
    
    // Verify the response is an error
    assert_eq!(response.status, runar_node::services::ResponseStatus::Error);
    assert!(response.message.contains("not found"));
    
    // Check if the data contains error details
    if let Some(ValueType::Map(error_data)) = response.data {
        assert!(error_data.contains_key("message"));
        assert!(error_data.contains_key("code"));
        
        // Check the error code is 404 (not found)
        if let Some(ValueType::Number(code)) = error_data.get("code") {
            assert_eq!(*code, 404.0);
        } else {
            panic!("Error code is not a number");
        }
    } else {
        panic!("Response data is not a map");
    }
    
    Ok(())
}

#[tokio::test]
async fn test_database_error_handling() -> Result<()> {
    let service = create_test_service().await?;
    
    // Create a request for the database_error action with not_found error type
    let mut data_map = HashMap::new();
    data_map.insert("error_type".to_string(), ValueType::String("not_found".to_string()));
    let request = create_request("database_error", Some(data_map));
    
    // Call the service
    let response = service.handle_request(request).await?;
    
    // Verify the response is an error
    assert_eq!(response.status, runar_node::services::ResponseStatus::Error);
    assert!(response.message.contains("not found"));
    
    // Check if the data contains error details
    if let Some(ValueType::Map(error_data)) = response.data {
        // Check the error code is 404 (not found)
        if let Some(ValueType::Number(code)) = error_data.get("code") {
            assert_eq!(*code, 404.0);
        } else {
            panic!("Error code is not a number");
        }
    } else {
        panic!("Response data is not a map");
    }
    
    Ok(())
}

#[tokio::test]
async fn test_service_response_extensions() -> Result<()> {
    // Test the from_error method
    let error = "Test error message".to_string();
    let response = ServiceResponse::from_error(error);
    
    assert_eq!(response.status, runar_node::services::ResponseStatus::Error);
    assert_eq!(response.message, "Test error message");
    assert!(response.data.is_none());
    
    // Test the from_error_with_code method
    let error = "Test error with code".to_string();
    let response = ServiceResponse::from_error_with_code(error, 418); // I'm a teapot
    
    assert_eq!(response.status, runar_node::services::ResponseStatus::Error);
    assert_eq!(response.message, "Test error with code");
    
    if let Some(ValueType::Map(error_data)) = response.data {
        if let Some(ValueType::String(message)) = error_data.get("message") {
            assert_eq!(message, "Test error with code");
        } else {
            panic!("Error message is not a string");
        }
        
        if let Some(ValueType::Number(code)) = error_data.get("code") {
            assert_eq!(*code, 418.0);
        } else {
            panic!("Error code is not a number");
        }
    } else {
        panic!("Response data is not a map");
    }
    
    // Test the from_service_error method
    let service_error = ServiceError::ServiceNotFound("test_service".to_string());
    let response = ServiceResponse::from_service_error(service_error);
    
    assert_eq!(response.status, runar_node::services::ResponseStatus::Error);
    assert!(response.message.contains("not found"));
    
    if let Some(ValueType::Map(error_data)) = response.data {
        if let Some(ValueType::Number(code)) = error_data.get("code") {
            assert_eq!(*code, 404.0);
        } else {
            panic!("Error code is not a number");
        }
    } else {
        panic!("Response data is not a map");
    }
    
    // Test the from_database_error method
    let db_error = DatabaseError::QueryError("SQL syntax error".to_string());
    let response = ServiceResponse::from_database_error(db_error);
    
    assert_eq!(response.status, runar_node::services::ResponseStatus::Error);
    assert!(response.message.contains("SQL syntax error"));
    
    if let Some(ValueType::Map(error_data)) = response.data {
        if let Some(ValueType::Number(code)) = error_data.get("code") {
            assert_eq!(*code, 500.0);
        } else {
            panic!("Error code is not a number");
        }
    } else {
        panic!("Response data is not a map");
    }
    
    // Test the from_result method
    let result: Result<String> = Ok("success".to_string());
    let response = ServiceResponse::from_result(result)?;
    
    assert_eq!(response.status, runar_node::services::ResponseStatus::Success);
    assert_eq!(response.message, "Success");
    
    if let Some(ValueType::String(data)) = response.data {
        assert_eq!(data, "success");
    } else {
        panic!("Response data is not a string");
    }
    
    // Test the from_result method with an error
    let result: Result<String> = Err(anyhow::anyhow!("Test error"));
    let response = ServiceResponse::from_result(result)?;
    
    assert_eq!(response.status, runar_node::services::ResponseStatus::Error);
    assert_eq!(response.message, "Test error");
    
    Ok(())
}

#[tokio::test]
async fn test_unknown_action_handling() -> Result<()> {
    let service = create_test_service().await?;
    
    // Create a request for an unknown action
    let request = create_request("unknown_action", None);
    
    // Call the service
    let response = service.handle_request(request).await?;
    
    // Verify the response is an error
    assert_eq!(response.status, runar_node::services::ResponseStatus::Error);
    assert!(response.message.contains("not supported"));
    
    // Check if the data contains error details
    if let Some(ValueType::Map(error_data)) = response.data {
        // Check the error code is 400 (bad request)
        if let Some(ValueType::Number(code)) = error_data.get("code") {
            assert_eq!(*code, 400.0);
        } else {
            panic!("Error code is not a number");
        }
    } else {
        panic!("Response data is not a map");
    }
    
    Ok(())
} 