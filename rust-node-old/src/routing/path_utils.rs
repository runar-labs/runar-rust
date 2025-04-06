use anyhow::{anyhow, Result};
use crate::routing::topic_path::TopicPath;

/// Parse a path that might include a network prefix.
/// If the path doesn't have a network prefix, the default_network is used.
/// 
/// # Arguments
/// * `path` - A path that might be in formats like "network:service/action" or "service/action"
/// * `default_network` - The network ID to use if not specified in the path
/// 
/// # Returns
/// A Result containing a TopicPath if parsing succeeds
pub fn parse_path_with_network(path: &str, default_network: &str) -> Result<TopicPath> {
    match TopicPath::parse(path, default_network) {
        Ok(tp) => Ok(tp),
        Err(_) => {
            // Try as a simple path
            parse_simple_path(path, default_network)
        }
    }
}

/// Parse a simple path in the format "service/action" without network prefix.
/// 
/// # Arguments
/// * `path` - A path in the format "service/action"
/// * `network` - The network ID to use for the TopicPath
/// 
/// # Returns
/// A Result containing a TopicPath if parsing succeeds
pub fn parse_simple_path(path: &str, network: &str) -> Result<TopicPath> {
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() < 2 {
        return Err(anyhow!("Invalid path format. Expected 'service/action'"));
    }
    
    Ok(TopicPath::new_action(network, parts[0], parts[1]))
}

/// Parse a topic string in the format "service/event".
/// 
/// # Arguments
/// * `topic` - A topic string in the format "service/event"
/// * `network` - The network ID to use for the TopicPath
/// 
/// # Returns
/// A Result containing a TopicPath if parsing succeeds
pub fn parse_topic(topic: &str, network: &str) -> Result<TopicPath> {
    let parts: Vec<&str> = topic.split('/').collect();
    if parts.is_empty() {
        return Err(anyhow!("Invalid topic format. Expected 'service/event'"));
    }
    
    let service = parts[0];
    let event = if parts.len() > 1 { parts[1] } else { "" };
    
    Ok(TopicPath::new_event(network, service, event))
}

/// Validate a topic string.
/// 
/// # Arguments
/// * `topic` - A topic string to validate
/// 
/// # Returns
/// A Result indicating if validation succeeded
pub fn validate_topic(topic: &str) -> Result<()> {
    let parts: Vec<&str> = topic.split('/').collect();
    if parts.is_empty() || parts[0].is_empty() {
        return Err(anyhow!("Invalid topic format. Expected 'service/event'"));
    }
    
    Ok(())
}

/// Extract the service and action/event from a path.
/// 
/// # Arguments
/// * `path` - A path string
/// 
/// # Returns
/// A tuple of (service, action_or_event)
pub fn extract_service_and_action(path: &str) -> Result<(String, String)> {
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() < 2 {
        return Err(anyhow!("Invalid path format. Expected 'service/action'"));
    }
    
    Ok((parts[0].to_string(), parts[1].to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_path_with_network() {
        let network = "test_network";
        
        // With network prefix
        let path = "other_network:service/action";
        let topic_path = parse_path_with_network(path, network).unwrap();
        assert_eq!(topic_path.network_id, "other_network");
        assert_eq!(topic_path.service_path, "service");
        assert_eq!(topic_path.action_or_event, "action");
        
        // Without network prefix
        let path = "service/action";
        let topic_path = parse_path_with_network(path, network).unwrap();
        assert_eq!(topic_path.network_id, network);
        assert_eq!(topic_path.service_path, "service");
        assert_eq!(topic_path.action_or_event, "action");
    }
    
    #[test]
    fn test_parse_simple_path() {
        let network = "test_network";
        let path = "service/action";
        
        let topic_path = parse_simple_path(path, network).unwrap();
        assert_eq!(topic_path.network_id, network);
        assert_eq!(topic_path.service_path, "service");
        assert_eq!(topic_path.action_or_event, "action");
        
        // Invalid path
        let result = parse_simple_path("invalid", network);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_parse_topic() {
        let network = "test_network";
        
        // With event
        let topic = "service/event";
        let topic_path = parse_topic(topic, network).unwrap();
        assert_eq!(topic_path.network_id, network);
        assert_eq!(topic_path.service_path, "service");
        assert_eq!(topic_path.action_or_event, "event");
        
        // Without event
        let topic = "service";
        let topic_path = parse_topic(topic, network).unwrap();
        assert_eq!(topic_path.network_id, network);
        assert_eq!(topic_path.service_path, "service");
        assert_eq!(topic_path.action_or_event, "");
    }
    
    #[test]
    fn test_validate_topic() {
        // Valid topic
        let result = validate_topic("service/event");
        assert!(result.is_ok());
        
        // Valid topic without event
        let result = validate_topic("service");
        assert!(result.is_ok());
        
        // Invalid topic
        let result = validate_topic("");
        assert!(result.is_err());
    }
    
    #[test]
    fn test_extract_service_and_action() {
        // Valid path
        let (service, action) = extract_service_and_action("service/action").unwrap();
        assert_eq!(service, "service");
        assert_eq!(action, "action");
        
        // Invalid path
        let result = extract_service_and_action("invalid");
        assert!(result.is_err());
    }
} 