use anyhow::{anyhow, Result};
use std::fmt;

/// Indicates whether a path references an action or event
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathType {
    /// Path represents a service action (request/response)
    Action,
    /// Path represents an event topic (publish/subscribe)
    Event,
    /// Path represents a service (without action or event)
    Service,
}

impl fmt::Display for PathType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathType::Action => write!(f, "Action"),
            PathType::Event => write!(f, "Event"),
            PathType::Service => write!(f, "Service"),
        }
    }
}

/// Represents a standardized path in the system with clear semantics
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TopicPath {
    /// Network ID for this path
    pub network_id: String,
    
    /// Service path - the actual routing path for the service
    pub service_path: String,
    
    /// Action name or event topic
    pub action_or_event: String,
    
    /// Path type indicator (action vs event)
    pub path_type: PathType,
}

impl TopicPath {
    /// Create a new action path
    pub fn new_action(network_id: &str, service_path: &str, action: &str) -> Self {
        Self {
            network_id: network_id.to_string(),
            service_path: service_path.to_string(),
            action_or_event: action.to_string(),
            path_type: PathType::Action,
        }
    }
    
    /// Create a new event path
    pub fn new_event(network_id: &str, service_path: &str, event: &str) -> Self {
        Self {
            network_id: network_id.to_string(),
            service_path: service_path.to_string(),
            action_or_event: event.to_string(),
            path_type: PathType::Event,
        }
    }
    
    /// Create a new service path (without action or event)
    pub fn new_service(network_id: &str, service_path: &str) -> Self {
        Self {
            network_id: network_id.to_string(),
            service_path: service_path.to_string(),
            action_or_event: String::new(),
            path_type: PathType::Service,
        }
    }
    
    /// Creates a new TopicPath representing just the service part of this path
    pub fn to_service_path(&self) -> Self {
        Self {
            network_id: self.network_id.clone(),
            service_path: self.service_path.clone(),
            action_or_event: String::new(),
            path_type: PathType::Service,
        }
    }
    
    /// Extracts the service path string from this TopicPath
    pub fn service_path_str(&self) -> String {
        format!("{}:{}", self.network_id, self.service_path)
    }
    
    /// Creates a TopicPath for an action on this service
    pub fn with_action(&self, action: &str) -> Self {
        Self {
            network_id: self.network_id.clone(),
            service_path: self.service_path.clone(),
            action_or_event: action.to_string(),
            path_type: PathType::Action,
        }
    }
    
    /// Creates a TopicPath for an event on this service
    pub fn with_event(&self, event: &str) -> Self {
        Self {
            network_id: self.network_id.clone(),
            service_path: self.service_path.clone(),
            action_or_event: event.to_string(),
            path_type: PathType::Event,
        }
    }
    
    /// Parse a path string into a TopicPath
    /// 
    /// Supports the following formats:
    /// - Format 1: Full format with network ID - "network:service/action"
    /// - Format 2: Network and service only - "network:service"
    /// - Format 3: Service and action without network - "service/action" (uses default network ID)
    /// - Format 4: Just service name - "service" (uses default network ID)
    pub fn parse(path_str: &str, default_network_id: &str) -> Result<Self> {
        // Format 1: Full format with network ID - "network:service/action"
        if let Some((network_prefix, remainder)) = path_str.split_once(':') {
            if let Some((service, action)) = remainder.split_once('/') {
                return Ok(Self {
                    network_id: network_prefix.to_string(),
                    service_path: service.to_string(),
                    action_or_event: action.to_string(),
                    path_type: if path_str.contains("(Event)") {
                        PathType::Event
                    } else {
                        PathType::Action
                    },
                });
            }
            // Format 2: Network and service only - "network:service"
            return Ok(Self {
                network_id: network_prefix.to_string(),
                service_path: remainder.to_string(),
                action_or_event: String::new(),
                path_type: PathType::Service,
            });
        }
        
        // Format 3: Service and action without network - "service/action"
        if let Some((service, action)) = path_str.split_once('/') {
            return Ok(Self {
                network_id: default_network_id.to_string(),
                service_path: service.to_string(),
                action_or_event: action.to_string(),
                path_type: if path_str.contains("(Event)") {
                    PathType::Event
                } else {
                    PathType::Action
                },
            });
        }
        
        // Format 4: Just service name - "service"
        if !path_str.is_empty() {
            return Ok(Self {
                network_id: default_network_id.to_string(),
                service_path: path_str.to_string(),
                action_or_event: String::new(),
                path_type: PathType::Service,
            });
        }
        
        Err(anyhow!("Invalid path format: {}", path_str))
    }
    
    /// Try to parse a path string into a TopicPath, without a default network ID
    /// 
    /// Supports only the explicit network format:
    /// - "network:service_path/action"
    pub fn try_parse(path_str: &str) -> Result<Self> {
        // Check for network separator
        if let Some(network_index) = path_str.find(':') {
            // Format: "network:service_path/action"
            let network_id = &path_str[0..network_index];
            let remainder = &path_str[network_index+1..];
            
            // Split the remainder by '/'
            let parts: Vec<&str> = remainder.split('/').collect();
            if parts.len() != 2 {
                return Err(anyhow!("Invalid path format after network ID: {}", remainder));
            }
            
            Ok(Self {
                network_id: network_id.to_string(),
                service_path: parts[0].to_string(),
                action_or_event: parts[1].to_string(),
                path_type: PathType::Action, // Default, can be changed by caller
            })
        } else {
            Err(anyhow!("Missing network ID in path: {}", path_str))
        }
    }
    
    /// Set the path type
    pub fn with_path_type(mut self, path_type: PathType) -> Self {
        self.path_type = path_type;
        self
    }
    
    /// Convert TopicPath to string representation with network ID
    pub fn to_string(&self) -> String {
        if self.action_or_event.is_empty() {
            // Service path only
            format!("{}:{}", self.network_id, self.service_path)
        } else {
            // Full path
            format!("{}:{}/{}", self.network_id, self.service_path, self.action_or_event)
        }
    }
    
    /// Convert TopicPath to string representation without network ID
    /// This is useful for local routing where network ID is implicit
    pub fn to_local_string(&self) -> String {
        format!("{}/{}", self.service_path, self.action_or_event)
    }
    
    /// Check if this path matches another path for routing purposes
    /// For actions: exact match is required
    /// For events: subscription paths can use wildcards
    pub fn matches(&self, other: &TopicPath) -> bool {
        // Network ID must match
        if self.network_id != other.network_id {
            return false;
        }
        
        // For actions, we need exact match
        if self.path_type == PathType::Action && other.path_type == PathType::Action {
            return self.service_path == other.service_path && 
                   self.action_or_event == other.action_or_event;
        }
        
        // For events, we allow special matching rules
        if self.path_type == PathType::Event || other.path_type == PathType::Event {
            // If service paths don't match, check for wildcards
            if self.service_path != other.service_path {
                if self.service_path == "#" || other.service_path == "#" {
                    // '#' matches any service path
                    return true;
                }
                return false;
            }
            
            // If service paths match but event topics don't, check for wildcards
            if self.action_or_event != other.action_or_event {
                if self.action_or_event == "#" || other.action_or_event == "#" {
                    // '#' matches any topic
                    return true;
                }
                
                // '+' matches one segment
                if self.action_or_event == "+" || other.action_or_event == "+" {
                    return true;
                }
                
                return false;
            }
            
            // Exact match
            return true;
        }
        
        // Fallback
        false
    }
}

impl fmt::Display for TopicPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}/{} ({})", 
            self.network_id, 
            self.service_path, 
            self.action_or_event,
            self.path_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_with_network() {
        let path = TopicPath::parse("test_network:auth_service/login", "default").unwrap();
        assert_eq!(path.network_id, "test_network");
        assert_eq!(path.service_path, "auth_service");
        assert_eq!(path.action_or_event, "login");
        assert_eq!(path.path_type, PathType::Action);
    }
    
    #[test]
    fn test_parse_without_network() {
        let path = TopicPath::parse("auth_service/login", "test_network").unwrap();
        assert_eq!(path.network_id, "test_network");
        assert_eq!(path.service_path, "auth_service");
        assert_eq!(path.action_or_event, "login");
        assert_eq!(path.path_type, PathType::Action);
    }
    
    #[test]
    fn test_parse_service_only() {
        let path = TopicPath::parse("auth_service", "test_network").unwrap();
        assert_eq!(path.network_id, "test_network");
        assert_eq!(path.service_path, "auth_service");
        assert_eq!(path.action_or_event, "");
        assert_eq!(path.path_type, PathType::Service);
    }
    
    #[test]
    fn test_parse_network_and_service_only() {
        let path = TopicPath::parse("test_network:auth_service", "default").unwrap();
        assert_eq!(path.network_id, "test_network");
        assert_eq!(path.service_path, "auth_service");
        assert_eq!(path.action_or_event, "");
        assert_eq!(path.path_type, PathType::Service);
    }
    
    #[test]
    fn test_to_string() {
        let path = TopicPath::new_action("test", "auth", "login");
        assert_eq!(path.to_string(), "test:auth/login");
    }
    
    #[test]
    fn test_to_local_string() {
        let path = TopicPath::new_action("test", "auth", "login");
        assert_eq!(path.to_local_string(), "auth/login");
    }
    
    #[test]
    fn test_matches_action() {
        let path1 = TopicPath::new_action("test", "auth", "login");
        let path2 = TopicPath::new_action("test", "auth", "login");
        let path3 = TopicPath::new_action("test", "auth", "logout");
        
        assert!(path1.matches(&path2));
        assert!(!path1.matches(&path3));
    }
    
    #[test]
    fn test_matches_event() {
        let path1 = TopicPath::new_event("test", "auth", "logged_in");
        let path2 = TopicPath::new_event("test", "auth", "logged_in");
        let path3 = TopicPath::new_event("test", "auth", "#"); // Wildcard
        
        assert!(path1.matches(&path2));
        assert!(path1.matches(&path3)); // Wildcard should match
        assert!(path3.matches(&path1)); // Matching should be symmetric
    }
    
    #[test]
    fn test_different_networks_dont_match() {
        let path1 = TopicPath::new_action("test1", "auth", "login");
        let path2 = TopicPath::new_action("test2", "auth", "login");
        
        assert!(!path1.matches(&path2));
    }
    
    #[test]
    fn test_topic_path_conversion() {
        // Create service-only TopicPath from full path
        let full_path = TopicPath::parse("network:service/action", "").unwrap();
        let service_path = full_path.to_service_path();
        assert_eq!(service_path.network_id, "network");
        assert_eq!(service_path.service_path, "service");
        assert_eq!(service_path.action_or_event, "");
        assert_eq!(service_path.path_type, PathType::Service);
        
        // Create action variation from service path
        let service_path = TopicPath::parse("network:service", "").unwrap();
        let action_path = service_path.with_action("new_action");
        assert_eq!(action_path.network_id, "network");
        assert_eq!(action_path.service_path, "service");
        assert_eq!(action_path.action_or_event, "new_action");
        assert_eq!(action_path.path_type, PathType::Action);
        
        // Create event variation from service path
        let event_path = service_path.with_event("new_event");
        assert_eq!(event_path.network_id, "network");
        assert_eq!(event_path.service_path, "service");
        assert_eq!(event_path.action_or_event, "new_event");
        assert_eq!(event_path.path_type, PathType::Event);
    }
    
    #[test]
    fn test_topic_path_string_representation() {
        // Test string representation is normalized
        let path = TopicPath::parse("network:service/action", "").unwrap();
        assert_eq!(path.to_string(), "network:service/action");
        
        // Service path representation
        let service_path = path.to_service_path();
        assert_eq!(service_path.to_string(), "network:service");
        
        // Service path string helper
        assert_eq!(path.service_path_str(), "network:service");
    }
    
    #[test]
    fn test_service_path_extraction() {
        let path = TopicPath::parse("network:service/action", "").unwrap();
        let service_topic_path = path.to_service_path();
        
        assert_eq!(service_topic_path.network_id, "network");
        assert_eq!(service_topic_path.service_path, "service");
        assert_eq!(service_topic_path.action_or_event, "");
        assert_eq!(service_topic_path.path_type, PathType::Service);
    }
}
