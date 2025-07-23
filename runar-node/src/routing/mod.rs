// Routing Module
//
// INTENTION:
// This module provides the core routing components for the node's service architecture,
// establishing the message addressing and topic-based communication system. It defines
// how services are addressed, discovered, and how messages are routed between them.
//
// ARCHITECTURAL PRINCIPLES:
// 1. Path-based Addressing - Services are addressed using hierarchical paths
// 2. Topic-based Communication - Events use topics for publish-subscribe pattern
// 3. Separation of Concerns - Routing is separate from service implementation
// 4. Deterministic Resolution - Path resolution follows consistent rules
// 5. Network Isolation - Routing respects network boundaries
//
// The routing system is a foundational layer that enables the service architecture
// to function in a decentralized, loosely-coupled manner.

use anyhow::Result;
use std::fmt;
use std::fmt::Debug;
use std::hash::{Hash, Hasher};

/// Type of a path, indicating what kind of resource is being addressed
///
/// INTENTION: Clearly distinguish between different types of routing targets
/// to ensure proper handling of each type. This enables the system to apply
/// different routing rules and validations based on the path type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathType {
    /// A path to a service - used for service discovery and registration
    Service,
    /// A path to an action on a service - used for request routing
    Action,
    /// A path to an event - used for event routing
    Event,
}

/// Represents a single segment in a path, which can be a literal or a wildcard
///
/// INTENTION: Allow paths to include wildcard patterns for flexible topic matching
/// in the publish-subscribe system. This enables powerful pattern-based subscriptions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathSegment {
    /// A literal string segment (e.g., "services", "auth", "login")
    Literal(String),

    /// A template parameter segment (e.g., "{service_path}", "{user_id}")
    /// Stores the parameter name without the braces for easier access
    Template(String),

    /// A single-segment wildcard (*) - matches any single segment
    /// Example: "services/*/state" matches "services/math/state" but not "services/auth/user/state"
    SingleWildcard,

    /// A multi-segment wildcard (>) - matches one or more segments to the end
    /// Example: "services/>" matches "services/math", "services/auth/login", etc.
    /// Must be the last segment in a pattern.
    MultiWildcard,
}

impl PathSegment {
    /// Parse a string segment into a PathSegment
    ///
    /// INTENTION: Convert raw string segments into the appropriate PathSegment variant,
    /// handling special wildcard characters and template parameters.
    fn from_str(segment: &str) -> Self {
        match segment {
            "*" => Self::SingleWildcard,
            ">" => Self::MultiWildcard,
            s if s.starts_with('{') && s.ends_with('}') => {
                // This is a template parameter - extract the parameter name without braces
                let param_name = &s[1..s.len() - 1];
                Self::Template(param_name.to_string())
            }
            _ => Self::Literal(segment.to_string()),
        }
    }

    /// Check if this segment is a wildcard
    ///
    /// INTENTION: Quickly determine if a segment is a wildcard without pattern matching.
    pub fn is_wildcard(&self) -> bool {
        matches!(self, Self::SingleWildcard | Self::MultiWildcard)
    }

    /// Check if this segment is a multi-segment wildcard
    ///
    /// INTENTION: Identify multi-segment wildcards which have special matching rules.
    pub fn is_multi_wildcard(&self) -> bool {
        matches!(self, Self::MultiWildcard)
    }

    /// Check if this segment is a template parameter
    ///
    /// INTENTION: Quickly determine if a segment is a template parameter.
    pub fn is_template(&self) -> bool {
        matches!(self, Self::Template(_))
    }

    /// Get segment as string slice for display
    ///
    /// INTENTION: Get a string representation without allocating when possible.
    fn _as_str(&self) -> &str {
        match self {
            Self::Literal(s) => s.as_str(),
            // These require allocations - we return slices to the static strings
            Self::SingleWildcard => "*",
            Self::MultiWildcard => ">",
            // Template requires its own allocation in to_string()
            Self::Template(_) => "*", // This is a placeholder that should never be called
        }
    }
}

/// Path representation with network ID and segments, supporting wildcard patterns
///
/// INTENTION: Provide a structured representation of a path string,
/// enabling proper splitting of parts, validation of format, and wildcard matching.
///
/// A TopicPath can be in several formats:
/// - `main:auth/login` (Full path with network_id, service_path, and action)
/// - `auth/login` (Shorthand without network_id, which will be added when TopicPath is created)
/// - `services/*/state` (Pattern with single-segment wildcard)
/// - `events/>` (Pattern with multi-segment wildcard)
impl fmt::Display for PathSegment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathSegment::Literal(s) => f.write_str(s),
            PathSegment::Template(name) => write!(f, "{{{name}}}"),
            PathSegment::SingleWildcard => f.write_str("*"),
            PathSegment::MultiWildcard => f.write_str(">"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TopicPath {
    /// The raw path string with validated format
    path: String,

    /// The network ID for this path
    network_id: String,

    /// The segments after the network ID
    segments: Vec<PathSegment>,

    /// Whether this path contains wildcard patterns
    is_pattern: bool,

    /// Whether this path contains template parameters
    has_templates: bool,

    /// The service name (first segment of the path) - cached for convenience
    service_path: String,

    /// Cached action path (all segments joined) - computed once at creation time
    cached_action_path: String,

    /// Segment count - cached for quick filtering
    segment_count: usize,

    /// Pre-computed hash components for faster hashing
    hash_components: Vec<u64>,

    /// Bitmap representation of segment types for fast pattern matching
    /// Each 2 bits represent a segment type:
    /// - 00: Literal
    /// - 01: Template
    /// - 10: SingleWildcard
    /// - 11: MultiWildcard
    ///   This allows us to quickly check segment types without iterating through segments
    segment_type_bitmap: u64,
}

// Implement Hash trait for TopicPath to enable use in HashMaps
impl Hash for TopicPath {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Hash the network ID
        self.network_id.hash(state);

        // Use pre-computed hash components if available
        if !self.hash_components.is_empty() {
            for component in &self.hash_components {
                state.write_u64(*component);
            }
            return;
        }

        // Fallback implementation (should rarely be used)
        for segment in &self.segments {
            match segment {
                PathSegment::Literal(s) => {
                    // Hash type code + string for literal segments
                    0.hash(state);
                    s.hash(state);
                }
                PathSegment::Template(s) => {
                    // Hash type code + parameter name for template segments
                    3.hash(state);
                    s.hash(state);
                }
                PathSegment::SingleWildcard => {
                    // Just hash type code for wildcards
                    1.hash(state);
                }
                PathSegment::MultiWildcard => {
                    // Just hash type code for wildcards
                    2.hash(state);
                }
            }
        }
    }
}

// Implement PartialEq for TopicPath to enable equality comparisons and HashMap lookups
impl PartialEq for TopicPath {
    fn eq(&self, other: &Self) -> bool {
        // Fast path: if paths are identical strings, they're equal
        if self.path == other.path {
            return true;
        }

        // Network IDs must match
        if self.network_id != other.network_id {
            return false;
        }

        // Segment counts must match (now a cached field)
        if self.segment_count != other.segment_count {
            return false;
        }

        // Each segment must match exactly
        for (s1, s2) in self.segments.iter().zip(other.segments.iter()) {
            if s1 != s2 {
                return false;
            }
        }

        true
    }
}

// Implement Eq to confirm TopicPath can be used as HashMap keys
impl Eq for TopicPath {}

// Implement Display for TopicPath for easier use in format strings
impl std::fmt::Display for TopicPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.path)
    }
}

impl TopicPath {
    /// Creates a new TopicPath for an action based on this service path
    ///
    /// INTENTION: Provide a simple way to create an action path from a service path,
    /// ensuring consistent formatting and proper path type.
    ///
    /// Example:
    /// ```
    /// use runar_node::TopicPath;
    /// let service_path = TopicPath::new("main:auth", "default").expect("Valid path");
    /// let action_path = service_path.new_action_topic("login").expect("Valid action path");
    ///
    /// assert_eq!(action_path.action_path(), "auth/login");
    /// ```
    pub fn new_action_topic(&self, action_name: &str) -> Result<Self, String> {
        if self.segments.len() > 1 {
            //invalid.. u cannot create an action path on top of another action path
            return Err(
                "Invalid action path - cannot create an action path on top of another action path"
                    .to_string(),
            );
        }

        // Create the full path with the action name
        let full_path_string = format!("{}:{}/{}", self.network_id, self.service_path, action_name);
        TopicPath::new(&full_path_string, &self.network_id)
    }

    /// Creates a new TopicPath for an event based on this service path
    ///
    /// INTENTION: Provide a simple way to create an event path from a service path,
    /// ensuring consistent formatting and proper path type.
    ///
    /// Example:
    /// ```
    /// use runar_node::TopicPath;
    /// let service_path = TopicPath::new("main:auth", "default").expect("Valid path");
    /// let event_path = service_path.new_event_topic("user_logged_in").expect("Valid event path");
    ///
    /// assert_eq!(event_path.action_path(), "auth/user_logged_in");
    /// ```
    pub fn new_event_topic(&self, event_name: &str) -> Result<Self, String> {
        // For now, the format is the same as action_topic, but we'll mark it as an event
        let path = self.new_action_topic(event_name)?;

        // In the future, we might want to distinguish events from actions in the path format
        // For now, we'll just create a path with the event name
        Ok(path)
    }

    pub fn from_full_path(path: &str) -> Result<Self, String> {
        if path.contains(':') {
            // Split at the first colon to separate network_id and path
            let parts: Vec<&str> = path.split(':').collect();
            if parts.len() != 2 {
                return Err(format!("Invalid path format - should be 'network_id:service_path' or 'service_path': {path}"));
            }

            // Reject empty network IDs
            if parts[0].is_empty() {
                return Err(format!(
                    "Invalid path format - network ID cannot be empty: {path}"
                ));
            }

            let network_id = parts[0];
            let path_without_network = parts[1];
            Self::new(path_without_network, network_id)
        } else {
            Err(format!("Invalid path format - missing network_id: {path}"))
        }
    }

    /// Create a new TopicPath from a string
    ///
    /// INTENTION: Validate and construct a TopicPath from a string input,
    /// ensuring it follows the required format conventions.
    ///
    /// This method now supports wildcard patterns:
    /// - "*" matches any single segment
    /// - ">" matches one or more segments to the end (must be the last segment)
    ///
    /// Example:
    /// ```
    /// use runar_node::routing::TopicPath;
    ///
    /// // With network_id prefix
    /// let path = TopicPath::new("main:auth/login", "default").expect("Valid path");
    /// assert_eq!(path.network_id(), "main");
    /// assert_eq!(path.service_path(), "auth");
    /// assert_eq!(path.action_path(), "auth/login");
    ///
    /// // With wildcards
    /// let pattern = TopicPath::new("main:services/*/state", "default").expect("Valid pattern");
    /// assert!(pattern.is_pattern());
    /// ```
    pub fn new(path: &str, default_network: &str) -> Result<Self, String> {
        // Parse the network ID and path parts
        let (network_id, path_without_network) = if path.contains(':') {
            // Split at the first colon to separate network_id and path
            let parts: Vec<&str> = path.split(':').collect();
            if parts.len() != 2 {
                return Err(format!("Invalid path format - should be 'network_id:service_path' or 'service_path': {path}"));
            }

            // Reject empty network IDs
            if parts[0].is_empty() {
                return Err(format!("Network ID cannot be empty: {path}"));
            }

            (parts[0], parts[1])
        } else {
            // No network_id prefix, use the default
            (default_network, path)
        };

        // Split the path into segments
        let path_segments: Vec<&str> = path_without_network
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        // Paths must have at least one segment (the service name)
        if path_segments.is_empty() {
            return Err(format!(
                "Invalid path - must have at least one segment: {path}"
            ));
        }

        // Process each segment
        let mut segments = Vec::with_capacity(path_segments.len());
        let mut is_pattern = false;
        let mut has_templates = false;
        let mut _multi_wildcard_found = false;
        let mut hash_components = Vec::with_capacity(path_segments.len());
        let mut segment_type_bitmap: u64 = 0;

        for (i, segment_str) in path_segments.iter().enumerate() {
            let segment = PathSegment::from_str(segment_str);

            // Check for pattern and validate multi-wildcards
            match &segment {
                PathSegment::SingleWildcard => {
                    is_pattern = true;
                    Self::set_segment_type(
                        &mut segment_type_bitmap,
                        i,
                        Self::SEGMENT_TYPE_SINGLE_WILDCARD,
                    );
                }
                PathSegment::MultiWildcard => {
                    is_pattern = true;
                    _multi_wildcard_found = true;

                    // Ensure multi-wildcard is the last segment
                    if i < path_segments.len() - 1 {
                        return Err(
                            "Multi-segment wildcard (>) must be the last segment in a path"
                                .to_string(),
                        );
                    }

                    Self::set_segment_type(
                        &mut segment_type_bitmap,
                        i,
                        Self::SEGMENT_TYPE_MULTI_WILDCARD,
                    );
                }
                PathSegment::Template(_) => {
                    has_templates = true;
                    Self::set_segment_type(
                        &mut segment_type_bitmap,
                        i,
                        Self::SEGMENT_TYPE_TEMPLATE,
                    );
                }
                PathSegment::Literal(_) => {
                    Self::set_segment_type(&mut segment_type_bitmap, i, Self::SEGMENT_TYPE_LITERAL);
                }
            }

            // Compute hash component for this segment
            let mut segment_hasher = std::collections::hash_map::DefaultHasher::new();
            match &segment {
                PathSegment::Literal(s) => {
                    0.hash(&mut segment_hasher);
                    s.hash(&mut segment_hasher);
                }
                PathSegment::Template(s) => {
                    3.hash(&mut segment_hasher);
                    s.hash(&mut segment_hasher);
                }
                PathSegment::SingleWildcard => {
                    1.hash(&mut segment_hasher);
                }
                PathSegment::MultiWildcard => {
                    2.hash(&mut segment_hasher);
                }
            }
            hash_components.push(segment_hasher.finish());

            segments.push(segment);
        }

        // Save the service path (first segment) for easy access
        let service_path = match &segments[0] {
            PathSegment::Literal(s) => s.clone(),
            PathSegment::Template(s) => format!("{{{s}}}"),
            PathSegment::SingleWildcard => "*".to_string(),
            PathSegment::MultiWildcard => ">".to_string(),
        };

        // Create the full path string (for display/serialization)
        let full_path_str = format!("{network_id}:{path_without_network}");

        // Pre-compute the action path for caching
        let cached_action_path = if segments.len() <= 1 {
            "".to_string()
        } else {
            segments
                .iter()
                .map(|segment| segment.to_string())
                .collect::<Vec<String>>()
                .join("/")
        };

        let result = Self {
            path: full_path_str,
            network_id: network_id.to_string(),
            segment_count: segments.len(),
            segments,
            is_pattern,
            has_templates,
            service_path,
            cached_action_path,
            hash_components,
            segment_type_bitmap,
        };

        Ok(result)
    }

    /// Check if this path contains wildcards
    ///
    /// INTENTION: Quickly determine if a path is a wildcard pattern,
    /// which affects how it's used for matching.
    pub fn is_pattern(&self) -> bool {
        self.is_pattern
    }

    /// Check if this path contains a multi-segment wildcard
    ///
    /// INTENTION: Identify paths with multi-segment wildcards which have
    /// special matching rules and storage requirements.
    pub fn has_multi_wildcard(&self) -> bool {
        // Check if any segment is a multi-wildcard
        for i in 0..self.segment_count {
            if self.has_segment_type(i, Self::SEGMENT_TYPE_MULTI_WILDCARD) {
                return true;
            }
        }

        false
    }

    /// Get the path after the network ID
    ///
    /// INTENTION: Get the complete path after the network ID, including
    /// all segments. This is useful when you need the path for routing.
    ///
    /// Example:
    /// ```
    /// use runar_node::routing::TopicPath;
    ///
    /// let path = TopicPath::new("main:auth/login", "default").expect("Valid path");
    /// assert_eq!(path.action_path(), "auth/login");
    ///
    /// // When there is only a service with no action, returns empty string
    /// let service_only = TopicPath::new("main:auth", "default").expect("Valid path");
    /// assert_eq!(service_only.action_path(), "");
    /// ```
    pub fn action_path(&self) -> String {
        self.cached_action_path.clone()
    }

    /// Get the path as a string
    ///
    /// INTENTION: Access the raw path string for this TopicPath,
    /// useful for display and logging purposes.
    pub fn as_str(&self) -> &str {
        &self.path
    }

    /// Get the network ID from this path
    ///
    /// INTENTION: Extract just the network segment from the path,
    /// which is crucial for network isolation and routing.
    ///
    /// Example:
    /// ```
    /// use runar_node::routing::TopicPath;
    ///
    /// let path = TopicPath::new("main:auth/login", "default").expect("Valid path");
    /// assert_eq!(path.network_id(), "main");
    /// ```
    pub fn network_id(&self) -> String {
        self.network_id.clone()
    }

    /// Get the service path part of this path
    ///
    /// INTENTION: Extract the service path from the full path,
    /// which is used for service lookup and addressing.
    ///
    /// Example:
    /// ```
    /// use runar_node::routing::TopicPath;
    ///
    /// let path = TopicPath::new("main:auth/login", "default").expect("Valid path");
    /// // The service_path method returns just the service name (first segment)
    /// assert_eq!(path.service_path(), "auth");
    ///
    /// // If you need just the first segment, use get_segments
    /// let segments = path.get_segments();
    /// assert_eq!(segments[0], "auth");
    /// ```
    pub fn service_path(&self) -> String {
        self.service_path.clone()
    }

    /// Create a new service path from a network ID and service name
    ///
    /// INTENTION: Create a TopicPath specifically for a service,
    /// avoiding manual string concatenation and validation.
    ///
    /// Example:
    /// ```
    /// use runar_node::routing::TopicPath;
    ///
    /// let path = TopicPath::new_service("main", "auth");
    /// assert_eq!(path.as_str(), "main:auth");
    /// ```
    pub fn new_service(network_id: &str, service_name: &str) -> Self {
        let network_id_string = network_id.to_string();
        let service_name_string = service_name.to_string();

        let path = format!("{network_id_string}:{service_name_string}");
        Self {
            path,
            network_id: network_id_string,
            service_path: service_name_string.clone(),
            segments: vec![PathSegment::Literal(service_name_string)],
            is_pattern: false,
            has_templates: false,
            cached_action_path: "".to_string(),
            segment_count: 1,
            hash_components: Vec::new(),
            segment_type_bitmap: 0,
        }
    }

    /// Check if this path starts with another path
    ///
    /// INTENTION: Determine if this path is a "child" or more specific
    /// version of another path, useful for hierarchical routing and
    /// subscription matching.
    ///
    /// Example:
    /// ```
    /// use runar_node::routing::TopicPath;
    ///
    /// let path = TopicPath::new("main:auth/users", "default").expect("Valid path");
    /// let prefix = TopicPath::new("main:auth", "default").expect("Valid path");
    /// let different = TopicPath::new("main:payments", "default").expect("Valid path");
    ///
    /// assert!(path.starts_with(&prefix));
    /// assert!(!path.starts_with(&different));
    /// ```
    pub fn starts_with(&self, other: &TopicPath) -> bool {
        self.network_id == other.network_id && self.service_path.starts_with(&other.service_path)
    }

    /// Create a child path by appending a segment
    ///
    /// INTENTION: Generate a new TopicPath that is a child of this path,
    /// useful for creating more specific paths from a base path.
    ///
    /// Example:
    /// ```
    /// use runar_node::routing::TopicPath;
    ///
    /// let base = TopicPath::new("main:auth", "default").expect("Valid path");
    /// let child = base.child("login").expect("Valid child path");
    ///
    /// assert_eq!(child.as_str(), "main:auth/login");
    /// ```
    pub fn child(&self, segment: &str) -> Result<Self, String> {
        // Ensure segment doesn't contain slashes
        if segment.contains('/') {
            return Err(format!("Child segment cannot contain slashes: {segment}"));
        }

        // Create the new path string
        let new_path_str = if self.cached_action_path.is_empty() {
            // For service-only paths, new path should include service path + new segment
            format!("{}/{}", self.service_path, segment)
        } else {
            format!("{}/{}", self.cached_action_path, segment)
        };

        // Create a full path with network ID
        let full_path_str = format!("{}:{}", self.network_id, new_path_str);

        // Create a new set of segments based on the current segments plus the new one
        let mut new_segments = self.segments.clone();
        let new_segment = PathSegment::from_str(segment);

        // Check if this path is a pattern (has wildcards)
        let is_pattern = self.is_pattern
            || matches!(
                new_segment,
                PathSegment::SingleWildcard | PathSegment::MultiWildcard
            );

        // Check if this path has templates
        let has_templates = self.has_templates || matches!(new_segment, PathSegment::Template(_));

        // Add new segment to bitmap
        let mut segment_type_bitmap = self.segment_type_bitmap;
        match &new_segment {
            PathSegment::Literal(_) => {
                Self::set_segment_type(
                    &mut segment_type_bitmap,
                    self.segment_count,
                    Self::SEGMENT_TYPE_LITERAL,
                );
            }
            PathSegment::Template(_) => {
                Self::set_segment_type(
                    &mut segment_type_bitmap,
                    self.segment_count,
                    Self::SEGMENT_TYPE_TEMPLATE,
                );
            }
            PathSegment::SingleWildcard => {
                Self::set_segment_type(
                    &mut segment_type_bitmap,
                    self.segment_count,
                    Self::SEGMENT_TYPE_SINGLE_WILDCARD,
                );
            }
            PathSegment::MultiWildcard => {
                Self::set_segment_type(
                    &mut segment_type_bitmap,
                    self.segment_count,
                    Self::SEGMENT_TYPE_MULTI_WILDCARD,
                );
            }
        }

        new_segments.push(new_segment);

        Ok(Self {
            path: full_path_str,
            network_id: self.network_id.clone(),
            segment_count: self.segment_count + 1,
            segments: new_segments,
            is_pattern,
            has_templates,
            service_path: self.service_path.clone(),
            cached_action_path: new_path_str,
            hash_components: Vec::new(), // Recompute later if needed
            segment_type_bitmap,
        })
    }

    /// Get the path segments
    ///
    /// INTENTION: Get the segments of the path after the network ID.
    /// This is useful for path analysis and custom path parsing.
    ///
    /// Example:
    /// ```
    /// use runar_node::routing::TopicPath;
    ///
    /// let path = TopicPath::new("main:auth/login/form", "default").expect("Valid path");
    /// let segments = path.get_segments();
    /// assert_eq!(segments, vec!["auth", "login", "form"]);
    /// ```
    pub fn get_segments(&self) -> Vec<String> {
        self.segments
            .iter()
            .map(|segment| segment.to_string())
            .collect()
    }

    /// Create a parent path
    ///
    /// INTENTION: Generate a new TopicPath that is the parent of this path,
    /// useful for navigating up the path hierarchy.
    ///
    /// Example:
    /// ```
    /// use runar_node::routing::TopicPath;
    ///
    /// let path = TopicPath::new("main:auth/users", "default").expect("Valid path");
    /// let parent = path.parent().expect("Valid parent path");
    ///
    /// assert_eq!(parent.as_str(), "main:auth");
    /// ```
    pub fn parent(&self) -> Result<Self, String> {
        if self.segments.len() <= 1 {
            return Err("Cannot get parent of root or service-only path".to_string());
        }

        // Create a new set of segments without the last segment
        let parent_segments = self.segments[0..self.segments.len() - 1].to_vec();

        // Reconstruct the path string from segments
        let path_str = parent_segments
            .iter()
            .map(|segment| segment.to_string())
            .collect::<Vec<String>>()
            .join("/");

        // Create the full path with network ID
        let full_path = format!("{}:{}", self.network_id, path_str);

        // Check if parent is a pattern
        let mut is_pattern = false;
        let mut has_templates = false;

        // Create new bitmap by removing the last 2 bits
        let mut segment_type_bitmap = self.segment_type_bitmap;
        segment_type_bitmap &= !(0b11 << ((self.segment_count - 1) * 2));

        // Check each segment in the parent for patterns
        for i in 0..parent_segments.len() {
            let segment_type = Self::get_segment_type(segment_type_bitmap, i);
            match segment_type {
                Self::SEGMENT_TYPE_SINGLE_WILDCARD | Self::SEGMENT_TYPE_MULTI_WILDCARD => {
                    is_pattern = true;
                }
                Self::SEGMENT_TYPE_TEMPLATE => {
                    has_templates = true;
                }
                _ => {}
            }
        }

        Ok(Self {
            path: full_path,
            network_id: self.network_id.clone(),
            segment_count: self.segment_count - 1,
            segments: parent_segments,
            is_pattern,
            has_templates,
            service_path: self.service_path.clone(),
            cached_action_path: path_str,
            hash_components: Vec::new(), // Recompute later if needed
            segment_type_bitmap,
        })
    }

    /// Create a default path for running unit tests with default network ID
    ///
    /// INTENTION: Simplify test setup by creating a valid path with a default network ID.
    ///
    /// Note: This is primarily intended for testing purposes.
    ///
    /// Example:
    /// ```
    /// use runar_node::routing::TopicPath;
    ///
    /// let path = TopicPath::test_default("auth/login");
    /// assert_eq!(path.as_str(), "default:auth/login");
    /// ```
    pub fn test_default(path: &str) -> Self {
        Self::new(path, "default").unwrap()
    }

    /// Match this path against a template pattern and extract parameters
    ///
    /// INTENTION: Enable services to define URL-like templates with named parameters
    /// and extract those parameter values from actual request paths.
    ///
    /// Template patterns can include segments like `{param_name}` which will match
    /// any value in that position and capture it with the specified name.
    ///
    /// Example:
    /// ```
    /// use runar_node::routing::TopicPath;
    ///
    /// let template = "services/{service_path}/state";
    /// let path = TopicPath::new("main:services/math/state", "main").expect("Valid path");
    ///
    /// let params = path.extract_params(template).expect("Template should match");
    /// assert_eq!(params.get("service_path"), Some(&"math".to_string()));
    ///
    /// // Non-matching templates return an error
    /// let non_matching = TopicPath::new("main:users/profile", "main").expect("Valid path");
    /// assert!(non_matching.extract_params(template).is_err());
    /// ```
    pub fn extract_params(
        &self,
        template: &str,
    ) -> Result<std::collections::HashMap<String, String>, String> {
        let mut params = std::collections::HashMap::new();

        // Get segments from the actual path (excluding network_id)
        let path_segments = self.get_segments();

        // Get segments from the template
        let template_segments: Vec<&str> = template.split('/').filter(|s| !s.is_empty()).collect();

        // If segment counts don't match, the template doesn't apply
        if path_segments.len() != template_segments.len() {
            return Err(format!(
                "Path segment count ({}) doesn't match template segment count ({})",
                path_segments.len(),
                template_segments.len()
            ));
        }

        // Match each segment and extract parameters
        for (i, template_segment) in template_segments.iter().enumerate() {
            if template_segment.starts_with('{') && template_segment.ends_with('}') {
                // This is a parameter segment - extract the parameter name
                let param_name = template_segment[1..template_segment.len() - 1].to_string();
                // Store the actual value from the path
                params.insert(param_name, path_segments[i].clone());
            } else if template_segment != &path_segments[i] {
                // This is a literal segment and it doesn't match
                return Err(format!(
                    "Path segment '{}' doesn't match template segment '{}'",
                    path_segments[i], template_segment
                ));
            }
            // If it's a literal and matches, continue to next segment
        }

        Ok(params)
    }

    /// Check if a path matches a template pattern
    ///
    /// INTENTION: Quickly determine if a path can be processed by a particular
    /// template, without needing to extract parameters.
    ///
    /// Example:
    /// ```
    /// use runar_node::routing::TopicPath;
    ///
    /// let template = "services/{service_path}/state";
    /// let path = TopicPath::new("main:services/math/state", "default").expect("Valid path");
    ///
    /// assert!(path.matches_template(template));
    ///
    /// let non_matching = TopicPath::new("main:users/profile", "default").expect("Valid path");
    /// assert!(!non_matching.matches_template(template));
    /// ```
    pub fn matches_template(&self, template: &str) -> bool {
        // Fast path: if neither has templates, do simple comparison
        if !self.has_templates && !template.contains('{') {
            return self.path.contains(template);
        }

        // Use faster matching for common template patterns
        let template_segments: Vec<&str> = template.split('/').filter(|s| !s.is_empty()).collect();

        // Quickly check segment counts to avoid unnecessary processing
        if template_segments.len() != self.segment_count {
            return false;
        }

        // Iterate segments to check template compatibility
        let path_segments = self.get_segments();

        for (i, template_segment) in template_segments.iter().enumerate() {
            if template_segment.starts_with('{') && template_segment.ends_with('}') {
                // Template parameter segment - matches any literal in corresponding position
                continue;
            } else if template_segment != &path_segments[i] {
                // Literal segment must match exactly
                return false;
            }
        }

        true
    }

    /// Check if this path contains template parameters
    ///
    /// INTENTION: Quickly determine if a path has template parameters,
    /// which affects template matching behavior.
    pub fn has_templates(&self) -> bool {
        self.has_templates
    }

    /// Get the number of segments in this path
    ///
    /// INTENTION: Quickly get the segment count without iterating segments.
    pub fn segment_count(&self) -> usize {
        self.segment_count
    }

    // Helper methods for bitmap operations
    fn set_segment_type(bitmap: &mut u64, index: usize, segment_type: u8) {
        // Each segment uses 2 bits
        let shift = index * 2;
        // Clear the existing bits for this segment
        *bitmap &= !(0b11 << shift);
        // Set the new segment type
        *bitmap |= (segment_type as u64) << shift;
    }

    fn get_segment_type(bitmap: u64, index: usize) -> u8 {
        // Extract 2 bits representing the segment type
        ((bitmap >> (index * 2)) & 0b11) as u8
    }

    // Constants for segment types
    const SEGMENT_TYPE_LITERAL: u8 = 0b00;
    const SEGMENT_TYPE_TEMPLATE: u8 = 0b01;
    const SEGMENT_TYPE_SINGLE_WILDCARD: u8 = 0b10;
    const SEGMENT_TYPE_MULTI_WILDCARD: u8 = 0b11;

    // Use bitmap for faster segment type checking
    pub fn has_segment_type(&self, index: usize, segment_type: u8) -> bool {
        if index >= self.segment_count {
            return false;
        }

        Self::get_segment_type(self.segment_type_bitmap, index) == segment_type
    }

    /// Implement pattern matching against another path
    ///
    /// INTENTION: Allow checking if a topic matches a pattern with wildcards,
    /// enabling powerful pattern-based subscriptions.
    ///
    /// Example:
    /// ```
    /// use runar_node::routing::TopicPath;
    ///
    /// let pattern = TopicPath::new("main:services/*/state", "default").expect("Valid pattern");
    /// let topic1 = TopicPath::new("main:services/math/state", "default").expect("Valid topic");
    /// let topic2 = TopicPath::new("main:services/math/config", "default").expect("Valid topic");
    ///
    /// assert!(pattern.matches(&topic1));
    /// assert!(!pattern.matches(&topic2));
    /// ```
    pub fn matches(&self, topic: &TopicPath) -> bool {
        // Network ID must match
        if self.network_id != topic.network_id {
            return false;
        }

        // Fast path 1: if paths are identical strings, they're equal
        if self.path == topic.path {
            return true;
        }

        // Fast path 2: if segment counts don't match and there's no multi-wildcard,
        // the paths can't match
        if self.segment_count != topic.segment_count && !self.has_multi_wildcard() {
            return false;
        }

        // Fast path 3: If neither path is a pattern, and they're not identical strings,
        // they can't match
        if !self.is_pattern && !topic.is_pattern && !self.has_templates && !topic.has_templates {
            return false;
        }

        // Check for template path matching concrete path special case
        if self.has_templates && !topic.has_templates {
            // A template path doesn't match a concrete path in this direction
            // For example: "services/{service_path}" doesn't match "services/math"
            // But "services/math" does match "services/{service_path}"
            return false;
        }

        // Check for reverse template matching - concrete path matching template path
        if !self.has_templates && topic.has_templates {
            // A concrete path can match a template path
            // For example: "services/math" matches "services/{service_path}"
            // Verify by checking if the concrete path would extract valid parameters from the template
            return topic.matches_template(&self.action_path());
        }

        // Otherwise, perform segment-by-segment matching
        self.segments_match(&self.segments, &topic.segments)
    }

    // Optimized segment matching with improved template handling
    fn segments_match(
        &self,
        pattern_segments: &[PathSegment],
        topic_segments: &[PathSegment],
    ) -> bool {
        // Special case: multi-wildcard at the end
        if let Some(PathSegment::MultiWildcard) = pattern_segments.last() {
            // If pattern ends with >, topic must have at least as many segments as pattern minus 1
            if topic_segments.len() < pattern_segments.len() - 1 {
                return false;
            }

            // Check all segments before the multi-wildcard
            for i in 0..pattern_segments.len() - 1 {
                match &pattern_segments[i] {
                    PathSegment::Literal(p) => {
                        // For literals, the segments must match exactly
                        match &topic_segments[i] {
                            PathSegment::Literal(t) if p == t => continue,
                            _ => return false,
                        }
                    }
                    PathSegment::Template(_) => {
                        // Template parameters match any literal segment
                        match &topic_segments[i] {
                            PathSegment::Literal(_) => continue,
                            _ => return false,
                        }
                    }
                    PathSegment::SingleWildcard => {
                        // For single wildcards, any segment matches
                        continue;
                    }
                    PathSegment::MultiWildcard => {
                        // Should not happen, as we're iterating up to len-1
                        unreachable!("Multi-wildcard found before the end of pattern");
                    }
                }
            }

            // If we get here, all segments matched
            return true;
        }

        // If pattern doesn't end with multi-wildcard, segment counts must match
        if pattern_segments.len() != topic_segments.len() {
            return false;
        }

        // Check each segment - fast path for literal matches
        for (i, p) in pattern_segments.iter().enumerate() {
            let t = &topic_segments[i];

            // Fast path for identical segments
            if p == t {
                continue;
            }

            match p {
                PathSegment::Literal(_) => {
                    // Literals must match exactly, but we already checked
                    // p == t above, so if we get here they don't match
                    return false;
                }
                PathSegment::Template(_) => {
                    // Template parameters match any literal segment
                    match t {
                        PathSegment::Literal(_) => continue,
                        _ => return false,
                    }
                }
                PathSegment::SingleWildcard => {
                    // Single wildcards match any segment
                    continue;
                }
                PathSegment::MultiWildcard => {
                    // Multi-wildcards should only appear at the end
                    // This is a defensive check - should never happen due to parsing
                    return false;
                }
            }
        }

        // If we get here, all segments matched
        true
    }

    /// Create a TopicPath from a template and parameter values
    ///
    /// INTENTION: Allow dynamic construction of TopicPaths from templates with
    /// parameter placeholders, similar to route templates in web frameworks.
    ///
    /// Example:
    /// ```
    /// use runar_node::routing::TopicPath;
    /// use std::collections::HashMap;
    ///
    /// let mut params = HashMap::new();
    /// params.insert("service_path".to_string(), "math".to_string());
    /// params.insert("action".to_string(), "add".to_string());
    ///
    /// let path = TopicPath::from_template(
    ///     "services/{service_path}/{action}",
    ///     params,
    ///     "main"
    /// ).expect("Valid template");
    ///
    /// assert_eq!(path.as_str(), "main:services/math/add");
    /// ```
    pub fn from_template(
        template_string: &str,
        params: std::collections::HashMap<String, String>,
        network_id_string: &str,
    ) -> Result<Self, String> {
        // Get segments from the template
        let template_segments: Vec<&str> = template_string
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        let mut path_segments = Vec::new();

        // Process each template segment
        for template_segment in template_segments.iter() {
            if template_segment.starts_with('{') && template_segment.ends_with('}') {
                // This is a parameter segment - extract the parameter name
                let param_name = &template_segment[1..template_segment.len() - 1];

                // Look up the parameter value
                match params.get(param_name) {
                    Some(value) => path_segments.push(PathSegment::Literal(value.clone())),
                    None => return Err(format!("Missing parameter value for '{param_name}'")),
                }
            } else {
                // This is a literal segment
                path_segments.push(PathSegment::Literal(template_segment.to_string()));
            }
        }
        // Construct the final path
        let path_str = path_segments
            .iter()
            .map(|segment| segment.to_string())
            .collect::<Vec<String>>()
            .join("/");
        Self::new(path_str.as_str(), network_id_string)
    }
}

// Export the PathTrie module
mod path_registry;
pub use path_registry::PathTrie;
pub use path_registry::PathTrieMatch;
