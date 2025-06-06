use crate::routing::TopicPath;
use std::collections::HashMap;

/// Helper function to check if a segment is a template parameter
fn is_template_param(segment: &str) -> bool {
    segment.starts_with("{") && segment.ends_with("}")
}

/// Helper function to extract parameter name from a template segment
fn extract_param_name(segment: &str) -> String {
    // Remove the { and } from the segment
    segment[1..segment.len() - 1].to_string()
}

/// Result type that includes both the handler and any extracted parameters
#[derive(Clone)]
pub struct PathTrieMatch<T: Clone> {
    /// The handler that matched the path
    pub content: T,
    /// Parameters extracted from template segments
    pub params: HashMap<String, String>,
}

/// Optimized path trie structure for faster matching
///
/// INTENTION: Provide a hierarchical data structure that efficiently matches paths
/// by walking down the segments one at a time. This allows for fast lookup of handlers
/// registered for exact paths, template patterns, and wildcard patterns.
#[derive(Clone)]
pub struct PathTrie<T: Clone> {
    /// Content for this exact path
    content: Vec<T>,

    /// Child nodes for literal segments
    children: HashMap<String, PathTrie<T>>,

    /// Child node for single wildcard (*)
    wildcard_child: Option<Box<PathTrie<T>>>,

    /// Child node for template parameters ({param})
    template_child: Option<Box<PathTrie<T>>>,

    /// Template parameter name at this level (if this is a template node)
    template_param_name: Option<String>,

    /// content for multi-wildcard (>) at this level
    multi_wildcard: Vec<T>,

    /// Network-specific tries - the top level trie is keyed by network_id
    networks: HashMap<String, PathTrie<T>>,
}

impl<T: Clone> Default for PathTrie<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone> PathTrie<T> {
    /// Create a new empty path trie
    pub fn new() -> Self {
        PathTrie {
            content: Vec::new(),
            children: HashMap::new(),
            wildcard_child: None,
            template_child: None,
            template_param_name: None,
            multi_wildcard: Vec::new(),
            networks: HashMap::new(),
        }
    }

    /// Add a topic path and its handlers to the trie
    pub fn set_values(&mut self, topic: TopicPath, content_list: Vec<T>) {
        let network_id = topic.network_id();

        // Get or create network-specific trie
        let network_trie = self
            .networks
            .entry(network_id.to_string())
            .or_default();

        // Add to the network-specific trie
        network_trie.set_values_internal(&topic.get_segments(), 0, content_list);
    }

    /// Add a single handler for a topic path
    pub fn set_value(&mut self, topic: TopicPath, content: T) {
        self.set_values(topic, vec![content]);
    }

    /// Add handlers for a vector of topic paths
    pub fn add_batch_values(&mut self, topics: Vec<TopicPath>, contents: Vec<T>) {
        for topic in topics {
            self.set_values(topic, contents.clone());
        }
    }

    pub fn remove_values(&mut self, topic: &TopicPath) {
        let network_id = topic.network_id();

        // Get or create network-specific trie
        let network_trie = self
            .networks
            .entry(network_id.to_string())
            .or_default();

        // Remove from the network-specific trie
        network_trie.remove_values_internal(&topic.get_segments(), 0);
    }

    /// Internal recursive implementation of remove
    fn remove_values_internal(&mut self, segments: &[String], index: usize) {
        if index >= segments.len() {
            // We've reached the end of the path, remove handlers here
            self.content.clear();
            return;
        }

        let segment = &segments[index];

        if segment == "*" {
            // Single wildcard - remove from wildcard child
            if let Some(child) = &mut self.wildcard_child {
                child.remove_values_internal(segments, index + 1);
            }
        } else if is_template_param(segment) {
            // Template parameter - remove from template child
            if let Some(child) = &mut self.template_child {
                child.remove_values_internal(segments, index + 1);
            }
        } else {
            // Literal segment - remove from child
            if let Some(child) = self.children.get_mut(segment) {
                child.remove_values_internal(segments, index + 1);
            }
        }
    }

    /// Internal recursive implementation of add
    fn set_values_internal(&mut self, segments: &[String], index: usize, handlers: Vec<T>) {
        if index >= segments.len() {
            // We've reached the end of the path, add handlers here
            self.content.extend(handlers);
            return;
        }

        let segment = &segments[index];

        if segment == ">" {
            // Multi-wildcard - adds handlers here and matches everything below
            self.multi_wildcard.extend(handlers);
        } else if segment == "*" {
            // Single wildcard - create/get wildcard child and continue
            if self.wildcard_child.is_none() {
                self.wildcard_child = Some(Box::new(PathTrie::new()));
            }

            if let Some(child) = &mut self.wildcard_child {
                child.set_values_internal(segments, index + 1, handlers);
            }
        } else if is_template_param(segment) {
            // Template parameter - create/get template child and continue
            if self.template_child.is_none() {
                self.template_child = Some(Box::new(PathTrie::new()));
                // Store the parameter name
                self.template_param_name = Some(extract_param_name(segment));
            }

            if let Some(child) = &mut self.template_child {
                child.set_values_internal(segments, index + 1, handlers);
            }
        } else {
            // Literal segment - create/get child and continue
            let child = self
                .children
                .entry(segment.clone())
                .or_default();

            child.set_values_internal(segments, index + 1, handlers);
        }
    }

    /// Find all handlers that match the given topic, including any extracted parameters
    pub fn find_matches(&self, topic: &TopicPath) -> Vec<PathTrieMatch<T>> {
        // If the topic contains wildcards, use the wildcard search
        if topic.is_pattern() {
            return self.find_wildcard_matches(topic);
        }

        let network_id = topic.network_id();
        let segments = topic.get_segments();
        let mut results = Vec::new();

        // Only look in the network-specific trie
        if let Some(network_trie) = self.networks.get(&network_id.to_string()) {
            // Start with empty parameters map
            let mut params = HashMap::new();
            network_trie.find_matches_internal(&segments, 0, &mut results, &mut params);
        }

        results
    }

    /// Find all handlers that match a wildcard topic pattern
    ///
    /// INTENTION: Support searching with wildcard patterns, allowing clients to find
    /// all handlers that match a specific pattern (e.g., "serviceA/*" to find all actions
    /// for serviceA).
    pub fn find_wildcard_matches(&self, pattern: &TopicPath) -> Vec<PathTrieMatch<T>> {
        let network_id = pattern.network_id();
        let pattern_segments = pattern.get_segments();
        let mut results = Vec::new();

        // Only look in the network-specific trie
        if let Some(network_trie) = self.networks.get(&network_id.to_string()) {
            // Collect all handlers from the network trie that match the pattern
            network_trie.collect_wildcard_matches(&pattern_segments, 0, &mut results);
        }

        results
    }

    /// Recursively collect all handlers that match a wildcard pattern
    fn collect_wildcard_matches(
        &self,
        pattern_segments: &[String],
        index: usize,
        results: &mut Vec<PathTrieMatch<T>>,
    ) {
        // If we've reached the end of the pattern, add all handlers at this level
        if index >= pattern_segments.len() {
            for handler in &self.content {
                results.push(PathTrieMatch {
                    content: handler.clone(),
                    params: HashMap::new(), // No parameter extraction for wildcard searches
                });
            }
            return;
        }

        let segment = &pattern_segments[index];

        // Handle different segment types
        if segment == "*" {
            // Single wildcard - match any single segment
            // Check all children at this level
            for child in self.children.values() {
                child.collect_wildcard_matches(pattern_segments, index + 1, results);
            }

            // Also check wildcard and template children if they exist
            if let Some(child) = &self.wildcard_child {
                child.collect_wildcard_matches(pattern_segments, index + 1, results);
            }

            if let Some(child) = &self.template_child {
                child.collect_wildcard_matches(pattern_segments, index + 1, results);
            }
        } else if segment == ">" {
            // Multi-wildcard - match everything below this level
            // Add all handlers from this level and all children recursively
            self.collect_all_handlers(results);
        } else {
            // Literal segment - only check the matching child
            if let Some(child) = self.children.get(segment) {
                child.collect_wildcard_matches(pattern_segments, index + 1, results);
            }
        }
    }

    /// Recursively collect all handlers from this node and all its children
    fn collect_all_handlers(&self, results: &mut Vec<PathTrieMatch<T>>) {
        // Add handlers at this level
        for handler in &self.content {
            results.push(PathTrieMatch {
                content: handler.clone(),
                params: HashMap::new(), // No parameter extraction for wildcard searches
            });
        }

        // Add multi-wildcard handlers
        for handler in &self.multi_wildcard {
            results.push(PathTrieMatch {
                content: handler.clone(),
                params: HashMap::new(),
            });
        }

        // Recursively add handlers from all children
        for child in self.children.values() {
            child.collect_all_handlers(results);
        }

        // Check wildcard and template children if they exist
        if let Some(child) = &self.wildcard_child {
            child.collect_all_handlers(results);
        }

        if let Some(child) = &self.template_child {
            child.collect_all_handlers(results);
        }
    }

    /// Internal recursive implementation of find_matches
    fn find_matches_internal(
        &self,
        segments: &[String],
        index: usize,
        results: &mut Vec<PathTrieMatch<T>>,
        current_params: &mut HashMap<String, String>,
    ) {
        if index >= segments.len() {
            // We've reached the end of the path
            // Add all handlers at this level with the current parameters
            for handler in &self.content {
                results.push(PathTrieMatch {
                    content: handler.clone(),
                    params: current_params.clone(),
                });
            }
            return;
        }

        // Add any multi-wildcard handlers at this level
        for handler in &self.multi_wildcard {
            results.push(PathTrieMatch {
                content: handler.clone(),
                params: current_params.clone(),
            });
        }

        let segment = &segments[index];

        // Check literal children
        if let Some(child) = self.children.get(segment) {
            child.find_matches_internal(segments, index + 1, results, current_params);
        }

        // Check wildcard child
        if let Some(child) = &self.wildcard_child {
            child.find_matches_internal(segments, index + 1, results, current_params);
        }

        // Check template child
        if let Some(child) = &self.template_child {
            // If this is a template node, extract and store the parameter
            if let Some(param_name) = &self.template_param_name {
                // Save old value in case we need to restore it
                let old_value = current_params.get(param_name).cloned();

                // Set the parameter value from the current segment
                current_params.insert(param_name.clone(), segment.clone());

                // Continue matching with the updated parameters
                child.find_matches_internal(segments, index + 1, results, current_params);

                // Restore old value or remove the parameter
                match old_value {
                    Some(value) => {
                        current_params.insert(param_name.clone(), value);
                    }
                    None => {
                        current_params.remove(param_name);
                    }
                }
            } else {
                // No parameter name defined, just continue matching
                child.find_matches_internal(segments, index + 1, results, current_params);
            }
        }
    }

    /// For backward compatibility - get just the handlers without parameters
    pub fn find(&self, topic: &TopicPath) -> Vec<T> {
        self.find_matches(topic)
            .into_iter()
            .map(|m| m.content)
            .collect()
    }

    /// Remove handlers that match a predicate for a specific topic path
    pub fn remove_handler<F>(&mut self, topic: &TopicPath, predicate: F) -> bool
    where
        F: Fn(&T) -> bool + Copy,
    {
        let network_id = topic.network_id();

        // Only remove from the specific network trie
        if let Some(network_trie) = self.networks.get_mut(&network_id.to_string()) {
            return network_trie.remove_handler_internal(&topic.get_segments(), 0, predicate);
        }

        false
    }

    /// Internal recursive implementation of remove_handler
    fn remove_handler_internal<F>(
        &mut self,
        segments: &[String],
        index: usize,
        predicate: F,
    ) -> bool
    where
        F: Fn(&T) -> bool + Copy,
    {
        if index >= segments.len() {
            // We've reached the end of the path
            let initial_len = self.content.len();
            self.content.retain(|h| !predicate(h));
            return initial_len > self.content.len();
        }

        let segment = &segments[index];
        let mut removed = false;

        if segment == ">" {
            // Multi-wildcard - remove from multi_wildcard_handlers
            let initial_len = self.multi_wildcard.len();
            self.multi_wildcard.retain(|h| !predicate(h));
            removed = initial_len > self.multi_wildcard.len();
        } else if segment == "*" {
            // Single wildcard - delegate to wildcard child if it exists
            if let Some(child) = &mut self.wildcard_child {
                removed = child.remove_handler_internal(segments, index + 1, predicate);
            }
        } else if is_template_param(segment) {
            // Template parameter - delegate to template child if it exists
            if let Some(child) = &mut self.template_child {
                removed = child.remove_handler_internal(segments, index + 1, predicate);
            }
        } else {
            // Literal segment - delegate to the appropriate child if it exists
            if let Some(child) = self.children.get_mut(segment) {
                removed = child.remove_handler_internal(segments, index + 1, predicate);
            }
        }

        removed
    }

    /// Check if this trie is empty (has no handlers or children)
    pub fn is_empty(&self) -> bool {
        self.content.is_empty()
            && self.multi_wildcard.is_empty()
            && self.children.is_empty()
            && self.wildcard_child.is_none()
            && self.template_child.is_none()
            && self.networks.is_empty()
    }

    /// Get the count of handlers in this trie
    pub fn handler_count(&self) -> usize {
        let mut count = self.content.len() + self.multi_wildcard.len();

        // Count handlers in children
        for child in self.children.values() {
            count += child.handler_count();
        }

        // Count handlers in wildcard child
        if let Some(child) = &self.wildcard_child {
            count += child.handler_count();
        }

        // Count handlers in template child
        if let Some(child) = &self.template_child {
            count += child.handler_count();
        }

        // Count handlers in network-specific tries
        for network_trie in self.networks.values() {
            count += network_trie.handler_count();
        }

        count
    }
}
