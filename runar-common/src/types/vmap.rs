//! VMap module for runar_common
//! Provides a convenient wrapper for working with maps with string keys

use crate::types::ArcValueType;
use std::collections::HashMap;
use std::fmt;

/// VMap wrapper for easier map manipulation with string keys and generic values
#[derive(Clone)]
pub struct VMap<T> {
    pub inner: HashMap<String, T>,
}

// Manual Debug implementation that doesn't require T: Debug
impl<T> fmt::Debug for VMap<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VMap")
            .field("keys", &self.inner.keys().collect::<Vec<_>>())
            .field("size", &self.inner.len())
            .finish()
    }
}

impl<T> VMap<T> {
    /// Create a new empty VMap
    pub fn new() -> Self {
        VMap {
            inner: HashMap::new(),
        }
    }

    /// Create a VMap from an existing HashMap
    pub fn from_hashmap(map: HashMap<String, T>) -> Self {
        VMap { inner: map }
    }

    /// Get a value by key
    pub fn get(&self, key: &str) -> Option<&T> {
        self.inner.get(key)
    }

    /// Insert a value
    pub fn insert<K: Into<String>>(&mut self, key: K, value: T) {
        self.inner.insert(key.into(), value);
    }

    /// Convert to inner HashMap
    pub fn into_inner(self) -> HashMap<String, T> {
        self.inner
    }

    /// Get reference to inner HashMap
    pub fn as_hashmap(&self) -> &HashMap<String, T> {
        &self.inner
    }
}

impl<T> From<HashMap<String, T>> for VMap<T> {
    fn from(map: HashMap<String, T>) -> Self {
        VMap { inner: map }
    }
}

impl<T> From<VMap<T>> for HashMap<String, T> {
    fn from(vmap: VMap<T>) -> Self {
        vmap.inner
    }
}

impl<T> Default for VMap<T> {
    fn default() -> Self {
        Self::new()
    }
}
// Extension methods for ArcValueType conversions
impl<T> VMap<T>
where
    T: 'static + Clone + Send + Sync + fmt::Debug,
    HashMap<String, T>: 'static + Send + Sync,
{
    /// Convert VMap to an ArcValueType with Map category
    pub fn to_arc_value_type(self) -> ArcValueType {
        ArcValueType::from_map(self.inner)
    }
}
