//! Safe ErasedArc implementation using Arc<dyn Any> for type-erased Arc values

use std::any::{Any, TypeId};
use std::fmt;
use std::sync::Arc;

use anyhow::Result;

// Custom serde implementation for ErasedArc
// Only registered types can be (de)serialized.
use serde::{Deserialize, Deserializer, Serialize, Serializer};

impl Serialize for ErasedArc {
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        panic!("ErasedArc should never be serialized directly. Serialize ArcValue instead.");
    }
}

impl<'de> Deserialize<'de> for ErasedArc {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        panic!("ErasedArc should never be deserialized directly. Deserialize ArcValue instead.");
    }
}

/// Safe type-erased Arc implementation using Arc<dyn Any>
/// This struct holds an `Arc<dyn Any + Send + Sync>` and provides methods
/// to interact with the underlying data in a type-safe manner.
#[derive(Clone)]
pub struct ErasedArc {
    inner: Arc<dyn Any + Send + Sync>,
    type_name: String, // Stored separately for serialization/eq
    pub is_lazy: bool,
}

impl fmt::Debug for ErasedArc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ErasedArc<{}>({:?})", self.type_name, self.inner)
    }
}

impl ErasedArc {
    /// Create a new ErasedArc from an Arc
    pub fn new<T: 'static + fmt::Debug + Send + Sync>(arc: Arc<T>) -> Self {
        ErasedArc {
            inner: arc, // Implicit upcast to Arc<dyn Any + Send + Sync>
            type_name: std::any::type_name::<T>().to_string(),
            is_lazy: false,
        }
    }

    /// Create a new ErasedArc from a value by wrapping it in an Arc
    pub fn from_value<T: 'static + fmt::Debug + Send + Sync>(value: T) -> Self {
        let is_lazy_value =
            TypeId::of::<T>() == TypeId::of::<super::arc_value::LazyDataWithOffset>();
        let type_name = if is_lazy_value {
            // Safe downcast since we know T is LazyDataWithOffset
            let any_ref = &value as &dyn Any;
            if let Some(lazy) = any_ref.downcast_ref::<super::arc_value::LazyDataWithOffset>() {
                lazy.type_name.clone()
            } else {
                // This should never happen since we checked TypeId
                std::any::type_name::<T>().to_string()
            }
        } else {
            std::any::type_name::<T>().to_string()
        };

        ErasedArc {
            inner: Arc::new(value) as Arc<dyn Any + Send + Sync>,
            type_name,
            is_lazy: is_lazy_value,
        }
    }

    /// Get the type name of the contained value
    pub fn type_name(&self) -> &str {
        &self.type_name
    }

    /// Directly get the LazyDataWithOffset when we know this contains one
    pub fn get_lazy_data(&self) -> Result<Arc<super::arc_value::LazyDataWithOffset>> {
        if !self.is_lazy {
            return Err(anyhow::anyhow!("Value is not lazy (is_lazy flag is false)"));
        }

        self.inner
            .clone()
            .downcast::<super::arc_value::LazyDataWithOffset>()
            .map_err(|_| anyhow::anyhow!("Type mismatch: not LazyDataWithOffset"))
    }

    /// Compare the actual value behind the erased arc for equality
    pub fn eq_value(&self, other: &ErasedArc) -> bool {
        if self.type_name != other.type_name || self.is_lazy != other.is_lazy {
            return false;
        }

        if self.is_lazy {
            // Compare lazy data fields
            if let (Ok(lazy1), Ok(lazy2)) = (self.get_lazy_data(), other.get_lazy_data()) {
                return lazy1.type_name == lazy2.type_name
                    && lazy1.original_buffer == lazy2.original_buffer
                    && lazy1.start_offset == lazy2.start_offset
                    && lazy1.end_offset == lazy2.end_offset
                    && lazy1.encrypted == lazy2.encrypted;
            }
            return false;
        }

        // For non-lazy, compare Arc identity (current behavior)
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    /// Try to extract an Arc<T> from this ErasedArc
    pub fn as_arc<T: 'static + Send + Sync>(&self) -> Result<Arc<T>> {
        if self.is_lazy {
            return Err(anyhow::anyhow!("Cannot directly downcast lazy data"));
        }

        self.inner.clone().downcast::<T>().map_err(|_| {
            let expected_type_name = std::any::type_name::<T>();
            anyhow::anyhow!(
                "Type mismatch: expected {}, but has {}",
                expected_type_name,
                self.type_name
            )
        })
    }
}
