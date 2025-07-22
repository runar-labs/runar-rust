//! Allow specific clippy lint scopes for this module
#![allow(clippy::type_id_on_box)]

use std::any::{Any, TypeId};
use std::fmt;
use std::sync::Arc;

use anyhow::{anyhow, Result};

/// ArcRead is a trait for safely accessing an Arc's contents
pub trait ArcRead: fmt::Debug + Send + Sync {
    /// Get the pointer to the inner value
    fn ptr(&self) -> *const ();

    /// Get the Arc's strong reference count
    fn strong_count(&self) -> usize;

    /// Get the Arc's weak reference count
    fn weak_count(&self) -> usize;

    /// Get the type name of the contained value
    fn type_name(&self) -> &str;

    /// Get the type ID of the contained value
    fn type_id(&self) -> TypeId;

    /// Clone this trait object
    fn clone_box(&self) -> Box<dyn ArcRead>;

    /// Get this value as a dynamic Any
    fn as_any(&self) -> &dyn Any;
}

// Custom serde implementation for ErasedArc
// Only registered types can be (de)serialized.
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::ArcValue;

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
// ErasedArc is always nested in ArcValue and should never be (de)serialized directly.

// Implement Clone for Box<dyn ArcRead>
impl Clone for Box<dyn ArcRead> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

/// The actual type-erased Arc implementation
/// This struct holds an `Arc<dyn Any + Send + Sync>` and provides methods
/// to interact with the underlying data in a type-safe manner, including
/// downcasting and checking type compatibility.
pub struct ErasedArc {
    /// The type-erased Arc reader
    pub reader: Box<dyn ArcRead>,
    /// Flag indicating if this contains a LazyDeserializer
    pub is_lazy: bool,
}

// Update ArcReader to store TypeId and String type_name (no leak)
struct ArcReader<T: 'static + fmt::Debug + Send + Sync> {
    arc: Arc<T>,
    type_id: TypeId,
    type_name: String,
}

impl<T: 'static + fmt::Debug + Send + Sync> fmt::Debug for ArcReader<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ArcReader<{}>(", self.type_name)?;
        self.arc.fmt(f)?;
        write!(f, ")")
    }
}

impl<T: 'static + fmt::Debug + Send + Sync> ArcReader<T> {
    fn new(arc: Arc<T>) -> Self {
        Self {
            arc,
            type_id: TypeId::of::<T>(),
            type_name: std::any::type_name::<T>().to_string(),
        }
    }
}

impl<T: 'static + fmt::Debug + Send + Sync> ArcRead for ArcReader<T> {
    fn ptr(&self) -> *const () {
        Arc::as_ptr(&self.arc) as *const ()
    }

    fn strong_count(&self) -> usize {
        Arc::strong_count(&self.arc)
    }

    fn weak_count(&self) -> usize {
        Arc::weak_count(&self.arc)
    }

    fn type_name(&self) -> &str {
        self.type_name.as_str()
    }

    fn type_id(&self) -> TypeId {
        self.type_id
    }

    fn clone_box(&self) -> Box<dyn ArcRead> {
        Box::new(ArcReader {
            arc: self.arc.clone(),
            type_id: self.type_id,
            type_name: self.type_name.clone(),
        })
    }

    fn as_any(&self) -> &dyn Any {
        &*self.arc
    }
}

impl fmt::Debug for ErasedArc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ErasedArc({:?})", self.reader)
    }
}

impl Clone for ErasedArc {
    fn clone(&self) -> Self {
        ErasedArc {
            reader: self.reader.clone(),
            is_lazy: self.is_lazy,
        }
    }
}

impl ErasedArc {
    /// Create a new ErasedArc from an Arc
    pub fn new<T: 'static + fmt::Debug + Send + Sync>(arc: Arc<T>) -> Self {
        ErasedArc {
            reader: Box::new(ArcReader::new(arc)),
            is_lazy: false,
        }
    }

    /// Create a new ErasedArc from a value by wrapping it in an Arc
    pub fn from_value<T: 'static + fmt::Debug + Send + Sync>(value: T) -> Self {
        // Use TypeId for a more reliable check for the lazy data struct
        let is_lazy_value =
            TypeId::of::<T>() == TypeId::of::<super::arc_value::LazyDataWithOffset>();

        // Need to get the type name before moving the value
        let type_name_override = if is_lazy_value {
            // Cast to Any first, then downcast specifically to LazyDataWithOffset
            (&value as &dyn Any)
                .downcast_ref::<super::arc_value::LazyDataWithOffset>()
                .map(|lazy| lazy.type_name.clone())
        } else {
            None
        };

        // Create the Arc
        let arc = Arc::new(value);

        // If we have a type name override (meaning it's our lazy struct), use it
        if let Some(type_name) = type_name_override {
            let reader = Box::new(ArcReader {
                arc,
                type_id: TypeId::of::<T>(),
                type_name,
            });
            ErasedArc {
                reader,
                is_lazy: true, // Mark as lazy
            }
        } else {
            // Default behavior for other types
            ErasedArc {
                reader: Box::new(ArcReader {
                    arc,
                    type_id: TypeId::of::<T>(),
                    type_name: std::any::type_name::<T>().to_string(),
                }),
                is_lazy: false, // Not lazy
            }
        }
    }

    /// Get the raw pointer to the contained value
    pub fn as_ptr(&self) -> *const () {
        self.reader.ptr()
    }

    /// Get the Arc's strong reference count
    pub fn strong_count(&self) -> usize {
        self.reader.strong_count()
    }

    /// Get the Arc's weak reference count
    pub fn weak_count(&self) -> usize {
        self.reader.weak_count()
    }

    /// Get the type name of the contained value
    pub fn type_name(&self) -> &str {
        self.reader.type_name()
    }

    /// Get the type ID of the contained value
    pub fn type_id(&self) -> TypeId {
        self.reader.type_id()
    }

    /// Get the contained value as a dynamic Any reference
    pub fn as_any(&self) -> Result<&dyn Any> {
        Ok(self.reader.as_any())
    }

    /// Create an ErasedArc from a boxed Any
    pub fn from_boxed_any(boxed: Box<dyn Any + Send + Sync>) -> Result<Self> {
        // Get the type info for better type matching later
        let type_name = std::any::type_name_of_val(&*boxed);

        // Create the Arc containing the box as-is
        let arc = Arc::new(boxed);

        // Preserve the complete, accurate type name
        let reader = Box::new(ArcReader {
            arc,
            type_id: TypeId::of::<Box<dyn Any + Send + Sync>>(),
            type_name: type_name.to_string(),
        });

        Ok(ErasedArc {
            reader,
            is_lazy: false, // This is not a LazyDeserializer
        })
    }

    /// Check if this ArcAny contains a value of type T
    pub fn is_type<T: 'static>(&self) -> bool {
        let expected_type_id = TypeId::of::<T>();
        let actual_type_id = self.type_id();

        // We need this slightly more complex matching because the std::any type names
        // can have slight differences based on the package/crate names
        if expected_type_id == actual_type_id {
            return true;
        }

        // Handle some common cases where type names might differ but are compatible
        match (expected_type_id, actual_type_id) {
            // String variations
            (e, a) if e == TypeId::of::<String>() && a == TypeId::of::<std::string::String>() => {
                true
            }
            (e, a) if e == TypeId::of::<std::string::String>() && a == TypeId::of::<String>() => {
                true
            }

            // HashMap variations - more robust check for both simple and complex value types
            (e, a)
                if (e == TypeId::of::<std::collections::HashMap<String, ArcValue>>()
                    || e == TypeId::of::<
                        std::collections::HashMap<String, Box<dyn Any + Send + Sync>>,
                    >())
                    && (a == TypeId::of::<std::collections::HashMap<String, ArcValue>>()
                        || a == TypeId::of::<Box<dyn Any + Send + Sync>>()) =>
            {
                // Special handling for Box<dyn Any> that might contain a HashMap
                if a == TypeId::of::<Box<dyn Any + Send + Sync>>() {
                    // This Box<dyn Any> might contain our HashMap, so be optimistic and return true
                    // The actual check will happen in as_arc or as_map_ref
                    return true;
                }

                // Extract keys and values for normal HashMap cases
                let extract_key_value = |s: &str| -> (String, String) {
                    let parts = s
                        .split("HashMap<")
                        .nth(1)
                        .unwrap_or("")
                        .trim_end_matches('>')
                        .split(',')
                        .collect::<Vec<_>>();

                    if parts.len() >= 2 {
                        let key = parts[0].trim().to_string();

                        // Join all remaining parts for the value type (in case it contains commas)
                        let value = parts[1..].join(",").trim().to_string();

                        (key, value)
                    } else {
                        (String::new(), String::new())
                    }
                };

                let (e_key, e_value) = extract_key_value(self.type_name());
                let (a_key, a_value) = extract_key_value(std::any::type_name::<T>());

                // Keys must be compatible - usually both String
                let keys_compatible =
                    e_key == a_key || (e_key.contains("String") && a_key.contains("String"));

                // Values can be more complex - look for type compatibility
                let values_compatible = e_value == a_value
                    || (e_value.contains("String") && a_value.contains("String"))
                    || (e_value.contains("i32") && a_value.contains("i32"))
                    || (e_value.contains("i64") && a_value.contains("i64"))
                    || (e_value.contains("f64") && a_value.contains("f64"))
                    || (e_value.contains("bool") && a_value.contains("bool"))
                    || e_value.contains("ArcValue")
                    || a_value.contains("ArcValue")
                    // Handle when one side has a fully qualified path and the other has a simple type name
                    || compare_type_names(&e_value, &a_value);

                keys_compatible && values_compatible
            }

            // Generic structs and other types
            (_e, _a) => compare_type_names(std::any::type_name::<T>(), self.type_name()),
        }
    }

    /// Try to extract an Arc<T> from this ErasedArc
    pub fn as_arc<T: 'static>(&self) -> Result<Arc<T>> {
        // Check if the type matches based on name (potentially overridden)
        if !self.is_type::<T>() {
            let expected_type_name = std::any::type_name::<T>();
            let actual_type_name = self.type_name();
            return Err(anyhow!(
                "Type mismatch: expected {}, but has {}",
                expected_type_name,
                actual_type_name
            ));
        }

        // Attempt to downcast
        let ptr = self.as_ptr() as *const T;
        let arc = unsafe {
            // Safety: Cloning an Arc with a known type as we've verified the type above
            let arc = Arc::from_raw(ptr);
            let clone = arc.clone();
            // Prevent dropping the original Arc
            std::mem::forget(arc);
            clone
        };

        Ok(arc)
    }

    /// Directly get the LazyDataWithOffset when we know this contains one
    pub fn get_lazy_data(&self) -> Result<Arc<super::arc_value::LazyDataWithOffset>> {
        if !self.is_lazy {
            return Err(anyhow!("Value is not lazy (is_lazy flag is false)"));
        }

        // Since we know it's lazy based on the flag, directly extract it
        let ptr = self.reader.ptr() as *const super::arc_value::LazyDataWithOffset;

        let arc = unsafe {
            // Safety: We trust that when is_lazy is true, the pointed value is LazyDataWithOffset
            let arc = Arc::from_raw(ptr);
            let clone = arc.clone();
            // Prevent dropping the original Arc
            std::mem::forget(arc);
            clone
        };

        Ok(arc)
    }
}

/// Helper to compare type names accounting for namespaces
pub fn compare_type_names(a: &str, b: &str) -> bool {
    // Types are identical
    if a == b {
        return true;
    }

    // Compare last segment (type name without namespace)
    let a_simple = a.split("::").last().unwrap_or(a);
    let b_simple = b.split("::").last().unwrap_or(b);

    if a_simple == b_simple {
        return true;
    }

    // If one contains the other's simple name (handles nested namespaces)
    if a.contains(b_simple) || b.contains(a_simple) {
        return true;
    }

    // Special case: One might be a boxed version
    if a.contains("Box<") && a.contains(b_simple) {
        return true;
    }
    if b.contains("Box<") && b.contains(a_simple) {
        return true;
    }

    // Special case: if either type contains ArcValue as the value of a HashMap, consider compatible
    if a.contains("HashMap")
        && b.contains("HashMap")
        && (a.contains("ArcValue") || b.contains("ArcValue"))
    {
        // Ensure keys are same (String) if needed
        return true;
    }

    false
}

impl ErasedArc {
    /// Compare the actual value behind the erased arc for equality
    pub fn eq_value(&self, other: &ErasedArc) -> bool {
        // First, ensure type compatibility (ignoring namespaces)
        if !compare_type_names(self.type_name(), other.type_name()) {
            return false;
        }

        // Try common primitive & standard types
        macro_rules! try_downcast_eq {
            ($ty:ty) => {
                if let (Ok(left), Ok(right)) = (self.as_arc::<$ty>(), other.as_arc::<$ty>()) {
                    return *left == *right;
                }
            };
        }

        try_downcast_eq!(String);
        try_downcast_eq!(bool);
        try_downcast_eq!(i32);
        try_downcast_eq!(i64);
        try_downcast_eq!(f64);

        // Fallback to pointer equality when we can't compare contents safely
        self.reader.ptr() == other.reader.ptr()
    }
}
