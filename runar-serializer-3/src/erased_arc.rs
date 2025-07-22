//! ErasedArc implementation for type-erased Arc values

use std::any::{Any, TypeId};
use std::fmt;
use std::sync::Arc;

use anyhow::Result;

/// ArcRead is a trait for safely accessing an Arc's contents
pub trait ArcRead: fmt::Debug + Send + Sync {
    /// Get the type name of the contained value
    fn type_name(&self) -> &str;

    /// Get the type ID of the contained value
    fn type_id(&self) -> TypeId;

    /// Clone this trait object
    fn clone_box(&self) -> Box<dyn ArcRead>;

    /// Get the pointer to the inner value
    fn ptr(&self) -> *const ();
}

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

// Implement Clone for Box<dyn ArcRead>
impl Clone for Box<dyn ArcRead> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

/// The actual type-erased Arc implementation
/// This struct holds an `Arc<dyn Any + Send + Sync>` and provides methods
/// to interact with the underlying data in a type-safe manner.
pub struct ErasedArc {
    /// The type-erased Arc reader
    pub reader: Box<dyn ArcRead>,
    /// Flag indicating if this contains a LazyDeserializer
    pub is_lazy: bool,
}

// ArcReader to store TypeId and String type_name
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

    fn ptr(&self) -> *const () {
        Arc::as_ptr(&self.arc) as *const ()
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

    /// Get the type name of the contained value
    pub fn type_name(&self) -> &str {
        self.reader.type_name()
    }

    /// Directly get the LazyDataWithOffset when we know this contains one
    pub fn get_lazy_data(&self) -> Result<Arc<super::arc_value::LazyDataWithOffset>> {
        if !self.is_lazy {
            return Err(anyhow::anyhow!("Value is not lazy (is_lazy flag is false)"));
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

    /// Try to extract an Arc<T> from this ErasedArc
    pub fn as_arc<T: 'static>(&self) -> Result<Arc<T>> {
        // Check if the type matches based on name
        if !compare_type_names(std::any::type_name::<T>(), self.type_name()) {
            let expected_type_name = std::any::type_name::<T>();
            let actual_type_name = self.type_name();
            return Err(anyhow::anyhow!(
                "Type mismatch: expected {}, but has {}",
                expected_type_name,
                actual_type_name
            ));
        }

        // Attempt to downcast
        let ptr = self.reader.ptr() as *const T;
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
}

/// Helper to compare type names accounting for namespaces
fn compare_type_names(a: &str, b: &str) -> bool {
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
        return true;
    }

    false
}
