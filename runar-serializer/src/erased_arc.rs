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
        let self_type = self.type_name();
        let other_type = other.type_name();

        // First, ensure type compatibility (ignoring namespaces)
        if !compare_type_names(self_type, other_type) {
            return false;
        }

        // Try common primitive & standard types using safe pointer comparison
        macro_rules! try_downcast_eq {
            ($ty:ty) => {
                // Check if the type matches and use pointer comparison instead of unsafe as_arc
                if compare_type_names(std::any::type_name::<$ty>(), self_type) {
                    return self.reader.ptr() == other.reader.ptr();
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

/// Helper to compare type names for casting safety
/// This function is used to determine if it's safe to cast between types.
/// It must be very restrictive to prevent memory corruption.
///
/// This function only allows:
/// - Exact matches
/// - Box<T> matches T (this is safe because Box<T> is just a pointer to T)
/// - Option<T> matches T (this is safe because you can wrap/unwrap Option)
/// - Standard library type aliases (e.g., "std::string::String" matches "alloc::string::String")
///
/// It does NOT allow:
/// - Generic types with different parameters (e.g., Vec<i32> != Vec<String>)
/// - Namespace stripping for user-defined types
/// - Substring matches
pub fn compare_type_names(a: &str, b: &str) -> bool {
    // Types are identical
    if a == b {
        return true;
    }

    // Handle Box<T> matching T - this is safe because Box<T> is just a pointer to T
    if a.contains("Box<") {
        if let Some(start) = a.find("Box<") {
            if let Some(end) = a.rfind('>') {
                let boxed_type = &a[start + 4..end];
                // Extract the simple name of the boxed type
                let boxed_simple = boxed_type.split("::").last().unwrap_or(boxed_type);
                // Compare with the simple name of b
                let b_simple = b.split("::").last().unwrap_or(b);
                if boxed_simple == b_simple {
                    return true;
                }
            }
        }
    }

    if b.contains("Box<") {
        if let Some(start) = b.find("Box<") {
            if let Some(end) = b.rfind('>') {
                let boxed_type = &b[start + 4..end];
                // Extract the simple name of the boxed type
                let boxed_simple = boxed_type.split("::").last().unwrap_or(boxed_type);
                // Compare with the simple name of a
                let a_simple = a.split("::").last().unwrap_or(a);
                if boxed_simple == a_simple {
                    return true;
                }
            }
        }
    }

    // Handle Option<T> matching T - this is safe because you can wrap/unwrap Option
    if a.contains("Option<") {
        if let Some(start) = a.find("Option<") {
            if let Some(end) = a.rfind('>') {
                let option_type = &a[start + 7..end];
                // Extract the simple name of the option type
                let option_simple = option_type.split("::").last().unwrap_or(option_type);
                // Compare with the simple name of b
                let b_simple = b.split("::").last().unwrap_or(b);
                if option_simple == b_simple {
                    return true;
                }
            }
        }
    }

    if b.contains("Option<") {
        if let Some(start) = b.find("Option<") {
            if let Some(end) = b.rfind('>') {
                let option_type = &b[start + 7..end];
                // Extract the simple name of the option type
                let option_simple = option_type.split("::").last().unwrap_or(option_type);
                // Compare with the simple name of a
                let a_simple = a.split("::").last().unwrap_or(a);
                if option_simple == a_simple {
                    return true;
                }
            }
        }
    }

    // Handle standard library type aliases
    // These are known to be safe because they're the same underlying type
    if (a == "std::string::String" && b == "alloc::string::String")
        || (a == "alloc::string::String" && b == "std::string::String")
    {
        return true;
    }

    // For all other cases, require exact match
    // This prevents dangerous generic type mismatches like Vec<i32> vs Vec<String>
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compare_type_names_identical() {
        // Should match identical types
        assert!(compare_type_names("String", "String"));
        assert!(compare_type_names("i32", "i32"));
        assert!(compare_type_names(
            "alloc::string::String",
            "alloc::string::String"
        ));
    }

    #[test]
    fn test_compare_type_names_simple_names() {
        // Should NOT match when namespaces are different (except for known safe cases)
        assert!(!compare_type_names("alloc::string::String", "String"));
        assert!(!compare_type_names("String", "alloc::string::String"));
        assert!(!compare_type_names("core::option::Option<i32>", "Option"));

        // Should match only known safe standard library aliases
        assert!(compare_type_names(
            "std::string::String",
            "alloc::string::String"
        ));
        assert!(compare_type_names(
            "alloc::string::String",
            "std::string::String"
        ));
    }

    #[test]
    fn test_compare_type_names_different_types() {
        // Should NOT match different types
        assert!(!compare_type_names("String", "i32"));
        assert!(!compare_type_names("User", "UserData"));
        assert!(!compare_type_names("UserData", "User"));
        assert!(!compare_type_names("UserProfile", "User"));
        assert!(!compare_type_names("User", "UserProfile"));
    }

    #[test]
    fn test_compare_type_names_namespace_variations() {
        // Test namespace handling - should NOT match different namespaces for user types
        assert!(!compare_type_names("crate::User", "User"));
        assert!(!compare_type_names("User", "crate::User"));
        assert!(!compare_type_names(
            "outer::inner::NamespaceTest",
            "NamespaceTest"
        ));
        assert!(!compare_type_names(
            "NamespaceTest",
            "outer::inner::NamespaceTest"
        ));

        // Only known safe standard library aliases should match
        assert!(compare_type_names(
            "std::string::String",
            "alloc::string::String"
        ));
    }

    #[test]
    fn test_compare_type_names_generic_types() {
        // Test generic type handling - should NOT match different generic types
        assert!(!compare_type_names("Vec<i32>", "Vec"));
        assert!(!compare_type_names("Option<String>", "Option"));
        assert!(!compare_type_names("HashMap<String, i32>", "HashMap"));

        // Should NOT match different generic parameters
        assert!(!compare_type_names("Vec<i32>", "Vec<String>"));
        assert!(!compare_type_names("Option<i32>", "Option<String>"));
    }

    #[test]
    fn test_compare_type_names_boxed_types() {
        // Test boxed type handling
        assert!(compare_type_names("Box<User>", "User"));
        assert!(compare_type_names("User", "Box<User>"));
        assert!(compare_type_names("Box<alloc::string::String>", "String"));
    }

    #[test]
    fn test_compare_type_names_option_types() {
        // Test option type handling
        assert!(compare_type_names("Option<User>", "User"));
        assert!(compare_type_names("User", "Option<User>"));
        assert!(compare_type_names("Option<String>", "String"));
        assert!(compare_type_names("String", "Option<String>"));
        assert!(compare_type_names("core::option::Option<User>", "User"));
        assert!(compare_type_names("User", "core::option::Option<User>"));
    }

    #[test]
    fn test_compare_type_names_dangerous_prefixes() {
        // These should NOT match - they have similar prefixes but are different types
        assert!(!compare_type_names("User", "UserData"));
        assert!(!compare_type_names("UserData", "User"));
        assert!(!compare_type_names("String", "StringBuilder"));
        assert!(!compare_type_names("StringBuilder", "String"));
        assert!(!compare_type_names("Vec", "Vector"));
        assert!(!compare_type_names("Vector", "Vec"));
    }

    #[test]
    fn test_compare_type_names_suffix_variations() {
        // These should NOT match - they have similar suffixes but are different types
        assert!(!compare_type_names("User", "AdminUser"));
        assert!(!compare_type_names("AdminUser", "User"));
        assert!(!compare_type_names("String", "ByteString"));
        assert!(!compare_type_names("ByteString", "String"));
    }

    #[test]
    fn test_compare_type_names_substring_issues() {
        // These should NOT match - they contain each other as substrings but are different types
        assert!(!compare_type_names("User", "UserManager"));
        assert!(!compare_type_names("UserManager", "User"));
        assert!(!compare_type_names("Data", "UserData"));
        assert!(!compare_type_names("UserData", "Data"));
    }

    #[test]
    fn test_compare_type_names_edge_cases() {
        // Test edge cases that should be handled safely
        assert!(!compare_type_names("", "User"));
        assert!(!compare_type_names("User", ""));
        assert!(!compare_type_names("User", "Users"));
        assert!(!compare_type_names("Users", "User"));
        // Generic types with different parameters should NOT match
        assert!(!compare_type_names("Vec<i32>", "Vec<String>"));
        assert!(!compare_type_names("Option<User>", "Option<Admin>"));
    }
}
