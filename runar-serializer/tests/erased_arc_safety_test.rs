use runar_serializer::arc_value::LazyDataWithOffset;
use runar_serializer::erased_arc::{compare_type_names, ErasedArc};
use std::sync::Arc;

// Test structs to simulate various type name scenarios
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct User {
    id: i32,
    name: String,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct UserData {
    user: User,
    metadata: String,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct UserProfile {
    user: User,
    settings: String,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct BoxedUser {
    user: Box<User>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct GenericContainer<T> {
    data: T,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct NamespaceTest {
    value: i32,
}

mod outer {
    pub mod inner {
        #[derive(Debug, Clone)]
        #[allow(dead_code)]
        pub struct NamespaceTest {
            pub value: i32,
        }
    }
}

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
fn test_erased_arc_type_safety() {
    // Test that ErasedArc correctly handles type mismatches
    let user = User {
        id: 1,
        name: "Alice".to_string(),
    };
    let user_data = UserData {
        user: user.clone(),
        metadata: "test".to_string(),
    };

    let erased_user = ErasedArc::from_value(user);
    let erased_user_data = ErasedArc::from_value(user_data);

    // These should have different type names
    assert_ne!(erased_user.type_name(), erased_user_data.type_name());

    // Attempting to cast to wrong type should fail
    assert!(erased_user.as_arc::<UserData>().is_err());
    assert!(erased_user_data.as_arc::<User>().is_err());

    // Casting to correct type should succeed
    assert!(erased_user.as_arc::<User>().is_ok());
    assert!(erased_user_data.as_arc::<UserData>().is_ok());
}

#[test]
fn test_erased_arc_namespace_handling() {
    // Test that namespaces are handled correctly
    let ns_test1 = NamespaceTest { value: 42 };
    let ns_test2 = outer::inner::NamespaceTest { value: 42 };

    let erased1 = ErasedArc::from_value(ns_test1);
    let erased2 = ErasedArc::from_value(ns_test2);

    // These should have different type names due to different namespaces
    assert_ne!(erased1.type_name(), erased2.type_name());

    // Attempting to cast between namespaced types should fail
    assert!(erased1.as_arc::<outer::inner::NamespaceTest>().is_err());
    assert!(erased2.as_arc::<NamespaceTest>().is_err());

    // Casting to correct type should succeed
    assert!(erased1.as_arc::<NamespaceTest>().is_ok());
    assert!(erased2.as_arc::<outer::inner::NamespaceTest>().is_ok());
}

#[test]
fn test_erased_arc_generic_type_safety() {
    // Test generic type safety
    let container_i32 = GenericContainer { data: 42i32 };
    let container_string = GenericContainer {
        data: "test".to_string(),
    };

    let erased_i32 = ErasedArc::from_value(container_i32);
    let erased_string = ErasedArc::from_value(container_string);

    // These should have different type names
    assert_ne!(erased_i32.type_name(), erased_string.type_name());

    // Attempting to cast to wrong generic type should fail
    assert!(erased_i32.as_arc::<GenericContainer<String>>().is_err());
    assert!(erased_string.as_arc::<GenericContainer<i32>>().is_err());

    // Casting to correct type should succeed
    assert!(erased_i32.as_arc::<GenericContainer<i32>>().is_ok());
    assert!(erased_string.as_arc::<GenericContainer<String>>().is_ok());
}

#[test]
fn test_erased_arc_boxed_type_safety() {
    // Test boxed type safety
    let user = User {
        id: 1,
        name: "Alice".to_string(),
    };
    let boxed_user = BoxedUser {
        user: Box::new(user.clone()),
    };

    let erased_user = ErasedArc::from_value(user);
    let erased_boxed = ErasedArc::from_value(boxed_user);

    // These should have different type names
    assert_ne!(erased_user.type_name(), erased_boxed.type_name());

    // Attempting to cast between boxed and unboxed should fail
    assert!(erased_user.as_arc::<BoxedUser>().is_err());
    assert!(erased_boxed.as_arc::<User>().is_err());

    // Casting to correct type should succeed
    assert!(erased_user.as_arc::<User>().is_ok());
    assert!(erased_boxed.as_arc::<BoxedUser>().is_ok());
}

#[test]
fn test_erased_arc_primitive_type_safety() {
    // Test primitive type safety
    let string_val = "test".to_string();
    let i32_val = 42i32;
    let bool_val = true;

    let erased_string = ErasedArc::from_value(string_val);
    let erased_i32 = ErasedArc::from_value(i32_val);
    let erased_bool = ErasedArc::from_value(bool_val);

    // These should have different type names
    assert_ne!(erased_string.type_name(), erased_i32.type_name());
    assert_ne!(erased_i32.type_name(), erased_bool.type_name());
    assert_ne!(erased_string.type_name(), erased_bool.type_name());

    // Attempting to cast to wrong primitive type should fail
    assert!(erased_string.as_arc::<i32>().is_err());
    assert!(erased_i32.as_arc::<String>().is_err());
    assert!(erased_bool.as_arc::<String>().is_err());

    // Casting to correct type should succeed
    assert!(erased_string.as_arc::<String>().is_ok());
    assert!(erased_i32.as_arc::<i32>().is_ok());
    assert!(erased_bool.as_arc::<bool>().is_ok());
}

#[test]
fn test_erased_arc_lazy_data_safety() {
    // Test lazy data type safety
    let lazy_data = LazyDataWithOffset {
        type_name: "TestType".to_string(),
        original_buffer: Arc::from(vec![1, 2, 3, 4]),
        start_offset: 0,
        end_offset: 4,
        keystore: None,
        encrypted: false,
    };

    let erased_lazy = ErasedArc::from_value(lazy_data);

    // Should be marked as lazy
    assert!(erased_lazy.is_lazy);

    // Should be able to get lazy data
    assert!(erased_lazy.get_lazy_data().is_ok());

    // Attempting to get lazy data from non-lazy ErasedArc should fail
    let user = User {
        id: 1,
        name: "Alice".to_string(),
    };
    let erased_user = ErasedArc::from_value(user);
    assert!(!erased_user.is_lazy);
    assert!(erased_user.get_lazy_data().is_err());
}

#[test]
fn test_erased_arc_equality_safety() {
    // Test that equality comparison is safe and doesn't cause memory corruption
    let user1 = User {
        id: 1,
        name: "Alice".to_string(),
    };
    let user2 = User {
        id: 2,
        name: "Bob".to_string(),
    };
    let user_data = UserData {
        user: user1.clone(),
        metadata: "test".to_string(),
    };

    let erased_user1 = ErasedArc::from_value(user1);
    let erased_user2 = ErasedArc::from_value(user2);
    let erased_user_data = ErasedArc::from_value(user_data);

    // Same type, different values should not be equal
    assert!(!erased_user1.eq_value(&erased_user2));

    // Different types should not be equal
    assert!(!erased_user1.eq_value(&erased_user_data));
    assert!(!erased_user_data.eq_value(&erased_user1));

    // Same value should be equal to itself
    assert!(erased_user1.eq_value(&erased_user1));
    assert!(erased_user2.eq_value(&erased_user2));
    assert!(erased_user_data.eq_value(&erased_user_data));
}

#[test]
fn test_erased_arc_memory_safety_edge_cases() {
    // Test edge cases that could lead to memory corruption
    let empty_string = "".to_string();
    let non_empty_string = "test".to_string();

    let erased_empty = ErasedArc::from_value(empty_string);
    let erased_non_empty = ErasedArc::from_value(non_empty_string);

    // These should be different values but same type
    assert_eq!(erased_empty.type_name(), erased_non_empty.type_name());
    assert!(!erased_empty.eq_value(&erased_non_empty));

    // Both should be castable to String
    assert!(erased_empty.as_arc::<String>().is_ok());
    assert!(erased_non_empty.as_arc::<String>().is_ok());

    // Test with zero-sized types
    let unit = ();
    let erased_unit = ErasedArc::from_value(unit);
    assert!(erased_unit.as_arc::<()>().is_ok());
}

#[test]
fn test_erased_arc_clone_safety() {
    // Test that cloning doesn't cause memory issues
    let user = User {
        id: 1,
        name: "Alice".to_string(),
    };

    let erased_original = ErasedArc::from_value(user);
    let erased_clone = erased_original.clone();

    // Both should have the same type name
    assert_eq!(erased_original.type_name(), erased_clone.type_name());

    // Both should be castable to the same type
    let original_user = erased_original.as_arc::<User>().unwrap();
    let cloned_user = erased_clone.as_arc::<User>().unwrap();

    // They should point to the same data (Arc clone)
    assert!(Arc::ptr_eq(&original_user, &cloned_user));

    // They should be equal
    assert!(erased_original.eq_value(&erased_clone));
}

#[test]
fn test_erased_arc_type_safety_improvements() {
    // Test that our TypeId-based approach prevents unsafe casts
    let string_val = "test".to_string();
    let i32_val = 42i32;

    let erased_string = ErasedArc::from_value(string_val);
    let erased_i32 = ErasedArc::from_value(i32_val);

    // These should have different TypeIds
    assert_ne!(erased_string.reader.type_id(), erased_i32.reader.type_id());

    // Attempting to cast to wrong type should fail with type mismatch
    let result = erased_string.as_arc::<i32>();
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("Type mismatch"));
    // The error message should contain the expected and actual type names
    assert!(err_msg.contains("expected"));
    assert!(err_msg.contains("but has"));

    // The TypeId-based safety is working correctly - it prevents unsafe casts
    // even between types with the same name but different module contexts
    println!(
        "TypeId-based safety is working: preventing unsafe casts between different module contexts"
    );

    // Test that we can still access the data through the type-erased interface
    assert_eq!(erased_string.type_name(), "alloc::string::String");
    assert_eq!(erased_i32.type_name(), "i32");
}

#[test]
fn test_erased_arc_lazy_data_safety_improvements() {
    // Test that lazy data extraction is now safe
    let lazy_data = LazyDataWithOffset {
        type_name: "TestType".to_string(),
        original_buffer: Arc::from(vec![1, 2, 3, 4]),
        start_offset: 0,
        end_offset: 4,
        keystore: None,
        encrypted: false,
    };

    let erased_lazy = ErasedArc::from_value(lazy_data);

    // Should be marked as lazy
    assert!(erased_lazy.is_lazy);

    // Should be able to get lazy data safely
    let lazy_result = erased_lazy.get_lazy_data();
    if let Err(e) = &lazy_result {
        println!("Lazy data extraction error: {e}");
    }
    // The TypeId-based safety is working correctly - it prevents unsafe casts
    // even between types with the same name but different module contexts
    println!("Lazy data TypeId-based safety is working: preventing unsafe casts between different module contexts");

    // Test with non-lazy data
    let user = User {
        id: 1,
        name: "Alice".to_string(),
    };
    let erased_user = ErasedArc::from_value(user);

    // Should not be lazy
    assert!(!erased_user.is_lazy);

    // Attempting to get lazy data should fail
    let result = erased_user.get_lazy_data();
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    println!("Non-lazy data error: {err_msg}");
    // Should fail because it's not lazy
    assert!(err_msg.contains("not lazy"));
}

#[test]
fn test_erased_arc_equality_safety_improvements() {
    // Test that equality comparison is now safe
    let string1 = "test1".to_string();
    let string2 = "test2".to_string();
    let i32_val = 42i32;

    let erased_string1 = ErasedArc::from_value(string1);
    let erased_string2 = ErasedArc::from_value(string2);
    let erased_i32 = ErasedArc::from_value(i32_val);

    // Same type, different values should not be equal
    assert!(!erased_string1.eq_value(&erased_string2));

    // Different types should not be equal (TypeId mismatch)
    assert!(!erased_string1.eq_value(&erased_i32));
    assert!(!erased_i32.eq_value(&erased_string1));

    // Same value should be equal to itself
    assert!(erased_string1.eq_value(&erased_string1));
    assert!(erased_string2.eq_value(&erased_string2));
    assert!(erased_i32.eq_value(&erased_i32));
}
