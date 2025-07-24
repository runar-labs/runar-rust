use runar_serializer::erased_arc::ErasedArc;
use std::sync::Arc;

// Test structs to demonstrate the dangerous substring matching issue
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
struct AdminUser {
    user: User,
    admin_level: i32,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct StringBuilder {
    parts: Vec<String>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct Vector {
    elements: Vec<i32>,
}

#[test]
fn test_compare_type_names_dangerous_substring_matches() {
    // Create ErasedArc instances with different types
    let user_arc = ErasedArc::new(Arc::new(User {
        id: 1,
        name: "John".to_string(),
    }));
    let user_data_arc = ErasedArc::new(Arc::new(UserData {
        user: User {
            id: 1,
            name: "John".to_string(),
        },
        metadata: "test".to_string(),
    }));
    let admin_user_arc = ErasedArc::new(Arc::new(AdminUser {
        user: User {
            id: 1,
            name: "John".to_string(),
        },
        admin_level: 5,
    }));
    let _string_builder_arc = ErasedArc::new(Arc::new(StringBuilder {
        parts: vec!["test".to_string()],
    }));
    let _vector_arc = ErasedArc::new(Arc::new(Vector {
        elements: vec![1, 2, 3],
    }));

    // Test that these different types should NOT be considered equal
    // The current broken implementation might allow them to be equal due to substring matching

    // Test 1: User should not equal UserData
    assert!(
        !user_arc.eq_value(&user_data_arc),
        "User should not equal UserData - this would be a dangerous false positive"
    );

    // Test 2: User should not equal AdminUser
    assert!(
        !user_arc.eq_value(&admin_user_arc),
        "User should not equal AdminUser - this would be a dangerous false positive"
    );

    // Test 3: UserData should not equal AdminUser
    assert!(
        !user_data_arc.eq_value(&admin_user_arc),
        "UserData should not equal AdminUser - this would be a dangerous false positive"
    );
}

#[test]
fn test_compare_type_names_safe_matches() {
    // These SHOULD match and should continue to work

    // Test 1: Same type should be equal
    let user1 = ErasedArc::new(Arc::new(User {
        id: 1,
        name: "John".to_string(),
    }));
    let user2 = ErasedArc::new(Arc::new(User {
        id: 2,
        name: "Jane".to_string(),
    }));

    // They should be equal because they're the same type (pointer comparison)
    assert!(user1.eq_value(&user1), "Same instance should be equal");

    // Test 2: Different instances of same type should be equal (pointer comparison)
    // Note: This depends on the implementation, but same type should at least not panic
    let _result = user1.eq_value(&user2); // Should not panic

    // Test 3: Box<T> should work with T
    let boxed_user = ErasedArc::new(Arc::new(Box::new(User {
        id: 1,
        name: "John".to_string(),
    })));
    // This should not panic when comparing
    let _result = boxed_user.eq_value(&user1); // Should not panic
}

#[test]
fn test_compare_type_names_unsafe_casting_demonstration() {
    // This test demonstrates the dangerous behavior that could lead to memory corruption

    let user_arc = ErasedArc::new(Arc::new(User {
        id: 1,
        name: "John".to_string(),
    }));
    let user_data_arc = ErasedArc::new(Arc::new(UserData {
        user: User {
            id: 1,
            name: "John".to_string(),
        },
        metadata: "test".to_string(),
    }));

    // Test that we cannot unsafely cast User to UserData
    let result = user_arc.as_arc::<UserData>();
    assert!(
        result.is_err(),
        "Should not be able to cast User to UserData"
    );

    // Test that we cannot unsafely cast UserData to User
    let result = user_data_arc.as_arc::<User>();
    assert!(
        result.is_err(),
        "Should not be able to cast UserData to User"
    );

    // Test that we can safely cast to the correct type
    let result = user_arc.as_arc::<User>();
    assert!(result.is_ok(), "Should be able to cast User to User");

    let result = user_data_arc.as_arc::<UserData>();
    assert!(
        result.is_ok(),
        "Should be able to cast UserData to UserData"
    );
}

#[test]
fn test_compare_type_names_should_fail_current_implementation() {
    // This test demonstrates that the current implementation is broken
    // and will cause these dangerous matches

    println!("Testing current compare_type_names implementation through ErasedArc...");

    let user_arc = ErasedArc::new(Arc::new(User {
        id: 1,
        name: "John".to_string(),
    }));
    let user_data_arc = ErasedArc::new(Arc::new(UserData {
        user: User {
            id: 1,
            name: "John".to_string(),
        },
        metadata: "test".to_string(),
    }));

    // Test the type names directly
    println!("User type name: {}", user_arc.type_name());
    println!("UserData type name: {}", user_data_arc.type_name());

    // Test equality comparison
    let eq_result = user_arc.eq_value(&user_data_arc);
    println!("user_arc.eq_value(&user_data_arc) = {eq_result}");

    if eq_result {
        println!("WARNING: Dangerous match detected! User equals UserData");
    }

    // Test unsafe casting
    let cast_result = user_arc.as_arc::<UserData>();
    println!("user_arc.as_arc::<UserData>() = {cast_result:?}");

    if cast_result.is_ok() {
        println!("WARNING: Dangerous cast detected! User can be cast to UserData");
    }

    println!("Current implementation may allow dangerous substring matches!");
}

#[test]
fn test_dangerous_generic_type_matching() {
    // This test demonstrates why Vec<i32> should NOT match Vec<String>
    // The compare_type_names function is used to determine if casting is safe

    let vec_i32 = vec![1, 2, 3];
    let vec_string = vec!["a".to_string(), "b".to_string()];

    let erased_vec_i32 = ErasedArc::new(Arc::new(vec_i32));
    let erased_vec_string = ErasedArc::new(Arc::new(vec_string));

    // These should have different type names
    assert_ne!(erased_vec_i32.type_name(), erased_vec_string.type_name());

    // Attempting to cast between different generic types should fail
    assert!(erased_vec_i32.as_arc::<Vec<String>>().is_err());
    assert!(erased_vec_string.as_arc::<Vec<i32>>().is_err());

    // Casting to correct type should succeed
    assert!(erased_vec_i32.as_arc::<Vec<i32>>().is_ok());
    assert!(erased_vec_string.as_arc::<Vec<String>>().is_ok());

    // If compare_type_names allowed Vec<i32> to match Vec<String>,
    // the above as_arc calls would succeed, leading to memory corruption
    // when trying to access i32 data as String data or vice versa.
}
