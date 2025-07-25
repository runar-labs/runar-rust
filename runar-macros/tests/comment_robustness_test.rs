use runar_macros::service;

// Test that commented keywords don't interfere with macro parsing
#[service(
    name = "test_service",
    path = "/test",
    description = "Test service with commented keywords",
    version = "0.0.1"
)]
struct TestService {
    // This comment contains the word "impl" but shouldn't affect parsing
    // impl is a keyword in Rust
    field1: String,

    // This comment contains the word "struct" but shouldn't affect parsing
    // struct is also a keyword in Rust
    field2: i32,

    // String literal containing "impl" - should not affect parsing
    description: String, // "This service implements the impl pattern"
}

#[service]
impl TestService {
    // This comment contains "struct" but shouldn't affect impl parsing
    // struct is a keyword that defines data structures

    #[allow(dead_code)]
    fn test_action(&self, input: String) -> String {
        // This comment mentions "impl" and "struct" keywords
        // impl blocks contain struct implementations
        format!("Processed: {input}")
    }

    #[allow(dead_code)]
    fn another_action(&self, data: i32) -> i32 {
        // String literal with "struct" - should not break parsing
        let _message = "This struct contains data";
        data * 2
    }
}

// Test with more complex comments
#[service(
    name = "complex_service",
    path = "/complex",
    description = "Complex service with commented keywords",
    version = "0.0.1"
)]
struct ComplexService {
    // impl struct enum trait - all keywords in comments
    // should not affect macro parsing
    data: Vec<String>,
}

#[service]
impl ComplexService {
    #[allow(dead_code)]
    fn process(&self, items: Vec<String>) -> Vec<String> {
        // impl struct enum trait - keywords in comments
        // "impl" and "struct" in string literals
        let _debug_msg = "impl struct enum trait are Rust keywords";
        items
            .into_iter()
            .map(|item| format!("Processed: {item}"))
            .collect()
    }
}

// Test that the macro works with normal usage
#[test]
fn test_comment_robustness() {
    // This test verifies that the macro correctly parses struct and impl blocks
    // even when comments contain the keywords "impl" and "struct"

    // If we get here, the macro parsed correctly despite commented keywords
    // The service macro adds additional fields, so we can't construct directly
    // Just verify that the compilation succeeded
}

#[test]
fn test_comment_robustness_compile() {
    // This test just verifies that the code compiles
    // The actual test is that this file compiles at all
}
