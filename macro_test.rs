use std::collections::HashMap;

// Include the ValueType structure for the test
#[derive(Debug, Clone)]
pub enum ValueType {
    Map(HashMap<String, ValueType>),
    String(String),
    Number(f64),
    Bool(bool),
    Null,
}

// Define the vmap! macro
#[macro_export]
macro_rules! vmap {
    // Extract value from ValueType::Map with a default
    ($value:expr, $key:expr => $default:expr) => {{
        // Determine the type of the default value using a compile-time trick
        macro_rules! decltype {
            ($x:expr, $_type:ty) => {{ let _: $_type = $x; true }};
            ($x:expr) => {{ std::any::type_name_of_val(&$x) }};
        }

        match &$value {
            ValueType::Map(map) => {
                if let Some(v) = map.get($key) {
                    match v {
                        ValueType::String(s) => {
                            // If default is a String, return the string value
                            if decltype!($default, String) {
                                s.clone()
                            } else {
                                $default
                            }
                        },
                        ValueType::Number(n) => {
                            // If default is a numeric type, return the number
                            if decltype!($default, f64) { 
                                *n 
                            } else if decltype!($default, i32) { 
                                *n as i32
                            } else {
                                $default
                            }
                        },
                        ValueType::Bool(b) => {
                            // If default is a bool, return the boolean value
                            if decltype!($default, bool) {
                                *b
                            } else {
                                $default
                            }
                        },
                        _ => $default,
                    }
                } else {
                    $default
                }
            },
            _ => $default,
        }
    }};
    
    // Support the alternative syntax with comma
    ($value:expr, $key:expr, => $default:expr) => {
        vmap!($value, $key => $default)
    };
}

// Define the vmap_result! macro
#[macro_export]
macro_rules! vmap_result {
    // Extract from Option<ValueType> (service result)
    ($value:expr, $key:expr => $default:expr) => {{
        // Determine the type of the default value using a compile-time trick
        macro_rules! decltype {
            ($x:expr, $_type:ty) => {{ let _: $_type = $x; true }};
            ($x:expr) => {{ std::any::type_name_of_val(&$x) }};
        }

        match &$value {
            Some(value) => {
                if let ValueType::Map(map) = value {
                    if let Some(v) = map.get($key) {
                        match v {
                            ValueType::String(s) => {
                                // If default is a String, return the string value
                                if decltype!($default, String) {
                                    s.clone()
                                } else {
                                    $default
                                }
                            },
                            ValueType::Number(n) => {
                                // If default is a numeric type, return the number
                                if decltype!($default, f64) { 
                                    *n 
                                } else if decltype!($default, i32) { 
                                    *n as i32
                                } else {
                                    $default
                                }
                            },
                            ValueType::Bool(b) => {
                                // If default is a bool, return the boolean value
                                if decltype!($default, bool) {
                                    *b
                                } else {
                                    $default
                                }
                            },
                            _ => $default,
                        }
                    } else {
                        $default
                    }
                } else {
                    $default
                }
            },
            None => $default,
        }
    }};
    
    // Support the alternative syntax with comma
    ($value:expr, $key:expr, => $default:expr) => {
        vmap_result!($value, $key => $default)
    };
}

// Main function to test the macros
fn main() {
    // Create a test map
    let mut map = HashMap::new();
    map.insert("string_key".to_string(), ValueType::String("hello".to_string()));
    map.insert("int_key".to_string(), ValueType::Number(42.0));
    map.insert("bool_key".to_string(), ValueType::Bool(true));
    
    // Test extracting values with vmap! macro
    let string_val: String = vmap!(ValueType::Map(map.clone()), "string_key" => "default".to_string());
    println!("String value: {}", string_val);
    assert_eq!(string_val, "hello");
    
    let int_val: i32 = vmap!(ValueType::Map(map.clone()), "int_key" => 0);
    println!("Int value: {}", int_val);
    assert_eq!(int_val, 42);
    
    let bool_val: bool = vmap!(ValueType::Map(map.clone()), "bool_key" => false);
    println!("Bool value: {}", bool_val);
    assert_eq!(bool_val, true);
    
    // Test defaults when key doesn't exist
    let default_string: String = vmap!(ValueType::Map(map.clone()), "missing_key" => "default_value".to_string());
    println!("Default string: {}", default_string);
    assert_eq!(default_string, "default_value");
    
    let default_int: i32 = vmap!(ValueType::Map(map.clone()), "missing_key" => 100);
    println!("Default int: {}", default_int);
    assert_eq!(default_int, 100);
    
    // Create a service result (Option<ValueType>)
    let result = Some(ValueType::Map(map.clone()));
    
    // Test extracting values with vmap_result! macro
    let string_val: String = vmap_result!(result.clone(), "string_key" => "default".to_string());
    println!("Result string value: {}", string_val);
    assert_eq!(string_val, "hello");
    
    let int_val: i32 = vmap_result!(result.clone(), "int_key" => 0);
    println!("Result int value: {}", int_val);
    assert_eq!(int_val, 42);
    
    let bool_val: bool = vmap_result!(result.clone(), "bool_key" => false);
    println!("Result bool value: {}", bool_val);
    assert_eq!(bool_val, true);
    
    // Test defaults when key doesn't exist
    let default_string: String = vmap_result!(result.clone(), "missing_key" => "default_value".to_string());
    println!("Result default string: {}", default_string);
    assert_eq!(default_string, "default_value");
    
    // Test when result is None
    let none_result: Option<ValueType> = None;
    let none_string: String = vmap_result!(none_result, "any_key" => "none_default".to_string());
    println!("None result string: {}", none_string);
    assert_eq!(none_string, "none_default");
    
    println!("All tests passed!");
} 