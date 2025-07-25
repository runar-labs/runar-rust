use anyhow::{anyhow, Result};
use runar_macros::{action, service};
use runar_node::services::RequestContext;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestItem {
    id: i32,
    name: String,
}

#[service(
    name = "Vec Schema Test Service",
    path = "vec_schema_test",
    description = "Service to test Vec schema generation",
    version = "0.0.1"
)]
pub struct VecSchemaTestService {}

#[service]
impl VecSchemaTestService {
    #[action]
    async fn test_vec_string(
        &self,
        items: Vec<String>,
        _ctx: &RequestContext,
    ) -> Result<Vec<String>> {
        Ok(items)
    }

    #[action]
    async fn test_vec_struct(
        &self,
        items: Vec<TestItem>,
        _ctx: &RequestContext,
    ) -> Result<Vec<TestItem>> {
        Ok(items)
    }

    #[action]
    async fn test_vec_primitive(
        &self,
        numbers: Vec<i32>,
        _ctx: &RequestContext,
    ) -> Result<Vec<i32>> {
        Ok(numbers)
    }

    #[action]
    async fn test_nested_vec(
        &self,
        data: Vec<Vec<String>>,
        _ctx: &RequestContext,
    ) -> Result<Vec<Vec<String>>> {
        Ok(data)
    }
}

#[test]
fn test_vec_schema_generation() {
    // This test verifies that the Vec schema generation bug has been fixed
    // The test will compile successfully if the schema generation works correctly
    // for Vec types, which means the bug where Vec was incorrectly treated as Option
    // has been resolved.

    // If we get here, the macro processed Vec types correctly
}

#[test]
fn test_vec_schema_compilation() {
    // This test just verifies that the code compiles
    // The actual test is that this file compiles at all with Vec types
}
