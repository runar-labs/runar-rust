//! Test that a service whose actions only use primitive types compiles.
//! Previously this triggered `E0282` because the `#[service]` macro did not
//! handle an empty set of complex types during code generation.

use anyhow::{anyhow, Result};
use runar_macros::{action, service};
use runar_node::services::RequestContext;

#[derive(Clone)]
pub struct PrimitiveService;

#[service(name = "Primitive Service", path = "primitive")]
impl PrimitiveService {
    #[action]
    async fn add(&self, a: i32, b: i32, _ctx: &RequestContext) -> Result<i32> {
        Ok(a + b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitive_service_compiles() {
        // The mere presence of this test forces the file to compile.
        let _svc = PrimitiveService;
    }
}
