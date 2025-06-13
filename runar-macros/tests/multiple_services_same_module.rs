//! Ensure multiple #[service] definitions can coexist within one module without
//! duplicate static identifier conflicts.

use anyhow::{anyhow, Result};
use runar_macros::{action, service};
use runar_node::services::RequestContext;

#[derive(Clone)]
pub struct AlphaService;

#[service(path = "alpha", name = "Alpha Service")]
impl AlphaService {
    #[action]
    async fn foo(&self, _ctx: &RequestContext) -> Result<()> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct BetaService;

#[service(path = "beta", name = "Beta Service")]
impl BetaService {
    #[action]
    async fn bar(&self, _ctx: &RequestContext) -> Result<()> {
        Ok(())
    }
}

#[test]
fn multiple_services_compile() {
    let (_a, _b) = (AlphaService, BetaService);
}
