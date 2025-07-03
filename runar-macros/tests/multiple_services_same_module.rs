//! Ensure multiple #[service] definitions can coexist within one module without
//! duplicate static identifier conflicts.

use anyhow::{anyhow, Result};
use runar_macros::{action, service, service_impl};
use runar_node::services::RequestContext;

#[service(path = "alpha", name = "Alpha Service")]
pub struct AlphaService;

#[service_impl]
impl AlphaService {
    #[action]
    async fn foo(&self, _ctx: &RequestContext) -> Result<()> {
        Ok(())
    }
}

#[service(path = "beta", name = "Beta Service")]
pub struct BetaService;

#[service_impl]
impl BetaService {
    #[action]
    async fn bar(&self, _ctx: &RequestContext) -> Result<()> {
        Ok(())
    }
}

#[test]
fn multiple_services_compile() {
    let (_a, _b) = (AlphaService::default(), BetaService::default());
}
