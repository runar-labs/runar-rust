//! Ensure multiple #[service] definitions can coexist within one module without
//! duplicate static identifier conflicts.

use anyhow::{anyhow, Result};
use runar_macros::{action, service, service_meta};
use runar_node::services::RequestContext;

#[derive(Clone)]
#[service_meta(path = "alpha", name = "Alpha Service")]
pub struct AlphaService;

#[service]
impl AlphaService {
    #[action]
    async fn foo(&self, _ctx: &RequestContext) -> Result<()> {
        Ok(())
    }
}

#[derive(Clone)]
#[service_meta(path = "beta", name = "Beta Service")]
pub struct BetaService;

#[service]
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
