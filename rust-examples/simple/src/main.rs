use anyhow::{anyhow, Result};
use runar_common::{params, types::ArcValue};
use runar_macros::{action, publish, service, service_impl, subscribe};
use runar_node::{
    services::{EventContext, RequestContext},
    Node, NodeConfig,
};
use std::sync::{Arc, Mutex};

#[service(
    name = "Math Service",
    path = "math",
    description = "Simple arithmetic API",
    version = "0.1.0"
)]
pub struct MathService;

#[service_impl]
impl MathService {
    /// Add two numbers and publish the total to `math/added`.
    #[publish(path = "added")]
    #[action]
    async fn add(&self, a: f64, b: f64, ctx: &RequestContext) -> Result<f64> {
        ctx.debug(format!("Adding {a} + {b}"));
        Ok(a + b)
    }
}

#[service(path = "stats")]
pub struct StatsService {
    values: Arc<Mutex<Vec<f64>>>,
}

#[service_impl]
impl StatsService {
    /// Record a value
    #[action]
    async fn record(&self, value: f64) -> Result<()> {
        self.values.lock().unwrap().push(value);
        Ok(())
    }

    /// Return number of recorded values
    #[action]
    async fn count(&self) -> Result<usize> {
        Ok(self.values.lock().unwrap().len())
    }

    /// React to math/added events
    #[subscribe(path = "math/added")]
    async fn on_math_added(&self, total: f64, ctx: &EventContext) -> Result<()> {
        let _: () = ctx
            .request("stats/record", Some(ArcValue::new_primitive(total)))
            .await
            .expect("Call to stats/record failed");
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Create a minimal Node configuration
    let config = NodeConfig::new_with_generated_id("default_network");
    let mut node = Node::new(config).await?;

    // Register services
    node.add_service(MathService::default()).await?;
    node.add_service(StatsService::default()).await?;

    // call math/add
    let sum: f64 = node
        .request("math/add", Some(params! { "a" => 1.0, "b" => 2.0 }))
        .await?;
    assert_eq!(sum, 3.0);

    // Query stats count
    let count: usize = node.request("stats/count", None::<ArcValue>).await?;
    assert_eq!(count, 1);
    println!("All good – stats recorded {count} value(s)");
    Ok(())
}
