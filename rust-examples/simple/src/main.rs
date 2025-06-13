use anyhow::{anyhow, Result};
use runar_common::{hmap, types::ArcValue};
use runar_macros::{action, publish, service, subscribe};
use runar_node::{
    services::{EventContext, RequestContext},
    Node, NodeConfig,
};
use std::sync::{Arc, Mutex};

// ----- Math Service -----
/// Simple arithmetic service publishing the result of additions.
#[derive(Clone, Default)]
pub struct MathService;

#[service(
    name = "Math Service",
    path = "math",
    description = "Simple arithmetic API",
    version = "0.1.0"
)]
impl MathService {
    /// Add two numbers and publish the total to `math/added`.
    #[publish(path = "added")]
    #[action]
    async fn add(&self, a: f64, b: f64, ctx: &RequestContext) -> Result<f64> {
        ctx.debug(format!("Adding {a} + {b}"));
        Ok(a + b)
    }
}

// ----- Stats Service -----
/// Statistics collector service. Listens to math/added events and stores values.
#[derive(Clone)]
pub struct StatsService {
    values: Arc<Mutex<Vec<f64>>>,
}

impl Default for StatsService {
    fn default() -> Self {
        Self {
            values: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[service(path = "stats")]
impl StatsService {
    /// Record a value
    #[action]
    async fn record(&self, value: f64, _ctx: &RequestContext) -> Result<()> {
        self.values.lock().unwrap().push(value);
        Ok(())
    }

    /// Return number of recorded values
    #[action]
    async fn count(&self, _ctx: &RequestContext) -> Result<usize> {
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
    node.add_service(MathService).await?;
    node.add_service(StatsService::default()).await?;

    // call math/add
    let params = ArcValue::new_map(hmap! { "a" => 1.0, "b" => 2.0 });
    let sum: f64 = node.request("math/add", Some(params)).await?;
    assert_eq!(sum, 3.0);

    // Query stats count
    let count: usize = node.request("stats/count", None::<ArcValue>).await?;
    assert_eq!(count, 1);
    println!("All good – stats recorded {count} value(s)");
    Ok(())
}
