use anyhow::{anyhow, Result};
use runar_common::logging::{Component, Logger};
use runar_macros::{action, publish, service, subscribe};
use runar_macros_common::params;
use runar_node::{
    services::{EventContext, RequestContext},
    Node,
};
use runar_serializer::ArcValue;
use runar_test_utils::create_test_environment;
use std::sync::{Arc, Mutex};

#[service(
    name = "Math Service",
    path = "math",
    description = "Simple arithmetic API",
    version = "0.1.0"
)]
pub struct MathService;

#[service]
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

#[service]
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
        ctx.request("stats/record", Some(ArcValue::new_primitive(total)))
            .await
            .expect("Call to stats/record failed");
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Setup logging
    let logger = Arc::new(Logger::new_root(Component::System));

    // Create a test environment with mobile simulator
    let (simulator, config) = create_test_environment().expect("Error creating test environment");
    simulator.print_summary();
    let mut node = Node::new(config).await?;

    // Register services
    node.add_service(MathService::default()).await?;
    node.add_service(StatsService::default()).await?;

    // call math/add
    let sum_arc: ArcValue = node
        .request("math/add", Some(params! { "a" => 1.0, "b" => 2.0 }))
        .await?;
    let sum: f64 = sum_arc.as_type()?;
    assert_eq!(sum, 3.0);

    // Query stats count
    let count_arc: ArcValue = node.request("stats/count", None::<ArcValue>).await?;
    let count: usize = count_arc.as_type()?;
    assert_eq!(count, 1);
    logger.info(format!("All good – stats recorded {count} value(s)"));
    Ok(())
}
