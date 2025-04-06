use anyhow::Result;
use clap::{arg, command, Parser};
use log::info;

use runar_node;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the database file
    #[arg(short, long, default_value = "/tmp/runar.db")]
    db_path: String,

    /// Whether to run with local services
    #[arg(long)]
    services: bool,

    /// Network ID for services
    #[arg(long, default_value = "network_default")]
    network_id: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::init();

    info!("Starting Runar Node...");

    // Parse command-line arguments
    let args = Args::parse();

    // Run the appropriate mode based on arguments
    if args.services {
        // Run with services
        info!("Starting node with local services...");
        runar_node::init_with_services(&args.db_path, &args.network_id).await?;

        // Keep the main thread alive
        tokio::signal::ctrl_c().await?;
        info!("Shutting down...");
    } else {
        // Run the CLI
        runar_node::cli::run().await?;
    }

    Ok(())
}
