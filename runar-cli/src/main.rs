//! Runar CLI - Node Initialization and Management
//!
//! This CLI provides commands for initializing and managing Runar nodes.
//! The primary feature is the initialization flow that sets up a new node
//! with proper key management and certificate generation.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use runar_common::logging::{Component, Logger};
use std::path::PathBuf;
use std::sync::Arc;

mod config;
mod init;
mod key_store;
mod setup_server;
mod start;

use init::InitCommand;
use start::StartCommand;

#[derive(Parser)]
#[command(name = "runar")]
#[command(about = "Runar Node CLI - Initialize and manage Runar nodes")]
#[command(version = env!("CARGO_PKG_VERSION"))]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Configuration directory (default: ~/.runar)
    #[arg(short, long)]
    config_dir: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new Runar node
    #[command(name = "init")]
    Init {
        /// Force re-initialization even if config exists
        #[arg(short, long)]
        force: bool,
    },
    /// Start a Runar node
    #[command(name = "start")]
    Start {
        /// Configuration file to use
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::init();

    let cli = Cli::parse();

    // Create logger
    let logger = Arc::new(Logger::new_root(Component::CLI, "main"));

    // Determine config directory
    let config_dir = cli.config_dir.unwrap_or_else(|| {
        dirs::home_dir()
            .expect("Could not determine home directory")
            .join(".runar")
    });

    // Ensure config directory exists
    std::fs::create_dir_all(&config_dir)
        .with_context(|| format!("Failed to create config directory: {config_dir:?}"))?;

    match cli.command {
        Some(Commands::Init { force }) => {
            let init_cmd = InitCommand::new(config_dir, logger.clone());
            init_cmd.run(force).await?;
        }
        Some(Commands::Start { config }) => {
            let start_cmd = StartCommand::new(config_dir, logger.clone());
            start_cmd.run(config).await?;
        }
        None => {
            // No command specified - check if config exists and offer init or start
            let config_file = config_dir.join("config.json");
            if config_file.exists() {
                println!("Configuration found. Use 'runar start' to start the node.");
                println!("Use 'runar init --force' to re-initialize.");
            } else {
                println!("No configuration found. Use 'runar init' to initialize a new node.");
            }
        }
    }

    Ok(())
}
