use crate::db::{Database, SqliteDatabase};
use crate::key_management::{KeyManager, KeyType};
use crate::node::{Node, NodeConfig};
use crate::web::{start_web_server, WebServerMode};

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use dirs::home_dir;
use log::{error, info, warn};
use open;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::oneshot;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Optional configuration directory
    #[arg(short, long)]
    config_dir: Option<String>,

    /// Subcommand to execute
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Generate a new keypair
    Keygen {
        /// Optional output file path
        #[arg(short, long)]
        output: Option<String>,
    },
}

pub async fn run() -> Result<()> {
    info!("Starting Runar Node...");

    // Parse command line arguments
    let args = Args::parse();

    // Get the configuration directory
    let config_dir = match args.config_dir {
        Some(dir) => PathBuf::from(dir),
        None => {
            let home = home_dir().ok_or_else(|| anyhow!("Could not determine home directory"))?;
            home.join(".node_config")
        }
    };

    info!("Config directory: {}", config_dir.display());

    // Create the configuration directory if it doesn't exist
    if !config_dir.exists() {
        info!("Creating config directory: {}", config_dir.display());
        fs::create_dir_all(&config_dir)?;
    } else {
        info!("Config directory already exists: {}", config_dir.display());
    }

    // Create subdirectories
    let db_dir = config_dir.join("db");
    if !db_dir.exists() {
        info!("Creating db directory: {}", db_dir.display());
        fs::create_dir_all(&db_dir)?;
    } else {
        info!("Directory already exists: {}", db_dir.display());
    }

    let logs_dir = config_dir.join("logs");
    if !logs_dir.exists() {
        info!("Creating logs directory: {}", logs_dir.display());
        fs::create_dir_all(&logs_dir)?;
    } else {
        info!("Directory already exists: {}", logs_dir.display());
    }

    // Note: The webui directory is no longer needed as we're using UI files directly from the node directory
    // The paths are now handled in the web.rs file

    info!("Using configuration directory: {}", config_dir.display());

    // Handle subcommands
    match args.command {
        Some(Commands::Keygen { output }) => {
            keygen(output).await?;
            return Ok(());
        }
        None => {
            // Start the node
            info!("Starting node...");
            start_node(config_dir).await?;
        }
    }

    Ok(())
}

async fn start_node(config_dir: PathBuf) -> Result<()> {
    info!("Initializing key manager...");
    let _key_manager = KeyManager::new(config_dir.to_str().unwrap_or_default())?;

    // Initialize the database
    let db_path = config_dir.join("db/node.db");
    info!("Database path: {}", db_path.display());

    let db_dir = config_dir.join("db");
    info!("Database directory: {}", db_dir.display());

    if !db_dir.exists() {
        info!("Creating database directory: {}", db_dir.display());
        fs::create_dir_all(&db_dir)?;
    } else {
        info!("Database directory already exists: {}", db_dir.display());
    }

    info!("Initializing database...");
    let db = Arc::new(SqliteDatabase::new(db_path.to_str().unwrap()).await?);

    // Check if configuration exists
    info!("Checking if configuration exists...");
    let config_result = db.load_node_config(config_dir.clone()).await;

    match config_result {
        Ok(config) => {
            // Configuration exists, start the node
            info!("Configuration found, starting node: {}", config.node_name);

            // Create and initialize the node
            info!("Creating node...");
            let node_config = NodeConfig::new(
                &config.node_name,
                config_dir.to_str().unwrap_or("."),
                config_dir.to_str().unwrap_or("."),
            );
            let mut node = Node::new(node_config).await?;
            info!("Initializing node...");
            node.init().await?;
            let node_arc = Arc::new(node);

            // Start the IPC server
            info!("Starting IPC server...");
            crate::init_ipc_server(node_arc.clone(), PathBuf::from("/tmp/runar.sock")).await?;
            
            // Start the web server in normal mode
            info!("Starting web server in normal mode...");
            tokio::spawn(start_web_server(
                db.clone(),
                None,
                config_dir.clone(),
                WebServerMode::NodeUI,
            ));

            // Keep the process running
            info!("Node started successfully, running indefinitely...");
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }

            #[allow(unreachable_code)]
            Ok(())
        }
        Err(_) => {
            // No configuration exists, start the setup process
            info!("No config found, initiating setup workflow");

            // Run the initial node setup
            initial_node_setup(config_dir.clone()).await?;

            // After setup is complete, check for configuration again
            info!("Setup complete, checking for new configuration...");

            // Try to load the configuration again
            let config_result = db.load_node_config(config_dir.clone()).await;

            match config_result {
                Ok(config) => {
                    // Configuration now exists, start the node
                    info!(
                        "Configuration found after setup, starting node: {}",
                        config.node_name
                    );

                    // Create and initialize the node
                    info!("Creating node...");
                    let node_config = NodeConfig::new(
                        &config.node_name,
                        config_dir.to_str().unwrap_or("."),
                        config_dir.to_str().unwrap_or("."),
                    );
                    let mut node = Node::new(node_config).await?;
                    info!("Initializing node...");
                    node.init().await?;
                    let node_arc = Arc::new(node);

                    // Start the IPC server
                    info!("Starting IPC server...");
                    crate::init_ipc_server(node_arc.clone(), PathBuf::from("/tmp/runar.sock")).await?;
                    
                    // Start the web server in normal mode
                    info!("Starting web server in normal mode...");
                    tokio::spawn(start_web_server(
                        db.clone(),
                        None,
                        config_dir.clone(),
                        WebServerMode::NodeUI,
                    ));

                    // Keep the process running
                    info!("Node started successfully, running indefinitely...");
                    loop {
                        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    }

                    #[allow(unreachable_code)]
                    Ok(())
                }
                Err(e) => {
                    error!("Setup completed but no configuration found: {:?}", e);
                    Err(anyhow!("Setup completed but no configuration found: {}", e))
                }
            }
        }
    }
}

async fn initial_node_setup(config_dir: PathBuf) -> Result<()> {
    info!("Starting initial node setup...");

    // Create a oneshot channel for signaling when setup is complete
    info!("Creating oneshot channel...");
    let (setup_tx, setup_rx) = oneshot::channel::<()>();

    // Initialize the database
    let db_path = config_dir.join("db/node.db");
    info!("Database path: {}", db_path.display());

    let db_dir = config_dir.join("db");
    info!("Database directory: {}", db_dir.display());

    if !db_dir.exists() {
        info!("Creating database directory: {}", db_dir.display());
        std::fs::create_dir_all(&db_dir)?;
    } else {
        info!("Database directory already exists: {}", db_dir.display());
    }

    info!("Initializing database...");
    let db = Arc::new(SqliteDatabase::new(db_path.to_str().unwrap()).await?);

    // Start the web server in setup mode
    info!("Starting web server in setup mode...");
    let web_server_handle = tokio::spawn(start_web_server(
        db.clone(),
        Some(setup_tx),
        config_dir.clone(),
        WebServerMode::SetupUI,
    ));

    // Give the web server a moment to start
    info!("Waiting for web server to start...");
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Inform the user to visit the setup page
    info!("No previous configuration found. Please visit http://localhost:3000 to complete setup.");
    info!("If port 3000 is not available, the server may be running on a different port. Check the logs for details.");

    // Open the browser
    info!("Opening browser...");
    if let Err(e) = open::that("http://localhost:3000") {
        warn!("Failed to open browser: {}", e);
        info!("Please open http://localhost:3000 in your browser to complete setup.");
        info!("If port 3000 is not available, try ports 3001-3009.");
    }

    // Wait for setup to complete
    info!("Waiting for setup to complete...");
    match tokio::time::timeout(std::time::Duration::from_secs(300), setup_rx).await {
        Ok(result) => {
            match result {
                Ok(()) => {
                    info!("Setup completed successfully!");
                    // Abort the web server task since setup is complete
                    web_server_handle.abort();
                    Ok(())
                }
                Err(e) => {
                    error!("Setup channel error: {:?}", e);
                    // Check if configuration exists despite the channel error
                    match db.load_node_config(config_dir.clone()).await {
                        Ok(_) => {
                            info!("Configuration found despite channel error, continuing...");
                            web_server_handle.abort();
                            Ok(())
                        }
                        Err(_) => {
                            error!("No configuration found after setup attempt");
                            web_server_handle.abort();
                            Err(anyhow!(
                                "Setup failed: channel error and no configuration found"
                            ))
                        }
                    }
                }
            }
        }
        Err(_) => {
            error!("Setup timed out after 5 minutes");
            web_server_handle.abort();
            Err(anyhow!("Setup timed out after 5 minutes"))
        }
    }
}

async fn keygen(output: Option<String>) -> Result<()> {
    info!("Generating keypair...");

    // Generate a keypair
    let keypair = KeyManager::generate_keypair()?;

    // Convert the keypair to bytes
    let keypair_bytes = keypair.to_bytes();

    // Output the keypair
    match output {
        Some(path) => {
            // Write the keypair to a file
            info!("Writing keypair to file: {}", path);
            fs::write(path, keypair_bytes)?;
        }
        None => {
            // Print the keypair to stdout
            info!("Keypair: {:?}", keypair_bytes);
        }
    }

    Ok(())
}

async fn status(config_dir: PathBuf) -> Result<()> {
    // Initialize key manager to check for existing keys
    let key_manager = KeyManager::new(config_dir.to_str().unwrap_or_default())?;

    println!("Node Status:");
    println!("Config directory: {}", config_dir.display());

    // Check if the node has a key
    if let Some(node_key) = key_manager.get_key(KeyType::Node) {
        println!("Node public key: {:?}", node_key.public_key_bytes());
    } else {
        println!("No node key found");
    }

    // Check if the node database exists
    let db_path = config_dir.join("db/node.db");
    if db_path.exists() {
        println!("Database: Exists at {}", db_path.display());

        // Try to load the node config from the database
        let db = Arc::new(SqliteDatabase::new(db_path.to_str().unwrap()).await?);
        match db.load_node_config(config_dir.clone()).await {
            Ok(config) => {
                println!("Node name: {}", config.node_name);
                println!("Web UI port: {}", config.web_ui_port);
            }
            Err(_) => {
                println!("No node configuration found in database");
            }
        }
    } else {
        println!("Database: Not found");
    }

    Ok(())
}

// Removed the incomplete functions run_node, get, and put
