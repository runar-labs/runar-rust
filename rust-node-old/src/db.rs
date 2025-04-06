use crate::config::NodeConfig;
use anyhow::Result;
use async_trait::async_trait;
use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

#[async_trait]
pub trait Database {
    async fn load_node_config(&self, config_dir: PathBuf) -> Result<NodeConfig>;
    async fn save_node_config(&self, config: &NodeConfig) -> Result<()>;
}

pub struct SqliteDatabase {
    connection: Arc<Mutex<Connection>>,
}

impl SqliteDatabase {
    pub async fn new(db_path: &str) -> Result<Self> {
        let conn = Connection::open(db_path)?;

        // Create tables if they don't exist
        conn.execute(
            "CREATE TABLE IF NOT EXISTS node_config (
                id INTEGER PRIMARY KEY,
                node_name TEXT NOT NULL,
                private_key BLOB NOT NULL,
                web_ui_port INTEGER NOT NULL
            )",
            [],
        )?;

        Ok(Self {
            connection: Arc::new(Mutex::new(conn)),
        })
    }

    /// Get a connection to the database
    pub async fn get_connection(&self) -> Result<tokio::sync::MutexGuard<'_, Connection>> {
        Ok(self.connection.lock().await)
    }

    pub async fn init_db(db_path: &Path) -> Result<()> {
        let conn = Connection::open(db_path)?;

        // Create tables if they don't exist
        conn.execute(
            "CREATE TABLE IF NOT EXISTS node_config (
                id INTEGER PRIMARY KEY,
                node_name TEXT NOT NULL,
                private_key BLOB NOT NULL,
                web_ui_port INTEGER NOT NULL
            )",
            [],
        )?;

        Ok(())
    }
}

#[async_trait]
impl Database for SqliteDatabase {
    async fn load_node_config(&self, config_dir: PathBuf) -> Result<NodeConfig> {
        let conn = self.connection.lock().await;

        let mut stmt =
            conn.prepare("SELECT node_name, private_key, web_ui_port FROM node_config LIMIT 1")?;
        let mut rows = stmt.query([])?;

        if let Some(row) = rows.next()? {
            let node_name: String = row.get(0)?;
            let private_key: Vec<u8> = row.get(1)?;
            let web_ui_port: u16 = row.get(2)?;

            let config = NodeConfig::new(node_name, private_key, config_dir, web_ui_port)?;
            Ok(config)
        } else {
            Err(anyhow::anyhow!("No node configuration found in database"))
        }
    }

    async fn save_node_config(&self, config: &NodeConfig) -> Result<()> {
        let conn = self.connection.lock().await;

        conn.execute("DELETE FROM node_config", [])?;

        conn.execute(
            "INSERT INTO node_config (node_name, private_key, web_ui_port) VALUES (?, ?, ?)",
            params![
                config.node_name,
                config.private_key_bytes(),
                config.web_ui_port
            ],
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_management::KeyManager;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_sqlite_database_init() {
        // Create a temporary directory for testing
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test_init.db");

        // Initialize the database
        let result = SqliteDatabase::init_db(&db_path).await;
        assert!(result.is_ok(), "Database initialization failed");

        // Check that the file was created
        assert!(db_path.exists(), "Database file was not created");
    }

    #[tokio::test]
    async fn test_node_config_save_and_load() {
        // Create a temporary directory for testing
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test_config.db");
        let config_dir = temp_dir.path().to_path_buf();

        // Create a new database
        let db = SqliteDatabase::new(db_path.to_str().unwrap())
            .await
            .unwrap();

        // Generate a keypair for testing
        let keypair = KeyManager::generate_keypair().unwrap();
        let keypair_bytes = keypair.to_bytes().to_vec();

        // Create a node config
        let node_name = "test-node";
        let web_ui_port = 3000;
        let config = NodeConfig::new(
            node_name.to_string(),
            keypair_bytes.clone(),
            config_dir.clone(),
            web_ui_port,
        )
        .unwrap();

        // Save the config to the database
        let save_result = db.save_node_config(&config).await;
        assert!(save_result.is_ok(), "Failed to save node config");

        // Load the config from the database
        let loaded_config = db.load_node_config(config_dir).await;
        assert!(loaded_config.is_ok(), "Failed to load node config");

        let loaded_config = loaded_config.unwrap();

        // Verify the loaded config matches the original
        assert_eq!(
            loaded_config.node_name, node_name,
            "Node name doesn't match"
        );
        assert_eq!(
            loaded_config.web_ui_port, web_ui_port,
            "Web UI port doesn't match"
        );
        assert_eq!(
            loaded_config.private_key_bytes(),
            keypair_bytes,
            "Private key doesn't match"
        );
    }

    #[tokio::test]
    async fn test_node_config_update() {
        // Create a temporary directory for testing
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test_update.db");
        let config_dir = temp_dir.path().to_path_buf();

        // Create a new database
        let db = SqliteDatabase::new(db_path.to_str().unwrap())
            .await
            .unwrap();

        // Generate a keypair for testing
        let keypair = KeyManager::generate_keypair().unwrap();
        let keypair_bytes = keypair.to_bytes().to_vec();

        // Create initial node config
        let initial_node_name = "initial-node";
        let initial_web_ui_port = 3000;
        let initial_config = NodeConfig::new(
            initial_node_name.to_string(),
            keypair_bytes.clone(),
            config_dir.clone(),
            initial_web_ui_port,
        )
        .unwrap();

        // Save the initial config
        db.save_node_config(&initial_config).await.unwrap();

        // Create updated node config
        let updated_node_name = "updated-node";
        let updated_web_ui_port = 4000;
        let updated_config = NodeConfig::new(
            updated_node_name.to_string(),
            keypair_bytes.clone(),
            config_dir.clone(),
            updated_web_ui_port,
        )
        .unwrap();

        // Save the updated config
        db.save_node_config(&updated_config).await.unwrap();

        // Load the config
        let loaded_config = db.load_node_config(config_dir).await.unwrap();

        // Verify the loaded config matches the updated config
        assert_eq!(
            loaded_config.node_name, updated_node_name,
            "Updated node name doesn't match"
        );
        assert_eq!(
            loaded_config.web_ui_port, updated_web_ui_port,
            "Updated web UI port doesn't match"
        );
    }
}
