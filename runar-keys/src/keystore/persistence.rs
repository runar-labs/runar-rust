use crate::error::Result;
use crate::keystore::DeviceKeystore;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct PersistenceConfig {
    pub base_dir: PathBuf,
    pub auto_persist: bool,
}

impl PersistenceConfig {
    pub fn new(base_dir: PathBuf) -> Self {
        Self {
            base_dir,
            auto_persist: true,
        }
    }
}

pub enum Role<'a> {
    Mobile,
    Node { node_id: &'a str },
}

fn file_name_for(role: &Role) -> &'static str {
    match role {
        Role::Mobile => "mobile_state.bin",
        Role::Node { .. } => "node_state.bin",
    }
}

pub fn build_aad(role: &Role) -> Vec<u8> {
    match role {
        Role::Mobile => b"runar:keys_state:v1|role=mobile".to_vec(),
        Role::Node { node_id } => {
            format!("runar:keys_state:v1|role=node|node_id={node_id}").into_bytes()
        }
    }
}

pub fn save_state(
    keystore: &Arc<dyn DeviceKeystore>,
    cfg: &PersistenceConfig,
    role: &Role,
    state_bytes: &[u8],
) -> Result<()> {
    let aad = build_aad(role);
    let ciphertext = keystore.encrypt(state_bytes, &aad)?;
    let file_name = file_name_for(role);
    let tmp_name = format!("{file_name}.tmp");
    let path = cfg.base_dir.join(file_name);
    let tmp_path = cfg.base_dir.join(tmp_name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    {
        let mut f = fs::File::create(&tmp_path)?;
        f.write_all(&ciphertext)?;
        f.flush()?;
        f.sync_all()?;
    }
    fs::rename(tmp_path, path)?;
    Ok(())
}

pub fn load_state(
    keystore: &Arc<dyn DeviceKeystore>,
    cfg: &PersistenceConfig,
    role: &Role,
) -> Result<Option<Vec<u8>>> {
    let path = cfg.base_dir.join(file_name_for(role));
    if !path.exists() {
        return Ok(None);
    }
    let ciphertext = fs::read(&path)?;
    let aad = build_aad(role);
    let plain = keystore.decrypt(&ciphertext, &aad)?;
    Ok(Some(plain))
}

pub fn wipe(cfg: &PersistenceConfig, role: &Role) -> Result<()> {
    let path = cfg.base_dir.join(file_name_for(role));
    if path.exists() {
        fs::remove_file(&path)?;
    }
    Ok(())
}
