use anyhow::Result;
use tempfile::tempdir;
use runar_keri::{RunarKeriCore, RunarKeriService};
use keri::prefix::Prefix;

#[tokio::test]
async fn test_witness_management() -> Result<()> {
    // Create a temporary directory for the database
    let temp_dir = tempdir()?;
    let db_path = temp_dir.path().to_path_buf();
    
    // Create a new RunarKeriCore instance
    let mut keri_core = RunarKeriCore::new(db_path.to_str().unwrap()).await?;
    
    // Create a user identity
    let user_prefix = keri_core.create_user_identity().await?;
    assert!(!user_prefix.to_str().is_empty());
    
    println!("Created user identity: {}", user_prefix.to_str());
    
    // Create a witness identity
    let witness_prefix = keri_core.create_user_identity().await?;
    assert!(!witness_prefix.to_str().is_empty());
    
    println!("Created witness identity: {}", witness_prefix.to_str());
    
    // Get the initial state
    let initial_state = keri_core.compute_state(&user_prefix)?.unwrap();
    println!("Initial state: {:?}", initial_state);
    
    // Add the witness
    keri_core.add_witness(&user_prefix, &witness_prefix).await?;
    
    // Get the updated state after adding witness
    let updated_state = keri_core.compute_state(&user_prefix)?.unwrap();
    println!("State after adding witness: {:?}", updated_state);
    
    // Verify that the sequence number has increased
    assert!(updated_state.sn > initial_state.sn);
    
    // Verify that the event type has changed to interaction
    assert_eq!(format!("{:?}", updated_state.last_event_type.unwrap()), "Ixn");
    
    // Remove the witness
    keri_core.remove_witness(&user_prefix, &witness_prefix).await?;
    
    // Get the final state after removing witness
    let final_state = keri_core.compute_state(&user_prefix)?.unwrap();
    println!("State after removing witness: {:?}", final_state);
    
    // Verify that the sequence number has increased again
    assert!(final_state.sn > updated_state.sn);
    
    // Verify that the event type is still interaction
    assert_eq!(format!("{:?}", final_state.last_event_type.unwrap()), "Ixn");
    
    Ok(())
}
