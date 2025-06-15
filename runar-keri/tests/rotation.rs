use anyhow::Result;
use tempfile::tempdir;
use runar_keri::RunarKeriCore;

// Import the necessary types from keriox
use keri::signer::{CryptoBox, KeyManager};
use keri::derivation::basic::Basic;
use keri::event_message::EventTypeTag;
use keri::event_message::event_msg_builder::EventMsgBuilder;
use keri::event_message::signed_event_message::SignedEventMessage;
use keri::prefix::AttachedSignaturePrefix;
use keri::derivation::self_signing::SelfSigning;
use keri::event::sections::threshold::SignatureThreshold;

#[tokio::test]
async fn test_key_rotation() -> Result<()> {
    // Create a temporary directory for the database
    let temp_dir = tempdir()?;
    let db_path = temp_dir.path().to_path_buf();
    
    // Create a new RunarKeriCore instance
    let keri_core = RunarKeriCore::new(db_path.to_str().unwrap()).await?;
    
    // STEP 1: Create a controlled CryptoBox for our test
    // We'll use this same CryptoBox throughout the test to ensure key continuity
    let mut cryptobox = CryptoBox::new()?;
    
    // STEP 2: Get the current and next public keys for inception
    let current_pk = cryptobox.public_key()?;
    let current_key_prefix = Basic::Ed25519.derive(current_pk);
    
    let next_pk = cryptobox.next_public_key()?;
    let next_key_prefix = Basic::Ed25519.derive(next_pk);
    
    // STEP 3: Build inception event
    let icp_event = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![current_key_prefix.clone()])
        .with_next_keys(vec![next_key_prefix.clone()])
        .with_threshold(&SignatureThreshold::default())
        .with_next_threshold(&SignatureThreshold::default())
        .build()?;
    
    // Get the identifier prefix from the event
    let prefix = icp_event.event.content.prefix.clone();
    
    // STEP 4: Serialize and sign the inception event
    let serialized_icp = icp_event.serialize()?;
    let icp_signature = cryptobox.sign(&serialized_icp)?;
    let icp_attached_sig = AttachedSignaturePrefix::new(
        SelfSigning::Ed25519Sha512,
        icp_signature,
        0
    );
    
    // Create a signed inception event message
    let signed_icp = SignedEventMessage::new(&icp_event, vec![icp_attached_sig], None);
    
    // STEP 5: Process the inception event
    keri_core.process_event(&signed_icp)?;
    
    // Get the initial state
    let initial_state = keri_core.compute_state(&prefix)?.unwrap();
    println!("Initial state after inception: {:?}", initial_state);
    
    // STEP 6: Prepare for rotation - rotate the cryptobox to use the next key
    // This is critical - we need to use the pre-committed next key for signing
    cryptobox.rotate()?;
    
    // STEP 7: Generate new next keys for future rotations
    let new_next_pk = cryptobox.next_public_key()?;
    let new_next_key_prefix = Basic::Ed25519.derive(new_next_pk);
    
    // STEP 8: Build rotation event
    let rot_event = EventMsgBuilder::new(EventTypeTag::Rot)
        .with_prefix(&prefix)
        .with_sn(initial_state.sn + 1)
        .with_previous_event(&initial_state.last_event_digest)
        // Use the next keys from inception as current keys for rotation
        .with_keys(vec![next_key_prefix])
        // Set new next keys for future rotations
        .with_next_keys(vec![new_next_key_prefix])
        .with_threshold(&SignatureThreshold::default())
        .with_next_threshold(&SignatureThreshold::default())
        .build()?;
    
    // STEP 9: Serialize and sign the rotation event
    let serialized_rot = rot_event.serialize()?;
    let rot_signature = cryptobox.sign(&serialized_rot)?;
    let rot_attached_sig = AttachedSignaturePrefix::new(
        SelfSigning::Ed25519Sha512,
        rot_signature,
        0
    );
    
    // Create a signed rotation event message
    let signed_rot = SignedEventMessage::new(&rot_event, vec![rot_attached_sig], None);
    
    // STEP 10: Process the rotation event
    keri_core.process_event(&signed_rot)?;
    
    // Get the updated state
    let updated_state = keri_core.compute_state(&prefix)?.unwrap();
    println!("Updated state after rotation: {:?}", updated_state);
    
    // Verify that the sequence number has increased
    assert_eq!(updated_state.sn, initial_state.sn + 1, "Sequence number should increment by 1");
    
    // Verify that the current key config has changed
    assert_ne!(
        updated_state.current.public_keys[0], 
        initial_state.current.public_keys[0], 
        "Current public key should change after rotation"
    );
    
    // Verify that the next key digest has been updated
    assert!(updated_state.current.threshold_key_digest.is_some(), "Next key digest should be present");
    
    Ok(())
}
