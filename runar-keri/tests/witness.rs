use anyhow::Result;
use runar_keri::{RunarKeriCore, RunarKeriService};
use tempfile::tempdir;

// Import the necessary types from keriox
use keri::derivation::basic::Basic;
use keri::derivation::self_signing::SelfSigning;
use keri::event::sections::threshold::SignatureThreshold;
use keri::event_message::event_msg_builder::EventMsgBuilder;
use keri::event_message::signed_event_message::SignedEventMessage;
use keri::event_message::EventTypeTag;
use keri::prefix::{AttachedSignaturePrefix, Prefix};
use keri::signer::{CryptoBox, KeyManager};

#[tokio::test]
async fn test_witness_management() -> Result<()> {
    // Create a temporary directory for the database
    let temp_dir = tempdir()?;
    let db_path = temp_dir.path().to_path_buf();

    // Create a new RunarKeriCore instance
    let mut keri_core = RunarKeriCore::new(db_path.to_str().unwrap()).await?;

    // STEP 1: Create controlled CryptoBox instances for user and witness
    // We need to keep track of the user's cryptobox for signing events
    let mut user_cryptobox = CryptoBox::new()?;
    let witness_cryptobox = CryptoBox::new()?;

    // STEP 2: Create user identity with controlled keys
    let user_current_pk = user_cryptobox.public_key()?;
    let user_current_key_prefix = Basic::Ed25519.derive(user_current_pk);

    let user_next_pk = user_cryptobox.next_public_key()?;
    let user_next_key_prefix = Basic::Ed25519.derive(user_next_pk);

    // Build user inception event
    let user_icp_event = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![user_current_key_prefix.clone()])
        .with_next_keys(vec![user_next_key_prefix.clone()])
        .with_threshold(&SignatureThreshold::default())
        .with_next_threshold(&SignatureThreshold::default())
        .build()?;

    // Get the user identifier prefix
    let user_prefix = user_icp_event.event.content.prefix.clone();

    // Sign and process the user inception event
    let user_serialized_icp = user_icp_event.serialize()?;
    let user_icp_signature = user_cryptobox.sign(&user_serialized_icp)?;
    let user_icp_attached_sig =
        AttachedSignaturePrefix::new(SelfSigning::Ed25519Sha512, user_icp_signature, 0);

    let user_signed_icp =
        SignedEventMessage::new(&user_icp_event, vec![user_icp_attached_sig], None);
    keri_core.process_event(&user_signed_icp)?;

    println!("Created user identity: {}", user_prefix.to_str());

    // STEP 3: Create witness identity with controlled keys
    let witness_current_pk = witness_cryptobox.public_key()?;
    let witness_current_key_prefix = Basic::Ed25519.derive(witness_current_pk);

    let witness_next_pk = witness_cryptobox.next_public_key()?;
    let witness_next_key_prefix = Basic::Ed25519.derive(witness_next_pk);

    // Build witness inception event
    let witness_icp_event = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![witness_current_key_prefix.clone()])
        .with_next_keys(vec![witness_next_key_prefix.clone()])
        .with_threshold(&SignatureThreshold::default())
        .with_next_threshold(&SignatureThreshold::default())
        .build()?;

    // Get the witness identifier prefix
    let witness_prefix = witness_icp_event.event.content.prefix.clone();

    // Sign and process the witness inception event
    let witness_serialized_icp = witness_icp_event.serialize()?;
    let witness_icp_signature = witness_cryptobox.sign(&witness_serialized_icp)?;
    let witness_icp_attached_sig =
        AttachedSignaturePrefix::new(SelfSigning::Ed25519Sha512, witness_icp_signature, 0);

    let witness_signed_icp =
        SignedEventMessage::new(&witness_icp_event, vec![witness_icp_attached_sig], None);
    keri_core.process_event(&witness_signed_icp)?;

    println!("Created witness identity: {}", witness_prefix.to_str());

    // STEP 4: Get the initial state of the user identity
    let initial_state = keri_core.compute_state(&user_prefix)?.unwrap();
    println!("Initial state: {:?}", initial_state);
    
    // Log the current key state for debugging
    println!("User cryptobox current key: {:?}", user_cryptobox.public_key()?);
    println!("User state current key: {:?}", initial_state.current.public_keys[0]);
    println!("User cryptobox next key: {:?}", user_cryptobox.next_public_key()?);
    println!("User state threshold_key_digest: {:?}", initial_state.current.threshold_key_digest);

    // STEP 5: Use RunarKeriCore's add_witness method to add the witness
    // This handles all the complexity of creating and processing the correct event type
    // Pass the user_cryptobox as signer to ensure proper signature verification
    keri_core.add_witness(&user_prefix, &witness_prefix, &mut user_cryptobox).await?;

    // STEP 6: Get the updated state after adding witness
    let updated_state = keri_core.compute_state(&user_prefix)?.unwrap();
    println!("State after adding witness: {:?}", updated_state);

    // Verify that the sequence number has increased
    assert_eq!(
        updated_state.sn,
        initial_state.sn + 1,
        "Sequence number should increase by 1"
    );

    // Print the witness list for debugging
    println!("Witnesses after adding: {:?}", updated_state.witnesses);
    
    // Verify that the witness was added to the witness list
    assert!(
        updated_state.witnesses.contains(&witness_current_key_prefix),
        "Witness should be in the witness list after adding"
    );
    
    // Check if the last event digest has changed
    assert_ne!(
        updated_state.last_event_digest, initial_state.last_event_digest,
        "Event digest should change after processing"
    );
    
    // Verify witness list using the get_witness_list helper method
    let witness_list = keri_core.get_witness_list(&user_prefix)?;
    assert!(
        witness_list.contains(&witness_current_key_prefix),
        "get_witness_list should return the added witness"
    );

    // STEP 7: Use RunarKeriCore's remove_witness method to remove the witness
    // Note that we don't need to rotate the cryptobox again here since we already rotated it
    // before adding the witness, and we're using the same keys for current and next keys
    // in our rotation events for witness management
    keri_core.remove_witness(&user_prefix, &witness_prefix, &mut user_cryptobox).await?;

    // STEP 8: Get the final state after removing witness
    let final_state = keri_core.compute_state(&user_prefix)?.unwrap();
    println!("State after removing witness: {:?}", final_state);

    // Verify that the sequence number has increased again
    assert_eq!(
        final_state.sn,
        updated_state.sn + 1,
        "Sequence number should increase by 1"
    );

    // Print the witness list for debugging
    println!("Witnesses after removal: {:?}", final_state.witnesses);
    
    // Verify that the witness was removed from the witness list
    assert!(
        !final_state.witnesses.contains(&witness_current_key_prefix),
        "Witness should not be in the witness list after removal"
    );
    
    // Check if the last event digest has changed
    assert_ne!(
        final_state.last_event_digest, updated_state.last_event_digest,
        "Event digest should change after processing"
    );
    
    // Verify witness list using the get_witness_list helper method
    let final_witness_list = keri_core.get_witness_list(&user_prefix)?;
    assert!(
        !final_witness_list.contains(&witness_current_key_prefix),
        "get_witness_list should not contain the removed witness"
    );
    
    // Verify that the witness list is empty after removal
    assert!(
        final_witness_list.is_empty(),
        "Witness list should be empty after removing the only witness"
    );

    Ok(())
}
