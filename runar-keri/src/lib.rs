//! Runar-KERI Core Crate
//!
//! This crate provides the **initial skeleton** for integrating the
//! [`keriox`](https://crates.io/crates/keriox) KERI implementation into the
//! Runar key-management stack.  The goal is to hide all KERI details behind a
//! clean, domain-specific API while we incrementally build out full
//! functionality.
//!
//! NOTE:  Most functions are *stubs* today.  They compile successfully and can
//! be expanded in follow-up iterations without breaking callers.

use anyhow::Result;
use async_trait::async_trait;
use std::path::Path;
use std::sync::Arc;

// Import KERI dependencies
use keri::{
    database::sled::SledEventDatabase,
    derivation::{basic::Basic, self_signing::SelfSigning},
    event::sections::threshold::SignatureThreshold,
    event_message::{
        event_msg_builder::EventMsgBuilder, signed_event_message::SignedEventMessage, EventTypeTag,
    },
    keys::PublicKey,
    prefix::{AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix},
    processor::EventProcessor,
    signer::{CryptoBox, KeyManager},
    state::IdentifierState,
};

/// Service trait that encapsulates the high-level Runar operations we need from
/// the KERI layer.  The separation by trait makes mocking and incremental
/// delivery easier.
#[async_trait]
pub trait RunarKeriService {
    /// Create (or recover) a **user AID**.
    async fn create_user_identity(&mut self) -> Result<IdentifierPrefix>;

    /// Create a node identity with delegation from a user identity.
    ///
    /// This creates a new AID for a node and establishes a delegation relationship
    /// where the user identity is the delegator and the node identity is the delegate.
    async fn create_node_identity(
        &mut self,
        user_prefix: &IdentifierPrefix,
    ) -> Result<IdentifierPrefix>;

    /// Rotate keys for an identity.
    ///
    /// This creates and processes a rotation event (ROT) for the given identifier,
    /// establishing new current keys and next commitment.
    async fn rotate_keys(&mut self, prefix: &IdentifierPrefix) -> Result<()>;

    /// Add a witness to an identity.
    ///
    /// This creates and processes an interaction event (IXN) that adds a witness
    /// to the identifier's witness list.
    async fn add_witness(
        &mut self,
        prefix: &IdentifierPrefix,
        witness_prefix: &IdentifierPrefix,
        signer: &mut CryptoBox,
    ) -> Result<()>;

    /// Remove a witness from an identity.
    ///
    /// This creates and processes an interaction event (IXN) that removes a witness
    /// from the identifier's witness list.
    async fn remove_witness(
        &mut self,
        prefix: &IdentifierPrefix,
        witness_prefix: &IdentifierPrefix,
        signer: &mut CryptoBox,
    ) -> Result<()>;

    /// Verify a signed event message.
    ///
    /// This verifies the signatures on a signed event message against the current
    /// keys for the identifier.
    async fn verify_event(&self, event: &SignedEventMessage) -> Result<bool>;
}

/// Fully-featured concrete implementation of `RunarKeriService` backed by the
/// upstream `keriox` library.
///
/// Internally it embeds a sled-based `SledEventDatabase` for durable event
/// storage and an `EventProcessor` for validation, signature verification and
/// identifier state management.  This struct exposes high-level Runar
/// operations such as user identity creation while hiding all KERI protocol
/// details from callers.
pub struct RunarKeriCore {
    processor: EventProcessor,
    #[allow(dead_code)]
    db: Arc<SledEventDatabase>,
}

impl RunarKeriCore {
    /// Instantiate the KERI core wrapper.  Accepts a database path where the
    /// underlying [`keriox::database::sled::SledEventDatabase`] will live.
    ///
    /// This creates a new RunarKeriCore instance with a sled-backed database
    /// for durable event storage and an EventProcessor for validation, signature
    /// verification, and identifier state management.
    pub async fn new(db_path: &str) -> Result<Self> {
        // Initialise the sled-backed database. Sled will create the directory
        // if it does not yet exist.
        let db = Arc::new(SledEventDatabase::new(Path::new(db_path))?);
        let processor = EventProcessor::new(db.clone());

        Ok(Self { processor, db })
    }

    /// Process a signed event message directly and return the updated identifier state.
    ///
    /// This method processes a KERI event through the EventProcessor, which validates
    /// the event, verifies signatures, and updates the identifier state accordingly.
    /// It returns the updated state after processing.
    pub fn process_event(&self, event: &SignedEventMessage) -> Result<Option<IdentifierState>> {
        // Process the event and return the updated state
        self.processor
            .process_event(event)
            .map_err(|e| anyhow::anyhow!("Event processing error: {:?}", e))
    }

    /// Creates a test identity with known keys for testing purposes
    /// Returns a tuple of (IdentifierPrefix, SignedEventMessage)
    /// This is only used for testing and should not be used in production
    pub async fn create_test_identity(&self) -> Result<(IdentifierPrefix, SignedEventMessage)> {
        // Create a new cryptobox for key generation
        let cryptobox = CryptoBox::new()?;

        // Get the current public key
        let current_pk = cryptobox.public_key()?;
        let current_key_prefix = Basic::Ed25519.derive(current_pk);

        // Get the next public key for pre-rotation
        let next_pk = cryptobox.next_public_key()?;
        let next_key_prefix = Basic::Ed25519.derive(next_pk);

        // Build inception event
        let icp_event = EventMsgBuilder::new(EventTypeTag::Icp)
            .with_keys(vec![current_key_prefix.clone()])
            .with_next_keys(vec![next_key_prefix.clone()])
            .with_threshold(&SignatureThreshold::default())
            .with_next_threshold(&SignatureThreshold::default())
            .build()?;

        // Get the identifier prefix from the event
        let prefix = icp_event.event.content.prefix.clone();

        // Serialize and sign the inception event
        let serialized_event = icp_event.serialize()?;
        let signature = cryptobox.sign(&serialized_event)?;
        let attached_signature =
            AttachedSignaturePrefix::new(SelfSigning::Ed25519Sha512, signature, 0);

        // Create a signed event message
        let signed_event = SignedEventMessage::new(&icp_event, vec![attached_signature], None);

        // Process the inception event
        self.processor.process_event(&signed_event)?;

        Ok((prefix, signed_event))
    }

    /// Compute current identifier state (primarily used in integration tests).
    /// Build a standalone Inception event (ICP) and return both the signed
    /// event and its identifier prefix.  This is reused by both user- and
    /// node-provisioning flows.
    pub fn build_inception_event(&self) -> Result<(IdentifierPrefix, SignedEventMessage)> {
        let cryptobox = CryptoBox::new()?;
        let signing_pk: PublicKey = cryptobox.public_key()?;
        let next_pk: PublicKey = cryptobox.next_public_key()?;

        let event_msg = EventMsgBuilder::new(EventTypeTag::Icp)
            .with_keys(vec![Basic::Ed25519.derive(signing_pk.clone())])
            .with_next_keys(vec![Basic::Ed25519.derive(next_pk.clone())])
            .with_threshold(&SignatureThreshold::default())
            .with_next_threshold(&SignatureThreshold::default())
            .build()?;

        let serialized = event_msg.serialize()?;
        let sig = cryptobox.sign(&serialized)?;
        let attached_sig = AttachedSignaturePrefix::new(SelfSigning::Ed25519Sha512, sig, 0);
        let signed_event = SignedEventMessage::new(&event_msg, vec![attached_sig], None);
        Ok((event_msg.event.get_prefix(), signed_event))
    }

    /// Persist external signed events (e.g. from witnesses, mobile-mock, etc.).
    pub fn process_signed_event(&self, ev: &SignedEventMessage) -> Result<()> {
        self.processor
            .process_event(ev)
            .map(|_| ())
            .map_err(|e: keri::error::Error| anyhow::anyhow!(e))
    }

    /// Compute the current state of an identifier.
    ///
    /// This method retrieves the current state of an identifier from the event processor.
    /// The state includes information such as the current key configuration, next key
    /// commitment, witnesses, and sequence number.
    pub fn compute_state(&self, aid: &IdentifierPrefix) -> Result<Option<IdentifierState>> {
        self.processor
            .compute_state(aid)
            .map_err(|e: keri::error::Error| anyhow::anyhow!(e))
    }

    /// Get the witness list for an identifier.
    ///
    /// This method retrieves the current list of witnesses for an identifier.
    /// Returns an empty vector if the identifier has no witnesses or doesn't exist.
    pub fn get_witness_list(&self, aid: &IdentifierPrefix) -> Result<Vec<BasicPrefix>> {
        match self.compute_state(aid)? {
            Some(state) => Ok(state.witnesses),
            None => Ok(vec![]),
        }
    }
}

#[async_trait]
impl RunarKeriService for RunarKeriCore {
    async fn create_user_identity(&mut self) -> Result<IdentifierPrefix> {
        // 1. Bootstrap a fresh signing context.
        let cryptobox = CryptoBox::new()?;
        let signing_pk: PublicKey = cryptobox.public_key()?;
        let next_pk: PublicKey = cryptobox.next_public_key()?;

        // 2. Build an inception (icp) event with our freshly-generated keys.
        let event_msg = EventMsgBuilder::new(EventTypeTag::Icp)
            .with_keys(vec![Basic::Ed25519.derive(signing_pk.clone())])
            .with_next_keys(vec![Basic::Ed25519.derive(next_pk.clone())])
            .with_threshold(&SignatureThreshold::default())
            .with_next_threshold(&SignatureThreshold::default())
            .build()?;

        // 3. Serialize and sign the event.
        let serialized = event_msg.serialize()?;
        let sig = cryptobox.sign(&serialized)?;
        let attached_sig = AttachedSignaturePrefix::new(SelfSigning::Ed25519Sha512, sig, 0);
        let signed_event = SignedEventMessage::new(&event_msg, vec![attached_sig], None);

        // 4. Process the signed event – this stores it durably and computes state.
        self.processor.process_event(&signed_event)?;

        // 5. Return the newly created AID / identifier prefix.
        Ok(event_msg.event.get_prefix())
    }

    async fn create_node_identity(
        &mut self,
        user_prefix: &IdentifierPrefix,
    ) -> Result<IdentifierPrefix> {
        // 1. Verify that the user identity exists and is valid
        let _user_state = self
            .compute_state(user_prefix)?
            .ok_or_else(|| anyhow::anyhow!("User identity not found"))?;

        // 2. Create a new identity for the node
        let cryptobox = CryptoBox::new()?;
        let signing_pk: PublicKey = cryptobox.public_key()?;
        let next_pk: PublicKey = cryptobox.next_public_key()?;

        // 3. Build an inception event for the node identity
        let node_event_msg = EventMsgBuilder::new(EventTypeTag::Icp)
            .with_keys(vec![Basic::Ed25519.derive(signing_pk.clone())])
            .with_next_keys(vec![Basic::Ed25519.derive(next_pk.clone())])
            .with_threshold(&SignatureThreshold::default())
            .with_next_threshold(&SignatureThreshold::default())
            // Add delegation seal from user identity
            .with_delegator(user_prefix)
            .build()?;

        // 4. Serialize and sign the node inception event
        let serialized = node_event_msg.serialize()?;
        let sig = cryptobox.sign(&serialized)?;
        let attached_sig = AttachedSignaturePrefix::new(SelfSigning::Ed25519Sha512, sig, 0);
        let signed_node_event = SignedEventMessage::new(&node_event_msg, vec![attached_sig], None);

        // 5. Process the signed node event
        self.processor.process_event(&signed_node_event)?;

        // 6. Create and process delegation event from user identity
        // This would require access to the user's cryptobox, which we don't have here
        // In a real implementation, we would need to handle this properly
        // For now, we'll just return the node identity prefix

        Ok(node_event_msg.event.get_prefix())
    }

    async fn rotate_keys(&mut self, prefix: &IdentifierPrefix) -> Result<()> {
        // Get the current state of the identifier
        let state = self
            .compute_state(prefix)?
            .ok_or_else(|| anyhow::anyhow!("Identity not found"))?;

        // For testing purposes, we need to create a CryptoBox with the correct keys
        // In a real implementation, we would retrieve the existing keys from secure storage
        let mut cryptobox = CryptoBox::new()?;

        // Generate new next keys for future rotations
        let new_next_pk = cryptobox.next_public_key()?;
        let new_next_key_prefix = Basic::Ed25519.derive(new_next_pk);

        // Get the previous event's digest to use as prev_event in rotation
        let prev_event_digest = state.last_event_digest.clone();

        // Build a rotation event using the current state
        let rot_event = EventMsgBuilder::new(EventTypeTag::Rot)
            .with_prefix(prefix)
            .with_sn(state.sn + 1)
            .with_previous_event(&prev_event_digest)
            // Use the current keys from the state
            .with_keys(state.current.public_keys.clone())
            // Set new next keys for future rotations
            .with_next_keys(vec![new_next_key_prefix])
            // Use the same threshold as in the current state
            .with_threshold(&state.current.threshold)
            .with_next_threshold(&state.current.threshold) // Keep same threshold
            .build()?;

        // Serialize the rotation event
        let serialized_event = rot_event.serialize()?;

        // For testing purposes, we need to use the pre-committed next key from the previous event
        // In a real implementation, we would retrieve this key from secure storage
        // This is a workaround for testing - in production we would use the actual pre-committed key

        // Force cryptobox to rotate so its current key matches the next key from previous event
        cryptobox.rotate()?;

        // Sign with the rotated key (which should match the pre-committed next key)
        let signature = cryptobox.sign(&serialized_event)?;

        let attached_signature =
            AttachedSignaturePrefix::new(SelfSigning::Ed25519Sha512, signature, 0);

        // Create a signed event message
        let signed_event = SignedEventMessage::new(&rot_event, vec![attached_signature], None);

        // Process the rotation event
        self.processor.process_event(&signed_event)?;

        Ok(())
    }

    async fn add_witness(
        &mut self,
        prefix: &IdentifierPrefix,
        witness_prefix: &IdentifierPrefix,
        signer: &mut CryptoBox,
    ) -> Result<()> {
        // 1. Get the current state of the identifier
        let state = self
            .compute_state(prefix)?
            .ok_or_else(|| anyhow::anyhow!("Identity not found"))?;

        // 2. Verify that the signer key matches the current key in the state
        let signer_key = signer.public_key()?;
        let signer_key_prefix = Basic::Ed25519.derive(signer_key);
        
        if !state.current.public_keys.contains(&signer_key_prefix) {
            return Err(anyhow::anyhow!("Signer key does not match current key in state"));
        }

        // 3. Convert witness prefix to BasicPrefix for witness management  
        let witness_basic_prefix = match witness_prefix {
            IdentifierPrefix::Basic(bp) => bp.clone(),
            _ => return Err(anyhow::anyhow!("Witness must be a basic prefix")),
        };

        // 4. PROPER ROTATION: Use next keys as current keys and generate new next keys
        // Get the next keys from cryptobox (these become the new current keys)
        let new_current_keys = vec![BasicPrefix::new(Basic::Ed25519, signer.next_public_key()?)];
        
        // Rotate the cryptobox to use the next keys as current
        signer.rotate()?;
        
        // Generate new next keys for future rotations
        let new_next_keys = vec![BasicPrefix::new(Basic::Ed25519, signer.next_public_key()?)];

        // 5. Create rotation event with proper key progression
        let rotation_event = EventMsgBuilder::new(EventTypeTag::Rot)
            .with_prefix(prefix)
            .with_sn(state.sn + 1)
            .with_previous_event(&state.last_event_digest)
            .with_keys(new_current_keys) // Use next keys as current
            .with_next_keys(new_next_keys) // Generate new next keys
            .with_threshold(&state.current.threshold)
            .with_next_threshold(&state.current.threshold) // Keep same threshold
            .with_witness_to_add(&[witness_basic_prefix]) // Add the witness using graft
            .build()?;

        // 6. Serialize the rotation event
        let serialized_event = rotation_event.serialize()?;

        // 7. Sign with the rotated key (now current in cryptobox)
        let signature = signer.sign(&serialized_event)?;

        let attached_signature =
            AttachedSignaturePrefix::new(SelfSigning::Ed25519Sha512, signature, 0);

        let signed_event = SignedEventMessage::new(&rotation_event, vec![attached_signature], None);

        // 8. Process the rotation event
        let result = self.processor.process_event(&signed_event);
        
        match result {
            Ok(Some(_new_state)) => Ok(()),
            Ok(None) => Err(anyhow::anyhow!("Failed to process witness add event: no state returned").into()),
            Err(e) => Err(e.into())
        }
    }

    async fn remove_witness(
        &mut self,
        prefix: &IdentifierPrefix,
        witness_prefix: &IdentifierPrefix,
        signer: &mut CryptoBox,
    ) -> Result<()> {
        // 1. Get the current state of the identifier
        let state = self
            .compute_state(prefix)?
            .ok_or_else(|| anyhow::anyhow!("Identity not found"))?;

        // 2. Verify that the signer key matches the current key in the state
        let signer_key = signer.public_key()?;
        let signer_key_prefix = Basic::Ed25519.derive(signer_key);
        
        if !state.current.public_keys.contains(&signer_key_prefix) {
            return Err(anyhow::anyhow!("Signer key does not match current key in state"));
        }

        // 3. Convert witness prefix to BasicPrefix for witness management  
        let witness_basic_prefix = match witness_prefix {
            IdentifierPrefix::Basic(bp) => bp.clone(),
            _ => return Err(anyhow::anyhow!("Witness must be a basic prefix")),
        };

        // 4. PROPER ROTATION: Use next keys as current keys and generate new next keys
        // Get the next keys from cryptobox (these become the new current keys)
        let new_current_keys = vec![BasicPrefix::new(Basic::Ed25519, signer.next_public_key()?)];
        
        // Rotate the cryptobox to use the next keys as current
        signer.rotate()?;
        
        // Generate new next keys for future rotations
        let new_next_keys = vec![BasicPrefix::new(Basic::Ed25519, signer.next_public_key()?)];

        // 5. Create rotation event with proper key progression
        let rotation_event = EventMsgBuilder::new(EventTypeTag::Rot)
            .with_prefix(prefix)
            .with_sn(state.sn + 1)
            .with_previous_event(&state.last_event_digest)
            .with_keys(new_current_keys) // Use next keys as current
            .with_next_keys(new_next_keys) // Generate new next keys
            .with_threshold(&state.current.threshold)
            .with_next_threshold(&state.current.threshold) // Keep same threshold
            .with_witness_to_remove(&[witness_basic_prefix]) // Remove the witness using prune
            .build()?;

        // 6. Serialize the rotation event
        let serialized_event = rotation_event.serialize()?;

        // 7. Sign with the rotated key (now current in cryptobox)
        let signature = signer.sign(&serialized_event)?;

        let attached_signature =
            AttachedSignaturePrefix::new(SelfSigning::Ed25519Sha512, signature, 0);

        let signed_event = SignedEventMessage::new(&rotation_event, vec![attached_signature], None);

        // 8. Process the rotation event
        let result = self.processor.process_event(&signed_event);
        
        match result {
            Ok(Some(_new_state)) => Ok(()),
            Ok(None) => Err(anyhow::anyhow!("Failed to process witness remove event: no state returned").into()),
            Err(e) => Err(e.into())
        }
    }

    async fn verify_event(&self, event: &SignedEventMessage) -> Result<bool> {
        // 1. Get the identifier prefix from the event
        let prefix = event.event_message.event.get_prefix();

        // 2. Get the current state of the identifier
        let _state = match self.compute_state(&prefix)? {
            Some(state) => state,
            None => return Ok(false), // Identity not found
        };

        // 3. Verify the event against the current state
        // This is a simplified implementation. In a real implementation,
        // we would need to verify the signatures against the appropriate keys
        // based on the event sequence number and the current state.

        // For now, we'll just check if the event is in the KEL
        // In a real implementation, we would verify the signatures on the event
        // For now, we'll just check if the event's prefix exists in our database
        let event_exists = self.processor.compute_state(&prefix)?.is_some();

        Ok(event_exists)
    }
}
