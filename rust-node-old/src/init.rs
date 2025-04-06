//! Initialization module for distributed slices
//!
//! This module defines the INITIALIZERS distributed slice used by the macros to
//! initialize services.

use anyhow::Result;
use std::future::Future;
use std::pin::Pin;
use std::sync::RwLock;
use once_cell::sync::Lazy;
use log;

use crate::services::distributed_registry::{
    ActionHandler, ProcessHandler, EventSubscription, PublicationInfo,
};

/// Type alias for an initialization function
pub type InitFn = fn() -> Pin<Box<dyn Future<Output = Result<()>> + Send>>;

/// An initializer for node components
#[derive(Clone, Debug)]
pub struct Initializer {
    /// Name of the component to initialize
    pub name: String,
    /// Description of the initializer
    pub description: String,
    /// The initialization function
    pub initializer: InitFn,
}

/// Registry for initializers
#[cfg(feature = "distributed_slice")]
#[linkme::distributed_slice]
pub static INITIALIZERS: [Initializer] = [..];

/// Dummy implementation for when distributed_slice feature is not enabled
#[cfg(not(feature = "distributed_slice"))]
#[allow(non_upper_case_globals)]
pub static INITIALIZERS: [Initializer; 0] = [];

// Runtime registries for handlers when distributed slices are not available
/// Runtime registry for initializers
pub static RUNTIME_INITIALIZERS: Lazy<RwLock<Vec<Initializer>>> = 
    Lazy::new(|| RwLock::new(Vec::new()));

/// Runtime registry for action handlers
pub static RUNTIME_ACTION_HANDLERS: Lazy<RwLock<Vec<ActionHandler>>> = 
    Lazy::new(|| RwLock::new(Vec::new()));

/// Runtime registry for process handlers
pub static RUNTIME_PROCESS_HANDLERS: Lazy<RwLock<Vec<ProcessHandler>>> = 
    Lazy::new(|| RwLock::new(Vec::new()));

/// Runtime registry for event subscriptions
pub static RUNTIME_SUBSCRIPTIONS: Lazy<RwLock<Vec<EventSubscription>>> = 
    Lazy::new(|| RwLock::new(Vec::new()));

/// Runtime registry for publication info
pub static RUNTIME_PUBLICATIONS: Lazy<RwLock<Vec<PublicationInfo>>> = 
    Lazy::new(|| RwLock::new(Vec::new()));

/// Register a dynamic initializer
/// 
/// This can be used when distributed slices are not available
pub async fn register_initializer(initializer: Initializer) -> Result<()> {
    // Log the registration
    log::info!(
        "Dynamically registered initializer: {} - {}",
        initializer.name,
        initializer.description
    );
    
    // Add to the runtime registry
    if let Ok(mut initializers) = RUNTIME_INITIALIZERS.write() {
        initializers.push(initializer);
    } else {
        log::error!("Failed to acquire write lock on RUNTIME_INITIALIZERS");
    }
    
    Ok(())
}

/// Register a dynamic initializer synchronously
/// 
/// This function can be used from macros to register initializers at module load time
pub fn register_initializer_sync(initializer: Initializer) {
    // Use a thread to run the async registration 
    let _ = std::thread::spawn(move || {
        // Create a new runtime for this thread
        if let Ok(rt) = tokio::runtime::Runtime::new() {
            rt.block_on(async {
                if let Err(e) = register_initializer(initializer).await {
                    // Use println for macro usage where logging might not be set up yet
                    println!("Failed to register initializer: {}", e);
                }
            });
        } else {
            // Use println for macro usage where logging might not be set up yet
            println!("Failed to create runtime for initializer registration");
        }
    });
}

/// Register an action handler at runtime
pub async fn register_action_handler(handler: ActionHandler) -> Result<()> {
    log::info!(
        "Dynamically registered action handler: {} for service {}",
        handler.name,
        handler.service
    );
    
    if let Ok(mut handlers) = RUNTIME_ACTION_HANDLERS.write() {
        handlers.push(handler);
    } else {
        log::error!("Failed to acquire write lock on RUNTIME_ACTION_HANDLERS");
    }
    
    Ok(())
}

/// Register a process handler at runtime
pub async fn register_process_handler(handler: ProcessHandler) -> Result<()> {
    log::info!(
        "Dynamically registered process handler for service {}",
        handler.service
    );
    
    if let Ok(mut handlers) = RUNTIME_PROCESS_HANDLERS.write() {
        handlers.push(handler);
    } else {
        log::error!("Failed to acquire write lock on RUNTIME_PROCESS_HANDLERS");
    }
    
    Ok(())
}

/// Register an event subscription at runtime
pub async fn register_subscription(subscription: EventSubscription) -> Result<()> {
    log::info!(
        "Dynamically registered subscription for topic {} in service {}",
        subscription.topic,
        subscription.service
    );
    
    if let Ok(mut subscriptions) = RUNTIME_SUBSCRIPTIONS.write() {
        subscriptions.push(subscription);
    } else {
        log::error!("Failed to acquire write lock on RUNTIME_SUBSCRIPTIONS");
    }
    
    Ok(())
}

/// Register publication info at runtime
pub async fn register_publication(publication: PublicationInfo) -> Result<()> {
    log::info!(
        "Dynamically registered publication for topic {} in service {}",
        publication.topic,
        publication.service
    );
    
    if let Ok(mut publications) = RUNTIME_PUBLICATIONS.write() {
        publications.push(publication);
    } else {
        log::error!("Failed to acquire write lock on RUNTIME_PUBLICATIONS");
    }
    
    Ok(())
}

/// Get all registered action handlers
pub fn get_action_handlers() -> Vec<ActionHandler> {
    if let Ok(handlers) = RUNTIME_ACTION_HANDLERS.read() {
        handlers.clone()
    } else {
        log::error!("Failed to acquire read lock on RUNTIME_ACTION_HANDLERS");
        Vec::new()
    }
}

/// Get all registered process handlers
pub fn get_process_handlers() -> Vec<ProcessHandler> {
    if let Ok(handlers) = RUNTIME_PROCESS_HANDLERS.read() {
        handlers.clone()
    } else {
        log::error!("Failed to acquire read lock on RUNTIME_PROCESS_HANDLERS");
        Vec::new()
    }
}

/// Get all registered event subscriptions
pub fn get_subscriptions() -> Vec<EventSubscription> {
    if let Ok(subscriptions) = RUNTIME_SUBSCRIPTIONS.read() {
        subscriptions.clone()
    } else {
        log::error!("Failed to acquire read lock on RUNTIME_SUBSCRIPTIONS");
        Vec::new()
    }
}

/// Get all registered publication info
pub fn get_publications() -> Vec<PublicationInfo> {
    if let Ok(publications) = RUNTIME_PUBLICATIONS.read() {
        publications.clone()
    } else {
        log::error!("Failed to acquire read lock on RUNTIME_PUBLICATIONS");
        Vec::new()
    }
}

/// Run all initializers
pub async fn run_initializers() -> Result<()> {
    // Run distributed slice initializers if available
    for initializer in INITIALIZERS.iter() {
        log::info!(
            "Running initializer: {} - {}",
            initializer.name,
            initializer.description
        );
        
        // Call the initializer function
        (initializer.initializer)().await?;
    }
    
    // Run runtime-registered initializers
    if let Ok(initializers) = RUNTIME_INITIALIZERS.read() {
        for initializer in initializers.iter() {
            log::info!(
                "Running dynamic initializer: {} - {}",
                initializer.name,
                initializer.description
            );
            
            // Call the initializer function
            (initializer.initializer)().await?;
        }
    }
    
    Ok(())
} 