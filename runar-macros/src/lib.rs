// Runar Macros
//
// This crate provides procedural macros for the Runar framework.

extern crate proc_macro;

mod action;
mod publish;
mod service;
mod subscribe;
mod utils;
use proc_macro::TokenStream;

/// Service macro for implementing AbstractService
///
/// This macro automatically implements the AbstractService trait for a struct
/// and registers all methods marked with #[action] or #[subscribe].
#[proc_macro_attribute]
pub fn service(attr: TokenStream, item: TokenStream) -> TokenStream {
    service::service_macro(attr, item)
}

/// Action macro for registering service actions
///
/// This macro generates the necessary code to register a method as an action
/// that can be called via the request mechanism.
#[proc_macro_attribute]
pub fn action(attr: TokenStream, item: TokenStream) -> TokenStream {
    action::action_macro(attr, item)
}

/// Subscribe macro for registering event handlers
///
/// This macro generates the necessary code to register a method as an event
/// handler that will be called when events are published to the specified path.
#[proc_macro_attribute]
pub fn subscribe(attr: TokenStream, item: TokenStream) -> TokenStream {
    subscribe::subscribe_macro(attr, item)
}

/// Publish macro for publishing events
///
/// This macro generates code to automatically publish the result of an action
/// to the specified event path.
#[proc_macro_attribute]
pub fn publish(attr: TokenStream, item: TokenStream) -> TokenStream {
    publish::publish_macro(attr, item)
}
