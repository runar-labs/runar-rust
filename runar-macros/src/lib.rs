// Runar Macros
//
// This crate provides procedural macros for the Runar framework.

extern crate proc_macro;

mod action;
mod meta_support;
mod publish;
mod service;
mod service_meta;
mod subscribe;
mod utils;
use proc_macro::TokenStream;

/// Struct-level metadata macro (was `service_meta`)
#[proc_macro_attribute]
pub fn service(attr: TokenStream, item: TokenStream) -> TokenStream {
    service_meta::service_meta_impl(attr, item)
}

/// Impl-level macro that wires the service to the runtime (was `service`)
#[proc_macro_attribute]
pub fn service_impl(attr: TokenStream, item: TokenStream) -> TokenStream {
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
