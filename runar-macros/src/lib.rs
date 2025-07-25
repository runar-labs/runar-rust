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
use syn::{parse_macro_input, Item};

/// Unified service macro that works on both struct definitions and impl blocks
///
/// When used on a struct: #[service(name = "...", path = "...", ...)]
/// When used on an impl block: #[service]
#[proc_macro_attribute]
pub fn service(attr: TokenStream, item: TokenStream) -> TokenStream {
    // Clone the item for parsing since we need to use it in both branches
    let item_clone = item.clone();

    // Parse the item to determine if it's a struct or impl block
    match parse_macro_input!(item_clone as Item) {
        Item::Struct(_) => {
            // It's a struct - use the struct-level implementation
            service_meta::service_meta_impl(attr, item)
        }
        Item::Impl(_) => {
            // It's an impl block - use the impl-level implementation
            service::service_macro(attr, item)
        }
        _ => {
            // Neither struct nor impl - return a compilation error
            panic!("#[service] macro can only be used on struct definitions or impl blocks")
        }
    }
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
