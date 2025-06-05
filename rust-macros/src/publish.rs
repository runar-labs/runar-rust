// Publish macro implementation
//
// This module implements the publish macro, which automatically publishes
// the result of an action to a specified topic.

use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse::Parse, parse::ParseStream, parse_macro_input, Expr, ItemFn, Lit, LitStr, Meta, Result,
    Token,
};

// Define a struct to parse the macro attributes
pub struct PublishImpl {
    pub path: LitStr,
}

impl Parse for PublishImpl {
    fn parse(input: ParseStream) -> Result<Self> {
        // Check if we have path="value" format
        if input.peek(syn::Ident) {
            let meta = input.parse::<Meta>()?;
            if let Meta::NameValue(name_value) = meta {
                if name_value.path.is_ident("path") {
                    // Extract the string literal from the expression
                    if let Expr::Lit(expr_lit) = &name_value.value {
                        if let Lit::Str(lit_str) = &expr_lit.lit {
                            return Ok(PublishImpl {
                                path: lit_str.clone(),
                            });
                        }
                    }
                }
            }
            return Err(input.error("Expected path=\"value\" or a string literal"));
        }

        // Otherwise, try to parse as a string literal followed by a handler
        let path = input.parse::<LitStr>()?;

        // Check if we have a handler
        // if input.peek(Token![,]) {
        //     input.parse::<Token![,]>()?;
        //     let handler = input.parse::<Expr>()?;
        //     Ok(PublishImpl { path, handler: Some(handler) })
        // } else {
        // Just a path string
        Ok(PublishImpl { path })
        // }
    }
}

/// Implementation of the publish macro
pub fn publish_macro(attr: TokenStream, item: TokenStream) -> TokenStream {
    // Parse the input as a function
    let input = parse_macro_input!(item as ItemFn);

    // Parse the attributes
    let publish_impl = parse_macro_input!(attr as PublishImpl);
    let path = &publish_impl.path;

    // Get the function body
    let attrs = &input.attrs;
    let vis = &input.vis;
    let sig = &input.sig;
    let block = &input.block;

    // Check if the function is already async
    let is_async = input.sig.asyncness.is_some();

    // Generate the modified function with publishing
    let expanded = if is_async {
        quote! {
            #(#attrs)*
            #vis #sig {
                // Execute the original function body
                let result = #block;

                // If the result is Ok, publish it
                if let Ok(ref action_result) = &result {
                    // Publish the result to the specified topic
                    match ctx.publish(#path, Some(runar_common::types::ArcValueType::from_struct(action_result.clone()))).await {
                        Ok(_) => {},
                        Err(e) => {
                            ctx.error(format!("Failed to publish result to {}: {}", #path, e));
                        }
                    }
                }

                // Return the original result
                result
            }
        }
    } else {
        quote! {
            #(#attrs)*
            #vis async #sig {
                // Execute the original function body
                let result = (|| #block)();

                // If the result is Ok, publish it
                if let Ok(ref action_result) = &result {
                    // Publish the result to the specified topic
                    match ctx.publish(#path, Some(runar_common::types::ArcValueType::from_struct(action_result.clone()))).await {
                        Ok(_) => {},
                        Err(e) => {
                            ctx.error(format!("Failed to publish result to {}: {}", #path, e));
                        }
                    }
                }

                // Return the original result
                result
            }
        }
    };

    TokenStream::from(expanded)
}
