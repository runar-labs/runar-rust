// Subscribe macro implementation
//
// This module implements the subscribe macro, which simplifies the implementation
// of a Runar service event subscription by automatically generating handler code for
// parameter extraction and event handling.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{
    parse::Parse, parse::ParseStream, parse_macro_input, Expr, FnArg, Ident, ItemFn, Lit, LitStr,
    Meta, Pat, PatIdent, PatType, Result, Token, Type,
};

// Define a struct to parse the macro attributes
pub struct SubscribeImpl {
    pub path: LitStr,
    pub handler: Option<Expr>,
}

impl Parse for SubscribeImpl {
    fn parse(input: ParseStream) -> Result<Self> {
        // Check if we have path="value" format
        if input.peek(syn::Ident) {
            let meta = input.parse::<Meta>()?;
            if let Meta::NameValue(name_value) = meta {
                if name_value.path.is_ident("path") {
                    // Extract the string literal from the expression
                    if let Expr::Lit(expr_lit) = &name_value.value {
                        if let Lit::Str(lit_str) = &expr_lit.lit {
                            return Ok(SubscribeImpl {
                                path: lit_str.clone(),
                                handler: None,
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
        if input.peek(Token![,]) {
            input.parse::<Token![,]>()?;
            let handler = input.parse::<Expr>()?;
            Ok(SubscribeImpl {
                path,
                handler: Some(handler),
            })
        } else {
            // Just a path string
            Ok(SubscribeImpl {
                path,
                handler: None,
            })
        }
    }
}

/// Implementation of the subscribe macro
pub fn subscribe_macro(attr: TokenStream, item: TokenStream) -> TokenStream {
    // Parse the input as a function
    let input = parse_macro_input!(item as ItemFn);

    // Parse the attributes
    let subscribe_impl = parse_macro_input!(attr as SubscribeImpl);
    let path = &subscribe_impl.path;
    let path_value = &path.value();

    // Get the function identifier
    let fn_ident = &input.sig.ident;
    let attrs = &input.attrs;
    let vis = &input.vis;

    // Extract parameters from the function signature
    let params = extract_parameters(&input);

    // Generate a unique method name for the subscription registration
    let register_method_name = format_ident!("register_subscription_{}", fn_ident);

    // Generate the registration method based on parameters
    let register_method = if params.len() == 1 {
        let (param_ident, param_type) = &params[0];
        quote! {
            async fn #register_method_name(&self, context: &runar_node::services::LifecycleContext) -> anyhow::Result<()> {
                context.info(format!("Subscribing to '{}' event", #path_value));

                // Create a clone of self that can be moved into the closure
                let self_clone = self.clone();

                // Register the event handler
                context.subscribe(#path, Box::new(move |ctx, value| {
                    // Create a boxed future that returns Result<(), anyhow::Error>
                    let self_clone = self_clone.clone();
                    Box::pin(async move {

                        // Extract parameter from the event value
                        let #param_ident = match value {
                            Some(value) => match value.clone().as_type::<#param_type>() {
                                Ok(val) => val,
                                Err(err) => {
                                    return Err(anyhow!(format!("Failed to parse event value as {}: {}", stringify!(#param_type), err)));
                                }
                            },
                            None => {
                                return Err(anyhow!(format!("Required event value is missing for {}", #path_value)));
                            }
                        };

                        // Call the handler method with the extracted parameter
                        match self_clone.#fn_ident(#param_ident, &ctx).await {
                            Ok(_) => Ok(()),
                            Err(err) => {
                                Err(anyhow!(format!("Error in event handler for {}: {}", #path_value, err)))
                            }
                        }
                    })
                })).await?;

                context.info(format!("Registered event handler for {}", #path_value));
                Ok(())
            }
        }
    } else if params.is_empty() {
        quote! {
            async fn #register_method_name(&self, context: &runar_node::services::LifecycleContext) -> anyhow::Result<()> {
                context.info(format!("Subscribing to '{}' event", #path_value));

                // Create a clone of self that can be moved into the closure
                let self_clone = self.clone();

                // Register the event handler
                context.subscribe(#path, Box::new(move |ctx, value| {
                    // Create a boxed future that returns Result<(), anyhow::Error>
                    let self_clone = self_clone.clone();
                    Box::pin(async move {
                        // Call the handler method directly with the event context
                        match self_clone.#fn_ident(&ctx).await {
                            Ok(_) => Ok(()),
                            Err(err) => {
                                ctx.error(format!("Error in event handler for {}: {}", #path_value, err));
                                Ok(()) // Still return Ok to prevent subscription cancellation
                            }
                        }
                    })
                })).await?;

                context.info(format!("Registered event handler for {}", #path_value));
                Ok(())
            }
        }
    } else {
        // Multiple parameters case - this is not supported for subscriptions
        quote! {
            compile_error!("Subscription handlers can only have one parameter plus context");
        }
    };

    // Combine the original function with the generated register method
    let expanded = quote! {
        // Keep the original function
        #(#attrs)*
        #vis #input

        // Add the registration method
        #register_method
    };

    TokenStream::from(expanded)
}

/// Extract parameters from the function signature
fn extract_parameters(input: &ItemFn) -> Vec<(Ident, Type)> {
    let mut params = Vec::new();

    for arg in &input.sig.inputs {
        match arg {
            FnArg::Typed(PatType { pat, ty, .. }) => {
                // Skip the self parameter and context parameter
                if let Pat::Ident(PatIdent { ident, .. }) = &**pat {
                    let ident_string = ident.to_string();
                    if ident_string != "self"
                        && ident_string != "ctx"
                        && !ident_string.ends_with("ctx")
                    {
                        params.push((ident.clone(), (**ty).clone()));
                    }
                }
            }
            _ => {}
        }
    }

    params
}
