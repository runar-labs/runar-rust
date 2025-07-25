// Publish macro implementation
//
// This module implements the publish macro, which automatically publishes
// the result of an action to a specified topic.

use crate::utils::{
    extract_return_type_info, get_path_last_segment_ident_string, get_vec_inner_type,
    ReturnTypeInfo,
};
use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{
    parse::Parse, parse::ParseStream, parse_macro_input, Expr, FnArg, Ident, ItemFn, Lit, LitStr,
    Meta, Pat, Type,
};

// Define a struct to parse the macro attributes
pub struct PublishImpl {
    pub path: LitStr,
}

impl Parse for PublishImpl {
    fn parse(input: ParseStream) -> Result<Self, syn::Error> {
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

/// Generate the appropriate ArcValue creation based on return type
fn generate_arc_value_creation(return_type_info: &ReturnTypeInfo) -> TokenStream2 {
    if return_type_info.is_list {
        // For Vec<T>, check if it's Vec<ArcValue> to use new_list, otherwise use new_primitive
        if return_type_info.type_name == "Vec" {
            // Check if the inner type is ArcValue
            let inner_type = get_vec_inner_type(&return_type_info.actual_type);
            if let Some(syn::Type::Path(type_path)) = inner_type {
                if get_path_last_segment_ident_string(type_path).as_deref() == Some("ArcValue") {
                    quote! {
                        runar_serializer::ArcValue::new_list(action_result.clone())
                    }
                } else {
                    quote! {
                        runar_serializer::ArcValue::new_primitive(action_result.clone())
                    }
                }
            } else {
                quote! {
                    runar_serializer::ArcValue::new_primitive(action_result.clone())
                }
            }
        } else {
            quote! {
                runar_serializer::ArcValue::new_primitive(action_result.clone())
            }
        }
    } else if return_type_info.is_struct {
        // For struct types, use new_struct (let compiler handle trait bounds)
        quote! {
            runar_serializer::ArcValue::new_struct(action_result.clone())
        }
    } else {
        // For complex types, use new_primitive since new_struct requires RunarEncrypt trait
        quote! {
            runar_serializer::ArcValue::new_primitive(action_result.clone())
        }
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

    // Determine the identifier for the RequestContext parameter
    let mut original_fn_ctx_ident_opt: Option<Ident> = None;
    for fn_arg in &input.sig.inputs {
        if let FnArg::Typed(pat_type) = fn_arg {
            let type_to_check = match &*pat_type.ty {
                Type::Reference(type_ref) => {
                    // Check if it's an immutable reference before accessing elem
                    if type_ref.mutability.is_none() {
                        &*type_ref.elem
                    } else {
                        continue; // Skip mutable references for RequestContext
                    }
                }
                direct_type => direct_type,
            };

            if let Type::Path(type_path) = type_to_check {
                if get_path_last_segment_ident_string(type_path).as_deref()
                    == Some("RequestContext")
                {
                    if let Pat::Ident(pat_ident) = &*pat_type.pat {
                        original_fn_ctx_ident_opt = Some(pat_ident.ident.clone());
                        break;
                    }
                }
            }
        }
    }

    let original_fn_has_request_context_param = original_fn_ctx_ident_opt.is_some();
    let ctx_ident = original_fn_ctx_ident_opt
        .unwrap_or_else(|| Ident::new("ctx", proc_macro2::Span::call_site()));

    // Extract the return type information for proper handling
    let return_type_info = extract_return_type_info(&input.sig.output);

    // Generate the appropriate ArcValue creation
    let arc_value_creation = generate_arc_value_creation(&return_type_info);

    // Generate the modified function with publishing
    let expanded = if original_fn_has_request_context_param {
        // Function has RequestContext parameter, so we can add publishing logic
        if is_async {
            quote! {
                #(#attrs)*
                #vis #sig {
                    // Execute the original function body
                    let result = #block;

                    // If the result is Ok, publish it
                    if let Ok(ref action_result) = &result {
                        // Publish the result to the specified topic
                        match #ctx_ident.publish(#path, Some(#arc_value_creation)).await {
                            Ok(_) => {},
                            Err(e) => {
                                #ctx_ident.error(format!("Failed to publish result to {}: {}", #path, e));
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
                        match #ctx_ident.publish(#path, Some(#arc_value_creation)).await {
                            Ok(_) => {},
                            Err(e) => {
                                #ctx_ident.error(format!("Failed to publish result to {}: {}", #path, e));
                            }
                        }
                    }

                    // Return the original result
                    result
                }
            }
        }
    } else {
        // Function doesn't have RequestContext parameter, so we can't add publishing logic
        // Just pass through the function as-is
        if is_async {
            quote! {
                #(#attrs)*
                #vis #sig {
                    #block
                }
            }
        } else {
            quote! {
                #(#attrs)*
                #vis async #sig {
                    #block
                }
            }
        }
    };

    TokenStream::from(expanded)
}
