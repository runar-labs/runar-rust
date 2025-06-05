// Utility functions for the macro implementations
//
// This module provides utility functions for parsing and generating code
// for the service and action macros.

use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn::{Attribute, Lit, Meta, Path};

/// Extract a string value from an attribute
pub fn extract_string_from_attribute(
    attrs: &[Attribute],
    path_segments: &[&str],
) -> Option<String> {
    for attr in attrs {
        if path_matches(&attr.path(), path_segments) {
            // Use parse_args instead of parse_meta, which is deprecated in syn 2.0
            let meta = attr.meta.clone();
            if let Meta::NameValue(name_value) = meta {
                if let syn::Expr::Lit(expr_lit) = name_value.value {
                    if let Lit::Str(lit_str) = expr_lit.lit {
                        return Some(lit_str.value());
                    }
                }
            }
        }
    }
    None
}

/// Check if a path matches the given segments
pub fn path_matches(path: &Path, segments: &[&str]) -> bool {
    if path.segments.len() != segments.len() {
        return false;
    }

    path.segments
        .iter()
        .zip(segments.iter())
        .all(|(seg, &expected)| seg.ident == expected)
}

/// Generate a handler function name from an action name
pub fn generate_handler_name(action_name: &str) -> syn::Ident {
    syn::Ident::new(&format!("handle_{}", action_name), Span::call_site())
}

/// Generate a unique identifier for a function
pub fn generate_unique_id() -> String {
    use rand::{distributions::Alphanumeric, Rng};
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(10)
        .map(char::from)
        .collect()
}

/// Generate code to extract a parameter from a request
pub fn generate_param_extraction(
    param_name: &syn::Ident,
    param_type: &syn::Type,
    index: usize,
    action_name: &str,
) -> TokenStream2 {
    quote! {
        let #param_name: #param_type = match params.as_ref().and_then(|p| p.get(#index)) {
            Some(value) => match value.as_type() {
                Ok(val) => val,
                Err(_) => {
                    context.error(format!("Failed to parse parameter {} for action {}", #index, #action_name));
                    return Err(anyhow!(format!("Invalid parameter type for parameter {}", #index)));
                }
            },
            None => {
                context.error(format!("Missing parameter {} for action {}", #index, #action_name));
                return Err(anyhow!(format!("Missing parameter {} for action {}", #index, #action_name)));
            }
        };
    }
}
