// Utility functions for the macro implementations
//
// This module provides utility functions for parsing and generating code
// for the service and action macros.

use syn::{FnArg, Ident, ItemFn, Pat, PatIdent, PatType, Type};

/// Extract parameters from the function signature, skipping `self` and `ctx` or `*_ctx` parameters.
pub fn extract_parameters(input: &ItemFn) -> Vec<(Ident, Type)> {
    let mut params = Vec::new();

    for arg in &input.sig.inputs {
        if let FnArg::Typed(PatType { pat, ty, .. }) = arg {
            // Skip the self parameter and context parameter
            if let Pat::Ident(PatIdent { ident, .. }) = &**pat {
                let ident_string = ident.to_string();
                if ident_string != "self"
                    && ident_string != "ctx"
                    && !ident_string.ends_with("_ctx")
                {
                    params.push((ident.clone(), (**ty).clone()));
                }
            }
        }
    }

    params
}
