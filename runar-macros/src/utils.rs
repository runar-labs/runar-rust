// Utility functions for the macro implementations
//
// This module provides utility functions for parsing and generating code
// for the service and action macros.

use quote::quote;
use syn::{FnArg, Ident, ItemFn, Pat, PatIdent, PatType};
use syn::{ReturnType, Type};

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

#[derive(Debug, Clone)]
pub struct ReturnTypeInfo {
    pub is_primitive: bool,
    pub is_unit: bool,
    pub actual_type: Type,
    pub actual_type_is_option: bool,
    pub type_name: String,
    pub is_hashmap: bool,
    pub is_list: bool,
    pub is_struct: bool,
}

pub fn extract_return_type_info(return_type: &ReturnType) -> ReturnTypeInfo {
    let (
        actual_type,
        is_unit,
        actual_type_is_option,
        is_primitive,
        type_name,
        is_hashmap,
        is_list,
        is_struct,
    ) = match return_type {
        ReturnType::Default => (
            syn::parse_quote! { () },
            true,
            false,
            true,
            "unit".to_string(),
            false,
            false,
            false,
        ),
        ReturnType::Type(_, original_ty) => {
            let mut current_type = *original_ty.clone();
            let mut outer_is_option = false;

            // Check for outer Result<T, E>
            if let Some(inner_ty_of_result) = get_result_inner_type(&current_type) {
                current_type = inner_ty_of_result.clone();
            }

            // Check for outer Option<T> (could be Option<Result<...>> or Option<T>)
            if let Some(inner_ty_of_option) = get_option_inner_type(&current_type) {
                outer_is_option = true;
                current_type = inner_ty_of_option.clone();
            }

            // Now current_type is the innermost T
            let type_name_str = if let syn::Type::Path(type_path) = &current_type {
                get_path_last_segment_ident_string(type_path)
                    .unwrap_or_else(|| "unknown".to_string())
            } else if let syn::Type::Tuple(tuple_type) = &current_type {
                if tuple_type.elems.is_empty() {
                    "unit".to_string()
                } else {
                    "tuple".to_string() // Or some other representation for non-unit tuples
                }
            } else {
                quote!(#current_type).to_string().replace(" ", "")
            };

            let is_primitive_val = is_primitive_type(&current_type);
            let is_hashmap_val = is_hashmap_type(&current_type);
            let is_list_val = is_vec_type(&current_type);
            let is_struct_val =
                !is_primitive_val && !is_hashmap_val && !is_list_val && type_name_str != "unit";

            (
                current_type,
                false,
                outer_is_option,
                is_primitive_val,
                type_name_str,
                is_hashmap_val,
                is_list_val,
                is_struct_val,
            )
        }
    };

    ReturnTypeInfo {
        is_primitive,
        is_unit,
        actual_type,
        actual_type_is_option,
        type_name,
        is_hashmap,
        is_list,
        is_struct,
    }
}

pub fn get_path_last_segment_ident_string(type_path: &syn::TypePath) -> Option<String> {
    type_path
        .path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
}

pub fn get_option_inner_type(ty: &syn::Type) -> Option<&syn::Type> {
    if let syn::Type::Path(type_path) = ty {
        if let Some(segment) = type_path.path.segments.last() {
            if segment.ident == "Option" {
                if let syn::PathArguments::AngleBracketed(args) = &segment.arguments {
                    if let Some(syn::GenericArgument::Type(inner_ty)) = args.args.first() {
                        return Some(inner_ty);
                    }
                }
            }
        }
    }
    None
}

pub fn is_hashmap_type(ty: &syn::Type) -> bool {
    if let syn::Type::Path(type_path) = ty {
        if let Some(segment) = type_path.path.segments.last() {
            if segment.ident == "HashMap" {
                if let syn::PathArguments::AngleBracketed(args) = &segment.arguments {
                    if args.args.len() == 2 {
                        if let Some(syn::GenericArgument::Type(syn::Type::Path(key_path))) =
                            args.args.get(0)
                        {
                            // Check if key type is String
                            if let Some(key_segment) = key_path.path.segments.last() {
                                return key_segment.ident == "String";
                            }
                        }
                    }
                }
            }
        }
    }
    false
}

pub fn is_vec_type(ty: &syn::Type) -> bool {
    if let syn::Type::Path(type_path) = ty {
        if let Some(segment) = type_path.path.segments.last() {
            return segment.ident == "Vec";
        }
    }
    false
}

pub fn is_primitive_type(ty: &syn::Type) -> bool {
    if let syn::Type::Path(type_path) = ty {
        if let Some(segment) = type_path.path.segments.last() {
            let type_name = segment.ident.to_string();
            return matches!(
                type_name.as_str(),
                "bool"
                    | "char"
                    | "f32"
                    | "f64"
                    | "i8"
                    | "i16"
                    | "i32"
                    | "i64"
                    | "i128"
                    | "isize"
                    | "u8"
                    | "u16"
                    | "u32"
                    | "u64"
                    | "u128"
                    | "usize"
                    | "str"
                    | "String"
            );
        }
    }
    false
}

pub fn get_vec_inner_type(ty: &syn::Type) -> Option<&syn::Type> {
    if let syn::Type::Path(type_path) = ty {
        if let Some(segment) = type_path.path.segments.last() {
            if segment.ident == "Vec" {
                if let syn::PathArguments::AngleBracketed(args) = &segment.arguments {
                    if let Some(syn::GenericArgument::Type(inner_ty)) = args.args.first() {
                        return Some(inner_ty);
                    }
                }
            }
        }
    }
    None
}

pub fn get_result_inner_type(ty: &syn::Type) -> Option<&syn::Type> {
    if let syn::Type::Path(type_path) = ty {
        if let Some(segment) = type_path.path.segments.last() {
            if segment.ident == "Result" {
                if let syn::PathArguments::AngleBracketed(args) = &segment.arguments {
                    if let Some(syn::GenericArgument::Type(inner_ty)) = args.args.first() {
                        return Some(inner_ty);
                    }
                }
            }
        }
    }
    None
}
