// Action macro implementation
//
// This module implements the action macro, which simplifies the implementation
// of a Runar service action by automatically generating handler code for
// parameter extraction, validation, and response formatting.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::parse::Parser;
use syn::{
    parse_macro_input, punctuated::Punctuated, token::Comma, FnArg, Ident, ItemFn, Lit, Pat,
    PatIdent, PatType, ReturnType, Type,
};

/// Implementation of the action macro
pub fn action_macro(attr: TokenStream, item: TokenStream) -> TokenStream {
    // Parse the input as a function
    let input = parse_macro_input!(item as ItemFn);

    // Default to function name
    let fn_name = input.sig.ident.to_string();

    // Parse the attributes
    let mut action_name = fn_name.clone();
    let mut action_path = fn_name.clone();

    if !attr.is_empty() {
        // Convert attribute tokens to a string for simple parsing
        let attr_str = attr.to_string();

        // Extract attributes from the TokenStream
        if attr_str.contains("path") {
            // Try to parse as a name-value attribute
            // For safety, we're using a simple string parsing approach
            let attr_str = attr.to_string();

            if attr_str.contains("path") && attr_str.contains('=') && attr_str.contains('"') {
                // Find the path value
                let start_idx = attr_str.find("path").unwrap() + 4; // Skip 'path'
                let equals_idx = attr_str[start_idx..].find('=').unwrap() + start_idx + 1; // Skip '='
                let quote_start_idx = attr_str[equals_idx..].find('"').unwrap() + equals_idx + 1; // Skip opening quote
                let quote_end_idx =
                    attr_str[quote_start_idx..].find('"').unwrap() + quote_start_idx;

                // Extract the path value
                action_path = attr_str[quote_start_idx..quote_end_idx].to_string();
            }
        } else {
            // Try to parse as a simple string literal for backward compatibility
            let parser = Punctuated::<Lit, Comma>::parse_terminated;
            if let Ok(lit_args) = parser.parse(attr.clone()) {
                if !lit_args.is_empty() {
                    // Get the first argument as a string literal for the name
                    if let Lit::Str(s) = &lit_args[0] {
                        action_name = s.value();
                        action_path = action_name.clone(); // Use the same value for path if not specified separately
                    }
                }
            }
        }
    };

    // Extract parameters from the function signature
    let params = extract_parameters(&input);

    // Extract the return type information for proper handling
    let return_type_info = extract_return_type_info(&input.sig.output);

    // Check if the function is async
    let is_async = input.sig.asyncness.is_some();

    // Determine the identifier for the RequestContext parameter
    let mut ctx_ident_opt: Option<Ident> = None;
    for fn_arg in &input.sig.inputs {
        if let FnArg::Typed(pat_type) = fn_arg {
            if let Type::Path(type_path) = &*pat_type.ty {
                if type_path
                    .path
                    .segments
                    .iter()
                    .any(|segment| segment.ident == "RequestContext")
                {
                    if let Pat::Ident(pat_ident) = &*pat_type.pat {
                        ctx_ident_opt = Some(pat_ident.ident.clone());
                        break;
                    }
                }
            }
        }
    }
    let ctx_ident =
        ctx_ident_opt.unwrap_or_else(|| Ident::new("ctx", proc_macro2::Span::call_site()));

    // Generate the register action method based on return type information
    let register_action_method = generate_register_action_method(
        &input.sig.ident,
        &action_name,
        &action_path,
        &params,
        &input.sig.output,
        &return_type_info.is_primitive,
        &return_type_info.type_name,
        &return_type_info.needs_registration,
        is_async,
        &ctx_ident, // Added ctx_ident, passing by reference
    );

    // Combine the original function with the generated register method
    let expanded = quote! {

        #input

        #register_action_method
    };

    expanded.into()
}

/// Extract information about the return type for proper handling.
/// This function robustly supports all valid Rust types, including nested generics.
fn extract_return_type_info(return_type: &ReturnType) -> ReturnTypeInfo {
    use syn::{GenericArgument, PathArguments, Type};
    match return_type {
        ReturnType::Default => ReturnTypeInfo {
            is_result: false,
            type_name: "()".to_string(),
            is_primitive: true,
            needs_registration: false,
        },
        ReturnType::Type(_, ty) => {
            // Helper: recursively extract the first type parameter of Result<T, E>
            fn extract_result_ok_type(ty: &Type) -> Option<&Type> {
                if let Type::Path(type_path) = ty {
                    let seg = type_path.path.segments.last()?;
                    if seg.ident == "Result" {
                        if let PathArguments::AngleBracketed(ref ab) = seg.arguments {
                            // Find the first type argument (the Ok type)
                            for arg in &ab.args {
                                if let GenericArgument::Type(ref inner_ty) = arg {
                                    return Some(inner_ty);
                                }
                            }
                        }
                    }
                }
                None
            }

            let (is_result, inner_type_ast) = if let Some(ok_ty) = extract_result_ok_type(ty) {
                (true, ok_ty)
            } else {
                (false, &**ty)
            };

            let type_name = quote! { #inner_type_ast }.to_string();

            // Determine if this is a primitive type
            let is_primitive = type_name.contains("i32")
                || type_name.contains("i64")
                || type_name.contains("u32")
                || type_name.contains("u64")
                || type_name.contains("f32")
                || type_name.contains("f64")
                || type_name.contains("bool")
                || type_name.contains("String")
                || type_name.contains("&str")
                || type_name.contains("()");

            // Determine if this type needs registration with the serializer
            let needs_registration =
                !is_primitive && !type_name.contains("Vec") && !type_name.contains("HashMap");

            ReturnTypeInfo {
                is_result,
                type_name,
                is_primitive,
                needs_registration,
            }
        }
    }
}

/// Struct to hold information about the return type
struct ReturnTypeInfo {
    is_result: bool,          // Whether the return type is a Result
    type_name: String,        // The name of the type (or inner type if Result)
    is_primitive: bool,       // Whether it's a primitive type
    needs_registration: bool, // Whether it needs registration with the serializer
}

/// Extract parameters from the function signature
fn extract_parameters(input: &ItemFn) -> Vec<(Ident, Type)> {
    let mut params = Vec::new();

    for arg in &input.sig.inputs {
        match arg {
            FnArg::Typed(PatType { pat, ty, .. }) => {
                // Skip the context parameter
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

/// Generate the register action method
fn generate_register_action_method(
    fn_ident: &Ident,
    action_name: &str,
    action_path: &str,
    params: &[(Ident, Type)],
    return_type: &ReturnType,
    is_primitive: &bool,
    type_name: &String,
    needs_registration: &bool,
    is_async: bool,
    ctx_ident: &Ident, // Added ctx_ident
) -> TokenStream2 {
    // Create a boolean expression for checking if there are parameters
    let has_params = if params.is_empty() {
        quote! { false }
    } else {
        quote! { true }
    };

    // Generate parameter extraction code
    let param_extractions = generate_parameter_extractions(params, action_name, ctx_ident);

    // Generate method call with extracted parameters
    let method_call = generate_method_call(fn_ident, params, is_async);

    // Generate the appropriate result handling based on the return type
    let result_handling = if type_name == "()" {
        quote! {
            // For () return type, convert to ArcValueType::null()
            Ok(runar_common::types::ArcValueType::null())
        }
    } else if type_name == "ArcValueType" {
        // Check if the result is already an ArcValueType
        quote! {
            // Result is already ArcValueType, pass it through directly
            Ok(result)
        }
    } else if *is_primitive {
        quote! {
            // Convert the primitive result to ArcValueType
            let value_type = runar_common::types::ArcValueType::new_primitive(result);
            Ok(value_type)
        }
    } else {
        quote! {
            // Convert the complex result to ArcValueType using from_struct
            let value_type = runar_common::types::ArcValueType::from_struct(result);
            Ok(value_type)
        }
    };

    // Generate a unique method name for the action registration
    let register_method_name = format_ident!("register_action_{}", fn_ident);

    quote! {
        async fn #register_method_name(&self, context: &runar_node::services::LifecycleContext) -> anyhow::Result<()> {
            context.logger.info(format!("Registering '{}' action", #action_name));

            // Create a clone of self that can be moved into the closure
            let self_clone = self.clone();

            // Create the action handler as an Arc to match what the register_action expects
            let handler = std::sync::Arc::new(move |params_opt: Option<runar_common::types::ArcValueType>, ctx: runar_node::services::RequestContext|
                -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<runar_common::types::ArcValueType, anyhow::Error>> + Send>> {
                let inner_self = self_clone.clone();

                Box::pin(async move {
                    // Extract parameters from the map if available
                    let mut params_value = match params_opt {
                        Some(p) => p,
                        None => {
                            // Check if method expects parameters
                            if #has_params {
                                ctx.error("No parameters provided".to_string());
                                return Err(anyhow!("No parameters provided"));
                            } else {
                                // No parameters expected, so create an empty map
                                runar_common::types::ArcValueType::new_map(
                                    std::collections::HashMap::<String, runar_common::types::ArcValueType>::new()
                                )
                            }
                        }
                    };

                    #param_extractions

                    // Call the actual method with the extracted parameters
                    match #method_call {
                        Ok(result) => {
                            #result_handling
                        },
                        Err(err) => {
                            // Return an error response
                            ctx.error(format!("Action '{}' failed: {}", #action_name, err));
                            return Err(anyhow!(err.to_string()));
                        }
                    }
                })
            });

            // If this action returns a type that needs registration with the serializer,
            // we would register it here
            if #needs_registration {
                context.logger.debug(format!("Type registration needed for action '{}' with type: {}", #action_name, #type_name));
                // The actual registration logic would depend on the service's serializer API
            }

            // Register the action handler with the configured path
            context.register_action(
                #action_path.to_string(),
                handler
            ).await
        }
    }
}

/// Generate parameter extraction code to exactly match the reference implementation
// Helper function to determine if all parameters share a common type
fn determine_common_type(params: &[(Ident, Type)]) -> Option<Type> {
    if params.is_empty() {
        return None;
    }
    let first_type = &params[0].1;
    for (_, param_type) in params.iter().skip(1) {
        if param_type != first_type {
            return None; // Heterogeneous
        }
    }
    Some(first_type.clone()) // Homogeneous
}

/// Generate parameter extraction code
fn generate_parameter_extractions(
    params: &[(Ident, Type)],
    _fn_name_str: &str,
    func_param_ctx_ident: &Ident,
) -> TokenStream2 {
    let mut extractions = TokenStream2::new();

    if params.is_empty() {
        // No parameters to extract. params_value should be handled by the caller (e.g. warn if Some).
        return extractions;
    }

    // If there is only one parameter, deserialize the entire input into that type directly.
    // params_value is an ArcValueType here.
    if params.len() == 1 {
        let (param_ident, param_type) = &params[0];
        extractions.extend(quote! {
            let #param_ident: #param_type = match params_value.as_type::<#param_type>() {
                Ok(val) => val,
                Err(err) => {
                    #func_param_ctx_ident.error(format!("Failed to parse parameter for single-parameter action: {}", err));
                    return Err(anyhow!(format!("Failed to parse parameter for single-parameter action: {}", err)));
                }
            };
        });
        return extractions;
    }

    // Multiple parameters (params.len() > 1)
    // params_value is an ArcValueType. The caller ensures it's appropriately set up
    // (e.g., an empty map representation if original payload was None but all params are Option).
    let common_type_opt = determine_common_type(params);

    if let Some(common_type_token) = common_type_opt {
        // Homogeneous case: All parameters have the same type `common_type_token`.
        extractions.extend(quote! {
            let params_map_ref = match params_value.as_map_ref::<String, #common_type_token>() {
                Ok(map_ref) => map_ref,
                Err(err) => {
                    #func_param_ctx_ident.error(format!(
                        "Action parameters must be provided as a map of type Map<String, {}>, but received an incompatible type. Error: {}",
                        stringify!(#common_type_token),
                        err
                    ));
                    return Err(anyhow!(format!(
                        "Invalid payload type for parameters. Expected map of type Map<String, {}>, got incompatible type: {}",
                        stringify!(#common_type_token),
                        err
                    )));
                }
            };
        });

        for (param_ident, param_type) in params {
            // param_type is effectively common_type_token
            let param_name_str = param_ident.to_string();
            let param_type_str_for_check = quote!(#param_type).to_string().replace(" ", "");
            let is_option_common_type = param_type_str_for_check.starts_with("Option<")
                || param_type_str_for_check.starts_with("std::option::Option<")
                || param_type_str_for_check.starts_with("core::option::Option<");

            if is_option_common_type {
                // Common type is Option<T>. Map is Map<String, Option<T>>.
                // param_ident needs to be Option<T>.
                // params_map_ref.get() returns Option<&Option<T>>.
                // .cloned() on Option<&V> (where V=Option<T>) gives Option<Option<T>>.
                // .unwrap_or(None) on Option<Option<T>> gives Option<T>.
                extractions.extend(quote! {
                    let #param_ident: #param_type = params_map_ref.get(#param_name_str).cloned().unwrap_or(None);
                });
            } else {
                // Common type is T (not an Option). Map is Map<String, T>.
                // param_ident needs to be T.
                extractions.extend(quote! {
                    let #param_ident: #param_type = match params_map_ref.get(#param_name_str) {
                        Some(val_ref) => val_ref.clone(),
                        None => {
                            #func_param_ctx_ident.error(format!(
                                "Required parameter '{}' (type '{}') not found in payload. Expected map to contain this key.",
                                #param_name_str,
                                stringify!(#param_type)
                            ));
                            return Err(anyhow!(format!("Missing required parameter '{}'", #param_name_str)));
                        }
                    };
                });
            }
        }
    } else {
        // Heterogeneous case: Parameters have different types.
        // Fallback to expecting Map<String, ArcValueType>.
        extractions.extend(quote! {
            let params_map_ref = match params_value.as_map_ref::<String, runar_common::types::ArcValueType>() {
                Ok(map_ref) => map_ref,
                Err(err) => {
                    #func_param_ctx_ident.error(format!(
                        "Action parameters must be provided as a map (for heterogeneous types, expecting Map<String, ArcValueType>), but received an incompatible type. Error: {}",
                        err
                    ));
                    return Err(anyhow!(format!(
                        "Invalid payload type for parameters. Expected a map, got incompatible type: {}",
                        err
                    )));
                }
            };
        });

        for (param_ident, param_type) in params {
            let param_name_str = param_ident.to_string();
            let param_type_str_for_check = quote!(#param_type).to_string().replace(" ", "");
            let is_option_param_type = param_type_str_for_check.starts_with("Option<")
                || param_type_str_for_check.starts_with("std::option::Option<")
                || param_type_str_for_check.starts_with("core::option::Option<");

            let per_param_extraction_code = if is_option_param_type {
                quote! {
                    let #param_ident: #param_type;
                    match params_map_ref.get(#param_name_str) {
                        Some(arc_value_for_param) => {
                            match arc_value_for_param.clone().as_type::<#param_type>() {
                                Ok(val_option_t) => {
                                    #param_ident = val_option_t;
                                }
                                Err(err) => {
                                    #func_param_ctx_ident.error(format!("Failed to convert Option parameter '{}' (type '{}') from ArcValueType: {}", #param_name_str, stringify!(#param_type), err));
                                    return Err(anyhow!(format!("Type conversion error for Option parameter '{}': {}", #param_name_str, err)));
                                }
                            }
                        }
                        None => {
                            #param_ident = None;
                        }
                    }
                }
            } else {
                quote! {
                    let #param_ident: #param_type = match params_map_ref.get(#param_name_str) {
                        Some(arc_value_for_param) => {
                            arc_value_for_param.clone().as_type::<#param_type>().map_err(|err| {
                                #func_param_ctx_ident.error(format!(
                                    "Failed to convert parameter '{}' (type '{}') from ArcValueType. Expected concrete type. Error: {}",
                                    #param_name_str,
                                    stringify!(#param_type),
                                    err
                                ));
                                anyhow!(format!("Type conversion error for parameter '{}': {}", #param_name_str, err))
                            })?
                        }
                        None => {
                            #func_param_ctx_ident.error(format!("Required parameter '{}' (type '{}') not found in payload", #param_name_str, stringify!(#param_type)));
                            return Err(anyhow!(format!("Missing required parameter '{}'", #param_name_str)));
                        }
                    };
                }
            };
            extractions.extend(per_param_extraction_code);
        }
    }

    extractions
}

/// Generate method call with extracted parameters
fn generate_method_call(
    fn_ident: &Ident,
    params: &[(Ident, Type)],
    is_async: bool,
) -> TokenStream2 {
    let param_idents = params.iter().map(|(ident, _)| {
        quote! { #ident }
    });

    let method_call = quote! {
        inner_self.#fn_ident(#(#param_idents,)* &ctx)
    };

    if is_async {
        quote! { #method_call.await }
    } else {
        quote! { #method_call }
    }
}
