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
    parse_macro_input, punctuated::Punctuated, token::Comma, FnArg, GenericArgument, Ident, ItemFn,
    Lit, Pat, PathArguments, ReturnType, Type,
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
    let params = crate::utils::extract_parameters(&input);

    // Extract the return type information for proper handling
    let return_type_info = extract_return_type_info(&input.sig.output);

    // Check if the function is async
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
    // original_fn_ctx_ident_opt is now populated by the loop above,
    // the next line `original_fn_has_request_context_param` will use it.
    let original_fn_has_request_context_param = original_fn_ctx_ident_opt.is_some();
    // This ctx_ident is for the LifecycleContext in the generated register_action_... method
    let lifecycle_ctx_ident = Ident::new("context", proc_macro2::Span::call_site());

    // Generate schema for inputs
    let mut input_properties_map_tokens = Vec::new();
    let mut required_input_fields_tokens = Vec::new();
    let mut has_input_payload = false;

    for (param_ident, param_type) in params.iter() {
        // Skip RequestContext and other non-payload parameters if any are identified
        if let Type::Path(type_path) = param_type {
            if get_path_last_segment_ident_string(type_path).as_deref() == Some("RequestContext") {
                continue;
            }
        }
        has_input_payload = true;
        let param_name_str = param_ident.to_string();
        let (final_param_type_for_schema, is_option_for_schema_generation) =
            if let Some(inner_ty) = get_option_inner_type(param_type) {
                // Pass by reference
                (inner_ty, true)
            } else {
                (param_type, false) // Ensure consistent return type (&Type, bool)
            };

        let field_schema_tokens = generate_field_schema_for_type(
            &param_name_str,
            final_param_type_for_schema,
            is_option_for_schema_generation,
            None,
        );
        input_properties_map_tokens.push(quote! {
            properties_map.insert(#param_name_str.to_string(), #field_schema_tokens);
        });

        if !is_option_for_schema_generation {
            required_input_fields_tokens.push(quote!(#param_name_str.to_string()));
        }
    }

    let input_schema_tokens = if has_input_payload {
        quote! {{
            let mut properties_map = ::std::collections::HashMap::new();
            #(#input_properties_map_tokens)*
            let required_fields = vec![#(#required_input_fields_tokens),*];
            let mut schema = ::runar_common::types::schemas::FieldSchema::new(
                "input_payload",
                ::runar_common::types::schemas::SchemaDataType::OBJECT
            );
            schema.properties = properties_map;
            schema.required = required_fields;
            Some(schema)
        }}
    } else {
        quote!(None)
    };

    // Generate schema for output
    let output_schema_tokens = if return_type_info.is_unit {
        quote!(None)
    } else {
        let schema_gen_type = &return_type_info.actual_type;
        let schema_is_nullable = return_type_info.actual_type_is_option;
        let generated_schema = generate_field_schema_for_type(
            "output_payload",
            schema_gen_type,
            schema_is_nullable,
            None,
        );
        quote!(Some(#generated_schema))
    };

    // Generate the register action method based on return type information
    let generated_code = generate_register_action_method(
        &input.sig.ident,
        &action_name,
        &action_path,
        &params,
        &return_type_info.is_primitive,
        &return_type_info.type_name,
        is_async,
        &lifecycle_ctx_ident, // Pass the ident for LifecycleContext
        original_fn_has_request_context_param,
        input_schema_tokens,
        output_schema_tokens,
    );

    // Combine the original function with the generated register method
    let expanded = quote! {
        #input

        #generated_code
    };

    expanded.into()
}

/// Extract information about the return type for proper handling.
// This function robustly supports all valid Rust types, including nested generics.
fn extract_return_type_info(return_type: &ReturnType) -> ReturnTypeInfo {
    let (actual_type, is_unit, actual_type_is_option, is_primitive, type_name) = match return_type {
        ReturnType::Default => (
            syn::parse_quote! { () },
            true,
            false,
            true,
            "unit".to_string(),
        ),
        ReturnType::Type(_, original_ty) => {
            let mut current_type = *original_ty.clone();
            let mut outer_is_option = false;

            // Check for outer Result<T, E>
            if let Some(inner_ty_of_result) = get_result_inner_type(&current_type) {
                // is_result = true; // This info is not directly used by schema or ArcValue conversion logic anymore
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
                // Handle other types like arrays, references, etc., or default to unknown
                // For simplicity, using quote to stringify, but this might not be ideal for all cases.
                quote!(#current_type).to_string().replace(" ", "")
            };

            let is_primitive_val = matches!(
                type_name_str.as_str(),
                "String" | "str" | "i32" | "i64" | "f32" | "f64" | "bool" | "unit"
            );

            (
                current_type,
                false,
                outer_is_option,
                is_primitive_val,
                type_name_str,
            )
        }
    };

    ReturnTypeInfo {
        is_primitive,
        is_unit,
        actual_type,
        actual_type_is_option,
        type_name,
    }
}

/// Struct to hold information about the return type
#[derive(Debug, Clone)]
struct ReturnTypeInfo {
    is_primitive: bool,
    is_unit: bool,
    actual_type: Type,
    actual_type_is_option: bool,
    type_name: String,
}

// Helper to get the last segment of a TypePath as a String
fn get_path_last_segment_ident_string(type_path: &syn::TypePath) -> Option<String> {
    type_path
        .path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
}

// Helper to extract T from Option<T>
fn get_option_inner_type(ty: &syn::Type) -> Option<&syn::Type> {
    if let syn::Type::Path(type_path) = ty {
        if type_path.path.segments.len() == 1
            && type_path.path.segments.first().unwrap().ident == "Option"
        {
            if let PathArguments::AngleBracketed(params) =
                &type_path.path.segments.first().unwrap().arguments
            {
                if let Some(syn::GenericArgument::Type(inner_ty)) = params.args.first() {
                    return Some(inner_ty);
                }
            }
        }
    }
    None
}

// Helper to extract T from Result<T, E>
fn get_result_inner_type(ty: &syn::Type) -> Option<&syn::Type> {
    if let syn::Type::Path(type_path) = ty {
        if type_path.qself.is_none() && type_path.path.segments.len() == 1 {
            let segment = &type_path.path.segments[0];
            if segment.ident == "Result" {
                if let syn::PathArguments::AngleBracketed(params) = &segment.arguments {
                    if let Some(syn::GenericArgument::Type(inner_ty)) = params.args.first() {
                        return Some(inner_ty);
                    }
                }
            }
        }
    }
    None
}

// Helper to extract T from Vec<T>
fn get_vec_inner_type(ty: &syn::Type) -> Option<&syn::Type> {
    if let syn::Type::Path(type_path) = ty {
        if type_path.path.segments.len() == 1
            && type_path.path.segments.first().unwrap().ident == "Vec"
        {
            if let PathArguments::AngleBracketed(params) =
                &type_path.path.segments.first().unwrap().arguments
            {
                if let Some(GenericArgument::Type(inner_ty)) = params.args.first() {
                    return Some(inner_ty); // Apply borrow as per E0308
                }
            }
        }
    }
    None
}

fn generate_field_schema_for_type(
    field_name_str: &str,
    ty: &syn::Type,
    is_top_level_nullable: bool,
    description_opt: Option<&str>,
) -> TokenStream2 {
    let name_literal = proc_macro2::Literal::string(field_name_str);
    let description_literal_opt = description_opt.map(proc_macro2::Literal::string);

    // Handle Option<T>: Generate schema for T, then set schema.nullable = Some(true).
    if let Some(inner_ty_for_option) = get_option_inner_type(ty) {
        // The schema name and description belong to the Option itself (conceptually).
        // The inner type T is generated with its own name (which is the same outer name here)
        // and its own nullability (is_top_level_nullable = false, unless T is Option<Option<U>>).
        let item_schema_tokens =
            generate_field_schema_for_type(field_name_str, inner_ty_for_option, false, None);

        let mut desc_setter = quote! {};
        if let Some(desc_lit) = description_literal_opt {
            desc_setter = quote! { schema.description = Some(#desc_lit.to_string()); };
        }

        return quote! {{
            let mut schema = #item_schema_tokens;
            schema.name = #name_literal.to_string(); // Ensure outer name is used
            schema.nullable = Some(true);
            #desc_setter
            schema
        }};
    }

    let base_schema_constructor_call;
    let mut additional_fields_setup = quote! {};

    // Handle Vec<T>
    if let Some(inner_ty_for_vec) = get_vec_inner_type(ty) {
        // For Vec items, the name is often context-dependent (e.g., "item") or not explicitly named in the schema structure itself.
        // The FieldSchema for the array will have the field_name_str.
        // The items schema describes the type of elements in the array.
        let items_schema_tokens =
            generate_field_schema_for_type("item", inner_ty_for_vec, false, None);
        base_schema_constructor_call = quote! {
            ::runar_common::types::schemas::FieldSchema::new(#name_literal, ::runar_common::types::schemas::SchemaDataType::ARRAY)
        };
        additional_fields_setup.extend(quote! {
            schema.items = Some(Box::new(#items_schema_tokens));
        });
    }
    // Handle Path types (structs, primitives)
    else if let syn::Type::Path(type_path) = ty {
        let type_name_str = get_path_last_segment_ident_string(type_path)
            .unwrap_or_else(|| "unknown_type".to_string());

        match type_name_str.as_str() {
            "String" => {
                base_schema_constructor_call = quote! { ::runar_common::types::schemas::FieldSchema::new(#name_literal, ::runar_common::types::schemas::SchemaDataType::STRING) }
            }
            "i32" | "isize" => {
                base_schema_constructor_call = quote! { ::runar_common::types::schemas::FieldSchema::new(#name_literal, ::runar_common::types::schemas::SchemaDataType::INT32) }
            }
            "i64" => {
                base_schema_constructor_call = quote! { ::runar_common::types::schemas::FieldSchema::new(#name_literal, ::runar_common::types::schemas::SchemaDataType::INT64) }
            }
            "f32" => {
                base_schema_constructor_call = quote! { ::runar_common::types::schemas::FieldSchema::new(#name_literal, ::runar_common::types::schemas::SchemaDataType::FLOAT) }
            }
            "f64" => {
                base_schema_constructor_call = quote! { ::runar_common::types::schemas::FieldSchema::new(#name_literal, ::runar_common::types::schemas::SchemaDataType::DOUBLE) }
            }
            "bool" => {
                base_schema_constructor_call = quote! { ::runar_common::types::schemas::FieldSchema::new(#name_literal, ::runar_common::types::schemas::SchemaDataType::BOOLEAN) }
            }
            // TODO: Add other specific types like Timestamp if they have constructors
            _ => {
                // Default to Object for unknown structs or complex types
                // For struct types, ideally, we would introspect fields here.
                // For now, creating an empty properties map for generic objects.
                base_schema_constructor_call = quote! {
                    ::runar_common::types::schemas::FieldSchema::new(#name_literal, ::runar_common::types::schemas::SchemaDataType::OBJECT)
                };
            }
        };
    }
    // Fallback for other unknown types
    else {
        base_schema_constructor_call = quote! {
            ::runar_common::types::schemas::FieldSchema::new(#name_literal, ::runar_common::types::schemas::SchemaDataType::ANY)
        };
    }

    // Set nullable and description for non-Option base types
    additional_fields_setup.extend(quote! {
        schema.nullable = Some(#is_top_level_nullable);
    });
    if let Some(desc_lit) = description_literal_opt {
        additional_fields_setup.extend(quote! {
            schema.description = Some(#desc_lit.to_string());
        });
    }

    quote! {{
        let mut schema = #base_schema_constructor_call;
        #additional_fields_setup
        schema
    }}
}

/// Generate the register action method
#[allow(clippy::too_many_arguments)]
fn generate_register_action_method(
    fn_ident: &Ident,
    action_name: &str,
    action_path: &str,
    params: &[(Ident, Type)],
    is_primitive: &bool,
    type_name: &String,
    is_async: bool,
    _lifecycle_ctx_ident: &Ident, // Renamed as it's for the LifecycleContext, not the RequestContext for the handler
    original_fn_has_request_context_param: bool,
    input_schema_opt_tokens: TokenStream2,
    output_schema_opt_tokens: TokenStream2,
) -> TokenStream2 {
    // Create a boolean expression for checking if there are parameters
    let has_params = if params.is_empty() {
        quote! { false }
    } else {
        quote! { true }
    };

    // Generate parameter extraction code
    let param_extractions = generate_parameter_extractions(params, action_name);

    // Generate method call with extracted parameters
    let method_call_params_only = params
        .iter()
        .filter(|(_, param_type)| match param_type {
            Type::Path(tp) => {
                get_path_last_segment_ident_string(tp).as_deref() != Some("RequestContext")
            }
            _ => true,
        })
        .cloned()
        .collect::<Vec<(Ident, Type)>>();

    let method_call = generate_method_call(
        fn_ident,
        &method_call_params_only,
        is_async,
        original_fn_has_request_context_param,
    );

    // Generate the appropriate result handling based on the return type
    let result_handling = if type_name == "()" {
        quote! {
            // For () return type, convert to ArcValue::null()
            Ok(runar_serializer::ArcValue::null())
        }
    } else if type_name == "ArcValue" {
        // Check if the result is already an ArcValue
        quote! {
            // Result is already ArcValue, pass it through directly
            Ok(result)
        }
    } else if *is_primitive {
        quote! {
            // Convert the primitive result to ArcValue
            let value_type = runar_serializer::ArcValue::new_primitive(result);
            Ok(value_type)
        }
    } else {
        quote! {
            // Convert the complex result to ArcValue using from_struct
            let value_type = runar_serializer::ArcValue::from_struct(result);
            Ok(value_type)
        }
    };

    // Generate a unique method name for the action registration
    let register_method_name = format_ident!("register_action_{}", fn_ident);

    // The handler's RequestContext parameter is hardcoded to `ctx`
    let handler_request_ctx_ident = format_ident!("ctx");

    quote! {
        async fn #register_method_name(&self, context: &runar_node::services::LifecycleContext) -> anyhow::Result<()> {
            context.logger.info(format!("Registering '{}' action", #action_name));

            // Create a clone of self that can be moved into the closure
            let self_clone = self.clone();

            // Create the action handler as an Arc to match what the register_action expects
            let handler = std::sync::Arc::new(move |params_opt: Option<runar_serializer::ArcValue>, #handler_request_ctx_ident: runar_node::services::RequestContext|
                -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<runar_serializer::ArcValue, anyhow::Error>> + Send>> {
                let inner_self = self_clone.clone();

                Box::pin(async move {
                    // Extract parameters from the map if available
                    let mut params_value = match params_opt {
                        Some(p) => p,
                        None => {
                            // Check if method expects parameters
                            if #has_params {
                                #handler_request_ctx_ident.error("No parameters provided".to_string());
                                return Err(anyhow!("No parameters provided"));
                            } else {
                                // No parameters expected, so create an empty map
                                runar_serializer::ArcValue::new_map(
                                    std::collections::HashMap::<String, runar_serializer::ArcValue>::new()
                                )
                            }
                        }
                    };

                    // #param_extractions uses `ctx` internally, which should resolve to #handler_request_ctx_ident
                    #param_extractions

                    // Call the actual method with the extracted parameters
                    match #method_call {
                        Ok(result) => {
                            #result_handling
                        },
                        Err(err) => {
                            // Return an error response
                            #handler_request_ctx_ident.error(format!("Action '{}' failed: {}", #action_name, err));
                            return Err(anyhow!(err.to_string()));
                        }
                    }
                })
            });

            // Construct ActionRegistrationOptions
            let action_registration_options = ::runar_node::services::ActionRegistrationOptions {
                description: Some(#action_name.to_string()),
                input_schema: #input_schema_opt_tokens,
                output_schema: #output_schema_opt_tokens,
            };

            // Register the action handler with the configured path
            context.register_action_with_options(
                #action_path, // This is &str
                handler.clone(),      // Pass the Arc'd handler closure
                action_registration_options
            ).await?;

            Ok(())
        }
    }
}

/// Generate parameter extraction code to exactly match the reference implementation
///
/// The extractor always assumes the inbound payload (if present) is an
/// `ArcValue::Map` whose values are `ArcValue`s. It converts each entry to the
/// concrete parameter type expected by the action method, handling `Option<T>`
/// parameters gracefully.
///
/// Single-parameter actions still benefit from a fallback where the payload can
/// be a direct primitive or struct value instead of a map.
fn generate_parameter_extractions(params: &[(Ident, Type)], _fn_name_str: &str) -> TokenStream2 {
    let mut extractions = TokenStream2::new();

    if params.is_empty() {
        // No parameters to extract. params_value should be handled by the caller (e.g. warn if Some).
        return extractions;
    }

    // If there is only one parameter, try to extract it from the payload in two ways:
    // 1. First try to extract the parameter from a map where the key is the parameter name
    // 2. If that fails, try to deserialize the entire input directly into the parameter type
    if params.len() == 1 {
        let (param_ident, param_type) = &params[0];
        let param_name_str = param_ident.to_string();

        extractions.extend(quote! {
            let #param_ident: #param_type = {
                // First try to extract from a map if the payload is a map
                let mut params_value_clone = params_value.clone();
                let map_result = params_value_clone.as_map_ref::<String, runar_serializer::ArcValue>();
                match map_result {
                    Ok(map_ref) => {
                        // If it's a map, try to get the parameter by name
                        if let Some(value) = map_ref.get(#param_name_str) {
                            match value.clone().as_type::<#param_type>() {
                                Ok(val) => val,
                                Err(map_err) => {
                                    ctx.error(format!(
                                        "Failed to parse parameter '{}' from map: {}",
                                        #param_name_str,
                                        map_err
                                    ));
                                    return Err(anyhow!(
                                        format!("Failed to parse parameter '{}': {}", #param_name_str, map_err)
                                    ));
                                }
                            }
                        } else {
                            // Parameter not found in map, try direct deserialization
                            match params_value.as_type::<#param_type>() {
                                Ok(val) => val,
                                Err(err) => {
                                    ctx.error(format!(
                                        "Parameter '{}' not found in payload map and direct deserialization failed: {}",
                                        #param_name_str,
                                        err
                                    ));
                                    return Err(anyhow!(
                                        format!("Parameter '{}' not found in payload", #param_name_str)
                                    ));
                                }
                            }
                        }
                    },
                    Err(_) => {
                        // If it's not a map, try direct deserialization
                        match params_value.as_type::<#param_type>() {
                            Ok(val) => val,
                            Err(err) => {
                                ctx.error(format!("Failed to parse parameter for single-parameter action: {}", err));
                                return Err(anyhow!(
                                    format!("Failed to parse parameter for single-parameter action: {}", err)
                                ));
                            }
                        }
                    }
                }
            };
        });
        return extractions;
    }

    // Multiple parameters (params.len() > 1)
    // Always treat the payload as Map<String, ArcValue>. This supports both homogeneous
    // and heterogeneous value types in a single, predictable path.
    extractions.extend(quote! {
        let params_map_ref = match params_value.as_map_ref::<String, runar_serializer::ArcValue>() {
            Ok(map_ref) => map_ref,
            Err(err) => {
                ctx.error(format!(
                    "Action parameters must be provided as a map (for heterogeneous types, expecting Map<String, ArcValue>), but received an incompatible type. Error: {}",
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
                                ctx.error(format!("Failed to convert value for parameter '{}' to type '{}'. Error: {}", #param_name_str, stringify!(#param_type), err));
                                return Err(anyhow!(format!("Type conversion error for parameter '{}': {}", #param_name_str, err)));
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
                            ctx.error(format!("Failed to convert value for parameter '{}' to type '{}'. Error: {}", #param_name_str, stringify!(#param_type), err));
                            anyhow!(format!("Type conversion error for parameter '{}': {}", #param_name_str, err))
                        })?
                    }
                    None => {
                        ctx.error(format!("Required parameter '{}' (type '{}') not found in payload", #param_name_str, stringify!(#param_type)));
                        return Err(anyhow!(format!("Missing required parameter '{}'", #param_name_str)));
                    }
                };
            }
        };
        extractions.extend(per_param_extraction_code);
    }

    extractions
}

/// Generate method call with extracted parameters
fn generate_method_call(
    fn_ident: &Ident,
    params: &[(Ident, Type)],
    is_async: bool,
    pass_request_context: bool,
) -> TokenStream2 {
    let param_idents = params.iter().map(|(ident, _)| {
        quote! { #ident }
    });

    let call_args = quote! { #(#param_idents,)* };
    let method_call = if pass_request_context {
        // The `&ctx` here refers to the `ctx: RequestContext` parameter of the handler closure
        quote! { inner_self.#fn_ident(#call_args &ctx) }
    } else {
        quote! { inner_self.#fn_ident(#call_args) }
    };

    if is_async {
        quote! { #method_call.await }
    } else {
        quote! { #method_call }
    }
}
