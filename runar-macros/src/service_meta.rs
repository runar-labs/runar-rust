use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use std::collections::HashMap;
use syn::{parse_macro_input, Fields, ItemStruct};

/// Internal helper – parse `name = ".."` style attribute list into a HashMap
fn parse_attrs(attr: TokenStream) -> HashMap<String, String> {
    let mut map = HashMap::new();

    if attr.is_empty() {
        return map;
    }

    let attr_str = attr.to_string();
    for pair in attr_str.split(',') {
        let parts: Vec<&str> = pair.split('=').collect();
        if parts.len() != 2 {
            continue;
        }
        let key = parts[0].trim().to_string();
        let value_part = parts[1].trim();
        if value_part.starts_with('"') && value_part.ends_with('"') {
            let value = value_part[1..value_part.len() - 1].to_string();
            map.insert(key, value);
        }
    }
    map
}

// Internal implementation called from lib.rs entry point.
pub fn service_meta_impl(attr: TokenStream, item: TokenStream) -> TokenStream {
    // Parse the original struct
    let input_ast = parse_macro_input!(item as ItemStruct);
    let struct_ident = &input_ast.ident;
    let vis = &input_ast.vis;
    let attrs = &input_ast.attrs;
    let generics = &input_ast.generics;
    let where_clause = &generics.where_clause;

    // Parse macro attribute key/value pairs
    let attr_map = parse_attrs(attr);

    let name_value = attr_map
        .get("name")
        .cloned()
        .unwrap_or_else(|| struct_ident.to_string());
    let path_value = attr_map
        .get("path")
        .cloned()
        .unwrap_or_else(|| name_value.to_lowercase().replace(' ', "_"));
    let description_value = attr_map
        .get("description")
        .cloned()
        .unwrap_or_else(|| format!("Service generated for {struct_ident}"));
    let version_value = attr_map
        .get("version")
        .cloned()
        .unwrap_or_else(|| "1.0.0".to_string());

    // Collect original fields and build new field list
    let (field_defs, default_inits, clone_inits): (TokenStream2, TokenStream2, TokenStream2) =
        match &input_ast.fields {
            Fields::Named(fields_named) => {
                let mut defs = Vec::<TokenStream2>::new();
                let mut inits = Vec::<TokenStream2>::new();
                let mut clones = Vec::<TokenStream2>::new();

                for field in &fields_named.named {
                    let field_ident = field.ident.as_ref().unwrap();
                    defs.push(quote! { #field, });
                    inits.push(quote! { #field_ident: ::core::default::Default::default(), });
                    clones.push(quote! { #field_ident: self.#field_ident.clone(), });
                }
                (
                    quote! { #(#defs)* },
                    quote! { #(#inits)* },
                    quote! { #(#clones)* },
                )
            }
            Fields::Unit => (quote! {}, quote! {}, quote! {}),
            Fields::Unnamed(_) => {
                return TokenStream::from(quote! {
                    compile_error!("`#[service_meta]` does not currently support tuple structs");
                });
            }
        };

    // Metadata hidden fields
    let meta_fields = quote! {
        #[doc(hidden)]
        name: ::std::string::String,
        #[doc(hidden)]
        path: ::std::string::String,
        #[doc(hidden)]
        description: ::std::string::String,
        #[doc(hidden)]
        version: ::std::string::String,
        #[doc(hidden)]
        network_id: ::std::option::Option<::std::string::String>,
    };

    // Build struct definition
    let struct_def = if matches!(input_ast.fields, Fields::Unit) {
        quote! {
            #(#attrs)*
            #vis struct #struct_ident #generics {
                #meta_fields
            } #where_clause
        }
    } else {
        quote! {
            #(#attrs)*
            #vis struct #struct_ident #generics {
                #field_defs
                #meta_fields
            } #where_clause
        }
    };

    // Implement Default
    let default_impl = quote! {
        impl #generics ::core::default::Default for #struct_ident #generics #where_clause {
            fn default() -> Self {
                Self {
                    #default_inits
                    name: #name_value.to_string(),
                    path: #path_value.to_string(),
                    description: #description_value.to_string(),
                    version: #version_value.to_string(),
                    network_id: None,
                }
            }
        }
    };

    // Implement helper getters & setters
    let helpers = quote! {
        impl #generics #struct_ident #generics #where_clause {
            #[inline]
            pub fn get_name(&self) -> &str { &self.name }
            #[inline]
            pub fn get_path(&self) -> &str { &self.path }
            #[inline]
            pub fn get_description(&self) -> &str { &self.description }
            #[inline]
            pub fn get_version(&self) -> &str { &self.version }
            #[inline]
            pub fn get_network_id(&self) -> Option<String> { self.network_id.clone() }

            pub fn set_name(&mut self, value: impl Into<String>) { self.name = value.into(); }
            pub fn set_path(&mut self, value: impl Into<String>) { self.path = value.into(); }
            pub fn set_description(&mut self, value: impl Into<String>) { self.description = value.into(); }
            pub fn set_version(&mut self, value: impl Into<String>) { self.version = value.into(); }
            pub fn set_network_id(&mut self, value: impl Into<String>) { self.network_id = Some(value.into()); }
        }
    };

    // Implement Clone (deep clone of all fields)
    let clone_impl = quote! {
        impl #generics ::core::clone::Clone for #struct_ident #generics #where_clause {
            fn clone(&self) -> Self {
                Self {
                    #clone_inits
                    name: self.name.clone(),
                    path: self.path.clone(),
                    description: self.description.clone(),
                    version: self.version.clone(),
                    network_id: self.network_id.clone(),
                }
            }
        }
    };

    let expanded = quote! {
        #struct_def
        #default_impl
        #helpers
        #clone_impl
    };

    TokenStream::from(expanded)
}
