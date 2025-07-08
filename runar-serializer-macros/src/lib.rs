use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::punctuated::Punctuated;
use syn::token::Comma;
use syn::{parse_macro_input, Attribute, Data, DeriveInput, Fields, Ident, LitStr, Type};

/// Capitalize first letter of a &str
fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

/// Parse a `#[runar(label1, label2)]` attribute and return Vec<label>
fn parse_runar_labels(attr: &Attribute) -> Vec<String> {
    if !attr.path().is_ident("runar") {
        return vec![];
    }
    // Parse inside the parentheses as a punctuated list of idents
    let parsed: Punctuated<Ident, Comma> = match attr.parse_args_with(Punctuated::parse_terminated)
    {
        Ok(p) => p,
        Err(_) => return vec![],
    };
    parsed.iter().map(|ident| ident.to_string()).collect()
}

/// Derive macro for encryption
#[proc_macro_derive(Encrypt, attributes(runar))]
pub fn derive_encrypt(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let struct_name = input.ident.clone();
    let encrypted_name = format_ident!("Encrypted{}", struct_name);

    // Collect fields metadata
    let mut plaintext_fields: Vec<(Ident, Type)> = Vec::new();
    let mut label_groups: std::collections::BTreeMap<String, Vec<(Ident, Type)>> =
        std::collections::BTreeMap::new();

    if let Data::Struct(ds) = input.data {
        if let Fields::Named(named) = ds.fields {
            for field in named.named.iter() {
                let field_ident = field.ident.clone().expect("Expected named field");
                let field_ty = field.ty.clone();
                let mut labels = Vec::new();
                for attr in &field.attrs {
                    labels.extend(parse_runar_labels(attr));
                }
                if labels.is_empty() {
                    plaintext_fields.push((field_ident, field_ty));
                } else {
                    for label in labels {
                        label_groups
                            .entry(label)
                            .or_default()
                            .push((field_ident.clone(), field_ty.clone()));
                    }
                }
            }
        } else {
            return syn::Error::new_spanned(
                struct_name,
                "Encrypt derive only supports structs with named fields",
            )
            .to_compile_error()
            .into();
        }
    } else {
        return syn::Error::new_spanned(struct_name, "Encrypt derive only supports structs")
            .to_compile_error()
            .into();
    }

    // ---------- Generate code tokens ----------
    let mut substruct_defs = Vec::new();
    let mut encrypt_label_match_arms = Vec::new();
    let mut decrypt_label_blocks = Vec::new();
    let mut encrypted_struct_label_fields = Vec::new();
    // Proto generation collections
    let mut proto_substruct_defs = Vec::new();
    let mut _encrypted_struct_proto_label_fields_unused: Vec<proc_macro2::TokenStream> = Vec::new();
    let mut label_to_proto_assigns = Vec::new();
    let mut proto_to_label_assigns = Vec::new();

    // Determine label processing order: system first, user second, then alphabetical
    let mut label_order: Vec<_> = label_groups.keys().cloned().collect();
    label_order.sort_by(|a, b| {
        let rank = |l: &String| match l.as_str() {
            "system" => 0,
            "user" => 1,
            _ => 2,
        };
        rank(a).cmp(&rank(b)).then_with(|| a.cmp(b))
    });

    for label in &label_order {
        let fields = &label_groups[label];
        let cap_label = capitalize(label);
        let substruct_ident = format_ident!("{}{}Fields", struct_name, cap_label);
        let substruct_proto_ident = format_ident!("{}{}FieldsProto", struct_name, cap_label);
        let group_field_ident = format_ident!("{}_encrypted", label);

        // Build substruct definition (plain struct without prost)
        let sub_fields_tokens: Vec<_> = fields
            .iter()
            .map(|(id, ty)| quote! { pub #id: #ty, })
            .collect();

        // Keeping a plain substruct for ergonomic access; no derives needed beyond Clone for build
        substruct_defs.push(quote! {
            #[derive(Clone)]
            struct #substruct_ident {
                #(#sub_fields_tokens)*
            }
        });

        // Build encryption arm for this label using the *Proto* variant (which is prost::Message)
        let substruct_build_fields: Vec<_> = fields
            .iter()
            .map(|(id, _)| quote! { #id: self.#id.clone(), })
            .collect();
        let label_lit = LitStr::new(label, proc_macro2::Span::call_site());
        encrypt_label_match_arms.push(quote! {
            #group_field_ident: if resolver.can_resolve(#label_lit) {
                let group_struct = #substruct_proto_ident { #(#substruct_build_fields)* };
                Some(runar_serializer::encryption::encrypt_label_group(#label_lit, &group_struct, keystore, resolver)?)
            } else { None },
        });

        // Build decryption block (will assign into `decrypted`)
        let assign_fields: Vec<_> = fields
            .iter()
            .map(|(id, _)| quote! { decrypted.#id = tmp.#id; })
            .collect();

        decrypt_label_blocks.push(quote! {
            if let Some(ref group) = self.#group_field_ident {
                if let Ok(tmp) = runar_serializer::encryption::decrypt_label_group::<#substruct_proto_ident>(group, keystore) {
                    #(#assign_fields)*
                }
            }
        });

        // field in encrypted struct
        encrypted_struct_label_fields.push(quote! { pub #group_field_ident: Option<runar_serializer::encryption::EncryptedLabelGroup>, });

        // -------- Proto specific --------

        // Build proto substruct fields with prost attributes
        let mut sub_fields_proto_tokens: Vec<proc_macro2::TokenStream> = Vec::new();
        for (idx, (fid, fty)) in fields.iter().enumerate() {
            let tag_num = idx + 1;
            // Map Rust types to prost types
            let proto_ty_ident = match quote::quote!(#fty).to_string().replace(' ', "").as_str() {
                "String" => proc_macro2::Ident::new("string", proc_macro2::Span::call_site()),
                "u64" => proc_macro2::Ident::new("uint64", proc_macro2::Span::call_site()),
                "u32" => proc_macro2::Ident::new("uint32", proc_macro2::Span::call_site()),
                "i32" => proc_macro2::Ident::new("int32", proc_macro2::Span::call_site()),
                "i64" => proc_macro2::Ident::new("int64", proc_macro2::Span::call_site()),
                "bool" => proc_macro2::Ident::new("bool", proc_macro2::Span::call_site()),
                _ => proc_macro2::Ident::new("bytes", proc_macro2::Span::call_site()),
            };
            sub_fields_proto_tokens.push(quote! {
                #[prost(#proto_ty_ident, tag = #tag_num)]
                pub #fid: #fty,
            });
        }

        proto_substruct_defs.push(quote! {
            #[derive(serde::Serialize, serde::Deserialize, Clone, prost::Message)]
            pub struct #substruct_proto_ident {
                #(#sub_fields_proto_tokens)*
            }
        });

        // Field in encrypted *proto* struct uses raw bytes (serialized label group)
        _encrypted_struct_proto_label_fields_unused
            .push(quote! { pub #group_field_ident: Option<Vec<u8>>, });

        // Conversion assignment tokens (Encrypted -> Proto)
        label_to_proto_assigns.push(quote! {
            #group_field_ident: value.#group_field_ident.as_ref().map(|g| {
                let mut buf = Vec::new();
                prost::Message::encode(g, &mut buf).expect("encode label group");
                buf
            }),
        });

        // Conversion assignment tokens (Proto -> Encrypted)
        proto_to_label_assigns.push(quote! {
            #group_field_ident: value.#group_field_ident.as_ref().map(|bytes| {
                let group = prost::Message::decode(bytes.as_slice()).expect("decode label group");
                group
            }),
        });
    }

    // Initialisation tokens for plaintext fields in encrypt impl
    let encrypt_plaintext_inits: Vec<_> = plaintext_fields
        .iter()
        .map(|(id, _)| quote! { #id: self.#id.clone(), })
        .collect();

    // For decrypted initial default values
    let decrypted_plaintext_init: Vec<_> = plaintext_fields
        .iter()
        .map(|(id, _)| quote! { #id: self.#id.clone(), })
        .collect();

    // All labeled fields default init (Default::default())
    let mut labeled_field_defaults = Vec::new();
    for fields in label_groups.values() {
        for (id, _) in fields {
            labeled_field_defaults.push(quote! { #id: Default::default(), });
        }
    }

    // Remove duplicates in labeled_field_defaults (if field belongs to multiple labels)
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    let labeled_field_defaults: Vec<_> = labeled_field_defaults
        .into_iter()
        .filter(|tok| {
            // Extract ident name as string for uniqueness
            let s = tok.to_string();
            if seen.contains(&s) {
                false
            } else {
                seen.insert(s);
                true
            }
        })
        .collect();

    // Build encrypted struct field tokens with prost attributes
    let mut enc_plain_tokens: Vec<proc_macro2::TokenStream> = Vec::new();
    for (idx, (fid, fty)) in plaintext_fields.iter().enumerate() {
        let tag_num = idx + 1;
        let proto_ty_ident = match quote::quote!(#fty).to_string().replace(' ', "").as_str() {
            "String" => proc_macro2::Ident::new("string", proc_macro2::Span::call_site()),
            "u64" => proc_macro2::Ident::new("uint64", proc_macro2::Span::call_site()),
            "u32" => proc_macro2::Ident::new("uint32", proc_macro2::Span::call_site()),
            "i32" => proc_macro2::Ident::new("int32", proc_macro2::Span::call_site()),
            "i64" => proc_macro2::Ident::new("int64", proc_macro2::Span::call_site()),
            "bool" => proc_macro2::Ident::new("bool", proc_macro2::Span::call_site()),
            _ => proc_macro2::Ident::new("bytes", proc_macro2::Span::call_site()),
        };
        enc_plain_tokens.push(quote! {
            #[prost(#proto_ty_ident, tag = #tag_num)]
            pub #fid: #fty,
        });
    }

    // Label field tokens
    let mut enc_label_tokens: Vec<proc_macro2::TokenStream> = Vec::new();
    for (label_idx, label) in label_order.iter().enumerate() {
        let group_field_ident = format_ident!("{}_encrypted", label);
        let tag_num = plaintext_fields.len() + label_idx + 1;
        enc_label_tokens.push(quote! {
            #[prost(message, optional, tag = #tag_num)]
            pub #group_field_ident: ::core::option::Option<runar_serializer::encryption::EncryptedLabelGroup>,
        });
    }

    let encrypted_struct_def = quote! {
        #[derive(serde::Serialize, serde::Deserialize, Clone, prost::Message)]
        pub struct #encrypted_name {
            #(#enc_plain_tokens)*
            #(#enc_label_tokens)*
        }
    };

    // ---------- Encrypted *Proto* struct definition ----------
    let encrypted_proto_name = format_ident!("{}Proto", encrypted_name);
    // Build proto plaintext fields with prost attributes
    let mut proto_plaintext_fields_tokens: Vec<proc_macro2::TokenStream> = Vec::new();
    for (idx, (fid, fty)) in plaintext_fields.iter().enumerate() {
        let tag_num = idx + 1;
        // Map Rust types to prost types
        let proto_ty_ident = match quote::quote!(#fty).to_string().replace(' ', "").as_str() {
            "String" => proc_macro2::Ident::new("string", proc_macro2::Span::call_site()),
            "u64" => proc_macro2::Ident::new("uint64", proc_macro2::Span::call_site()),
            "u32" => proc_macro2::Ident::new("uint32", proc_macro2::Span::call_site()),
            "i32" => proc_macro2::Ident::new("int32", proc_macro2::Span::call_site()),
            "i64" => proc_macro2::Ident::new("int64", proc_macro2::Span::call_site()),
            "bool" => proc_macro2::Ident::new("bool", proc_macro2::Span::call_site()),
            _ => proc_macro2::Ident::new("bytes", proc_macro2::Span::call_site()),
        };
        proto_plaintext_fields_tokens.push(quote! {
            #[prost(#proto_ty_ident, tag = #tag_num)]
            pub #fid: #fty,
        });
    }

    // Build proto label fields with prost attributes
    let mut proto_label_field_tokens: Vec<proc_macro2::TokenStream> = Vec::new();
    for (label_idx, label) in label_order.iter().enumerate() {
        let group_field_ident = format_ident!("{}_encrypted", label);
        let tag_num = plaintext_fields.len() + label_idx + 1;
        proto_label_field_tokens.push(quote! {
            #[prost(bytes = "vec", optional, tag = #tag_num)]
            pub #group_field_ident: ::core::option::Option<Vec<u8>>,
        });
    }

    let encrypted_proto_struct_def = quote! {
        #[derive(serde::Serialize, serde::Deserialize, Clone, prost::Message)]
        pub struct #encrypted_proto_name {
            #(#proto_plaintext_fields_tokens)*
            #(#proto_label_field_tokens)*
        }
    };

    // ---------- Conversion impls between encrypted and proto ----------

    // Encrypted -> Proto
    let proto_assign_plaintext: Vec<_> = plaintext_fields
        .iter()
        .map(|(id, _)| quote! { #id: value.#id.clone(), })
        .collect();

    let encrypted_to_proto_impl = quote! {
        impl From<#encrypted_name> for #encrypted_proto_name {
            fn from(value: #encrypted_name) -> Self {
                Self {
                    #(#proto_assign_plaintext)*
                    #(#label_to_proto_assigns)*
                }
            }
        }
    };

    // Proto -> Encrypted
    let proto_to_encrypted_impl = quote! {
        impl From<#encrypted_proto_name> for #encrypted_name {
            fn from(value: #encrypted_proto_name) -> Self {
                Self {
                    #(#proto_assign_plaintext)* // plaintext cloning logic identical
                    #(#proto_to_label_assigns)*
                }
            }
        }
    };

    // Encrypt impl
    let encrypt_impl = quote! {
        let encrypted = #encrypted_name {
            #(#encrypt_plaintext_inits)*
            #(#encrypt_label_match_arms)*
        };
        Ok(encrypted)
    };

    // Decrypt impl
    let decrypt_impl = quote! {
        let mut decrypted = #struct_name {
            #(#decrypted_plaintext_init)*
            #(#labeled_field_defaults)*
        };
        #(#decrypt_label_blocks)*
        Ok(decrypted)
    };

    // Final expanded tokens
    let expanded = quote! {
        // ----- generated substructs -----
        #(#substruct_defs)*

        // ----- generated proto substructs -----
        #(#proto_substruct_defs)*

        // ----- encrypted struct -----
        #encrypted_struct_def

        // ----- encrypted proto struct -----
        #encrypted_proto_struct_def

        // ----- conversion impls between encrypted and proto -----
        #encrypted_to_proto_impl
        #proto_to_encrypted_impl

        // ----- trait impls -----
        impl runar_serializer::traits::RunarEncryptable for #struct_name {}

        impl runar_serializer::traits::RunarEncrypt for #struct_name {
            type Encrypted = #encrypted_name;
            fn encrypt_with_keystore(&self, keystore: &runar_serializer::traits::KeyStore, resolver: &dyn runar_serializer::traits::LabelResolver) -> anyhow::Result<Self::Encrypted> {
                #encrypt_impl
            }
        }

        impl runar_serializer::traits::RunarDecrypt for #encrypted_name {
            type Decrypted = #struct_name;
            fn decrypt_with_keystore(&self, keystore: &runar_serializer::traits::KeyStore) -> anyhow::Result<Self::Decrypted> {
                #decrypt_impl
            }
        }
    };

    TokenStream::from(expanded)
}

/// Decryption derive is just an alias
#[proc_macro_derive(Decrypt, attributes(runar))]
pub fn derive_decrypt(input: TokenStream) -> TokenStream {
    derive_encrypt(input)
}

/// No-op attribute macro to allow `#[runar(...)]` field annotations.
#[proc_macro_attribute]
pub fn runar(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}
