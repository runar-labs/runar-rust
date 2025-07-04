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
        let group_field_ident = format_ident!("{}_encrypted", label);

        // Build substruct definition
        let sub_fields_tokens: Vec<_> = fields
            .iter()
            .map(|(id, ty)| quote! { pub #id: #ty, })
            .collect();

        substruct_defs.push(quote! {
            #[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
            struct #substruct_ident {
                #(#sub_fields_tokens)*
            }
        });

        // Build encryption arm for this label
        let substruct_build_fields: Vec<_> = fields
            .iter()
            .map(|(id, _)| quote! { #id: self.#id.clone(), })
            .collect();
        let label_lit = LitStr::new(label, proc_macro2::Span::call_site());
        encrypt_label_match_arms.push(quote! {
            #group_field_ident: if resolver.can_resolve(#label_lit) {
                let group_struct = #substruct_ident { #(#substruct_build_fields)* };
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
                if let Ok(tmp) = runar_serializer::encryption::decrypt_label_group::<#substruct_ident>(group, keystore) {
                    #(#assign_fields)*
                }
            }
        });

        // field in encrypted struct
        encrypted_struct_label_fields.push(quote! { pub #group_field_ident: Option<runar_serializer::encryption::EncryptedLabelGroup>, });
    }

    // Plaintext fields in encrypted struct
    let encrypted_plaintext_fields: Vec<_> = plaintext_fields
        .iter()
        .map(|(id, ty)| quote! { pub #id: #ty, })
        .collect();

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

    // Generate encrypted struct definition
    let encrypted_struct_def = quote! {
        #[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
        pub struct #encrypted_name {
            #(#encrypted_plaintext_fields)*
            #(#encrypted_struct_label_fields)*
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

        // ----- encrypted struct -----
        #encrypted_struct_def

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
