use proc_macro::TokenStream;
use quote::{format_ident, quote};
use std::collections::HashSet;
use syn::punctuated::Punctuated;
use syn::token::Comma;
use syn::{parse_macro_input, Attribute, Data, DeriveInput, Fields, Ident, Type};

fn parse_runar_labels(attr: &Attribute) -> Vec<String> {
    if !attr.path().is_ident("runar") {
        return vec![];
    }
    let parsed: Punctuated<Ident, Comma> =
        attr.parse_args_with(Punctuated::parse_terminated).unwrap();
    parsed.iter().map(|ident| ident.to_string()).collect()
}

fn label_to_camel_case(s: &str) -> String {
    s.split(['_', '-'])
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().collect::<String>() + chars.as_str(),
            }
        })
        .collect()
}

#[proc_macro_derive(Plain)]
pub fn derive_plain(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let struct_name = input.ident.clone();

    let expanded = quote! {
        impl runar_serializer::traits::RunarEncryptable for #struct_name {}

        impl runar_serializer::traits::RunarEncrypt for #struct_name {
            type Encrypted = #struct_name;

            fn encrypt_with_keystore(
                &self,
                _keystore: &std::sync::Arc<runar_serializer::KeyStore>,
                _resolver: &dyn runar_serializer::LabelResolver,
            ) -> anyhow::Result<Self::Encrypted> {
                Ok(self.clone())
            }
        }

        impl runar_serializer::traits::RunarDecrypt for #struct_name {
            type Decrypted = #struct_name;

            fn decrypt_with_keystore(
                &self,
                _keystore: &std::sync::Arc<runar_serializer::KeyStore>,
            ) -> anyhow::Result<Self::Decrypted> {
                Ok(self.clone())
            }
        }
    };

    TokenStream::from(expanded)
}

#[proc_macro_derive(Encrypt, attributes(runar))]
pub fn derive_encrypt(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let struct_name = input.ident.clone();
    let encrypted_name = format_ident!("Encrypted{}", struct_name);

    let mut plaintext_fields: Vec<(Ident, Type)> = Vec::new();
    let mut label_groups: std::collections::BTreeMap<String, Vec<(Ident, Type)>> =
        std::collections::BTreeMap::new();

    if let Data::Struct(ds) = input.data {
        if let Fields::Named(named) = ds.fields {
            for field in named.named.iter() {
                let field_ident = field.ident.clone().expect("Expected named field");
                let field_ty = field.ty.clone();
                let labels = field
                    .attrs
                    .iter()
                    .flat_map(parse_runar_labels)
                    .collect::<Vec<_>>();
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

    let mut label_order: Vec<_> = label_groups.keys().cloned().collect();
    label_order.sort_by(|a, b| {
        let rank = |l: &String| match l.as_str() {
            "system" => 0,
            "user" => 1,
            _ => 2,
        };
        rank(a).cmp(&rank(b)).then_with(|| a.cmp(b))
    });

    let mut substruct_defs = Vec::new();
    let mut encrypt_label_match_arms = Vec::new();
    let mut decrypt_label_blocks = Vec::new();
    let mut enc_label_tokens = Vec::new();
    let mut proto_plaintext_fields = Vec::new();

    for label in label_order.iter() {
        let fields = &label_groups[label];
        let cap_label = label_to_camel_case(label);
        let substruct_ident = format_ident!("{}{}Fields", struct_name, cap_label);
        let group_field_ident = format_ident!("{}_encrypted", label);

        let sub_fields_tokens: Vec<_> = fields
            .iter()
            .map(|(id, ty)| quote! { pub #id: #ty, })
            .collect();
        substruct_defs.push(quote! {
            #[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Default)]
            struct #substruct_ident {
                #(#sub_fields_tokens)*
            }
        });

        let substruct_build_fields: Vec<_> = fields
            .iter()
            .map(|(id, _)| quote! { #id: self.#id.clone(), })
            .collect();
        let label_lit = syn::LitStr::new(label, proc_macro2::Span::call_site());
        encrypt_label_match_arms.push(quote! {
            #group_field_ident: if resolver.can_resolve(#label_lit) {
                let group_struct = #substruct_ident { #(#substruct_build_fields)* };
                Some(runar_serializer::encryption::encrypt_label_group(#label_lit, &group_struct, keystore.as_ref(), resolver)?)
            } else {
                None
            },
        });

        let assign_fields: Vec<_> = fields
            .iter()
            .map(|(id, _)| quote! { decrypted.#id = tmp.#id; })
            .collect();
        decrypt_label_blocks.push(quote! {
            if let Some(ref group) = self.#group_field_ident {
                if let Ok(tmp) = runar_serializer::encryption::decrypt_label_group::<#substruct_ident>(group, keystore.as_ref()) {
                    #(#assign_fields)*
                }
            }
        });

        enc_label_tokens.push(quote! { pub #group_field_ident: ::core::option::Option<runar_serializer::encryption::EncryptedLabelGroup>, });
    }

    for (fid, fty) in plaintext_fields.iter() {
        proto_plaintext_fields.push(quote! { pub #fid: #fty, });
    }

    let encrypted_struct_def = quote! {
        #[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
        pub struct #encrypted_name {
            #(#proto_plaintext_fields)*
            #(#enc_label_tokens)*
        }
    };

    let encrypt_plaintext_inits: Vec<_> = plaintext_fields
        .iter()
        .map(|(id, _)| quote! { #id: self.#id.clone(), })
        .collect();
    let decrypted_plaintext_init: Vec<_> = plaintext_fields
        .iter()
        .map(|(id, _)| quote! { #id: self.#id.clone(), })
        .collect();
    let mut seen = HashSet::new();
    let labeled_field_defaults: Vec<_> = label_groups
        .values()
        .flat_map(|f| f.iter().map(|(id, _)| quote! { #id: Default::default(), }))
        .filter(|tok| {
            let s = tok.to_string();
            if seen.contains(&s) {
                false
            } else {
                seen.insert(s);
                true
            }
        })
        .collect();

    let encrypt_impl = quote! { let encrypted = #encrypted_name { #(#encrypt_plaintext_inits)* #(#encrypt_label_match_arms)* }; Ok(encrypted) };

    let decrypt_impl = quote! { let mut decrypted = #struct_name { #(#decrypted_plaintext_init)* #(#labeled_field_defaults)* }; #(#decrypt_label_blocks)* Ok(decrypted) };

    let expanded = quote! {
        #(#substruct_defs)*
        #encrypted_struct_def

        impl runar_serializer::traits::RunarEncryptable for #struct_name {}

        impl runar_serializer::traits::RunarEncrypt for #struct_name {
            type Encrypted = #encrypted_name;

            fn encrypt_with_keystore(
                &self,
                keystore: &std::sync::Arc<runar_serializer::KeyStore>,
                resolver: &dyn runar_serializer::LabelResolver,
            ) -> anyhow::Result<Self::Encrypted> {
                let encrypted = #encrypted_name { #(#encrypt_plaintext_inits)* #(#encrypt_label_match_arms)* };
                Ok(encrypted)
            }
        }

        impl runar_serializer::traits::RunarDecrypt for #encrypted_name {
            type Decrypted = #struct_name;

            fn decrypt_with_keystore(
                &self,
                keystore: &std::sync::Arc<runar_serializer::KeyStore>,
            ) -> anyhow::Result<Self::Decrypted> {
                let mut decrypted = #struct_name { #(#decrypted_plaintext_init)* #(#labeled_field_defaults)* };
                #(#decrypt_label_blocks)*
                Ok(decrypted)
            }
        }

        impl #struct_name {
            fn encrypt_with_keystore(
                &self,
                keystore: &std::sync::Arc<runar_serializer::KeyStore>,
                resolver: &dyn runar_serializer::LabelResolver,
            ) -> anyhow::Result<#encrypted_name> {
                #encrypt_impl
            }
        }

        impl #encrypted_name {
            fn decrypt_with_keystore(
                &self,
                keystore: &std::sync::Arc<runar_serializer::KeyStore>,
            ) -> anyhow::Result<#struct_name> {
                #decrypt_impl
            }
        }

        // Automatically register decryptor for this struct at program start.
        const _: () = {
            #[ctor::ctor]
            fn register_decryptor() {
                runar_serializer::registry::register_decrypt::<#struct_name, #encrypted_name>();
            }
        };

        // Mark encrypted struct as RunarEncryptable so it can appear inside ArcValue without further bounds.
        impl runar_serializer::traits::RunarEncryptable for #encrypted_name {}
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
