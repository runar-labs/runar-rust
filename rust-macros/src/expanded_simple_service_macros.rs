#![feature(prelude_import)]
#[prelude_import]
use std::prelude::rust_2021::*;
#[macro_use]
extern crate std;
use anyhow::{anyhow, Result};
use futures::lock::Mutex;
use runar_common::types::ArcValueType;
use runar_macros::{action, publish, service, subscribe};
use runar_node::services::{EventContext, RequestContext};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
struct MyData {
    id: i32,
    text_field: String,
    number_field: i32,
    boolean_field: bool,
    float_field: f64,
    vector_field: Vec<i32>,
    map_field: HashMap<String, i32>,
}
#[automatically_derived]
impl ::core::fmt::Debug for MyData {
    #[inline]
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        let names: &'static _ = &[
            "id",
            "text_field",
            "number_field",
            "boolean_field",
            "float_field",
            "vector_field",
            "map_field",
        ];
        let values: &[&dyn ::core::fmt::Debug] = &[
            &self.id,
            &self.text_field,
            &self.number_field,
            &self.boolean_field,
            &self.float_field,
            &self.vector_field,
            &&self.map_field,
        ];
        ::core::fmt::Formatter::debug_struct_fields_finish(f, "MyData", names, values)
    }
}
#[automatically_derived]
impl ::core::clone::Clone for MyData {
    #[inline]
    fn clone(&self) -> MyData {
        MyData {
            id: ::core::clone::Clone::clone(&self.id),
            text_field: ::core::clone::Clone::clone(&self.text_field),
            number_field: ::core::clone::Clone::clone(&self.number_field),
            boolean_field: ::core::clone::Clone::clone(&self.boolean_field),
            float_field: ::core::clone::Clone::clone(&self.float_field),
            vector_field: ::core::clone::Clone::clone(&self.vector_field),
            map_field: ::core::clone::Clone::clone(&self.map_field),
        }
    }
}
#[doc(hidden)]
#[allow(
    non_upper_case_globals,
    unused_attributes,
    unused_qualifications,
    clippy::absolute_paths
)]
const _: () = {
    #[allow(unused_extern_crates, clippy::useless_attribute)]
    extern crate serde as _serde;
    #[automatically_derived]
    impl _serde::Serialize for MyData {
        fn serialize<__S>(
            &self,
            __serializer: __S,
        ) -> _serde::__private::Result<__S::Ok, __S::Error>
        where
            __S: _serde::Serializer,
        {
            let mut __serde_state = _serde::Serializer::serialize_struct(
                __serializer,
                "MyData",
                false as usize + 1 + 1 + 1 + 1 + 1 + 1 + 1,
            )?;
            _serde::ser::SerializeStruct::serialize_field(&mut __serde_state, "id", &self.id)?;
            _serde::ser::SerializeStruct::serialize_field(
                &mut __serde_state,
                "text_field",
                &self.text_field,
            )?;
            _serde::ser::SerializeStruct::serialize_field(
                &mut __serde_state,
                "number_field",
                &self.number_field,
            )?;
            _serde::ser::SerializeStruct::serialize_field(
                &mut __serde_state,
                "boolean_field",
                &self.boolean_field,
            )?;
            _serde::ser::SerializeStruct::serialize_field(
                &mut __serde_state,
                "float_field",
                &self.float_field,
            )?;
            _serde::ser::SerializeStruct::serialize_field(
                &mut __serde_state,
                "vector_field",
                &self.vector_field,
            )?;
            _serde::ser::SerializeStruct::serialize_field(
                &mut __serde_state,
                "map_field",
                &self.map_field,
            )?;
            _serde::ser::SerializeStruct::end(__serde_state)
        }
    }
};
#[doc(hidden)]
#[allow(
    non_upper_case_globals,
    unused_attributes,
    unused_qualifications,
    clippy::absolute_paths
)]
const _: () = {
    #[allow(unused_extern_crates, clippy::useless_attribute)]
    extern crate serde as _serde;
    #[automatically_derived]
    impl<'de> _serde::Deserialize<'de> for MyData {
        fn deserialize<__D>(__deserializer: __D) -> _serde::__private::Result<Self, __D::Error>
        where
            __D: _serde::Deserializer<'de>,
        {
            #[allow(non_camel_case_types)]
            #[doc(hidden)]
            enum __Field {
                __field0,
                __field1,
                __field2,
                __field3,
                __field4,
                __field5,
                __field6,
                __ignore,
            }
            #[doc(hidden)]
            struct __FieldVisitor;
            #[automatically_derived]
            impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                type Value = __Field;
                fn expecting(
                    &self,
                    __formatter: &mut _serde::__private::Formatter,
                ) -> _serde::__private::fmt::Result {
                    _serde::__private::Formatter::write_str(__formatter, "field identifier")
                }
                fn visit_u64<__E>(self, __value: u64) -> _serde::__private::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        0u64 => _serde::__private::Ok(__Field::__field0),
                        1u64 => _serde::__private::Ok(__Field::__field1),
                        2u64 => _serde::__private::Ok(__Field::__field2),
                        3u64 => _serde::__private::Ok(__Field::__field3),
                        4u64 => _serde::__private::Ok(__Field::__field4),
                        5u64 => _serde::__private::Ok(__Field::__field5),
                        6u64 => _serde::__private::Ok(__Field::__field6),
                        _ => _serde::__private::Ok(__Field::__ignore),
                    }
                }
                fn visit_str<__E>(
                    self,
                    __value: &str,
                ) -> _serde::__private::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        "id" => _serde::__private::Ok(__Field::__field0),
                        "text_field" => _serde::__private::Ok(__Field::__field1),
                        "number_field" => _serde::__private::Ok(__Field::__field2),
                        "boolean_field" => _serde::__private::Ok(__Field::__field3),
                        "float_field" => _serde::__private::Ok(__Field::__field4),
                        "vector_field" => _serde::__private::Ok(__Field::__field5),
                        "map_field" => _serde::__private::Ok(__Field::__field6),
                        _ => _serde::__private::Ok(__Field::__ignore),
                    }
                }
                fn visit_bytes<__E>(
                    self,
                    __value: &[u8],
                ) -> _serde::__private::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        b"id" => _serde::__private::Ok(__Field::__field0),
                        b"text_field" => _serde::__private::Ok(__Field::__field1),
                        b"number_field" => _serde::__private::Ok(__Field::__field2),
                        b"boolean_field" => _serde::__private::Ok(__Field::__field3),
                        b"float_field" => _serde::__private::Ok(__Field::__field4),
                        b"vector_field" => _serde::__private::Ok(__Field::__field5),
                        b"map_field" => _serde::__private::Ok(__Field::__field6),
                        _ => _serde::__private::Ok(__Field::__ignore),
                    }
                }
            }
            #[automatically_derived]
            impl<'de> _serde::Deserialize<'de> for __Field {
                #[inline]
                fn deserialize<__D>(
                    __deserializer: __D,
                ) -> _serde::__private::Result<Self, __D::Error>
                where
                    __D: _serde::Deserializer<'de>,
                {
                    _serde::Deserializer::deserialize_identifier(__deserializer, __FieldVisitor)
                }
            }
            #[doc(hidden)]
            struct __Visitor<'de> {
                marker: _serde::__private::PhantomData<MyData>,
                lifetime: _serde::__private::PhantomData<&'de ()>,
            }
            #[automatically_derived]
            impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                type Value = MyData;
                fn expecting(
                    &self,
                    __formatter: &mut _serde::__private::Formatter,
                ) -> _serde::__private::fmt::Result {
                    _serde::__private::Formatter::write_str(__formatter, "struct MyData")
                }
                #[inline]
                fn visit_seq<__A>(
                    self,
                    mut __seq: __A,
                ) -> _serde::__private::Result<Self::Value, __A::Error>
                where
                    __A: _serde::de::SeqAccess<'de>,
                {
                    let __field0 = match _serde::de::SeqAccess::next_element::<i32>(&mut __seq)? {
                        _serde::__private::Some(__value) => __value,
                        _serde::__private::None => {
                            return _serde::__private::Err(_serde::de::Error::invalid_length(
                                0usize,
                                &"struct MyData with 7 elements",
                            ));
                        }
                    };
                    let __field1 = match _serde::de::SeqAccess::next_element::<String>(&mut __seq)?
                    {
                        _serde::__private::Some(__value) => __value,
                        _serde::__private::None => {
                            return _serde::__private::Err(_serde::de::Error::invalid_length(
                                1usize,
                                &"struct MyData with 7 elements",
                            ));
                        }
                    };
                    let __field2 = match _serde::de::SeqAccess::next_element::<i32>(&mut __seq)? {
                        _serde::__private::Some(__value) => __value,
                        _serde::__private::None => {
                            return _serde::__private::Err(_serde::de::Error::invalid_length(
                                2usize,
                                &"struct MyData with 7 elements",
                            ));
                        }
                    };
                    let __field3 = match _serde::de::SeqAccess::next_element::<bool>(&mut __seq)? {
                        _serde::__private::Some(__value) => __value,
                        _serde::__private::None => {
                            return _serde::__private::Err(_serde::de::Error::invalid_length(
                                3usize,
                                &"struct MyData with 7 elements",
                            ));
                        }
                    };
                    let __field4 = match _serde::de::SeqAccess::next_element::<f64>(&mut __seq)? {
                        _serde::__private::Some(__value) => __value,
                        _serde::__private::None => {
                            return _serde::__private::Err(_serde::de::Error::invalid_length(
                                4usize,
                                &"struct MyData with 7 elements",
                            ));
                        }
                    };
                    let __field5 =
                        match _serde::de::SeqAccess::next_element::<Vec<i32>>(&mut __seq)? {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(_serde::de::Error::invalid_length(
                                    5usize,
                                    &"struct MyData with 7 elements",
                                ));
                            }
                        };
                    let __field6 = match _serde::de::SeqAccess::next_element::<HashMap<String, i32>>(
                        &mut __seq,
                    )? {
                        _serde::__private::Some(__value) => __value,
                        _serde::__private::None => {
                            return _serde::__private::Err(_serde::de::Error::invalid_length(
                                6usize,
                                &"struct MyData with 7 elements",
                            ));
                        }
                    };
                    _serde::__private::Ok(MyData {
                        id: __field0,
                        text_field: __field1,
                        number_field: __field2,
                        boolean_field: __field3,
                        float_field: __field4,
                        vector_field: __field5,
                        map_field: __field6,
                    })
                }
                #[inline]
                fn visit_map<__A>(
                    self,
                    mut __map: __A,
                ) -> _serde::__private::Result<Self::Value, __A::Error>
                where
                    __A: _serde::de::MapAccess<'de>,
                {
                    let mut __field0: _serde::__private::Option<i32> = _serde::__private::None;
                    let mut __field1: _serde::__private::Option<String> = _serde::__private::None;
                    let mut __field2: _serde::__private::Option<i32> = _serde::__private::None;
                    let mut __field3: _serde::__private::Option<bool> = _serde::__private::None;
                    let mut __field4: _serde::__private::Option<f64> = _serde::__private::None;
                    let mut __field5: _serde::__private::Option<Vec<i32>> = _serde::__private::None;
                    let mut __field6: _serde::__private::Option<HashMap<String, i32>> =
                        _serde::__private::None;
                    while let _serde::__private::Some(__key) =
                        _serde::de::MapAccess::next_key::<__Field>(&mut __map)?
                    {
                        match __key {
                            __Field::__field0 => {
                                if _serde::__private::Option::is_some(&__field0) {
                                    return _serde::__private::Err(
                                        <__A::Error as _serde::de::Error>::duplicate_field("id"),
                                    );
                                }
                                __field0 =
                                    _serde::__private::Some(_serde::de::MapAccess::next_value::<
                                        i32,
                                    >(
                                        &mut __map
                                    )?);
                            }
                            __Field::__field1 => {
                                if _serde::__private::Option::is_some(&__field1) {
                                    return _serde::__private::Err(
                                        <__A::Error as _serde::de::Error>::duplicate_field(
                                            "text_field",
                                        ),
                                    );
                                }
                                __field1 =
                                    _serde::__private::Some(_serde::de::MapAccess::next_value::<
                                        String,
                                    >(
                                        &mut __map
                                    )?);
                            }
                            __Field::__field2 => {
                                if _serde::__private::Option::is_some(&__field2) {
                                    return _serde::__private::Err(
                                        <__A::Error as _serde::de::Error>::duplicate_field(
                                            "number_field",
                                        ),
                                    );
                                }
                                __field2 =
                                    _serde::__private::Some(_serde::de::MapAccess::next_value::<
                                        i32,
                                    >(
                                        &mut __map
                                    )?);
                            }
                            __Field::__field3 => {
                                if _serde::__private::Option::is_some(&__field3) {
                                    return _serde::__private::Err(
                                        <__A::Error as _serde::de::Error>::duplicate_field(
                                            "boolean_field",
                                        ),
                                    );
                                }
                                __field3 =
                                    _serde::__private::Some(_serde::de::MapAccess::next_value::<
                                        bool,
                                    >(
                                        &mut __map
                                    )?);
                            }
                            __Field::__field4 => {
                                if _serde::__private::Option::is_some(&__field4) {
                                    return _serde::__private::Err(
                                        <__A::Error as _serde::de::Error>::duplicate_field(
                                            "float_field",
                                        ),
                                    );
                                }
                                __field4 =
                                    _serde::__private::Some(_serde::de::MapAccess::next_value::<
                                        f64,
                                    >(
                                        &mut __map
                                    )?);
                            }
                            __Field::__field5 => {
                                if _serde::__private::Option::is_some(&__field5) {
                                    return _serde::__private::Err(
                                        <__A::Error as _serde::de::Error>::duplicate_field(
                                            "vector_field",
                                        ),
                                    );
                                }
                                __field5 =
                                    _serde::__private::Some(_serde::de::MapAccess::next_value::<
                                        Vec<i32>,
                                    >(
                                        &mut __map
                                    )?);
                            }
                            __Field::__field6 => {
                                if _serde::__private::Option::is_some(&__field6) {
                                    return _serde::__private::Err(
                                        <__A::Error as _serde::de::Error>::duplicate_field(
                                            "map_field",
                                        ),
                                    );
                                }
                                __field6 =
                                    _serde::__private::Some(_serde::de::MapAccess::next_value::<
                                        HashMap<String, i32>,
                                    >(
                                        &mut __map
                                    )?);
                            }
                            _ => {
                                let _ = _serde::de::MapAccess::next_value::<_serde::de::IgnoredAny>(
                                    &mut __map,
                                )?;
                            }
                        }
                    }
                    let __field0 = match __field0 {
                        _serde::__private::Some(__field0) => __field0,
                        _serde::__private::None => _serde::__private::de::missing_field("id")?,
                    };
                    let __field1 = match __field1 {
                        _serde::__private::Some(__field1) => __field1,
                        _serde::__private::None => {
                            _serde::__private::de::missing_field("text_field")?
                        }
                    };
                    let __field2 = match __field2 {
                        _serde::__private::Some(__field2) => __field2,
                        _serde::__private::None => {
                            _serde::__private::de::missing_field("number_field")?
                        }
                    };
                    let __field3 = match __field3 {
                        _serde::__private::Some(__field3) => __field3,
                        _serde::__private::None => {
                            _serde::__private::de::missing_field("boolean_field")?
                        }
                    };
                    let __field4 = match __field4 {
                        _serde::__private::Some(__field4) => __field4,
                        _serde::__private::None => {
                            _serde::__private::de::missing_field("float_field")?
                        }
                    };
                    let __field5 = match __field5 {
                        _serde::__private::Some(__field5) => __field5,
                        _serde::__private::None => {
                            _serde::__private::de::missing_field("vector_field")?
                        }
                    };
                    let __field6 = match __field6 {
                        _serde::__private::Some(__field6) => __field6,
                        _serde::__private::None => {
                            _serde::__private::de::missing_field("map_field")?
                        }
                    };
                    _serde::__private::Ok(MyData {
                        id: __field0,
                        text_field: __field1,
                        number_field: __field2,
                        boolean_field: __field3,
                        float_field: __field4,
                        vector_field: __field5,
                        map_field: __field6,
                    })
                }
            }
            #[doc(hidden)]
            const FIELDS: &'static [&'static str] = &[
                "id",
                "text_field",
                "number_field",
                "boolean_field",
                "float_field",
                "vector_field",
                "map_field",
            ];
            _serde::Deserializer::deserialize_struct(
                __deserializer,
                "MyData",
                FIELDS,
                __Visitor {
                    marker: _serde::__private::PhantomData::<MyData>,
                    lifetime: _serde::__private::PhantomData,
                },
            )
        }
    }
};
#[automatically_derived]
impl ::core::marker::StructuralPartialEq for MyData {}
#[automatically_derived]
impl ::core::cmp::PartialEq for MyData {
    #[inline]
    fn eq(&self, other: &MyData) -> bool {
        self.id == other.id
            && self.text_field == other.text_field
            && self.number_field == other.number_field
            && self.boolean_field == other.boolean_field
            && self.float_field == other.float_field
            && self.vector_field == other.vector_field
            && self.map_field == other.map_field
    }
}
struct PreWrappedStruct {
    id: String,
    value: i32,
}
#[doc(hidden)]
#[allow(
    non_upper_case_globals,
    unused_attributes,
    unused_qualifications,
    clippy::absolute_paths
)]
const _: () = {
    #[allow(unused_extern_crates, clippy::useless_attribute)]
    extern crate serde as _serde;
    #[automatically_derived]
    impl _serde::Serialize for PreWrappedStruct {
        fn serialize<__S>(
            &self,
            __serializer: __S,
        ) -> _serde::__private::Result<__S::Ok, __S::Error>
        where
            __S: _serde::Serializer,
        {
            let mut __serde_state = _serde::Serializer::serialize_struct(
                __serializer,
                "PreWrappedStruct",
                false as usize + 1 + 1,
            )?;
            _serde::ser::SerializeStruct::serialize_field(&mut __serde_state, "id", &self.id)?;
            _serde::ser::SerializeStruct::serialize_field(
                &mut __serde_state,
                "value",
                &self.value,
            )?;
            _serde::ser::SerializeStruct::end(__serde_state)
        }
    }
};
#[doc(hidden)]
#[allow(
    non_upper_case_globals,
    unused_attributes,
    unused_qualifications,
    clippy::absolute_paths
)]
const _: () = {
    #[allow(unused_extern_crates, clippy::useless_attribute)]
    extern crate serde as _serde;
    #[automatically_derived]
    impl<'de> _serde::Deserialize<'de> for PreWrappedStruct {
        fn deserialize<__D>(__deserializer: __D) -> _serde::__private::Result<Self, __D::Error>
        where
            __D: _serde::Deserializer<'de>,
        {
            #[allow(non_camel_case_types)]
            #[doc(hidden)]
            enum __Field {
                __field0,
                __field1,
                __ignore,
            }
            #[doc(hidden)]
            struct __FieldVisitor;
            #[automatically_derived]
            impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                type Value = __Field;
                fn expecting(
                    &self,
                    __formatter: &mut _serde::__private::Formatter,
                ) -> _serde::__private::fmt::Result {
                    _serde::__private::Formatter::write_str(__formatter, "field identifier")
                }
                fn visit_u64<__E>(self, __value: u64) -> _serde::__private::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        0u64 => _serde::__private::Ok(__Field::__field0),
                        1u64 => _serde::__private::Ok(__Field::__field1),
                        _ => _serde::__private::Ok(__Field::__ignore),
                    }
                }
                fn visit_str<__E>(
                    self,
                    __value: &str,
                ) -> _serde::__private::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        "id" => _serde::__private::Ok(__Field::__field0),
                        "value" => _serde::__private::Ok(__Field::__field1),
                        _ => _serde::__private::Ok(__Field::__ignore),
                    }
                }
                fn visit_bytes<__E>(
                    self,
                    __value: &[u8],
                ) -> _serde::__private::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        b"id" => _serde::__private::Ok(__Field::__field0),
                        b"value" => _serde::__private::Ok(__Field::__field1),
                        _ => _serde::__private::Ok(__Field::__ignore),
                    }
                }
            }
            #[automatically_derived]
            impl<'de> _serde::Deserialize<'de> for __Field {
                #[inline]
                fn deserialize<__D>(
                    __deserializer: __D,
                ) -> _serde::__private::Result<Self, __D::Error>
                where
                    __D: _serde::Deserializer<'de>,
                {
                    _serde::Deserializer::deserialize_identifier(__deserializer, __FieldVisitor)
                }
            }
            #[doc(hidden)]
            struct __Visitor<'de> {
                marker: _serde::__private::PhantomData<PreWrappedStruct>,
                lifetime: _serde::__private::PhantomData<&'de ()>,
            }
            #[automatically_derived]
            impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                type Value = PreWrappedStruct;
                fn expecting(
                    &self,
                    __formatter: &mut _serde::__private::Formatter,
                ) -> _serde::__private::fmt::Result {
                    _serde::__private::Formatter::write_str(__formatter, "struct PreWrappedStruct")
                }
                #[inline]
                fn visit_seq<__A>(
                    self,
                    mut __seq: __A,
                ) -> _serde::__private::Result<Self::Value, __A::Error>
                where
                    __A: _serde::de::SeqAccess<'de>,
                {
                    let __field0 = match _serde::de::SeqAccess::next_element::<String>(&mut __seq)?
                    {
                        _serde::__private::Some(__value) => __value,
                        _serde::__private::None => {
                            return _serde::__private::Err(_serde::de::Error::invalid_length(
                                0usize,
                                &"struct PreWrappedStruct with 2 elements",
                            ));
                        }
                    };
                    let __field1 = match _serde::de::SeqAccess::next_element::<i32>(&mut __seq)? {
                        _serde::__private::Some(__value) => __value,
                        _serde::__private::None => {
                            return _serde::__private::Err(_serde::de::Error::invalid_length(
                                1usize,
                                &"struct PreWrappedStruct with 2 elements",
                            ));
                        }
                    };
                    _serde::__private::Ok(PreWrappedStruct {
                        id: __field0,
                        value: __field1,
                    })
                }
                #[inline]
                fn visit_map<__A>(
                    self,
                    mut __map: __A,
                ) -> _serde::__private::Result<Self::Value, __A::Error>
                where
                    __A: _serde::de::MapAccess<'de>,
                {
                    let mut __field0: _serde::__private::Option<String> = _serde::__private::None;
                    let mut __field1: _serde::__private::Option<i32> = _serde::__private::None;
                    while let _serde::__private::Some(__key) =
                        _serde::de::MapAccess::next_key::<__Field>(&mut __map)?
                    {
                        match __key {
                            __Field::__field0 => {
                                if _serde::__private::Option::is_some(&__field0) {
                                    return _serde::__private::Err(
                                        <__A::Error as _serde::de::Error>::duplicate_field("id"),
                                    );
                                }
                                __field0 =
                                    _serde::__private::Some(_serde::de::MapAccess::next_value::<
                                        String,
                                    >(
                                        &mut __map
                                    )?);
                            }
                            __Field::__field1 => {
                                if _serde::__private::Option::is_some(&__field1) {
                                    return _serde::__private::Err(
                                        <__A::Error as _serde::de::Error>::duplicate_field("value"),
                                    );
                                }
                                __field1 =
                                    _serde::__private::Some(_serde::de::MapAccess::next_value::<
                                        i32,
                                    >(
                                        &mut __map
                                    )?);
                            }
                            _ => {
                                let _ = _serde::de::MapAccess::next_value::<_serde::de::IgnoredAny>(
                                    &mut __map,
                                )?;
                            }
                        }
                    }
                    let __field0 = match __field0 {
                        _serde::__private::Some(__field0) => __field0,
                        _serde::__private::None => _serde::__private::de::missing_field("id")?,
                    };
                    let __field1 = match __field1 {
                        _serde::__private::Some(__field1) => __field1,
                        _serde::__private::None => _serde::__private::de::missing_field("value")?,
                    };
                    _serde::__private::Ok(PreWrappedStruct {
                        id: __field0,
                        value: __field1,
                    })
                }
            }
            #[doc(hidden)]
            const FIELDS: &'static [&'static str] = &["id", "value"];
            _serde::Deserializer::deserialize_struct(
                __deserializer,
                "PreWrappedStruct",
                FIELDS,
                __Visitor {
                    marker: _serde::__private::PhantomData::<PreWrappedStruct>,
                    lifetime: _serde::__private::PhantomData,
                },
            )
        }
    }
};
#[automatically_derived]
impl ::core::fmt::Debug for PreWrappedStruct {
    #[inline]
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        ::core::fmt::Formatter::debug_struct_field2_finish(
            f,
            "PreWrappedStruct",
            "id",
            &self.id,
            "value",
            &&self.value,
        )
    }
}
#[automatically_derived]
impl ::core::clone::Clone for PreWrappedStruct {
    #[inline]
    fn clone(&self) -> PreWrappedStruct {
        PreWrappedStruct {
            id: ::core::clone::Clone::clone(&self.id),
            value: ::core::clone::Clone::clone(&self.value),
        }
    }
}
#[automatically_derived]
impl ::core::marker::StructuralPartialEq for PreWrappedStruct {}
#[automatically_derived]
impl ::core::cmp::PartialEq for PreWrappedStruct {
    #[inline]
    fn eq(&self, other: &PreWrappedStruct) -> bool {
        self.id == other.id && self.value == other.value
    }
}
struct User {
    id: i32,
    name: String,
    email: String,
    age: i32,
}
#[doc(hidden)]
#[allow(
    non_upper_case_globals,
    unused_attributes,
    unused_qualifications,
    clippy::absolute_paths
)]
const _: () = {
    #[allow(unused_extern_crates, clippy::useless_attribute)]
    extern crate serde as _serde;
    #[automatically_derived]
    impl _serde::Serialize for User {
        fn serialize<__S>(
            &self,
            __serializer: __S,
        ) -> _serde::__private::Result<__S::Ok, __S::Error>
        where
            __S: _serde::Serializer,
        {
            let mut __serde_state = _serde::Serializer::serialize_struct(
                __serializer,
                "User",
                false as usize + 1 + 1 + 1 + 1,
            )?;
            _serde::ser::SerializeStruct::serialize_field(&mut __serde_state, "id", &self.id)?;
            _serde::ser::SerializeStruct::serialize_field(&mut __serde_state, "name", &self.name)?;
            _serde::ser::SerializeStruct::serialize_field(
                &mut __serde_state,
                "email",
                &self.email,
            )?;
            _serde::ser::SerializeStruct::serialize_field(&mut __serde_state, "age", &self.age)?;
            _serde::ser::SerializeStruct::end(__serde_state)
        }
    }
};
#[doc(hidden)]
#[allow(
    non_upper_case_globals,
    unused_attributes,
    unused_qualifications,
    clippy::absolute_paths
)]
const _: () = {
    #[allow(unused_extern_crates, clippy::useless_attribute)]
    extern crate serde as _serde;
    #[automatically_derived]
    impl<'de> _serde::Deserialize<'de> for User {
        fn deserialize<__D>(__deserializer: __D) -> _serde::__private::Result<Self, __D::Error>
        where
            __D: _serde::Deserializer<'de>,
        {
            #[allow(non_camel_case_types)]
            #[doc(hidden)]
            enum __Field {
                __field0,
                __field1,
                __field2,
                __field3,
                __ignore,
            }
            #[doc(hidden)]
            struct __FieldVisitor;
            #[automatically_derived]
            impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                type Value = __Field;
                fn expecting(
                    &self,
                    __formatter: &mut _serde::__private::Formatter,
                ) -> _serde::__private::fmt::Result {
                    _serde::__private::Formatter::write_str(__formatter, "field identifier")
                }
                fn visit_u64<__E>(self, __value: u64) -> _serde::__private::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        0u64 => _serde::__private::Ok(__Field::__field0),
                        1u64 => _serde::__private::Ok(__Field::__field1),
                        2u64 => _serde::__private::Ok(__Field::__field2),
                        3u64 => _serde::__private::Ok(__Field::__field3),
                        _ => _serde::__private::Ok(__Field::__ignore),
                    }
                }
                fn visit_str<__E>(
                    self,
                    __value: &str,
                ) -> _serde::__private::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        "id" => _serde::__private::Ok(__Field::__field0),
                        "name" => _serde::__private::Ok(__Field::__field1),
                        "email" => _serde::__private::Ok(__Field::__field2),
                        "age" => _serde::__private::Ok(__Field::__field3),
                        _ => _serde::__private::Ok(__Field::__ignore),
                    }
                }
                fn visit_bytes<__E>(
                    self,
                    __value: &[u8],
                ) -> _serde::__private::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        b"id" => _serde::__private::Ok(__Field::__field0),
                        b"name" => _serde::__private::Ok(__Field::__field1),
                        b"email" => _serde::__private::Ok(__Field::__field2),
                        b"age" => _serde::__private::Ok(__Field::__field3),
                        _ => _serde::__private::Ok(__Field::__ignore),
                    }
                }
            }
            #[automatically_derived]
            impl<'de> _serde::Deserialize<'de> for __Field {
                #[inline]
                fn deserialize<__D>(
                    __deserializer: __D,
                ) -> _serde::__private::Result<Self, __D::Error>
                where
                    __D: _serde::Deserializer<'de>,
                {
                    _serde::Deserializer::deserialize_identifier(__deserializer, __FieldVisitor)
                }
            }
            #[doc(hidden)]
            struct __Visitor<'de> {
                marker: _serde::__private::PhantomData<User>,
                lifetime: _serde::__private::PhantomData<&'de ()>,
            }
            #[automatically_derived]
            impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                type Value = User;
                fn expecting(
                    &self,
                    __formatter: &mut _serde::__private::Formatter,
                ) -> _serde::__private::fmt::Result {
                    _serde::__private::Formatter::write_str(__formatter, "struct User")
                }
                #[inline]
                fn visit_seq<__A>(
                    self,
                    mut __seq: __A,
                ) -> _serde::__private::Result<Self::Value, __A::Error>
                where
                    __A: _serde::de::SeqAccess<'de>,
                {
                    let __field0 = match _serde::de::SeqAccess::next_element::<i32>(&mut __seq)? {
                        _serde::__private::Some(__value) => __value,
                        _serde::__private::None => {
                            return _serde::__private::Err(_serde::de::Error::invalid_length(
                                0usize,
                                &"struct User with 4 elements",
                            ));
                        }
                    };
                    let __field1 = match _serde::de::SeqAccess::next_element::<String>(&mut __seq)?
                    {
                        _serde::__private::Some(__value) => __value,
                        _serde::__private::None => {
                            return _serde::__private::Err(_serde::de::Error::invalid_length(
                                1usize,
                                &"struct User with 4 elements",
                            ));
                        }
                    };
                    let __field2 = match _serde::de::SeqAccess::next_element::<String>(&mut __seq)?
                    {
                        _serde::__private::Some(__value) => __value,
                        _serde::__private::None => {
                            return _serde::__private::Err(_serde::de::Error::invalid_length(
                                2usize,
                                &"struct User with 4 elements",
                            ));
                        }
                    };
                    let __field3 = match _serde::de::SeqAccess::next_element::<i32>(&mut __seq)? {
                        _serde::__private::Some(__value) => __value,
                        _serde::__private::None => {
                            return _serde::__private::Err(_serde::de::Error::invalid_length(
                                3usize,
                                &"struct User with 4 elements",
                            ));
                        }
                    };
                    _serde::__private::Ok(User {
                        id: __field0,
                        name: __field1,
                        email: __field2,
                        age: __field3,
                    })
                }
                #[inline]
                fn visit_map<__A>(
                    self,
                    mut __map: __A,
                ) -> _serde::__private::Result<Self::Value, __A::Error>
                where
                    __A: _serde::de::MapAccess<'de>,
                {
                    let mut __field0: _serde::__private::Option<i32> = _serde::__private::None;
                    let mut __field1: _serde::__private::Option<String> = _serde::__private::None;
                    let mut __field2: _serde::__private::Option<String> = _serde::__private::None;
                    let mut __field3: _serde::__private::Option<i32> = _serde::__private::None;
                    while let _serde::__private::Some(__key) =
                        _serde::de::MapAccess::next_key::<__Field>(&mut __map)?
                    {
                        match __key {
                            __Field::__field0 => {
                                if _serde::__private::Option::is_some(&__field0) {
                                    return _serde::__private::Err(
                                        <__A::Error as _serde::de::Error>::duplicate_field("id"),
                                    );
                                }
                                __field0 =
                                    _serde::__private::Some(_serde::de::MapAccess::next_value::<
                                        i32,
                                    >(
                                        &mut __map
                                    )?);
                            }
                            __Field::__field1 => {
                                if _serde::__private::Option::is_some(&__field1) {
                                    return _serde::__private::Err(
                                        <__A::Error as _serde::de::Error>::duplicate_field("name"),
                                    );
                                }
                                __field1 =
                                    _serde::__private::Some(_serde::de::MapAccess::next_value::<
                                        String,
                                    >(
                                        &mut __map
                                    )?);
                            }
                            __Field::__field2 => {
                                if _serde::__private::Option::is_some(&__field2) {
                                    return _serde::__private::Err(
                                        <__A::Error as _serde::de::Error>::duplicate_field("email"),
                                    );
                                }
                                __field2 =
                                    _serde::__private::Some(_serde::de::MapAccess::next_value::<
                                        String,
                                    >(
                                        &mut __map
                                    )?);
                            }
                            __Field::__field3 => {
                                if _serde::__private::Option::is_some(&__field3) {
                                    return _serde::__private::Err(
                                        <__A::Error as _serde::de::Error>::duplicate_field("age"),
                                    );
                                }
                                __field3 =
                                    _serde::__private::Some(_serde::de::MapAccess::next_value::<
                                        i32,
                                    >(
                                        &mut __map
                                    )?);
                            }
                            _ => {
                                let _ = _serde::de::MapAccess::next_value::<_serde::de::IgnoredAny>(
                                    &mut __map,
                                )?;
                            }
                        }
                    }
                    let __field0 = match __field0 {
                        _serde::__private::Some(__field0) => __field0,
                        _serde::__private::None => _serde::__private::de::missing_field("id")?,
                    };
                    let __field1 = match __field1 {
                        _serde::__private::Some(__field1) => __field1,
                        _serde::__private::None => _serde::__private::de::missing_field("name")?,
                    };
                    let __field2 = match __field2 {
                        _serde::__private::Some(__field2) => __field2,
                        _serde::__private::None => _serde::__private::de::missing_field("email")?,
                    };
                    let __field3 = match __field3 {
                        _serde::__private::Some(__field3) => __field3,
                        _serde::__private::None => _serde::__private::de::missing_field("age")?,
                    };
                    _serde::__private::Ok(User {
                        id: __field0,
                        name: __field1,
                        email: __field2,
                        age: __field3,
                    })
                }
            }
            #[doc(hidden)]
            const FIELDS: &'static [&'static str] = &["id", "name", "email", "age"];
            _serde::Deserializer::deserialize_struct(
                __deserializer,
                "User",
                FIELDS,
                __Visitor {
                    marker: _serde::__private::PhantomData::<User>,
                    lifetime: _serde::__private::PhantomData,
                },
            )
        }
    }
};
#[automatically_derived]
impl ::core::fmt::Debug for User {
    #[inline]
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        ::core::fmt::Formatter::debug_struct_field4_finish(
            f,
            "User",
            "id",
            &self.id,
            "name",
            &self.name,
            "email",
            &self.email,
            "age",
            &&self.age,
        )
    }
}
#[automatically_derived]
impl ::core::clone::Clone for User {
    #[inline]
    fn clone(&self) -> User {
        User {
            id: ::core::clone::Clone::clone(&self.id),
            name: ::core::clone::Clone::clone(&self.name),
            email: ::core::clone::Clone::clone(&self.email),
            age: ::core::clone::Clone::clone(&self.age),
        }
    }
}
#[automatically_derived]
impl ::core::marker::StructuralPartialEq for User {}
#[automatically_derived]
impl ::core::cmp::PartialEq for User {
    #[inline]
    fn eq(&self, other: &User) -> bool {
        self.id == other.id
            && self.name == other.name
            && self.email == other.email
            && self.age == other.age
    }
}
pub struct TestService {
    store: Arc<Mutex<HashMap<String, ArcValueType>>>,
}
impl Clone for TestService {
    fn clone(&self) -> Self {
        Self {
            store: self.store.clone(),
        }
    }
}
impl TestService {
    fn new(path: impl Into<String>, store: Arc<Mutex<HashMap<String, ArcValueType>>>) -> Self {
        let instance = Self {
            store: store.clone(),
        };
        instance.set_path(&path.into());
        instance
    }
    async fn complex_data(
        &self,
        data: Vec<HashMap<String, String>>,
        ctx: &RequestContext,
    ) -> Result<Vec<HashMap<String, String>>> {
        Ok(data)
    }
    async fn register_action_complex_data(
        &self,
        context: &runar_node::services::LifecycleContext,
    ) -> anyhow::Result<()> {
        context.logger.info(::alloc::__export::must_use({
            ::alloc::fmt::format(format_args!("Registering \'{0}\' action", "complex_data"))
        }));
        let self_clone = self.clone();
        let handler = std::sync::Arc::new(
            move |params_opt: Option<runar_common::types::ArcValueType>,
                  ctx: runar_node::services::RequestContext|
                  -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = Result<runar_common::types::ArcValueType, anyhow::Error>,
                        > + Send,
                >,
            > {
                let inner_self = self_clone.clone();
                Box::pin(async move {
                    let mut params_value = match params_opt {
                        Some(p) => p,
                        None => {
                            if true {
                                ctx.error("No parameters provided".to_string());
                                return Err(::anyhow::__private::must_use({
                                    let error = ::anyhow::__private::format_err(format_args!(
                                        "No parameters provided"
                                    ));
                                    error
                                }));
                            } else {
                                runar_common::types::ArcValueType::new_map(
                                    std::collections::HashMap::<
                                        String,
                                        runar_common::types::ArcValueType,
                                    >::new(),
                                )
                            }
                        }
                    };
                    let data: Vec<HashMap<String, String>> = match params_value
                        .as_type::<Vec<HashMap<String, String>>>()
                    {
                        Ok(val) => val,
                        Err(err) => {
                            ctx.error(::alloc::__export::must_use({
                                ::alloc::fmt::format(format_args!(
                                    "Failed to parse parameter for single-parameter action: {0}",
                                    err,
                                ))
                            }));
                            return Err(::anyhow::__private::must_use({
                                use ::anyhow::__private::kind::*;
                                let error = match ::alloc::__export::must_use({
                                    ::alloc::fmt::format(
                                        format_args!(
                                            "Failed to parse parameter for single-parameter action: {0}",
                                            err,
                                        ),
                                    )
                                }) {
                                    error => (&error).anyhow_kind().new(error),
                                };
                                error
                            }));
                        }
                    };
                    match inner_self.complex_data(data, &ctx).await {
                        Ok(result) => {
                            let value_type =
                                runar_common::types::ArcValueType::new_primitive(result);
                            Ok(value_type)
                        }
                        Err(err) => {
                            ctx.error(::alloc::__export::must_use({
                                ::alloc::fmt::format(format_args!(
                                    "Action \'{0}\' failed: {1}",
                                    "complex_data", err,
                                ))
                            }));
                            return Err(::anyhow::__private::must_use({
                                use ::anyhow::__private::kind::*;
                                let error = match err.to_string() {
                                    error => (&error).anyhow_kind().new(error),
                                };
                                error
                            }));
                        }
                    }
                })
            },
        );
        if false {
            context.logger.debug(::alloc::__export::must_use({
                ::alloc::fmt::format(format_args!(
                    "Type registration needed for action \'{0}\' with type: {1}",
                    "complex_data", "Vec < HashMap < String, String > >",
                ))
            }));
        }
        context
            .register_action("complex_data".to_string(), handler)
            .await
    }
    async fn get_user(&self, id: i32, ctx: &RequestContext) -> Result<User> {
        let user = User {
            id,
            name: "John Doe".to_string(),
            email: "john.doe@example.com".to_string(),
            age: 30,
        };
        Ok(user)
    }
    async fn register_action_get_user(
        &self,
        context: &runar_node::services::LifecycleContext,
    ) -> anyhow::Result<()> {
        context.logger.info(::alloc::__export::must_use({
            ::alloc::fmt::format(format_args!("Registering \'{0}\' action", "get_user"))
        }));
        let self_clone = self.clone();
        let handler = std::sync::Arc::new(
            move |params_opt: Option<runar_common::types::ArcValueType>,
                  ctx: runar_node::services::RequestContext|
                  -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = Result<runar_common::types::ArcValueType, anyhow::Error>,
                        > + Send,
                >,
            > {
                let inner_self = self_clone.clone();
                Box::pin(async move {
                    let mut params_value = match params_opt {
                        Some(p) => p,
                        None => {
                            if true {
                                ctx.error("No parameters provided".to_string());
                                return Err(::anyhow::__private::must_use({
                                    let error = ::anyhow::__private::format_err(format_args!(
                                        "No parameters provided"
                                    ));
                                    error
                                }));
                            } else {
                                runar_common::types::ArcValueType::new_map(
                                    std::collections::HashMap::<
                                        String,
                                        runar_common::types::ArcValueType,
                                    >::new(),
                                )
                            }
                        }
                    };
                    let id: i32 = match params_value.as_type::<i32>() {
                        Ok(val) => val,
                        Err(err) => {
                            ctx.error(::alloc::__export::must_use({
                                ::alloc::fmt::format(format_args!(
                                    "Failed to parse parameter for single-parameter action: {0}",
                                    err,
                                ))
                            }));
                            return Err(::anyhow::__private::must_use({
                                use ::anyhow::__private::kind::*;
                                let error = match ::alloc::__export::must_use({
                                    ::alloc::fmt::format(
                                        format_args!(
                                            "Failed to parse parameter for single-parameter action: {0}",
                                            err,
                                        ),
                                    )
                                }) {
                                    error => (&error).anyhow_kind().new(error),
                                };
                                error
                            }));
                        }
                    };
                    match inner_self.get_user(id, &ctx).await {
                        Ok(result) => {
                            let value_type = runar_common::types::ArcValueType::from_struct(result);
                            Ok(value_type)
                        }
                        Err(err) => {
                            ctx.error(::alloc::__export::must_use({
                                ::alloc::fmt::format(format_args!(
                                    "Action \'{0}\' failed: {1}",
                                    "get_user", err
                                ))
                            }));
                            return Err(::anyhow::__private::must_use({
                                use ::anyhow::__private::kind::*;
                                let error = match err.to_string() {
                                    error => (&error).anyhow_kind().new(error),
                                };
                                error
                            }));
                        }
                    }
                })
            },
        );
        if true {
            context.logger.debug(::alloc::__export::must_use({
                ::alloc::fmt::format(format_args!(
                    "Type registration needed for action \'{0}\' with type: {1}",
                    "get_user", "User",
                ))
            }));
        }
        context
            .register_action("get_user".to_string(), handler)
            .await
    }
    async fn echo_pre_wrapped_struct(
        &self,
        id_str: String,
        val_int: i32,
        _ctx: &RequestContext,
    ) -> Result<ArcValueType> {
        let data = PreWrappedStruct {
            id: id_str,
            value: val_int,
        };
        Ok(ArcValueType::from_struct(data))
    }
    async fn register_action_echo_pre_wrapped_struct(
        &self,
        context: &runar_node::services::LifecycleContext,
    ) -> anyhow::Result<()> {
        context.logger.info(::alloc::__export::must_use({
            ::alloc::fmt::format(format_args!(
                "Registering \'{0}\' action",
                "echo_pre_wrapped_struct",
            ))
        }));
        let self_clone = self.clone();
        let handler = std::sync::Arc::new(
            move |params_opt: Option<runar_common::types::ArcValueType>,
                  ctx: runar_node::services::RequestContext|
                  -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = Result<runar_common::types::ArcValueType, anyhow::Error>,
                        > + Send,
                >,
            > {
                let inner_self = self_clone.clone();
                Box::pin(async move {
                    let mut params_value = match params_opt {
                        Some(p) => p,
                        None => {
                            if true {
                                ctx.error("No parameters provided".to_string());
                                return Err(::anyhow::__private::must_use({
                                    let error = ::anyhow::__private::format_err(format_args!(
                                        "No parameters provided"
                                    ));
                                    error
                                }));
                            } else {
                                runar_common::types::ArcValueType::new_map(
                                    std::collections::HashMap::<
                                        String,
                                        runar_common::types::ArcValueType,
                                    >::new(),
                                )
                            }
                        }
                    };
                    let params_map_ref = match params_value
                        .as_map_ref::<String, runar_common::types::ArcValueType>()
                    {
                        Ok(map_ref) => map_ref,
                        Err(err) => {
                            ctx.error(
                            ::alloc::__export::must_use({
                                ::alloc::fmt::format(
                                    format_args!(
                                        "Action parameters must be provided as a map (for heterogeneous types, expecting Map<String, ArcValueType>), but received an incompatible type. Error: {0}",
                                        err,
                                    ),
                                )
                            }),
                        );
                            return Err(::anyhow::__private::must_use({
                                use ::anyhow::__private::kind::*;
                                let error = match ::alloc::__export::must_use({
                                    ::alloc::fmt::format(
                                        format_args!(
                                            "Invalid payload type for parameters. Expected a map, got incompatible type: {0}",
                                            err,
                                        ),
                                    )
                                }) {
                                    error => (&error).anyhow_kind().new(error),
                                };
                                error
                            }));
                        }
                    };
                    let id_str: String = match params_map_ref.get("id_str") {
                    Some(arc_value_for_param) => {
                        arc_value_for_param
                            .clone()
                            .as_type::<String>()
                            .map_err(|err| {
                                ctx.error(
                                    ::alloc::__export::must_use({
                                        ::alloc::fmt::format(
                                            format_args!(
                                                "Failed to convert parameter \'{0}\' (type \'{1}\') from ArcValueType. Expected concrete type. Error: {2}",
                                                "id_str",
                                                "String",
                                                err,
                                            ),
                                        )
                                    }),
                                );
                                ::anyhow::__private::must_use({
                                    use ::anyhow::__private::kind::*;
                                    let error = match ::alloc::__export::must_use({
                                        ::alloc::fmt::format(
                                            format_args!(
                                                "Type conversion error for parameter \'{0}\': {1}",
                                                "id_str",
                                                err,
                                            ),
                                        )
                                    }) {
                                        error => (&error).anyhow_kind().new(error),
                                    };
                                    error
                                })
                            })?
                    }
                    None => {
                        ctx.error(
                            ::alloc::__export::must_use({
                                ::alloc::fmt::format(
                                    format_args!(
                                        "Required parameter \'{0}\' (type \'{1}\') not found in payload",
                                        "id_str",
                                        "String",
                                    ),
                                )
                            }),
                        );
                        return Err(
                            ::anyhow::__private::must_use({
                                use ::anyhow::__private::kind::*;
                                let error = match ::alloc::__export::must_use({
                                    ::alloc::fmt::format(
                                        format_args!("Missing required parameter \'{0}\'", "id_str"),
                                    )
                                }) {
                                    error => (&error).anyhow_kind().new(error),
                                };
                                error
                            }),
                        );
                    }
                };
                    let val_int: i32 = match params_map_ref.get("val_int") {
                    Some(arc_value_for_param) => {
                        arc_value_for_param
                            .clone()
                            .as_type::<i32>()
                            .map_err(|err| {
                                ctx.error(
                                    ::alloc::__export::must_use({
                                        ::alloc::fmt::format(
                                            format_args!(
                                                "Failed to convert parameter \'{0}\' (type \'{1}\') from ArcValueType. Expected concrete type. Error: {2}",
                                                "val_int",
                                                "i32",
                                                err,
                                            ),
                                        )
                                    }),
                                );
                                ::anyhow::__private::must_use({
                                    use ::anyhow::__private::kind::*;
                                    let error = match ::alloc::__export::must_use({
                                        ::alloc::fmt::format(
                                            format_args!(
                                                "Type conversion error for parameter \'{0}\': {1}",
                                                "val_int",
                                                err,
                                            ),
                                        )
                                    }) {
                                        error => (&error).anyhow_kind().new(error),
                                    };
                                    error
                                })
                            })?
                    }
                    None => {
                        ctx.error(
                            ::alloc::__export::must_use({
                                ::alloc::fmt::format(
                                    format_args!(
                                        "Required parameter \'{0}\' (type \'{1}\') not found in payload",
                                        "val_int",
                                        "i32",
                                    ),
                                )
                            }),
                        );
                        return Err(
                            ::anyhow::__private::must_use({
                                use ::anyhow::__private::kind::*;
                                let error = match ::alloc::__export::must_use({
                                    ::alloc::fmt::format(
                                        format_args!(
                                            "Missing required parameter \'{0}\'",
                                            "val_int",
                                        ),
                                    )
                                }) {
                                    error => (&error).anyhow_kind().new(error),
                                };
                                error
                            }),
                        );
                    }
                };
                    match inner_self
                        .echo_pre_wrapped_struct(id_str, val_int, &ctx)
                        .await
                    {
                        Ok(result) => Ok(result),
                        Err(err) => {
                            ctx.error(::alloc::__export::must_use({
                                ::alloc::fmt::format(format_args!(
                                    "Action \'{0}\' failed: {1}",
                                    "echo_pre_wrapped_struct", err,
                                ))
                            }));
                            return Err(::anyhow::__private::must_use({
                                use ::anyhow::__private::kind::*;
                                let error = match err.to_string() {
                                    error => (&error).anyhow_kind().new(error),
                                };
                                error
                            }));
                        }
                    }
                })
            },
        );
        if true {
            context.logger.debug(::alloc::__export::must_use({
                ::alloc::fmt::format(format_args!(
                    "Type registration needed for action \'{0}\' with type: {1}",
                    "echo_pre_wrapped_struct", "ArcValueType",
                ))
            }));
        }
        context
            .register_action("echo_pre_wrapped_struct".to_string(), handler)
            .await
    }
    async fn get_my_data(&self, id: i32, ctx: &RequestContext) -> Result<MyData> {
        let result = {
            ctx.debug(::alloc::__export::must_use({
                ::alloc::fmt::format(format_args!("get_my_data id: {0}", id))
            }));
            let total_res: f64 = ctx
                .request(
                    "math/add",
                    Some(ArcValueType::new_map(HashMap::from([
                        ("a".to_string(), 1000.0),
                        ("b".to_string(), 500.0),
                    ]))),
                )
                .await?;
            let total = total_res;
            let data = MyData {
                id,
                text_field: "test".to_string(),
                number_field: id,
                boolean_field: true,
                float_field: total,
                vector_field: <[_]>::into_vec(::alloc::boxed::box_new([1, 2, 3])),
                map_field: HashMap::new(),
            };
            ctx.publish(
                "my_data_changed",
                Some(ArcValueType::from_struct(data.clone())),
            )
            .await?;
            ctx.publish("age_changed", Some(ArcValueType::new_primitive(25)))
                .await?;
            Ok(data)
        };
        if let Ok(ref action_result) = &result {
            match ctx
                .publish(
                    "my_data_auto",
                    Some(runar_common::types::ArcValueType::from_struct(
                        action_result.clone(),
                    )),
                )
                .await
            {
                Ok(_) => {}
                Err(e) => {
                    ctx.error(::alloc::__export::must_use({
                        ::alloc::fmt::format(format_args!(
                            "Failed to publish result to {0}: {1}",
                            "my_data_auto", e,
                        ))
                    }));
                }
            }
        }
        result
    }
    async fn register_action_get_my_data(
        &self,
        context: &runar_node::services::LifecycleContext,
    ) -> anyhow::Result<()> {
        context.logger.info(::alloc::__export::must_use({
            ::alloc::fmt::format(format_args!("Registering \'{0}\' action", "get_my_data"))
        }));
        let self_clone = self.clone();
        let handler = std::sync::Arc::new(
            move |params_opt: Option<runar_common::types::ArcValueType>,
                  ctx: runar_node::services::RequestContext|
                  -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = Result<runar_common::types::ArcValueType, anyhow::Error>,
                        > + Send,
                >,
            > {
                let inner_self = self_clone.clone();
                Box::pin(async move {
                    let mut params_value = match params_opt {
                        Some(p) => p,
                        None => {
                            if true {
                                ctx.error("No parameters provided".to_string());
                                return Err(::anyhow::__private::must_use({
                                    let error = ::anyhow::__private::format_err(format_args!(
                                        "No parameters provided"
                                    ));
                                    error
                                }));
                            } else {
                                runar_common::types::ArcValueType::new_map(
                                    std::collections::HashMap::<
                                        String,
                                        runar_common::types::ArcValueType,
                                    >::new(),
                                )
                            }
                        }
                    };
                    let id: i32 = match params_value.as_type::<i32>() {
                        Ok(val) => val,
                        Err(err) => {
                            ctx.error(::alloc::__export::must_use({
                                ::alloc::fmt::format(format_args!(
                                    "Failed to parse parameter for single-parameter action: {0}",
                                    err,
                                ))
                            }));
                            return Err(::anyhow::__private::must_use({
                                use ::anyhow::__private::kind::*;
                                let error = match ::alloc::__export::must_use({
                                    ::alloc::fmt::format(
                                        format_args!(
                                            "Failed to parse parameter for single-parameter action: {0}",
                                            err,
                                        ),
                                    )
                                }) {
                                    error => (&error).anyhow_kind().new(error),
                                };
                                error
                            }));
                        }
                    };
                    match inner_self.get_my_data(id, &ctx).await {
                        Ok(result) => {
                            let value_type = runar_common::types::ArcValueType::from_struct(result);
                            Ok(value_type)
                        }
                        Err(err) => {
                            ctx.error(::alloc::__export::must_use({
                                ::alloc::fmt::format(format_args!(
                                    "Action \'{0}\' failed: {1}",
                                    "get_my_data", err,
                                ))
                            }));
                            return Err(::anyhow::__private::must_use({
                                use ::anyhow::__private::kind::*;
                                let error = match err.to_string() {
                                    error => (&error).anyhow_kind().new(error),
                                };
                                error
                            }));
                        }
                    }
                })
            },
        );
        if true {
            context.logger.debug(::alloc::__export::must_use({
                ::alloc::fmt::format(format_args!(
                    "Type registration needed for action \'{0}\' with type: {1}",
                    "get_my_data", "MyData",
                ))
            }));
        }
        context
            .register_action("my_data".to_string(), handler)
            .await
    }
    async fn on_my_data_auto(&self, data: MyData, ctx: &EventContext) -> Result<()> {
        ctx.debug(::alloc::__export::must_use({
            ::alloc::fmt::format(format_args!(
                "my_data_auto was an event published using the publish macro ->: {0}",
                data.text_field,
            ))
        }));
        let mut lock = self.store.lock().await;
        let existing = lock.get("my_data_auto");
        if let Some(existing) = existing {
            let mut existing = existing.clone();
            let mut existing = existing.as_type::<Vec<MyData>>().unwrap();
            existing.push(data.clone());
            lock.insert("my_data_auto".to_string(), ArcValueType::new_list(existing));
        } else {
            lock.insert(
                "my_data_auto".to_string(),
                ArcValueType::new_list(<[_]>::into_vec(::alloc::boxed::box_new([data.clone()]))),
            );
        }
        Ok(())
    }
    async fn register_subscription_on_my_data_auto(
        &self,
        context: &runar_node::services::LifecycleContext,
    ) -> anyhow::Result<()> {
        context.info(::alloc::__export::must_use({
            ::alloc::fmt::format(format_args!(
                "Subscribing to \'{0}\' event",
                "math/my_data_auto"
            ))
        }));
        let self_clone = self.clone();
        context
            .subscribe(
                "math/my_data_auto",
                Box::new(move |ctx, value| {
                    let self_clone = self_clone.clone();
                    Box::pin(async move {
                        let data = match value {
                            Some(value) => match value.clone().as_type::<MyData>() {
                                Ok(val) => val,
                                Err(err) => {
                                    return Err(::anyhow::__private::must_use({
                                        use ::anyhow::__private::kind::*;
                                        let error = match ::alloc::__export::must_use({
                                            ::alloc::fmt::format(format_args!(
                                                "Failed to parse event value as {0}: {1}",
                                                "MyData", err,
                                            ))
                                        }) {
                                            error => (&error).anyhow_kind().new(error),
                                        };
                                        error
                                    }));
                                }
                            },
                            None => {
                                return Err(::anyhow::__private::must_use({
                                    use ::anyhow::__private::kind::*;
                                    let error = match ::alloc::__export::must_use({
                                        ::alloc::fmt::format(format_args!(
                                            "Required event value is missing for {0}",
                                            "math/my_data_auto",
                                        ))
                                    }) {
                                        error => (&error).anyhow_kind().new(error),
                                    };
                                    error
                                }));
                            }
                        };
                        match self_clone.on_my_data_auto(data, &ctx).await {
                            Ok(_) => Ok(()),
                            Err(err) => Err(::anyhow::__private::must_use({
                                use ::anyhow::__private::kind::*;
                                let error = match ::alloc::__export::must_use({
                                    ::alloc::fmt::format(format_args!(
                                        "Error in event handler for {0}: {1}",
                                        "math/my_data_auto", err,
                                    ))
                                }) {
                                    error => (&error).anyhow_kind().new(error),
                                };
                                error
                            })),
                        }
                    })
                }),
            )
            .await?;
        context.info(::alloc::__export::must_use({
            ::alloc::fmt::format(format_args!(
                "Registered event handler for {0}",
                "math/my_data_auto",
            ))
        }));
        Ok(())
    }
    async fn on_added(&self, total: f64, ctx: &EventContext) -> Result<()> {
        ctx.debug(::alloc::__export::must_use({
            ::alloc::fmt::format(format_args!("on_added: {0}", total))
        }));
        let mut lock = self.store.lock().await;
        let existing = lock.get("added");
        if let Some(existing) = existing {
            let mut existing = existing.clone();
            let mut existing = existing.as_type::<Vec<f64>>().unwrap();
            existing.push(total);
            lock.insert("added".to_string(), ArcValueType::new_list(existing));
        } else {
            lock.insert(
                "added".to_string(),
                ArcValueType::new_list(<[_]>::into_vec(::alloc::boxed::box_new([total]))),
            );
        }
        Ok(())
    }
    async fn register_subscription_on_added(
        &self,
        context: &runar_node::services::LifecycleContext,
    ) -> anyhow::Result<()> {
        context.info(::alloc::__export::must_use({
            ::alloc::fmt::format(format_args!("Subscribing to \'{0}\' event", "math/added"))
        }));
        let self_clone = self.clone();
        context
            .subscribe(
                "math/added",
                Box::new(move |ctx, value| {
                    let self_clone = self_clone.clone();
                    Box::pin(async move {
                        let total = match value {
                            Some(value) => match value.clone().as_type::<f64>() {
                                Ok(val) => val,
                                Err(err) => {
                                    return Err(::anyhow::__private::must_use({
                                        use ::anyhow::__private::kind::*;
                                        let error = match ::alloc::__export::must_use({
                                            ::alloc::fmt::format(format_args!(
                                                "Failed to parse event value as {0}: {1}",
                                                "f64", err,
                                            ))
                                        }) {
                                            error => (&error).anyhow_kind().new(error),
                                        };
                                        error
                                    }));
                                }
                            },
                            None => {
                                return Err(::anyhow::__private::must_use({
                                    use ::anyhow::__private::kind::*;
                                    let error = match ::alloc::__export::must_use({
                                        ::alloc::fmt::format(format_args!(
                                            "Required event value is missing for {0}",
                                            "math/added",
                                        ))
                                    }) {
                                        error => (&error).anyhow_kind().new(error),
                                    };
                                    error
                                }));
                            }
                        };
                        match self_clone.on_added(total, &ctx).await {
                            Ok(_) => Ok(()),
                            Err(err) => Err(::anyhow::__private::must_use({
                                use ::anyhow::__private::kind::*;
                                let error = match ::alloc::__export::must_use({
                                    ::alloc::fmt::format(format_args!(
                                        "Error in event handler for {0}: {1}",
                                        "math/added", err,
                                    ))
                                }) {
                                    error => (&error).anyhow_kind().new(error),
                                };
                                error
                            })),
                        }
                    })
                }),
            )
            .await?;
        context.info(::alloc::__export::must_use({
            ::alloc::fmt::format(format_args!(
                "Registered event handler for {0}",
                "math/added"
            ))
        }));
        Ok(())
    }
    async fn on_my_data_changed(&self, data: MyData, ctx: &EventContext) -> Result<()> {
        ctx.debug(::alloc::__export::must_use({
            ::alloc::fmt::format(format_args!("my_data_changed: {0}", data.text_field))
        }));
        let mut lock = self.store.lock().await;
        let existing = lock.get("my_data_changed");
        if let Some(existing) = existing {
            let mut existing = existing.clone();
            let mut existing = existing.as_type::<Vec<MyData>>().unwrap();
            existing.push(data.clone());
            lock.insert(
                "my_data_changed".to_string(),
                ArcValueType::new_list(existing),
            );
        } else {
            lock.insert(
                "my_data_changed".to_string(),
                ArcValueType::new_list(<[_]>::into_vec(::alloc::boxed::box_new([data.clone()]))),
            );
        }
        Ok(())
    }
    async fn register_subscription_on_my_data_changed(
        &self,
        context: &runar_node::services::LifecycleContext,
    ) -> anyhow::Result<()> {
        context.info(::alloc::__export::must_use({
            ::alloc::fmt::format(format_args!(
                "Subscribing to \'{0}\' event",
                "math/my_data_changed",
            ))
        }));
        let self_clone = self.clone();
        context
            .subscribe(
                "math/my_data_changed",
                Box::new(move |ctx, value| {
                    let self_clone = self_clone.clone();
                    Box::pin(async move {
                        let data = match value {
                            Some(value) => match value.clone().as_type::<MyData>() {
                                Ok(val) => val,
                                Err(err) => {
                                    return Err(::anyhow::__private::must_use({
                                        use ::anyhow::__private::kind::*;
                                        let error = match ::alloc::__export::must_use({
                                            ::alloc::fmt::format(format_args!(
                                                "Failed to parse event value as {0}: {1}",
                                                "MyData", err,
                                            ))
                                        }) {
                                            error => (&error).anyhow_kind().new(error),
                                        };
                                        error
                                    }));
                                }
                            },
                            None => {
                                return Err(::anyhow::__private::must_use({
                                    use ::anyhow::__private::kind::*;
                                    let error = match ::alloc::__export::must_use({
                                        ::alloc::fmt::format(format_args!(
                                            "Required event value is missing for {0}",
                                            "math/my_data_changed",
                                        ))
                                    }) {
                                        error => (&error).anyhow_kind().new(error),
                                    };
                                    error
                                }));
                            }
                        };
                        match self_clone.on_my_data_changed(data, &ctx).await {
                            Ok(_) => Ok(()),
                            Err(err) => Err(::anyhow::__private::must_use({
                                use ::anyhow::__private::kind::*;
                                let error = match ::alloc::__export::must_use({
                                    ::alloc::fmt::format(format_args!(
                                        "Error in event handler for {0}: {1}",
                                        "math/my_data_changed", err,
                                    ))
                                }) {
                                    error => (&error).anyhow_kind().new(error),
                                };
                                error
                            })),
                        }
                    })
                }),
            )
            .await?;
        context.info(::alloc::__export::must_use({
            ::alloc::fmt::format(format_args!(
                "Registered event handler for {0}",
                "math/my_data_changed",
            ))
        }));
        Ok(())
    }
    async fn on_age_changed(&self, new_age: i32, ctx: &EventContext) -> Result<()> {
        ctx.debug(::alloc::__export::must_use({
            ::alloc::fmt::format(format_args!("age_changed: {0}", new_age))
        }));
        let mut lock = self.store.lock().await;
        let existing = lock.get("age_changed");
        if let Some(existing) = existing {
            let mut existing = existing.clone();
            let mut existing = existing.as_type::<Vec<i32>>().unwrap();
            existing.push(new_age);
            lock.insert("age_changed".to_string(), ArcValueType::new_list(existing));
        } else {
            lock.insert(
                "age_changed".to_string(),
                ArcValueType::new_list(<[_]>::into_vec(::alloc::boxed::box_new([new_age]))),
            );
        }
        Ok(())
    }
    async fn register_subscription_on_age_changed(
        &self,
        context: &runar_node::services::LifecycleContext,
    ) -> anyhow::Result<()> {
        context.info(::alloc::__export::must_use({
            ::alloc::fmt::format(format_args!(
                "Subscribing to \'{0}\' event",
                "math/age_changed"
            ))
        }));
        let self_clone = self.clone();
        context
            .subscribe(
                "math/age_changed",
                Box::new(move |ctx, value| {
                    let self_clone = self_clone.clone();
                    Box::pin(async move {
                        let new_age = match value {
                            Some(value) => match value.clone().as_type::<i32>() {
                                Ok(val) => val,
                                Err(err) => {
                                    return Err(::anyhow::__private::must_use({
                                        use ::anyhow::__private::kind::*;
                                        let error = match ::alloc::__export::must_use({
                                            ::alloc::fmt::format(format_args!(
                                                "Failed to parse event value as {0}: {1}",
                                                "i32", err,
                                            ))
                                        }) {
                                            error => (&error).anyhow_kind().new(error),
                                        };
                                        error
                                    }));
                                }
                            },
                            None => {
                                return Err(::anyhow::__private::must_use({
                                    use ::anyhow::__private::kind::*;
                                    let error = match ::alloc::__export::must_use({
                                        ::alloc::fmt::format(format_args!(
                                            "Required event value is missing for {0}",
                                            "math/age_changed",
                                        ))
                                    }) {
                                        error => (&error).anyhow_kind().new(error),
                                    };
                                    error
                                }));
                            }
                        };
                        match self_clone.on_age_changed(new_age, &ctx).await {
                            Ok(_) => Ok(()),
                            Err(err) => Err(::anyhow::__private::must_use({
                                use ::anyhow::__private::kind::*;
                                let error = match ::alloc::__export::must_use({
                                    ::alloc::fmt::format(format_args!(
                                        "Error in event handler for {0}: {1}",
                                        "math/age_changed", err,
                                    ))
                                }) {
                                    error => (&error).anyhow_kind().new(error),
                                };
                                error
                            })),
                        }
                    })
                }),
            )
            .await?;
        context.info(::alloc::__export::must_use({
            ::alloc::fmt::format(format_args!(
                "Registered event handler for {0}",
                "math/age_changed",
            ))
        }));
        Ok(())
    }
    async fn add(&self, a: f64, b: f64, ctx: &RequestContext) -> Result<f64> {
        let result = {
            ctx.debug(::alloc::__export::must_use({
                ::alloc::fmt::format(format_args!("Adding {0} + {1}", a, b))
            }));
            Ok(a + b)
        };
        if let Ok(ref action_result) = &result {
            match ctx
                .publish(
                    "added",
                    Some(runar_common::types::ArcValueType::from_struct(
                        action_result.clone(),
                    )),
                )
                .await
            {
                Ok(_) => {}
                Err(e) => {
                    ctx.error(::alloc::__export::must_use({
                        ::alloc::fmt::format(format_args!(
                            "Failed to publish result to {0}: {1}",
                            "added", e,
                        ))
                    }));
                }
            }
        }
        result
    }
    async fn register_action_add(
        &self,
        context: &runar_node::services::LifecycleContext,
    ) -> anyhow::Result<()> {
        context.logger.info(::alloc::__export::must_use({
            ::alloc::fmt::format(format_args!("Registering \'{0}\' action", "add"))
        }));
        let self_clone = self.clone();
        let handler = std::sync::Arc::new(
            move |params_opt: Option<runar_common::types::ArcValueType>,
                  ctx: runar_node::services::RequestContext|
                  -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = Result<runar_common::types::ArcValueType, anyhow::Error>,
                        > + Send,
                >,
            > {
                let inner_self = self_clone.clone();
                Box::pin(async move {
                    let mut params_value = match params_opt {
                        Some(p) => p,
                        None => {
                            if true {
                                ctx.error("No parameters provided".to_string());
                                return Err(::anyhow::__private::must_use({
                                    let error = ::anyhow::__private::format_err(format_args!(
                                        "No parameters provided"
                                    ));
                                    error
                                }));
                            } else {
                                runar_common::types::ArcValueType::new_map(
                                    std::collections::HashMap::<
                                        String,
                                        runar_common::types::ArcValueType,
                                    >::new(),
                                )
                            }
                        }
                    };
                    let params_map_ref = match params_value.as_map_ref::<String, f64>() {
                        Ok(map_ref) => map_ref,
                        Err(err) => {
                            ctx.error(
                            ::alloc::__export::must_use({
                                ::alloc::fmt::format(
                                    format_args!(
                                        "Action parameters must be provided as a map of type Map<String, {0}>, but received an incompatible type. Error: {1}",
                                        "f64",
                                        err,
                                    ),
                                )
                            }),
                        );
                            return Err(::anyhow::__private::must_use({
                                use ::anyhow::__private::kind::*;
                                let error = match ::alloc::__export::must_use({
                                    ::alloc::fmt::format(
                                        format_args!(
                                            "Invalid payload type for parameters. Expected map of type Map<String, {0}>, got incompatible type: {1}",
                                            "f64",
                                            err,
                                        ),
                                    )
                                }) {
                                    error => (&error).anyhow_kind().new(error),
                                };
                                error
                            }));
                        }
                    };
                    let a: f64 = match params_map_ref.get("a") {
                        Some(val_ref) => val_ref.clone(),
                        None => {
                            ctx.error(
                            ::alloc::__export::must_use({
                                ::alloc::fmt::format(
                                    format_args!(
                                        "Required parameter \'{0}\' (type \'{1}\') not found in payload. Expected map to contain this key.",
                                        "a",
                                        "f64",
                                    ),
                                )
                            }),
                        );
                            return Err(::anyhow::__private::must_use({
                                use ::anyhow::__private::kind::*;
                                let error = match ::alloc::__export::must_use({
                                    ::alloc::fmt::format(format_args!(
                                        "Missing required parameter \'{0}\'",
                                        "a"
                                    ))
                                }) {
                                    error => (&error).anyhow_kind().new(error),
                                };
                                error
                            }));
                        }
                    };
                    let b: f64 = match params_map_ref.get("b") {
                        Some(val_ref) => val_ref.clone(),
                        None => {
                            ctx.error(
                            ::alloc::__export::must_use({
                                ::alloc::fmt::format(
                                    format_args!(
                                        "Required parameter \'{0}\' (type \'{1}\') not found in payload. Expected map to contain this key.",
                                        "b",
                                        "f64",
                                    ),
                                )
                            }),
                        );
                            return Err(::anyhow::__private::must_use({
                                use ::anyhow::__private::kind::*;
                                let error = match ::alloc::__export::must_use({
                                    ::alloc::fmt::format(format_args!(
                                        "Missing required parameter \'{0}\'",
                                        "b"
                                    ))
                                }) {
                                    error => (&error).anyhow_kind().new(error),
                                };
                                error
                            }));
                        }
                    };
                    match inner_self.add(a, b, &ctx).await {
                        Ok(result) => {
                            let value_type =
                                runar_common::types::ArcValueType::new_primitive(result);
                            Ok(value_type)
                        }
                        Err(err) => {
                            ctx.error(::alloc::__export::must_use({
                                ::alloc::fmt::format(format_args!(
                                    "Action \'{0}\' failed: {1}",
                                    "add", err
                                ))
                            }));
                            return Err(::anyhow::__private::must_use({
                                use ::anyhow::__private::kind::*;
                                let error = match err.to_string() {
                                    error => (&error).anyhow_kind().new(error),
                                };
                                error
                            }));
                        }
                    }
                })
            },
        );
        if false {
            context.logger.debug(::alloc::__export::must_use({
                ::alloc::fmt::format(format_args!(
                    "Type registration needed for action \'{0}\' with type: {1}",
                    "add", "f64",
                ))
            }));
        }
        context.register_action("add".to_string(), handler).await
    }
    async fn subtract(&self, a: f64, b: f64, ctx: &RequestContext) -> Result<f64> {
        ctx.debug(::alloc::__export::must_use({
            ::alloc::fmt::format(format_args!("Subtracting {0} - {1}", a, b))
        }));
        Ok(a - b)
    }
    async fn register_action_subtract(
        &self,
        context: &runar_node::services::LifecycleContext,
    ) -> anyhow::Result<()> {
        context.logger.info(::alloc::__export::must_use({
            ::alloc::fmt::format(format_args!("Registering \'{0}\' action", "subtract"))
        }));
        let self_clone = self.clone();
        let handler = std::sync::Arc::new(
            move |params_opt: Option<runar_common::types::ArcValueType>,
                  ctx: runar_node::services::RequestContext|
                  -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = Result<runar_common::types::ArcValueType, anyhow::Error>,
                        > + Send,
                >,
            > {
                let inner_self = self_clone.clone();
                Box::pin(async move {
                    let mut params_value = match params_opt {
                        Some(p) => p,
                        None => {
                            if true {
                                ctx.error("No parameters provided".to_string());
                                return Err(::anyhow::__private::must_use({
                                    let error = ::anyhow::__private::format_err(format_args!(
                                        "No parameters provided"
                                    ));
                                    error
                                }));
                            } else {
                                runar_common::types::ArcValueType::new_map(
                                    std::collections::HashMap::<
                                        String,
                                        runar_common::types::ArcValueType,
                                    >::new(),
                                )
                            }
                        }
                    };
                    let params_map_ref = match params_value.as_map_ref::<String, f64>() {
                        Ok(map_ref) => map_ref,
                        Err(err) => {
                            ctx.error(
                            ::alloc::__export::must_use({
                                ::alloc::fmt::format(
                                    format_args!(
                                        "Action parameters must be provided as a map of type Map<String, {0}>, but received an incompatible type. Error: {1}",
                                        "f64",
                                        err,
                                    ),
                                )
                            }),
                        );
                            return Err(::anyhow::__private::must_use({
                                use ::anyhow::__private::kind::*;
                                let error = match ::alloc::__export::must_use({
                                    ::alloc::fmt::format(
                                        format_args!(
                                            "Invalid payload type for parameters. Expected map of type Map<String, {0}>, got incompatible type: {1}",
                                            "f64",
                                            err,
                                        ),
                                    )
                                }) {
                                    error => (&error).anyhow_kind().new(error),
                                };
                                error
                            }));
                        }
                    };
                    let a: f64 = match params_map_ref.get("a") {
                        Some(val_ref) => val_ref.clone(),
                        None => {
                            ctx.error(
                            ::alloc::__export::must_use({
                                ::alloc::fmt::format(
                                    format_args!(
                                        "Required parameter \'{0}\' (type \'{1}\') not found in payload. Expected map to contain this key.",
                                        "a",
                                        "f64",
                                    ),
                                )
                            }),
                        );
                            return Err(::anyhow::__private::must_use({
                                use ::anyhow::__private::kind::*;
                                let error = match ::alloc::__export::must_use({
                                    ::alloc::fmt::format(format_args!(
                                        "Missing required parameter \'{0}\'",
                                        "a"
                                    ))
                                }) {
                                    error => (&error).anyhow_kind().new(error),
                                };
                                error
                            }));
                        }
                    };
                    let b: f64 = match params_map_ref.get("b") {
                        Some(val_ref) => val_ref.clone(),
                        None => {
                            ctx.error(
                            ::alloc::__export::must_use({
                                ::alloc::fmt::format(
                                    format_args!(
                                        "Required parameter \'{0}\' (type \'{1}\') not found in payload. Expected map to contain this key.",
                                        "b",
                                        "f64",
                                    ),
                                )
                            }),
                        );
                            return Err(::anyhow::__private::must_use({
                                use ::anyhow::__private::kind::*;
                                let error = match ::alloc::__export::must_use({
                                    ::alloc::fmt::format(format_args!(
                                        "Missing required parameter \'{0}\'",
                                        "b"
                                    ))
                                }) {
                                    error => (&error).anyhow_kind().new(error),
                                };
                                error
                            }));
                        }
                    };
                    match inner_self.subtract(a, b, &ctx).await {
                        Ok(result) => {
                            let value_type =
                                runar_common::types::ArcValueType::new_primitive(result);
                            Ok(value_type)
                        }
                        Err(err) => {
                            ctx.error(::alloc::__export::must_use({
                                ::alloc::fmt::format(format_args!(
                                    "Action \'{0}\' failed: {1}",
                                    "subtract", err
                                ))
                            }));
                            return Err(::anyhow::__private::must_use({
                                use ::anyhow::__private::kind::*;
                                let error = match err.to_string() {
                                    error => (&error).anyhow_kind().new(error),
                                };
                                error
                            }));
                        }
                    }
                })
            },
        );
        if false {
            context.logger.debug(::alloc::__export::must_use({
                ::alloc::fmt::format(format_args!(
                    "Type registration needed for action \'{0}\' with type: {1}",
                    "subtract", "f64",
                ))
            }));
        }
        context
            .register_action("subtract".to_string(), handler)
            .await
    }
    async fn multiply(&self, a: f64, b: f64, ctx: &RequestContext) -> Result<f64> {
        ctx.debug(::alloc::__export::must_use({
            ::alloc::fmt::format(format_args!("Multiplying {0} * {1}", a, b))
        }));
        Ok(a * b)
    }
    async fn register_action_multiply(
        &self,
        context: &runar_node::services::LifecycleContext,
    ) -> anyhow::Result<()> {
        context.logger.info(::alloc::__export::must_use({
            ::alloc::fmt::format(format_args!(
                "Registering \'{0}\' action",
                "multiply_numbers"
            ))
        }));
        let self_clone = self.clone();
        let handler = std::sync::Arc::new(
            move |params_opt: Option<runar_common::types::ArcValueType>,
                  ctx: runar_node::services::RequestContext|
                  -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = Result<runar_common::types::ArcValueType, anyhow::Error>,
                        > + Send,
                >,
            > {
                let inner_self = self_clone.clone();
                Box::pin(async move {
                    let mut params_value = match params_opt {
                        Some(p) => p,
                        None => {
                            if true {
                                ctx.error("No parameters provided".to_string());
                                return Err(::anyhow::__private::must_use({
                                    let error = ::anyhow::__private::format_err(format_args!(
                                        "No parameters provided"
                                    ));
                                    error
                                }));
                            } else {
                                runar_common::types::ArcValueType::new_map(
                                    std::collections::HashMap::<
                                        String,
                                        runar_common::types::ArcValueType,
                                    >::new(),
                                )
                            }
                        }
                    };
                    let params_map_ref = match params_value.as_map_ref::<String, f64>() {
                        Ok(map_ref) => map_ref,
                        Err(err) => {
                            ctx.error(
                            ::alloc::__export::must_use({
                                ::alloc::fmt::format(
                                    format_args!(
                                        "Action parameters must be provided as a map of type Map<String, {0}>, but received an incompatible type. Error: {1}",
                                        "f64",
                                        err,
                                    ),
                                )
                            }),
                        );
                            return Err(::anyhow::__private::must_use({
                                use ::anyhow::__private::kind::*;
                                let error = match ::alloc::__export::must_use({
                                    ::alloc::fmt::format(
                                        format_args!(
                                            "Invalid payload type for parameters. Expected map of type Map<String, {0}>, got incompatible type: {1}",
                                            "f64",
                                            err,
                                        ),
                                    )
                                }) {
                                    error => (&error).anyhow_kind().new(error),
                                };
                                error
                            }));
                        }
                    };
                    let a: f64 = match params_map_ref.get("a") {
                        Some(val_ref) => val_ref.clone(),
                        None => {
                            ctx.error(
                            ::alloc::__export::must_use({
                                ::alloc::fmt::format(
                                    format_args!(
                                        "Required parameter \'{0}\' (type \'{1}\') not found in payload. Expected map to contain this key.",
                                        "a",
                                        "f64",
                                    ),
                                )
                            }),
                        );
                            return Err(::anyhow::__private::must_use({
                                use ::anyhow::__private::kind::*;
                                let error = match ::alloc::__export::must_use({
                                    ::alloc::fmt::format(format_args!(
                                        "Missing required parameter \'{0}\'",
                                        "a"
                                    ))
                                }) {
                                    error => (&error).anyhow_kind().new(error),
                                };
                                error
                            }));
                        }
                    };
                    let b: f64 = match params_map_ref.get("b") {
                        Some(val_ref) => val_ref.clone(),
                        None => {
                            ctx.error(
                            ::alloc::__export::must_use({
                                ::alloc::fmt::format(
                                    format_args!(
                                        "Required parameter \'{0}\' (type \'{1}\') not found in payload. Expected map to contain this key.",
                                        "b",
                                        "f64",
                                    ),
                                )
                            }),
                        );
                            return Err(::anyhow::__private::must_use({
                                use ::anyhow::__private::kind::*;
                                let error = match ::alloc::__export::must_use({
                                    ::alloc::fmt::format(format_args!(
                                        "Missing required parameter \'{0}\'",
                                        "b"
                                    ))
                                }) {
                                    error => (&error).anyhow_kind().new(error),
                                };
                                error
                            }));
                        }
                    };
                    match inner_self.multiply(a, b, &ctx).await {
                        Ok(result) => {
                            let value_type =
                                runar_common::types::ArcValueType::new_primitive(result);
                            Ok(value_type)
                        }
                        Err(err) => {
                            ctx.error(::alloc::__export::must_use({
                                ::alloc::fmt::format(format_args!(
                                    "Action \'{0}\' failed: {1}",
                                    "multiply_numbers", err,
                                ))
                            }));
                            return Err(::anyhow::__private::must_use({
                                use ::anyhow::__private::kind::*;
                                let error = match err.to_string() {
                                    error => (&error).anyhow_kind().new(error),
                                };
                                error
                            }));
                        }
                    }
                })
            },
        );
        if false {
            context.logger.debug(::alloc::__export::must_use({
                ::alloc::fmt::format(format_args!(
                    "Type registration needed for action \'{0}\' with type: {1}",
                    "multiply_numbers", "f64",
                ))
            }));
        }
        context
            .register_action("multiply_numbers".to_string(), handler)
            .await
    }
    async fn divide(&self, a: f64, b: f64, ctx: &RequestContext) -> Result<f64> {
        ctx.debug(::alloc::__export::must_use({
            ::alloc::fmt::format(format_args!("Dividing {0} / {1}", a, b))
        }));
        if b == 0.0 {
            ctx.error("Division by zero".to_string());
            return Err(::anyhow::__private::must_use({
                let error = ::anyhow::__private::format_err(format_args!("Division by zero"));
                error
            }));
        }
        Ok(a / b)
    }
    async fn register_action_divide(
        &self,
        context: &runar_node::services::LifecycleContext,
    ) -> anyhow::Result<()> {
        context.logger.info(::alloc::__export::must_use({
            ::alloc::fmt::format(format_args!("Registering \'{0}\' action", "divide"))
        }));
        let self_clone = self.clone();
        let handler = std::sync::Arc::new(
            move |params_opt: Option<runar_common::types::ArcValueType>,
                  ctx: runar_node::services::RequestContext|
                  -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = Result<runar_common::types::ArcValueType, anyhow::Error>,
                        > + Send,
                >,
            > {
                let inner_self = self_clone.clone();
                Box::pin(async move {
                    let mut params_value = match params_opt {
                        Some(p) => p,
                        None => {
                            if true {
                                ctx.error("No parameters provided".to_string());
                                return Err(::anyhow::__private::must_use({
                                    let error = ::anyhow::__private::format_err(format_args!(
                                        "No parameters provided"
                                    ));
                                    error
                                }));
                            } else {
                                runar_common::types::ArcValueType::new_map(
                                    std::collections::HashMap::<
                                        String,
                                        runar_common::types::ArcValueType,
                                    >::new(),
                                )
                            }
                        }
                    };
                    let params_map_ref = match params_value.as_map_ref::<String, f64>() {
                        Ok(map_ref) => map_ref,
                        Err(err) => {
                            ctx.error(
                            ::alloc::__export::must_use({
                                ::alloc::fmt::format(
                                    format_args!(
                                        "Action parameters must be provided as a map of type Map<String, {0}>, but received an incompatible type. Error: {1}",
                                        "f64",
                                        err,
                                    ),
                                )
                            }),
                        );
                            return Err(::anyhow::__private::must_use({
                                use ::anyhow::__private::kind::*;
                                let error = match ::alloc::__export::must_use({
                                    ::alloc::fmt::format(
                                        format_args!(
                                            "Invalid payload type for parameters. Expected map of type Map<String, {0}>, got incompatible type: {1}",
                                            "f64",
                                            err,
                                        ),
                                    )
                                }) {
                                    error => (&error).anyhow_kind().new(error),
                                };
                                error
                            }));
                        }
                    };
                    let a: f64 = match params_map_ref.get("a") {
                        Some(val_ref) => val_ref.clone(),
                        None => {
                            ctx.error(
                            ::alloc::__export::must_use({
                                ::alloc::fmt::format(
                                    format_args!(
                                        "Required parameter \'{0}\' (type \'{1}\') not found in payload. Expected map to contain this key.",
                                        "a",
                                        "f64",
                                    ),
                                )
                            }),
                        );
                            return Err(::anyhow::__private::must_use({
                                use ::anyhow::__private::kind::*;
                                let error = match ::alloc::__export::must_use({
                                    ::alloc::fmt::format(format_args!(
                                        "Missing required parameter \'{0}\'",
                                        "a"
                                    ))
                                }) {
                                    error => (&error).anyhow_kind().new(error),
                                };
                                error
                            }));
                        }
                    };
                    let b: f64 = match params_map_ref.get("b") {
                        Some(val_ref) => val_ref.clone(),
                        None => {
                            ctx.error(
                            ::alloc::__export::must_use({
                                ::alloc::fmt::format(
                                    format_args!(
                                        "Required parameter \'{0}\' (type \'{1}\') not found in payload. Expected map to contain this key.",
                                        "b",
                                        "f64",
                                    ),
                                )
                            }),
                        );
                            return Err(::anyhow::__private::must_use({
                                use ::anyhow::__private::kind::*;
                                let error = match ::alloc::__export::must_use({
                                    ::alloc::fmt::format(format_args!(
                                        "Missing required parameter \'{0}\'",
                                        "b"
                                    ))
                                }) {
                                    error => (&error).anyhow_kind().new(error),
                                };
                                error
                            }));
                        }
                    };
                    match inner_self.divide(a, b, &ctx).await {
                        Ok(result) => {
                            let value_type =
                                runar_common::types::ArcValueType::new_primitive(result);
                            Ok(value_type)
                        }
                        Err(err) => {
                            ctx.error(::alloc::__export::must_use({
                                ::alloc::fmt::format(format_args!(
                                    "Action \'{0}\' failed: {1}",
                                    "divide", err
                                ))
                            }));
                            return Err(::anyhow::__private::must_use({
                                use ::anyhow::__private::kind::*;
                                let error = match err.to_string() {
                                    error => (&error).anyhow_kind().new(error),
                                };
                                error
                            }));
                        }
                    }
                })
            },
        );
        if false {
            context.logger.debug(::alloc::__export::must_use({
                ::alloc::fmt::format(format_args!(
                    "Type registration needed for action \'{0}\' with type: {1}",
                    "divide", "f64",
                ))
            }));
        }
        context.register_action("divide".to_string(), handler).await
    }
    async fn test_lifetime_issue(&self, ctx: &RequestContext) -> Result<String> {
        let data = "test_data".to_string();
        let data_ref = &data;
        let result = async move { data_ref.to_string() }.await;
        Ok(result)
    }
    async fn register_action_test_lifetime_issue(
        &self,
        context: &runar_node::services::LifecycleContext,
    ) -> anyhow::Result<()> {
        context.logger.info(::alloc::__export::must_use({
            ::alloc::fmt::format(format_args!(
                "Registering \'{0}\' action",
                "test_lifetime_issue"
            ))
        }));
        let self_clone = self.clone();
        let handler = std::sync::Arc::new(
            move |params_opt: Option<runar_common::types::ArcValueType>,
                  ctx: runar_node::services::RequestContext|
                  -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = Result<runar_common::types::ArcValueType, anyhow::Error>,
                        > + Send,
                >,
            > {
                let inner_self = self_clone.clone();
                Box::pin(async move {
                    let mut params_value = match params_opt {
                        Some(p) => p,
                        None => {
                            if false {
                                ctx.error("No parameters provided".to_string());
                                return Err(::anyhow::__private::must_use({
                                    let error = ::anyhow::__private::format_err(format_args!(
                                        "No parameters provided"
                                    ));
                                    error
                                }));
                            } else {
                                runar_common::types::ArcValueType::new_map(
                                    std::collections::HashMap::<
                                        String,
                                        runar_common::types::ArcValueType,
                                    >::new(),
                                )
                            }
                        }
                    };
                    match inner_self.test_lifetime_issue(&ctx).await {
                        Ok(result) => {
                            let value_type =
                                runar_common::types::ArcValueType::new_primitive(result);
                            Ok(value_type)
                        }
                        Err(err) => {
                            ctx.error(::alloc::__export::must_use({
                                ::alloc::fmt::format(format_args!(
                                    "Action \'{0}\' failed: {1}",
                                    "test_lifetime_issue", err,
                                ))
                            }));
                            return Err(::anyhow::__private::must_use({
                                use ::anyhow::__private::kind::*;
                                let error = match err.to_string() {
                                    error => (&error).anyhow_kind().new(error),
                                };
                                error
                            }));
                        }
                    }
                })
            },
        );
        if false {
            context.logger.debug(::alloc::__export::must_use({
                ::alloc::fmt::format(format_args!(
                    "Type registration needed for action \'{0}\' with type: {1}",
                    "test_lifetime_issue", "String",
                ))
            }));
        }
        context
            .register_action("test_lifetime_issue".to_string(), handler)
            .await
    }
}
static SERVICE_NAME: std::sync::OnceLock<String> = std::sync::OnceLock::new();
static SERVICE_PATH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
static SERVICE_DESCRIPTION: std::sync::OnceLock<String> = std::sync::OnceLock::new();
static SERVICE_VERSION: std::sync::OnceLock<String> = std::sync::OnceLock::new();
impl runar_node::services::abstract_service::AbstractService for TestService {
    fn name(&self) -> &str {
        SERVICE_NAME.get_or_init(|| "Test Service Name".to_string())
    }
    fn path(&self) -> &str {
        SERVICE_PATH.get_or_init(|| "math".to_string())
    }
    fn description(&self) -> &str {
        SERVICE_DESCRIPTION.get_or_init(|| "Test Service Description".to_string())
    }
    fn version(&self) -> &str {
        SERVICE_VERSION.get_or_init(|| "0.0.1".to_string())
    }
    fn network_id(&self) -> Option<String> {
        None
    }
    #[allow(
        elided_named_lifetimes,
        clippy::async_yields_async,
        clippy::diverging_sub_expression,
        clippy::let_unit_value,
        clippy::needless_arbitrary_self_type,
        clippy::no_effect_underscore_binding,
        clippy::shadow_same,
        clippy::type_complexity,
        clippy::type_repetition_in_bounds,
        clippy::used_underscore_binding
    )]
    fn init<'life0, 'async_trait>(
        &'life0 self,
        context: runar_node::services::LifecycleContext,
    ) -> ::core::pin::Pin<
        Box<
            dyn ::core::future::Future<Output = anyhow::Result<()>>
                + ::core::marker::Send
                + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            if let ::core::option::Option::Some(__ret) =
                ::core::option::Option::None::<anyhow::Result<()>>
            {
                #[allow(unreachable_code)]
                return __ret;
            }
            let __self = self;
            let context = context;
            let __ret: anyhow::Result<()> = {
                let context_ref = &context;
                __self.register_action_complex_data(context_ref).await?;
                __self.register_action_get_user(context_ref).await?;
                __self
                    .register_action_echo_pre_wrapped_struct(context_ref)
                    .await?;
                __self.register_action_get_my_data(context_ref).await?;
                __self
                    .register_subscription_on_my_data_auto(context_ref)
                    .await?;
                __self.register_subscription_on_added(context_ref).await?;
                __self
                    .register_subscription_on_my_data_changed(context_ref)
                    .await?;
                __self
                    .register_subscription_on_age_changed(context_ref)
                    .await?;
                __self.register_action_add(context_ref).await?;
                __self.register_action_subtract(context_ref).await?;
                __self.register_action_multiply(context_ref).await?;
                __self.register_action_divide(context_ref).await?;
                __self
                    .register_action_test_lifetime_issue(context_ref)
                    .await?;
                Self::register_types(context_ref).await?;
                Ok(())
            };
            #[allow(unreachable_code)]
            __ret
        })
    }
    #[allow(
        elided_named_lifetimes,
        clippy::async_yields_async,
        clippy::diverging_sub_expression,
        clippy::let_unit_value,
        clippy::needless_arbitrary_self_type,
        clippy::no_effect_underscore_binding,
        clippy::shadow_same,
        clippy::type_complexity,
        clippy::type_repetition_in_bounds,
        clippy::used_underscore_binding
    )]
    fn start<'life0, 'async_trait>(
        &'life0 self,
        _context: runar_node::services::LifecycleContext,
    ) -> ::core::pin::Pin<
        Box<
            dyn ::core::future::Future<Output = anyhow::Result<()>>
                + ::core::marker::Send
                + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            if let ::core::option::Option::Some(__ret) =
                ::core::option::Option::None::<anyhow::Result<()>>
            {
                #[allow(unreachable_code)]
                return __ret;
            }
            let __self = self;
            let _context = _context;
            let __ret: anyhow::Result<()> = { Ok(()) };
            #[allow(unreachable_code)]
            __ret
        })
    }
    #[allow(
        elided_named_lifetimes,
        clippy::async_yields_async,
        clippy::diverging_sub_expression,
        clippy::let_unit_value,
        clippy::needless_arbitrary_self_type,
        clippy::no_effect_underscore_binding,
        clippy::shadow_same,
        clippy::type_complexity,
        clippy::type_repetition_in_bounds,
        clippy::used_underscore_binding
    )]
    fn stop<'life0, 'async_trait>(
        &'life0 self,
        _context: runar_node::services::LifecycleContext,
    ) -> ::core::pin::Pin<
        Box<
            dyn ::core::future::Future<Output = anyhow::Result<()>>
                + ::core::marker::Send
                + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            if let ::core::option::Option::Some(__ret) =
                ::core::option::Option::None::<anyhow::Result<()>>
            {
                #[allow(unreachable_code)]
                return __ret;
            }
            let __self = self;
            let _context = _context;
            let __ret: anyhow::Result<()> = { Ok(()) };
            #[allow(unreachable_code)]
            __ret
        })
    }
}
impl TestService {
    /// Set the service name. Can only be set once per process (OnceLock).
    pub fn set_name(&self, value: &str) {
        let _ = SERVICE_NAME.set(value.to_string());
    }
    /// Set the service path. Can only be set once per process (OnceLock).
    pub fn set_path(&self, value: &str) {
        let _ = SERVICE_PATH.set(value.to_string());
    }
    /// Set the service description. Can only be set once per process (OnceLock).
    pub fn set_description(&self, value: &str) {
        let _ = SERVICE_DESCRIPTION.set(value.to_string());
    }
    /// Set the service version. Can only be set once per process (OnceLock).
    pub fn set_version(&self, value: &str) {
        let _ = SERVICE_VERSION.set(value.to_string());
    }
    async fn register_types(
        context: &runar_node::services::LifecycleContext,
    ) -> anyhow::Result<()> {
        let mut serializer = context.serializer.write().await;
        context.info(::alloc::__export::must_use({
            ::alloc::fmt::format(format_args!(
                "Types used by service {0}:\n    {1}",
                "TestService", "ArcValueType\nMyData\nUser\nVec <HashMap <String, String>>",
            ))
        }));
        {
            context.debug(::alloc::__export::must_use({
                ::alloc::fmt::format(format_args!("Registering type: {0}", "ArcValueType"))
            }));
        }
        {
            context.debug(::alloc::__export::must_use({
                ::alloc::fmt::format(format_args!("Registering type: {0}", "MyData"))
            }));
        }
        {
            context.debug(::alloc::__export::must_use({
                ::alloc::fmt::format(format_args!("Registering type: {0}", "User"))
            }));
        }
        {
            context.debug(::alloc::__export::must_use({
                ::alloc::fmt::format(format_args!(
                    "Registering type: {0}",
                    "Vec < HashMap < String, String > >",
                ))
            }));
        }
        context.debug(::alloc::__export::must_use({
            ::alloc::fmt::format(format_args!(
                "All types registered: [{0}]",
                [
                    "ArcValueType",
                    "MyData",
                    "User",
                    "Vec < HashMap < String, String > >",
                ]
                .join(", "),
            ))
        }));
        {
            serializer.register::<ArcValueType>()?;
        }
        {
            serializer.register::<MyData>()?;
        }
        {
            serializer.register::<User>()?;
        }
        {
            serializer.register::<Vec<HashMap<String, String>>>()?;
        }
        Ok(())
    }
}
mod tests {
    use super::*;
    use runar_node::config::LogLevel;
    use runar_node::config::LoggingConfig;
    use runar_node::vmap;
    use runar_node::Node;
    use runar_node::NodeConfig;
    extern crate test;
    #[rustc_test_marker = "tests::test_math_service"]
    #[doc(hidden)]
    pub const test_math_service: test::TestDescAndFn = test::TestDescAndFn {
        desc: test::TestDesc {
            name: test::StaticTestName("tests::test_math_service"),
            ignore: false,
            ignore_message: ::core::option::Option::None,
            source_file: "rust-macros\\tests\\simple_service_macros.rs",
            start_line: 307usize,
            start_col: 14usize,
            end_line: 307usize,
            end_col: 31usize,
            compile_fail: false,
            no_run: false,
            should_panic: test::ShouldPanic::No,
            test_type: test::TestType::IntegrationTest,
        },
        testfn: test::StaticTestFn(
            #[coverage(off)]
            || test::assert_test_result(test_math_service()),
        ),
    };
    fn test_math_service() {
        let body = async {
            let logging_config = LoggingConfig::new().with_default_level(LogLevel::Debug);
            let mut config =
                NodeConfig::new("test-node", "test_network").with_logging_config(logging_config);
            config.network_config = None;
            let mut node = Node::new(config).await.unwrap();
            let store = Arc::new(Mutex::new(HashMap::new()));
            let service = TestService::new("math", store.clone());
            node.add_service(service).await.unwrap();
            node.start().await.expect("Failed to start node");
            let params = {
                use ::runar_common::types::ArcValueType;
                use std::collections::HashMap;
                let mut map = HashMap::new();
                map.insert("a".to_string(), ArcValueType::new_primitive(10.0));
                map.insert("b".to_string(), ArcValueType::new_primitive(5.0));
                ArcValueType::new_map(map)
            };
            let response: f64 = node
                .request("math/add", Some(params))
                .await
                .expect("Failed to call add action");
            match (&response, &15.0) {
                (left_val, right_val) => {
                    if !(*left_val == *right_val) {
                        let kind = ::core::panicking::AssertKind::Eq;
                        ::core::panicking::assert_failed(
                            kind,
                            &*left_val,
                            &*right_val,
                            ::core::option::Option::None,
                        );
                    }
                }
            };
            let params = {
                use ::runar_common::types::ArcValueType;
                use std::collections::HashMap;
                let mut map = HashMap::new();
                map.insert("a".to_string(), ArcValueType::new_primitive(10.0));
                map.insert("b".to_string(), ArcValueType::new_primitive(5.0));
                ArcValueType::new_map(map)
            };
            let response: f64 = node
                .request("math/subtract", Some(params))
                .await
                .expect("Failed to call subtract action");
            match (&response, &5.0) {
                (left_val, right_val) => {
                    if !(*left_val == *right_val) {
                        let kind = ::core::panicking::AssertKind::Eq;
                        ::core::panicking::assert_failed(
                            kind,
                            &*left_val,
                            &*right_val,
                            ::core::option::Option::None,
                        );
                    }
                }
            };
            let params = {
                use ::runar_common::types::ArcValueType;
                use std::collections::HashMap;
                let mut map = HashMap::new();
                map.insert("a".to_string(), ArcValueType::new_primitive(5.0));
                map.insert("b".to_string(), ArcValueType::new_primitive(3.0));
                ArcValueType::new_map(map)
            };
            let response: f64 = node
                .request("math/multiply_numbers", Some(params))
                .await
                .expect("Failed to call multiply_numbers action");
            match (&response, &15.0) {
                (left_val, right_val) => {
                    if !(*left_val == *right_val) {
                        let kind = ::core::panicking::AssertKind::Eq;
                        ::core::panicking::assert_failed(
                            kind,
                            &*left_val,
                            &*right_val,
                            ::core::option::Option::None,
                        );
                    }
                }
            };
            let params = {
                use ::runar_common::types::ArcValueType;
                use std::collections::HashMap;
                let mut map = HashMap::new();
                map.insert("a".to_string(), ArcValueType::new_primitive(6.0));
                map.insert("b".to_string(), ArcValueType::new_primitive(3.0));
                ArcValueType::new_map(map)
            };
            let response: f64 = node
                .request("math/divide", Some(params))
                .await
                .expect("Failed to call divide action");
            match (&response, &2.0) {
                (left_val, right_val) => {
                    if !(*left_val == *right_val) {
                        let kind = ::core::panicking::AssertKind::Eq;
                        ::core::panicking::assert_failed(
                            kind,
                            &*left_val,
                            &*right_val,
                            ::core::option::Option::None,
                        );
                    }
                }
            };
            let params = {
                use ::runar_common::types::ArcValueType;
                use std::collections::HashMap;
                let mut map = HashMap::new();
                map.insert("a".to_string(), ArcValueType::new_primitive(6.0));
                map.insert("b".to_string(), ArcValueType::new_primitive(0.0));
                ArcValueType::new_map(map)
            };
            let response: Result<f64, anyhow::Error> =
                node.request("math/divide", Some(params)).await;
            if !response
                .unwrap_err()
                .to_string()
                .contains("Division by zero")
            {
                ::core::panicking::panic(
                    "assertion failed: response.unwrap_err().to_string().contains(\"Division by zero\")",
                )
            }
            let params = ArcValueType::new_primitive(42);
            let response: User = node
                .request("math/get_user", Some(params))
                .await
                .expect("Failed to call get_user action");
            match (&response.name, &"John Doe") {
                (left_val, right_val) => {
                    if !(*left_val == *right_val) {
                        let kind = ::core::panicking::AssertKind::Eq;
                        ::core::panicking::assert_failed(
                            kind,
                            &*left_val,
                            &*right_val,
                            ::core::option::Option::None,
                        );
                    }
                }
            };
            let response: MyData = node
                .request("math/my_data", Some(ArcValueType::new_primitive(100)))
                .await
                .expect("Failed to call my_data action");
            let my_data = response;
            match (
                &my_data,
                &MyData {
                    id: 100,
                    text_field: "test".to_string(),
                    number_field: 100,
                    boolean_field: true,
                    float_field: 1500.0,
                    vector_field: <[_]>::into_vec(::alloc::boxed::box_new([1, 2, 3])),
                    map_field: HashMap::new(),
                },
            ) {
                (left_val, right_val) => {
                    if !(*left_val == *right_val) {
                        let kind = ::core::panicking::AssertKind::Eq;
                        ::core::panicking::assert_failed(
                            kind,
                            &*left_val,
                            &*right_val,
                            ::core::option::Option::None,
                        );
                    }
                }
            };
            let store = store.lock().await;
            if let Some(my_data_arc) = store.get("my_data_auto") {
                let mut my_data_arc = my_data_arc.clone();
                let my_data_vec = my_data_arc.as_list_ref::<MyData>().unwrap();
                if !!my_data_vec.is_empty() {
                    {
                        ::core::panicking::panic_fmt(format_args!(
                            "Expected at least one my_data_auto event"
                        ));
                    }
                }
                match (&my_data_vec[0], &my_data) {
                    (left_val, right_val) => {
                        if !(*left_val == *right_val) {
                            let kind = ::core::panicking::AssertKind::Eq;
                            ::core::panicking::assert_failed(
                                kind,
                                &*left_val,
                                &*right_val,
                                ::core::option::Option::Some(format_args!(
                                    "The first my_data_auto event doesn\'t match expected data",
                                )),
                            );
                        }
                    }
                };
                {
                    ::std::io::_print(format_args!(
                        "my_data_auto events count: {0}\n",
                        my_data_vec.len(),
                    ));
                };
            } else {
                {
                    ::core::panicking::panic_fmt(format_args!(
                        "Expected \'my_data_auto\' key in store, but it wasn\'t found",
                    ));
                };
            }
            if let Some(added_arc) = store.get("added") {
                let mut added_arc = added_arc.clone();
                let added_vec = added_arc.as_list_ref::<f64>().unwrap();
                if !!added_vec.is_empty() {
                    {
                        ::core::panicking::panic_fmt(format_args!(
                            "Expected at least one added event"
                        ));
                    }
                }
                match (&added_vec[0], &15.0) {
                    (left_val, right_val) => {
                        if !(*left_val == *right_val) {
                            let kind = ::core::panicking::AssertKind::Eq;
                            ::core::panicking::assert_failed(
                                kind,
                                &*left_val,
                                &*right_val,
                                ::core::option::Option::Some(format_args!(
                                    "Expected first added value to be 15.0"
                                )),
                            );
                        }
                    }
                };
                match (&added_vec[1], &1500.0) {
                    (left_val, right_val) => {
                        if !(*left_val == *right_val) {
                            let kind = ::core::panicking::AssertKind::Eq;
                            ::core::panicking::assert_failed(
                                kind,
                                &*left_val,
                                &*right_val,
                                ::core::option::Option::Some(format_args!(
                                    "Expected second added value to be 1500.0"
                                )),
                            );
                        }
                    }
                };
                match (&added_vec.len(), &2) {
                    (left_val, right_val) => {
                        if !(*left_val == *right_val) {
                            let kind = ::core::panicking::AssertKind::Eq;
                            ::core::panicking::assert_failed(
                                kind,
                                &*left_val,
                                &*right_val,
                                ::core::option::Option::Some(format_args!(
                                    "Expected two added events"
                                )),
                            );
                        }
                    }
                };
                {
                    ::std::io::_print(format_args!("added events count: {0}\n", added_vec.len()));
                };
            } else {
                {
                    ::core::panicking::panic_fmt(format_args!(
                        "Expected \'added\' key in store, but it wasn\'t found",
                    ));
                };
            }
            if let Some(changed_arc) = store.get("my_data_changed") {
                let mut changed_arc = changed_arc.clone();
                let changed_vec = changed_arc.as_list_ref::<MyData>().unwrap();
                if !!changed_vec.is_empty() {
                    {
                        ::core::panicking::panic_fmt(format_args!(
                            "Expected at least one my_data_changed event"
                        ));
                    }
                }
                match (&changed_vec[0].id, &my_data.id) {
                    (left_val, right_val) => {
                        if !(*left_val == *right_val) {
                            let kind = ::core::panicking::AssertKind::Eq;
                            ::core::panicking::assert_failed(
                                kind,
                                &*left_val,
                                &*right_val,
                                ::core::option::Option::Some(format_args!(
                                    "Expected first my_data_changed.id to match"
                                )),
                            );
                        }
                    }
                };
                {
                    ::std::io::_print(format_args!(
                        "my_data_changed events count: {0}\n",
                        changed_vec.len(),
                    ));
                };
            } else {
                {
                    ::core::panicking::panic_fmt(format_args!(
                        "Expected \'my_data_changed\' key in store, but it wasn\'t found",
                    ));
                };
            }
            if let Some(age_arc) = store.get("age_changed") {
                let mut age_arc = age_arc.clone();
                let age_vec = age_arc.as_list_ref::<i32>().unwrap();
                if !!age_vec.is_empty() {
                    {
                        ::core::panicking::panic_fmt(format_args!(
                            "Expected at least one age_changed event"
                        ));
                    }
                }
                match (&age_vec[0], &25) {
                    (left_val, right_val) => {
                        if !(*left_val == *right_val) {
                            let kind = ::core::panicking::AssertKind::Eq;
                            ::core::panicking::assert_failed(
                                kind,
                                &*left_val,
                                &*right_val,
                                ::core::option::Option::Some(format_args!(
                                    "Expected first age_changed value to be 25"
                                )),
                            );
                        }
                    }
                };
                match (&age_vec.len(), &1) {
                    (left_val, right_val) => {
                        if !(*left_val == *right_val) {
                            let kind = ::core::panicking::AssertKind::Eq;
                            ::core::panicking::assert_failed(
                                kind,
                                &*left_val,
                                &*right_val,
                                ::core::option::Option::Some(format_args!(
                                    "Expected one age_changed event"
                                )),
                            );
                        }
                    }
                };
                {
                    ::std::io::_print(format_args!(
                        "age_changed events count: {0}\n",
                        age_vec.len()
                    ));
                };
            } else {
                {
                    ::core::panicking::panic_fmt(format_args!(
                        "Expected \'age_changed\' key in store, but it wasn\'t found",
                    ));
                };
            }
            let serializer = node.serializer.read().await;
            let arc_value = ArcValueType::from_struct(my_data.clone());
            let bytes = serializer.serialize_value(&arc_value).unwrap();
            let arc_bytes = Arc::from(bytes);
            let mut deserialized = serializer.deserialize_value(arc_bytes).unwrap();
            let deserialized_my_data = deserialized.as_type::<MyData>().unwrap();
            match (&deserialized_my_data, &my_data) {
                (left_val, right_val) => {
                    if !(*left_val == *right_val) {
                        let kind = ::core::panicking::AssertKind::Eq;
                        ::core::panicking::assert_failed(
                            kind,
                            &*left_val,
                            &*right_val,
                            ::core::option::Option::None,
                        );
                    }
                }
            };
            let user = User {
                id: 42,
                name: "John Doe".to_string(),
                email: "john.doe@example.com".to_string(),
                age: 30,
            };
            let arc_value = ArcValueType::from_struct(user.clone());
            let bytes = serializer.serialize_value(&arc_value).unwrap();
            let arc_bytes = Arc::from(bytes);
            let mut deserialized = serializer.deserialize_value(arc_bytes).unwrap();
            let deserialized_user = deserialized.as_type::<User>().unwrap();
            match (&deserialized_user, &user) {
                (left_val, right_val) => {
                    if !(*left_val == *right_val) {
                        let kind = ::core::panicking::AssertKind::Eq;
                        ::core::panicking::assert_failed(
                            kind,
                            &*left_val,
                            &*right_val,
                            ::core::option::Option::None,
                        );
                    }
                }
            };
            let mut temp_map = HashMap::new();
            temp_map.insert("key1".to_string(), "value1".to_string());
            let param: Vec<HashMap<String, String>> =
                <[_]>::into_vec(::alloc::boxed::box_new([temp_map]));
            let arc_value = ArcValueType::new_list(param);
            let list_result: Vec<HashMap<String, String>> = node
                .request("math/complex_data", Some(arc_value))
                .await
                .expect("Failed to call complex_data action");
            match (&list_result.len(), &1) {
                (left_val, right_val) => {
                    if !(*left_val == *right_val) {
                        let kind = ::core::panicking::AssertKind::Eq;
                        ::core::panicking::assert_failed(
                            kind,
                            &*left_val,
                            &*right_val,
                            ::core::option::Option::None,
                        );
                    }
                }
            };
            match (&list_result[0].get("key1").unwrap(), &"value1") {
                (left_val, right_val) => {
                    if !(*left_val == *right_val) {
                        let kind = ::core::panicking::AssertKind::Eq;
                        ::core::panicking::assert_failed(
                            kind,
                            &*left_val,
                            &*right_val,
                            ::core::option::Option::None,
                        );
                    }
                }
            };
            let pre_wrapped_params = HashMap::from([
                (
                    "id_str".to_string(),
                    ArcValueType::new_primitive("test_pre_wrap".to_string()),
                ),
                ("val_int".to_string(), ArcValueType::new_primitive(999i32)),
            ]);
            let pre_wrapped_res: PreWrappedStruct = node
                .request(
                    "math/echo_pre_wrapped_struct",
                    Some(ArcValueType::new_map(pre_wrapped_params.clone())),
                )
                .await
                .expect("Failed to call echo_pre_wrapped_struct");
            match (&pre_wrapped_res.id, &"test_pre_wrap") {
                (left_val, right_val) => {
                    if !(*left_val == *right_val) {
                        let kind = ::core::panicking::AssertKind::Eq;
                        ::core::panicking::assert_failed(
                            kind,
                            &*left_val,
                            &*right_val,
                            ::core::option::Option::None,
                        );
                    }
                }
            };
            match (&pre_wrapped_res.value, &999) {
                (left_val, right_val) => {
                    if !(*left_val == *right_val) {
                        let kind = ::core::panicking::AssertKind::Eq;
                        ::core::panicking::assert_failed(
                            kind,
                            &*left_val,
                            &*right_val,
                            ::core::option::Option::None,
                        );
                    }
                }
            };
            let pre_wrapped_option_res: Option<PreWrappedStruct> = node
                .request(
                    "math/echo_pre_wrapped_struct",
                    Some(ArcValueType::new_map(pre_wrapped_params)),
                )
                .await
                .expect("Failed to call echo_pre_wrapped_struct for Option result");
            if !pre_wrapped_option_res.is_some() {
                {
                    ::core::panicking::panic_fmt(format_args!(
                        "Expected Some(PreWrappedStruct) but got None"
                    ));
                }
            }
            let unwrapped_option_res = pre_wrapped_option_res.unwrap();
            match (&unwrapped_option_res.id, &"test_pre_wrap") {
                (left_val, right_val) => {
                    if !(*left_val == *right_val) {
                        let kind = ::core::panicking::AssertKind::Eq;
                        ::core::panicking::assert_failed(
                            kind,
                            &*left_val,
                            &*right_val,
                            ::core::option::Option::None,
                        );
                    }
                }
            };
            match (&unwrapped_option_res.value, &999) {
                (left_val, right_val) => {
                    if !(*left_val == *right_val) {
                        let kind = ::core::panicking::AssertKind::Eq;
                        ::core::panicking::assert_failed(
                            kind,
                            &*left_val,
                            &*right_val,
                            ::core::option::Option::None,
                        );
                    }
                }
            };
            if let Some(added_arc) = store.get("added") {
                let mut added_arc = added_arc.clone();
                let added_vec = added_arc.as_list_ref::<f64>().unwrap();
                if !!added_vec.is_empty() {
                    {
                        ::core::panicking::panic_fmt(format_args!(
                            "Expected at least one added event"
                        ));
                    }
                }
                match (&added_vec[0], &15.0) {
                    (left_val, right_val) => {
                        if !(*left_val == *right_val) {
                            let kind = ::core::panicking::AssertKind::Eq;
                            ::core::panicking::assert_failed(
                                kind,
                                &*left_val,
                                &*right_val,
                                ::core::option::Option::Some(format_args!(
                                    "Expected first added value to be 15.0"
                                )),
                            );
                        }
                    }
                };
                match (&added_vec[1], &1500.0) {
                    (left_val, right_val) => {
                        if !(*left_val == *right_val) {
                            let kind = ::core::panicking::AssertKind::Eq;
                            ::core::panicking::assert_failed(
                                kind,
                                &*left_val,
                                &*right_val,
                                ::core::option::Option::Some(format_args!(
                                    "Expected second added value to be 1500.0"
                                )),
                            );
                        }
                    }
                };
                match (&added_vec.len(), &2) {
                    (left_val, right_val) => {
                        if !(*left_val == *right_val) {
                            let kind = ::core::panicking::AssertKind::Eq;
                            ::core::panicking::assert_failed(
                                kind,
                                &*left_val,
                                &*right_val,
                                ::core::option::Option::Some(format_args!(
                                    "Expected two added events"
                                )),
                            );
                        }
                    }
                };
                {
                    ::std::io::_print(format_args!("added events count: {0}\n", added_vec.len()));
                };
            } else {
                {
                    ::core::panicking::panic_fmt(format_args!(
                        "Expected \'added\' key in store, but it wasn\'t found",
                    ));
                };
            }
            if let Some(changed_arc) = store.get("my_data_changed") {
                let mut changed_arc = changed_arc.clone();
                let changed_vec = changed_arc.as_list_ref::<MyData>().unwrap();
                if !!changed_vec.is_empty() {
                    {
                        ::core::panicking::panic_fmt(format_args!(
                            "Expected at least one my_data_changed event"
                        ));
                    }
                }
                match (&changed_vec[0].id, &my_data.id) {
                    (left_val, right_val) => {
                        if !(*left_val == *right_val) {
                            let kind = ::core::panicking::AssertKind::Eq;
                            ::core::panicking::assert_failed(
                                kind,
                                &*left_val,
                                &*right_val,
                                ::core::option::Option::Some(format_args!(
                                    "Expected first my_data_changed.id to match"
                                )),
                            );
                        }
                    }
                };
                {
                    ::std::io::_print(format_args!(
                        "my_data_changed events count: {0}\n",
                        changed_vec.len(),
                    ));
                };
            } else {
                {
                    ::core::panicking::panic_fmt(format_args!(
                        "Expected \'my_data_changed\' key in store, but it wasn\'t found",
                    ));
                };
            }
            if let Some(age_arc) = store.get("age_changed") {
                let mut age_arc = age_arc.clone();
                let age_vec = age_arc.as_list_ref::<i32>().unwrap();
                if !!age_vec.is_empty() {
                    {
                        ::core::panicking::panic_fmt(format_args!(
                            "Expected at least one age_changed event"
                        ));
                    }
                }
                match (&age_vec[0], &25) {
                    (left_val, right_val) => {
                        if !(*left_val == *right_val) {
                            let kind = ::core::panicking::AssertKind::Eq;
                            ::core::panicking::assert_failed(
                                kind,
                                &*left_val,
                                &*right_val,
                                ::core::option::Option::Some(format_args!(
                                    "Expected first age_changed value to be 25"
                                )),
                            );
                        }
                    }
                };
                match (&age_vec.len(), &1) {
                    (left_val, right_val) => {
                        if !(*left_val == *right_val) {
                            let kind = ::core::panicking::AssertKind::Eq;
                            ::core::panicking::assert_failed(
                                kind,
                                &*left_val,
                                &*right_val,
                                ::core::option::Option::Some(format_args!(
                                    "Expected one age_changed event"
                                )),
                            );
                        }
                    }
                };
                {
                    ::std::io::_print(format_args!(
                        "age_changed events count: {0}\n",
                        age_vec.len()
                    ));
                };
            } else {
                {
                    ::core::panicking::panic_fmt(format_args!(
                        "Expected \'age_changed\' key in store, but it wasn\'t found",
                    ));
                };
            }
            let serializer = node.serializer.read().await;
            let arc_value = ArcValueType::from_struct(my_data.clone());
            let bytes = serializer.serialize_value(&arc_value).unwrap();
            let arc_bytes = Arc::from(bytes);
            let mut deserialized = serializer.deserialize_value(arc_bytes).unwrap();
            let deserialized_my_data = deserialized.as_type::<MyData>().unwrap();
            match (&deserialized_my_data, &my_data) {
                (left_val, right_val) => {
                    if !(*left_val == *right_val) {
                        let kind = ::core::panicking::AssertKind::Eq;
                        ::core::panicking::assert_failed(
                            kind,
                            &*left_val,
                            &*right_val,
                            ::core::option::Option::None,
                        );
                    }
                }
            };
            let user = User {
                id: 42,
                name: "John Doe".to_string(),
                email: "john.doe@example.com".to_string(),
                age: 30,
            };
            let arc_value = ArcValueType::from_struct(user.clone());
            let bytes = serializer.serialize_value(&arc_value).unwrap();
            let arc_bytes = Arc::from(bytes);
            let mut deserialized = serializer.deserialize_value(arc_bytes).unwrap();
            let deserialized_user = deserialized.as_type::<User>().unwrap();
            match (&deserialized_user, &user) {
                (left_val, right_val) => {
                    if !(*left_val == *right_val) {
                        let kind = ::core::panicking::AssertKind::Eq;
                        ::core::panicking::assert_failed(
                            kind,
                            &*left_val,
                            &*right_val,
                            ::core::option::Option::None,
                        );
                    }
                }
            };
            let mut temp_map = HashMap::new();
            temp_map.insert("key1".to_string(), "value1".to_string());
            let param: Vec<HashMap<String, String>> =
                <[_]>::into_vec(::alloc::boxed::box_new([temp_map]));
            let arc_value = ArcValueType::new_list(param);
            let list_result: Vec<HashMap<String, String>> = node
                .request("math/complex_data", Some(arc_value))
                .await
                .expect("Failed to call complex_data action");
            match (&list_result.len(), &1) {
                (left_val, right_val) => {
                    if !(*left_val == *right_val) {
                        let kind = ::core::panicking::AssertKind::Eq;
                        ::core::panicking::assert_failed(
                            kind,
                            &*left_val,
                            &*right_val,
                            ::core::option::Option::None,
                        );
                    }
                }
            };
            match (&list_result[0].get("key1").unwrap(), &"value1") {
                (left_val, right_val) => {
                    if !(*left_val == *right_val) {
                        let kind = ::core::panicking::AssertKind::Eq;
                        ::core::panicking::assert_failed(
                            kind,
                            &*left_val,
                            &*right_val,
                            ::core::option::Option::None,
                        );
                    }
                }
            };
        };
        let mut body = body;
        #[allow(unused_mut)]
        let mut body = unsafe { ::tokio::macros::support::Pin::new_unchecked(&mut body) };
        let body: ::core::pin::Pin<&mut dyn ::core::future::Future<Output = ()>> = body;
        #[allow(
            clippy::expect_used,
            clippy::diverging_sub_expression,
            clippy::needless_return
        )]
        {
            return tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Failed building the Runtime")
                .block_on(body);
        }
    }
}
#[rustc_main]
#[coverage(off)]
#[doc(hidden)]
pub fn main() -> () {
    extern crate test;
    test::test_main_static(&[&test_math_service])
}
