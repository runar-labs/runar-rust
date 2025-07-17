use anyhow::Result;
use prost::Message;
// Binary serialization tests for prost messages only require prost

#[derive(Clone, PartialEq, prost::Message)]
pub struct TestStruct {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(uint32, tag = "2")]
    pub value: u32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct UserData {
    #[prost(string, tag = "1")]
    pub user_id: String,
    #[prost(string, tag = "2")]
    pub name: String,
    #[prost(uint32, tag = "3")]
    pub age: u32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ProductData {
    #[prost(string, tag = "1")]
    pub product_id: String,
    #[prost(string, tag = "2")]
    pub name: String,
    #[prost(double, tag = "3")]
    pub price: f64,
}

#[test]
fn test_prost_message_roundtrip() -> Result<()> {
    let original = TestStruct {
        name: "test-struct-123".to_string(),
        value: 42,
    };
    let mut buf = Vec::new();
    original.encode(&mut buf)?;
    let decoded = TestStruct::decode(&*buf)?;
    assert_eq!(original, decoded);
    Ok(())
}

#[test]
fn test_multiple_struct_types_prost() -> Result<()> {
    let user = UserData {
        user_id: "user-123".to_string(),
        name: "testuser".to_string(),
        age: 30,
    };
    let mut user_buf = Vec::new();
    user.encode(&mut user_buf)?;
    let user_decoded = UserData::decode(&*user_buf)?;
    assert_eq!(user, user_decoded);
    let product = ProductData {
        product_id: "prod-456".to_string(),
        name: "Test Product".to_string(),
        price: 99.99,
    };
    let mut product_buf = Vec::new();
    product.encode(&mut product_buf)?;
    let product_decoded = ProductData::decode(&*product_buf)?;
    assert_eq!(product, product_decoded);
    Ok(())
}
