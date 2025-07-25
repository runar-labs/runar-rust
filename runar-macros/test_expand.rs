use runar_macros::action;
use runar_serializer::Plain;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Plain)]
pub struct PreWrappedStruct {
    id: String,
    value: i32,
}

#[action]
async fn echo_single_struct(
    params: PreWrappedStruct,
) -> Result<PreWrappedStruct, anyhow::Error> {
    Ok(params)
} 