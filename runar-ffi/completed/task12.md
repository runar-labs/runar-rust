GOAL add the missing get_network_public_key_by_id to the FFI.

Both node and mobile key managers offer this API and it must be available in the FFI also.
pub fn get_network_public_key_by_id(&self, network_id: &str) -> Result<Vec<u8>> {

runar-keys/src/mobile.rs
runar-keys/src/node.rs

Add to the FFI and udpate existin tests to test this API also, DO NOT CREATE A NEW TEST FILE, use exisitn tests for the mobile and node key managers to test this API