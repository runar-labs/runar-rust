Lets improve rn_discovery_new_with_multicast

It shuold not receive keys: *mut c_void, as parameter.. keys is onlyn used for:
let node_pk = match node_manager.get_node_public_key() {
To ge te node public key.

Instead it shuold reveid peerInfo as parameter(in CBOR just like -> options_cbor 

The options_cbor  just contain the DiscoveryOptions struct serialized.. nothing more.

Also we shuold not parse this manulay like this fn parse_discovery_options(cbor: &[u8]) -> DiscoveryOptions It shuold be a standards CBOR serialization of the struct DiscoveryOptions.

So itn shuold be

pub unsafe extern "C" fn rn_discovery_new_with_multicast(
    peer_info_cbor: *const u8,
    peer_info_len: usize,
    options_cbor: *const u8,
    options_len: usize,
    out_discovery: *mut *mut c_void,
    err: *mut RnError,
) -> i32 {


Both objects PeerIndo and DiscoveryOptions shuold use standard CBOR serailization. not specialized method like parse_discovery_options

Update tehe FFI lib and all tests to use this API.. no backwared compat.. do a full refactory. 