use runar_ffi::*;
use serde_cbor::Value;
use std::ffi::CString;

// Import common utilities
mod common;

#[repr(C)]
struct RnError {
    code: i32,
    message: *const std::os::raw::c_char,
}

// no-op: legacy callback removed in favor of push-based API

#[test]
#[ignore] // TODO: Enable when transport integration is implemented
fn two_transports_request_response() {
    unsafe {
        let mut err = RnError {
            code: 0,
            message: std::ptr::null(),
        };

        let mut keys_a: *mut std::ffi::c_void = std::ptr::null_mut();
        assert_eq!(rn_keys_new(&mut keys_a, &mut err as *mut _ as *mut _), 0);

        // Initialize as node first
        assert_eq!(
            rn_keys_init_as_node(keys_a, &mut err as *mut _ as *mut _),
            0
        );

        // Create second node keys for B
        let mut keys_b: *mut std::ffi::c_void = std::ptr::null_mut();
        assert_eq!(rn_keys_new(&mut keys_b, &mut err as *mut _ as *mut _), 0);
        assert_eq!(
            rn_keys_init_as_node(keys_b, &mut err as *mut _ as *mut _),
            0
        );

        // Set node info for B
        let info = runar_schemas::NodeInfo {
            node_public_key: vec![],
            network_ids: vec![],
            addresses: vec![],
            node_metadata: runar_schemas::NodeMetadata {
                services: vec![],
                subscriptions: vec![],
            },
            version: 0,
        };
        let info_buf = serde_cbor::to_vec(&info).unwrap();
        assert_eq!(
            rn_keys_set_local_node_info(keys_b, info_buf.as_ptr(), info_buf.len()),
            0
        );

        // Create mobile keys for processing setup tokens
        let mut keys_c: *mut std::ffi::c_void = std::ptr::null_mut();
        assert_eq!(rn_keys_new(&mut keys_c, &mut err as *mut _ as *mut _), 0);
        assert_eq!(
            rn_keys_init_as_mobile(keys_c, &mut err as *mut _ as *mut _),
            0
        );

        // Set node info for A
        assert_eq!(
            rn_keys_set_local_node_info(keys_a, info_buf.as_ptr(), info_buf.len()),
            0
        );

        let mut p: *mut u8 = std::ptr::null_mut();
        let mut l: usize = 0;
        assert_eq!(
            rn_keys_node_generate_csr(keys_a, &mut p, &mut l, &mut err as *mut _ as *mut _),
            0
        );
        let mut ncm_p: *mut u8 = std::ptr::null_mut();
        let mut ncm_l: usize = 0;
        assert_eq!(
            rn_keys_mobile_process_setup_token(
                keys_c,
                p,
                l,
                &mut ncm_p,
                &mut ncm_l,
                &mut err as *mut _ as *mut _
            ),
            0
        );
        rn_free(p, l);
        assert_eq!(
            rn_keys_node_install_certificate(keys_a, ncm_p, ncm_l, &mut err as *mut _ as *mut _),
            0
        );
        rn_free(ncm_p, ncm_l);
        // Label resolver functionality removed - no longer needed for transport

        let mut p2: *mut u8 = std::ptr::null_mut();
        let mut l2: usize = 0;
        assert_eq!(
            rn_keys_node_generate_csr(keys_b, &mut p2, &mut l2, &mut err as *mut _ as *mut _),
            0
        );
        let mut ncm_p2: *mut u8 = std::ptr::null_mut();
        let mut ncm_l2: usize = 0;
        // Use A as CA for B
        assert_eq!(
            rn_keys_mobile_process_setup_token(
                keys_c,
                p2,
                l2,
                &mut ncm_p2,
                &mut ncm_l2,
                &mut err as *mut _ as *mut _
            ),
            0
        );
        rn_free(p2, l2);
        assert_eq!(
            rn_keys_node_install_certificate(keys_b, ncm_p2, ncm_l2, &mut err as *mut _ as *mut _),
            0
        );
        rn_free(ncm_p2, ncm_l2);

        let mut omap = std::collections::BTreeMap::<Value, Value>::new();
        omap.insert(
            Value::Text("bind_addr".into()),
            Value::Text("127.0.0.1:0".into()),
        );
        omap.insert(
            Value::Text("max_message_size".into()),
            Value::Integer(65536),
        );
        let options = Value::Map(omap);
        let buf = serde_cbor::to_vec(&options).unwrap();

        let mut ta: *mut std::ffi::c_void = std::ptr::null_mut();
        assert_eq!(
            rn_transport_new_with_keys(
                keys_a,
                buf.as_ptr(),
                buf.len(),
                &mut ta,
                &mut err as *mut _ as *mut _
            ),
            0
        );
        assert_eq!(rn_transport_start(ta, &mut err as *mut _ as *mut _), 0);
        let mut a_addr: *mut std::os::raw::c_char = std::ptr::null_mut();
        let mut a_len: usize = 0;
        assert_eq!(
            rn_transport_local_addr(ta, &mut a_addr, &mut a_len, &mut err as *mut _ as *mut _),
            0
        );
        let a_addr_str = std::ffi::CStr::from_ptr(a_addr)
            .to_string_lossy()
            .into_owned();
        rn_string_free(a_addr);

        let mut tb: *mut std::ffi::c_void = std::ptr::null_mut();
        assert_eq!(
            rn_transport_new_with_keys(
                keys_b,
                buf.as_ptr(),
                buf.len(),
                &mut tb,
                &mut err as *mut _ as *mut _
            ),
            0
        );
        assert_eq!(rn_transport_start(tb, &mut err as *mut _ as *mut _), 0);

        let mut pk_out: *mut u8 = std::ptr::null_mut();
        let mut pk_len: usize = 0;
        assert_eq!(
            rn_keys_node_get_public_key(
                keys_a,
                &mut pk_out,
                &mut pk_len,
                &mut err as *mut _ as *mut _
            ),
            0
        );
        let pubk = std::slice::from_raw_parts(pk_out, pk_len).to_vec();
        rn_free(pk_out, pk_len);

        let peer = runar_transporter::discovery::multicast_discovery::PeerInfo::new(
            pubk,
            vec![a_addr_str.clone()],
        );
        let peer_cbor = serde_cbor::to_vec(&peer).unwrap();
        assert_eq!(
            rn_transport_connect_peer(
                tb,
                peer_cbor.as_ptr(),
                peer_cbor.len(),
                &mut err as *mut _ as *mut _
            ),
            0
        );

        let path = CString::new("/echo").unwrap();
        let cid = CString::new("c1").unwrap();
        let peer_id = runar_common::compact_ids::compact_id(&peer.public_key);
        let peer_id_c = CString::new(peer_id).unwrap();
        let payload: Vec<u8> = b"hello".to_vec();
        let empty_pk: Vec<u8> = vec![];
        assert_eq!(
            rn_transport_request(
                tb,
                path.as_ptr(),
                cid.as_ptr(),
                payload.as_ptr(),
                payload.len(),
                peer_id_c.as_ptr(),
                empty_pk.as_ptr(),
                empty_pk.len(),
                &mut err as *mut _ as *mut _
            ),
            0
        );

        // Handle request on A then complete
        let mut rid_c: Option<CString> = None;
        for _ in 0..50 {
            let mut ev_ptr: *mut u8 = std::ptr::null_mut();
            let mut ev_len: usize = 0;
            let rc =
                rn_transport_poll_event(ta, &mut ev_ptr, &mut ev_len, &mut err as *mut _ as *mut _);
            assert_eq!(rc, 0);
            if !ev_ptr.is_null() && ev_len > 0 {
                let v: Value =
                    serde_cbor::from_slice(std::slice::from_raw_parts(ev_ptr, ev_len)).unwrap();
                rn_free(ev_ptr, ev_len);
                if let Value::Map(m) = v {
                    let typ = m.get(&Value::Text("type".into())).and_then(|vv| match vv {
                        Value::Text(s) => Some(s.as_str()),
                        _ => None,
                    });
                    if typ == Some("RequestReceived") {
                        if let Some(Value::Text(rid)) = m.get(&Value::Text("request_id".into())) {
                            rid_c = Some(CString::new(rid.as_str()).unwrap());
                            break;
                        }
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let rid = rid_c.expect("no request received on server");
        let resp_payload: Vec<u8> = b"world".to_vec();
        assert_eq!(
            rn_transport_complete_request(
                ta,
                rid.as_ptr(),
                resp_payload.as_ptr(),
                resp_payload.len(),
                empty_pk.as_ptr(),
                empty_pk.len(),
                &mut err as *mut _ as *mut _
            ),
            0
        );

        // Expect response on B
        let mut got_resp = false;
        for _ in 0..50 {
            let mut ev_ptr: *mut u8 = std::ptr::null_mut();
            let mut ev_len: usize = 0;
            let rc =
                rn_transport_poll_event(tb, &mut ev_ptr, &mut ev_len, &mut err as *mut _ as *mut _);
            assert_eq!(rc, 0);
            if !ev_ptr.is_null() && ev_len > 0 {
                let v: Value =
                    serde_cbor::from_slice(std::slice::from_raw_parts(ev_ptr, ev_len)).unwrap();
                if let Value::Map(m) = v {
                    let typ = m.get(&Value::Text("type".into())).and_then(|vv| match vv {
                        Value::Text(s) => Some(s.as_str()),
                        _ => None,
                    });
                    if typ == Some("ResponseReceived") {
                        got_resp = true;
                        rn_free(ev_ptr, ev_len);
                        break;
                    }
                }
                rn_free(ev_ptr, ev_len);
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(got_resp, "did not get response event");

        // Cleanup
        let _ = rn_transport_stop(tb, &mut err as *mut _ as *mut _);
        rn_transport_free(tb);
        let _ = rn_transport_stop(ta, &mut err as *mut _ as *mut _);
        rn_transport_free(ta);
        rn_keys_free(keys_a);
        rn_keys_free(keys_b);
        rn_keys_free(keys_c);
    }
}
