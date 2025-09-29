IMplement in the nodejs API a test in TS equivalente to the FFI test /home/rafael/Development/runar-rust/runar-ffi/tests/ffi_transport_test.rs

Must be 100% aligned. 
same setup, same steps, same asserts. Nothing more nothing less. 100% aligment.


Review 01 - ISsues FOund:
 
## **DETAILED LINE-BY-LINE COMPARISON**

### **FFI Implementation (lines 4019-4057 in runar-ffi/src/lib.rs):**

```rust
let request_callback: runar_transporter::transport::RequestCallback = Arc::new(move |req| {
    let req_tx = req_tx.clone();
    let pending_cb = pending_cb.clone();
    Box::pin(async move {
        let request_id = uuid::Uuid::new_v4().to_string();
        let (tx_resp, rx_resp) = oneshot::channel();
        pending_cb.lock().await.insert(request_id.clone(), tx_resp);

        let mut map = std::collections::BTreeMap::new();
        map.insert(
            serde_cbor::Value::Text("type".into()),
            serde_cbor::Value::Text("RequestReceived".into()),
        );
        map.insert(
            serde_cbor::Value::Text("v".into()),
            serde_cbor::Value::Integer(1),
        );
        map.insert(
            serde_cbor::Value::Text("request_id".into()),
            serde_cbor::Value::Text(request_id),
        );
        map.insert(
            serde_cbor::Value::Text("path".into()),
            serde_cbor::Value::Text(req.payload.path.clone()),
        );
        map.insert(
            serde_cbor::Value::Text("correlation_id".into()),
            serde_cbor::Value::Text(req.payload.correlation_id.clone()),
        );
        map.insert(
            serde_cbor::Value::Text("payload".into()),
            serde_cbor::Value::Bytes(req.payload.payload_bytes.clone()),
        );
        map.insert(
            serde_cbor::Value::Text("profile_public_key".into()),
            serde_cbor::Value::Bytes(
                req.payload
                    .profile_public_keys
                    .first()
                    .cloned()
                    .unwrap_or_default(),
            ),
        );
        let _ = req_tx
            .send(serde_cbor::to_vec(&serde_cbor::Value::Map(map)).unwrap_or_default())
            .await;

        match rx_resp.await {
            Ok(resp) => Ok(resp),
            Err(_) => Ok(runar_transporter::transport::NetworkMessage {
                source_node_id: String::new(),
                destination_node_id: String::new(),
                message_type: 5, // MESSAGE_TYPE_RESPONSE
                payload: runar_transporter::transport::NetworkMessagePayloadItem {
                    path: String::new(),
                    payload_bytes: Vec::new(),
                    correlation_id: String::new(),
                    network_public_key: None,
                    profile_public_keys: Vec::new(),
                },
            }),
        }
    })
});
```

### **NodeJS Implementation (lines 1342-1450 in runar-nodejs-api/src/lib.rs):**

```rust
let request_cb: runar_transporter::transport::RequestCallback = {
    let event_tsfn = Arc::clone(&event_tsfn);
    let pending_map = Arc::clone(&pending_map);
    let events_tx = events_tx.clone();
    let logger = Arc::clone(&logger);
    Arc::new(move |req: runar_transporter::transport::NetworkMessage| {
        let event_tsfn = Arc::clone(&event_tsfn);
        let pending_map = Arc::clone(&pending_map);
        let events_tx = events_tx.clone();
        let logger = Arc::clone(&logger);
        Box::pin(async move {
            println!("[request_cb] Request callback called - PRINTLN TEST");
            panic!("[request_cb] PANIC TEST - This should crash if callback is called");
            
            // ... rest of implementation
        })
    })
};
```

## **CRITICAL ISSUES FOUND:**

### **1. MAJOR ISSUE: Panic in Request Callback**
- **FFI**: No panic, clean implementation
- **NodeJS**: Has `panic!("[request_cb] PANIC TEST - This should crash if callback is called");` on line 1354
- **Impact**: This will crash the entire process if the callback is ever called

### **2. MAJOR ISSUE: Missing Response Handling**
- **FFI**: Has proper response handling with `oneshot::channel()` and `rx_resp.await`
- **NodeJS**: Missing the response handling logic entirely
- **Impact**: Requests will never be completed properly

### **3. MAJOR ISSUE: Different Callback Structure**
- **FFI**: Uses `move |req|` (no type annotation)
- **NodeJS**: Uses `move |req: runar_transporter::transport::NetworkMessage|` (with type annotation)
- **Impact**: This might cause compilation issues

### **4. MAJOR ISSUE: Missing Pending Map Insertion**
- **FFI**: Inserts into `pending_cb.lock().await.insert(request_id.clone(), tx_resp);`
- **NodeJS**: Missing this critical step
- **Impact**: `completeRequestFfi` won't be able to find the request

### **5. MAJOR ISSUE: Different Event Channel Usage**
- **FFI**: Uses `req_tx.send(...).await`
- **NodeJS**: Uses `events_tx.send(...).await`
- **Impact**: Different channel, might not work the same way


## **DETAILED LINE-BY-LINE COMPARISON RESULTS**

Based on my analysis, I found the critical issue: **The request callback is not being called despite being registered correctly**. Here's what I discovered:

### **FFI Implementation (Working):**
- **Lines 4019-4057**: Request callback is properly defined and registered
- **Lines 3930-3932**: Callback is registered with `.with_request_callback(rq_cb)`
- **Lines 1101-1117**: `handle_request` method calls `(self.request_callback)(msg).await`

### **NodeJS Implementation (Broken):**
- **Lines 1342-1430**: Request callback is defined but has issues
- **Lines 1510**: Callback is registered with `.with_request_callback(request_cb)`
- **Lines 1101-1117**: `handle_request` method calls `(self.request_callback)(msg).await`

### **CRITICAL ISSUES FOUND:**

1. **Request Callback Not Being Called**: Despite the callback being registered correctly, the `println!` statements I added to the callback are not appearing in the output, indicating the callback is never invoked.

2. **Missing Debug Output**: The `println!` statements I added to `handle_request` are also not appearing, suggesting the method is being called but the callback invocation is failing silently.

3. **Potential Error Swallowing**: The callback might be failing with an error that's being caught and not logged properly.

### **ROOT CAUSE ANALYSIS:**

The issue appears to be that the request callback is registered but never actually called. This could be due to:

1. **Callback Type Mismatch**: The callback signature might not match what the transport expects
2. **Error in Callback Execution**: The callback might be failing silently
3. **Transport Configuration Issue**: The transport might not be properly configured to use the callback

### **NEXT STEPS:**

I need to investigate why the request callback is not being called despite being registered. The issue is likely in the callback registration or execution, not in the test structure itself. The test is 100% aligned with the FFI test structure, but the underlying transport callback mechanism is not working correctly.

The problem is **NOT** in the test alignment - it's in the **callback execution mechanism** in the NodeJS transport implementation.


Review 02 - Issues Found:
I'll do a detailed line-by-line comparison between the NodeJS API code and the FFI code, and then compare the tests. Let me start by reading both implementations systematically.
ssss
1. **FFI Callback Implementation (lines 4019-4082):**
   - Uses `req_tx` for sending events
   - Uses `pending_cb` for pending requests
   - Has proper oneshot channel handling
   - Uses `.await` for sending events

2. **NodeJS Callback Implementation (lines 1340-1426):**
   - Uses `events_tx` for sending events  
   - Uses `pending_map` for pending requests
   - Has proper oneshot channel handling
   - Does NOT use `.await` for sending events

3. **Key Difference Found:**
   - FFI: `let _ = req_tx.send(...).await;` (line 4062-4064)
   - NodeJS: `let _ = events_tx.send(...);` (line 1405-1406)

This is a critical difference! The FFI uses `.await` when sending events, but the NodeJS implementation doesn't. This could be causing the callback to not work properly.

Let me also check the callback registration order and other details systematically.
</think>

## **DETAILED LINE-BY-LINE COMPARISON ANALYSIS**

Based on my systematic analysis, here are the critical differences I found:

## **1. CALLBACK IMPLEMENTATION COMPARISON**

### **FFI Request Callback (lines 4019-4082):**
```rust
let request_callback: runar_transporter::transport::RequestCallback = Arc::new(move |req| {
    let req_tx = req_tx.clone();
    let pending_cb = pending_cb.clone();
    Box::pin(async move {
        let request_id = uuid::Uuid::new_v4().to_string();
        let (tx_resp, rx_resp) = oneshot::channel();
        pending_cb.lock().await.insert(request_id.clone(), tx_resp);
        
        // ... event map creation ...
        
        let _ = req_tx
            .send(serde_cbor::to_vec(&serde_cbor::Value::Map(map)).unwrap_or_default())
            .await;  // ← CRITICAL: Uses .await
        
        match rx_resp.await {
            Ok(resp) => Ok(resp),
            Err(_) => Ok(/* default response */),
        }
    })
});
```

### **NodeJS Request Callback (lines 1340-1426):**
```rust
let request_cb: runar_transporter::transport::RequestCallback = {
    let pending_map = Arc::clone(&pending_map);
    let events_tx = events_tx.clone();
    let logger = Arc::clone(&logger);
    Arc::new(move |req| {
        let pending_map = Arc::clone(&pending_map);
        let events_tx = events_tx.clone();
        let logger = Arc::clone(&logger);
        Box::pin(async move {
            // ... event map creation ...
            
            let _ = events_tx
                .send(serde_cbor::to_vec(&serde_cbor::Value::Map(map)).unwrap_or_default());
                // ← CRITICAL: Missing .await
            
            match rx_resp.await {
                Ok(resp) => Ok(resp),
                Err(_) => Ok(/* default response */),
            }
        })
    })
};
```

## **2. CRITICAL DIFFERENCES FOUND:**

### **❌ DIFFERENCE 1: Missing .await in Event Sending**
- **FFI**: `req_tx.send(...).await;` (line 4062-4064)
- **NodeJS**: `events_tx.send(...);` (line 1405-1406)
- **Impact**: This could cause the callback to not wait for the event to be sent, potentially causing issues

### **❌ DIFFERENCE 2: Different Channel Variable Names**
- **FFI**: Uses `req_tx` for request events
- **NodeJS**: Uses `events_tx` for all events
- **Impact**: This is actually correct for NodeJS implementation

### **❌ DIFFERENCE 3: Different Pending Map Variable Names**
- **FFI**: Uses `pending_cb` 
- **NodeJS**: Uses `pending_map`
- **Impact**: This is actually correct for NodeJS implementation

## **3. TEST COMPARISON ANALYSIS**

### **FFI Test Structure:**
```rust
// 1. Create keys A, B, C
// 2. Set node info for B
// 3. Generate CSR for A, process with C, install cert
// 4. Generate CSR for B, process with C, install cert  
// 5. Create transport options with bind_addr and max_message_size
// 6. Create transport A with keys_a
// 7. Start transport A
// 8. Get local address of A
// 9. Create transport B with keys_b
// 10. Start transport B
// 11. Get public key of A
// 12. Create peer info with A's public key and address
// 13. Connect B to A
// 14. Create request parameters
// 15. Send request from B to A
// 16. Poll events on A until RequestReceived
// 17. Extract request_id from event
// 18. Create complete request parameters
// 19. Complete request on A
// 20. Poll events on B until ResponseReceived
```

### **NodeJS Test Structure:**
```typescript
// 1. Create keys A, B, C
// 2. Set node info for B  
// 3. Generate CSR for A, process with C, install cert
// 4. Generate CSR for B, process with C, install cert
// 5. Create transport options with bind_addr and max_message_size
// 6. Create transport A with keys_a
// 7. Start transport A
// 8. Get local address of A
// 9. Create transport B with keys_b
// 10. Start transport B
// 11. Get public key of A
// 12. Create peer info with A's public key and address
// 13. Connect B to A
// 14. Create request parameters
// 15. Send request from B to A
// 16. Poll events on A until RequestReceived
// 17. Extract request_id from event
// 18. Create complete request parameters
// 19. Complete request on A
// 20. Poll events on B until ResponseReceived
```

**✅ Test Structure**: 100% identical

## **4. ROOT CAUSE ANALYSIS**

The **CRITICAL ISSUE** is in the NodeJS callback implementation:

**Missing `.await` in event sending** - This means the callback doesn't wait for the event to be sent to the channel before continuing. This could cause:

1. **Race conditions** where the callback completes before the event is sent
2. **Event loss** if the channel is full or there are timing issues
3. **Callback not being properly awaited** by the transport layer

## **5. FIX REQUIRED**

The NodeJS implementation needs to be fixed to match the FFI exactly:

```rust
// CURRENT (BROKEN):
let _ = events_tx
    .send(serde_cbor::to_vec(&serde_cbor::Value::Map(map)).unwrap_or_default());

// SHOULD BE (FIXED):
let _ = events_tx
    .send(serde_cbor::to_vec(&serde_cbor::Value::Map(map)).unwrap_or_default())
    .await;
```

This single missing `.await` is likely the root cause of why the request callback is not working properly in the NodeJS implementation.