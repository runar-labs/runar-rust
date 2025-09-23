# Task 1: Fix CA Node Handle API Inconsistency

## Summary

Fixed a critical FFI API design flaw where CA Node functions used inconsistent handle types, causing memory corruption and crashes. The issue was that `rn_keys_ca_node_new` returned raw `CANode*` handles, but `rn_keys_ca_node_add_admin_ski` expected shared `Arc<RwLock<CANode>>*` handles.

## Root Cause

- **Mixed Handle Types**: Same object (CA Node) had two different handle types
- **API Inconsistency**: Some functions expected raw handles, others expected shared handles
- **Memory Corruption**: Passing raw handle to function expecting shared handle caused SEGV
- **Design Flaw**: No single consistent handle type for CA Node operations

## Solution: Consistent Shared Handle API

### Changes Made

1. **Removed Inconsistent Functions**:
   - ❌ `rn_keys_ca_node_new` (returned raw `CANode*`)
   - ❌ `rn_keys_ca_node_free` (freed raw handles)
   - ❌ `rn_keys_ca_node_create_shared` (redundant creation function)

2. **Unified API with Shared Handles**:
   - ✅ `rn_keys_ca_node_new_shared` (creates shared `Arc<RwLock<CANode>>*`)
   - ✅ `rn_keys_ca_node_free_shared` (frees shared handles)
   - ✅ All CA Node functions now expect shared handles consistently

3. **Updated All CA Node Functions**:
   - `rn_keys_ca_node_setup_complete` → expects shared handle
   - `rn_keys_ca_node_configure_enrollment_authority` → expects shared handle
   - `rn_keys_ca_node_handle_enroll` → expects shared handle
   - `rn_keys_ca_node_handle_renew` → expects shared handle
   - `rn_keys_ca_node_handle_revoke` → expects shared handle
   - `rn_keys_ca_node_handle_chain` → expects shared handle
   - `rn_keys_ca_node_handle_status` → expects shared handle
   - `rn_keys_ca_node_handle_crl` → expects shared handle
   - `rn_keys_ca_node_add_admin_ski` → expects shared handle (was already correct)
   - `rn_keys_ca_node_revoke_token` → expects shared handle
   - `rn_keys_ca_node_generate_crl_lite` → expects shared handle

## Design Changes

### Updated FFI_API_DESIGN.md

1. **CA Node API Section**: Updated to show consistent shared handle usage
2. **E2E Test Plan**: Updated all test phases to use shared handles
3. **Function Signatures**: All CA Node functions now use `shared_ca_node: *mut c_void`
4. **Lessons Learned Section**: Added comprehensive analysis and prevention strategies

### Key Design Principles Established

1. **Single Handle Type Per Object**: Each FFI object has exactly one handle type
2. **Thread Safety by Default**: Use shared handles for multi-context access
3. **No Mixed APIs**: Never mix raw and shared handles for same object
4. **Consistent Naming**: Clear naming indicates handle type
5. **No Backward Compatibility for Broken APIs**: Fix completely rather than maintain compatibility

## Implementation Tasks

### Phase 1: Update Rust FFI Implementation
- [ ] Remove `rn_keys_ca_node_new` function
- [ ] Rename `rn_keys_ca_node_create_shared` to `rn_keys_ca_node_new_shared`
- [ ] Update all CA Node functions to expect shared handles
- [ ] Update function implementations to use `Arc<RwLock<CANode>>` consistently
- [ ] Remove `rn_keys_ca_node_free` function
- [ ] Update `rn_keys_ca_node_free_shared` function

### Phase 2: Update Header Files
- [ ] Update `runar_ffi.h` with new function signatures
- [ ] Remove old function declarations
- [ ] Add new function declarations with shared handle parameters

### Phase 3: Update Tests
- [ ] Update all test files to use `rn_keys_ca_node_new_shared`
- [ ] Update all test calls to pass shared handles
- [ ] Update cleanup code to use `rn_keys_ca_node_free_shared`
- [ ] Verify all tests pass with new API

### Phase 4: Update Swift Layer
- [ ] Remove `CANode` class (raw handle wrapper)
- [ ] Update `SharedCANode` class to be the primary CA Node class
- [ ] Update all Swift code to use shared handles consistently
- [ ] Remove `CANode.addAdminSki()` method (was incorrectly calling shared function)
- [ ] Update Swift tests to use new API

### Phase 5: Validation
- [ ] Run all FFI tests to ensure no regressions
- [ ] Run E2E integration tests
- [ ] Verify memory management is correct
- [ ] Check for any remaining handle type inconsistencies

## Benefits

1. **Eliminates Crashes**: No more memory corruption from handle type mismatches
2. **Thread Safety**: Shared handles provide inherent thread safety
3. **API Consistency**: Single handle type for all CA Node operations
4. **Simplified Swift Layer**: Only one CA Node class needed
5. **Better Memory Management**: Consistent allocation/deallocation patterns
6. **Future-Proof**: Prevents similar issues in other FFI objects

## Prevention

- **Design Review**: Always check handle type consistency for new FFI functions
- **Type Safety**: Use Rust's type system to prevent handle mismatches
- **Documentation**: Clearly document handle type requirements
- **Testing**: Test handle consistency across all function combinations
- **Code Review**: Check for handle type consistency in reviews

## References

- **Design Document**: `FFI_API_DESIGN.md` (updated with new API and lessons learned)
- **Root Cause Analysis**: Memory corruption in `rn_keys_ca_node_add_admin_ski`
- **Swift Crash**: ASan backtrace showing invalid pointer dereference in `RwLock::write()`
